"""Interactive debugging on top of Binary Ninja's DebuggerController.

``DebuggerSession`` wraps one controller for a BinaryView and exposes the
primitives an MCP client needs: manage breakpoints (with optional conditions),
run/continue while blocking until the target next stops, and inspect the halted
state (registers, backtrace, memory). Every run/continue returns a single
normalized "stop result" dict so the client always knows what happened.

``DebuggerOperations`` is the mixin that gives ``BinaryOperations`` a lazily
created session bound to the current view.
"""

import contextlib
import threading
from typing import Any

import binaryninja as bn
from binaryninja.settings import Settings

from .condition import evaluate_condition

# Binary Ninja setting controlling the debugger's automatic stop at the program
# entry point. Toggling it (rather than "skipping the first breakpoint") is the
# only reliable way to suppress ONLY the entry-point stop: with it off, the stop
# is never created, so it can never be confused with a real user breakpoint.
_STOP_AT_ENTRY_SETTING = "debugger.stopAtEntryPoint"

# Default seconds a run/continue blocks before it pauses the target and returns.
# Keeps an MCP client from being stuck indefinitely on a hung or long target.
DEFAULT_RUN_TIMEOUT = 30.0


@contextlib.contextmanager
def _entry_point_stop(enabled: bool):
    """Temporarily set debugger.stopAtEntryPoint, restoring the prior value."""
    settings = Settings()
    try:
        previous = settings.get_bool(_STOP_AT_ENTRY_SETTING)
    except Exception:
        previous = None
    if previous is not None and previous != enabled:
        settings.set_bool(_STOP_AT_ENTRY_SETTING, enabled)
    try:
        yield
    finally:
        if previous is not None and previous != enabled:
            try:
                settings.set_bool(_STOP_AT_ENTRY_SETTING, previous)
            except Exception:
                pass


# Stop-reason classification.
#
# Visibility principle: the ONLY stops reported without auto-attached context
# are (a) a process exit (nothing left to inspect) and (b) a small allowlist of
# clean, self-explanatory stops. EVERYTHING else — every signal, exception, or
# reason we did not foresee, including DebugStopReason.UnknownReason — is treated
# as unexpected and gets registers + backtrace attached. This is an allowlist of
# "clean" rather than a blocklist of "crash", so a stop reason we never
# anticipated can never silently lose context.

# The process is gone; there is no state to read.
_EXIT_REASONS = {"ProcessExited"}

# Clean, expected stops that are self-explanatory (the client knows why: it set
# the breakpoint, requested the step, or asked to stop at entry). State remains
# available on demand via the registers/backtrace/memory routes.
_CLEAN_STOP_REASONS = {"SingleStep", "InitialBreakpoint"}

# Fatal faults. Used ONLY to LABEL an unexpected stop as "crashed" vs "signal"
# in the status field — this set being imperfect never affects whether context
# is attached (that is decided by exclusion from the clean/exit sets above).
_FATAL_REASONS = {
    "AccessViolation",
    "IllegalInstruction",
    "Calculation",
    "SignalIll",
    "SignalTrap",
    "SignalAbrt",
    "SignalFpe",
    "SignalBus",
    "SignalSegv",
    "SignalSys",
    "SignalStkflt",
    "ExcEmulation",
    "ExcSoftware",
    "ExcSyscall",
    "ExcMachSyscall",
    "ExcRpcAlert",
}


class Breakpoint:
    """A user breakpoint tracked by the session (id, address, condition)."""

    def __init__(self, bp_id: int, address: int, condition: str | None = None):
        self.id = bp_id
        self.address = address
        self.condition = condition
        self.enabled = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "address": hex(self.address),
            "condition": self.condition,
            "enabled": self.enabled,
        }


class DebuggerSession:
    """Owns a DebuggerController for one BinaryView plus the breakpoint registry."""

    def __init__(self, bv: bn.BinaryView):
        from binaryninja.debugger import DebuggerController

        self.bv = bv
        self.controller = DebuggerController(bv)
        self._breakpoints: dict[int, Breakpoint] = {}
        self._next_bp_id = 1
        # Guards the breakpoint registry and the _running flag ONLY. It is held
        # for short critical sections and never across a blocking wait, so a
        # pause/quit/inspect request is never stuck behind a running target.
        self._lock = threading.RLock()
        # True while a run/continue is blocked in a wait. Prevents overlapping
        # runs and lets inspection report a clear "target is running" error.
        self._running = False

    # ---------- breakpoints ----------

    def add_breakpoint(self, address: int, condition: str | None = None) -> Breakpoint:
        with self._lock:
            # Reuse an existing breakpoint at this address; just update the condition.
            for bp in self._breakpoints.values():
                if bp.address == address:
                    bp.condition = condition
                    return bp
            bp = Breakpoint(self._next_bp_id, address, condition)
            self._next_bp_id += 1
            self._breakpoints[bp.id] = bp
            self.controller.add_breakpoint(address)
            return bp

    def delete_breakpoint(self, bp_id: int) -> bool:
        with self._lock:
            bp = self._breakpoints.pop(bp_id, None)
            if not bp:
                return False
            try:
                self.controller.delete_breakpoint(bp.address)
            except Exception:
                pass
            return True

    def list_breakpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            return [bp.to_dict() for bp in sorted(self._breakpoints.values(), key=lambda b: b.id)]

    def _breakpoint_at(self, address: int) -> Breakpoint | None:
        with self._lock:
            for bp in self._breakpoints.values():
                if bp.address == address:
                    return bp
        return None

    # ---------- run / continue ----------

    def launch_and_run(
        self,
        stop_at_entry: bool = False,
        timeout: float | None = DEFAULT_RUN_TIMEOUT,
        **launch_opts,
    ) -> dict[str, Any]:
        """Launch the target from scratch and run until the next stop.

        By default the debugger's automatic entry-point stop is suppressed, so
        the target runs to the first user breakpoint (or exit/crash). Pass
        ``stop_at_entry=True`` to instead halt at the program entry point.

        Blocks until the target stops or ``timeout`` seconds elapse; on timeout
        the target is paused and reported with its current location (so a hung
        or long-running target can always be inspected). ``timeout=None`` waits
        indefinitely (only interruptible via an explicit pause).

        launch_opts may include: cmd_line (str), working_directory (str),
        adapter_type (str).
        """
        if not self._begin_run():
            return _busy_result()
        try:
            with self._lock:
                self._apply_launch_opts(launch_opts)
            with _entry_point_stop(stop_at_entry):
                reason, timed_out = self._wait(self.controller.launch_and_wait, timeout)
            if timed_out:
                return self._timeout_result()
            # With the auto entry-point stop suppressed, launch_and_wait returns
            # the first real stop. Apply conditional-breakpoint filtering; if the
            # first stop is a conditional breakpoint that is false, keep running.
            filtered = self._filter_stop(self._resolve_stop(reason))
            if filtered is not None:
                return filtered
            return self._continue_loop(timeout)
        finally:
            self._end_run()

    def resume(self, timeout: float | None = DEFAULT_RUN_TIMEOUT) -> dict[str, Any]:
        """Continue a running target until the next stop (see launch_and_run)."""
        if not self.is_live:
            return {"status": "error", "message": "No live target. Run the program first."}
        if not self._begin_run():
            return _busy_result()
        try:
            return self._continue_loop(timeout)
        finally:
            self._end_run()

    def pause(self) -> dict[str, Any]:
        """Request a running target to stop, so it can be inspected.

        Non-blocking: it signals the target and returns immediately. The
        in-flight run/continue then returns with the stop location (registers
        and backtrace attached). Use this to break into a hung or long-running
        target from another request.
        """
        if not self.is_live:
            return {"status": "error", "message": "No live target."}
        try:
            self.controller.pause()
        except Exception as e:
            return {"status": "error", "message": f"Pause failed: {e}"}
        return {
            "status": "ok",
            "message": "Pause requested; the in-flight run/continue will return with the stop location.",
        }

    def _continue_loop(self, timeout: float | None) -> dict[str, Any]:
        """go_and_wait, transparently re-continuing past conditional breakpoints
        whose condition evaluates false. Returns on any real stop or timeout."""
        while True:
            reason, timed_out = self._wait(self.controller.go_and_wait, timeout)
            if timed_out:
                return self._timeout_result()
            result = self._resolve_stop(reason)
            filtered = self._filter_stop(result)
            if filtered is not None:
                return filtered
            # Condition evaluated false: keep going.

    def _wait(self, wait_fn, timeout: float | None):
        """Run a blocking wait (launch/go_and_wait) with an optional timeout.

        The blocking call runs in a worker thread with NO session lock held, so
        pause/quit/inspect requests stay responsive. On timeout the target is
        paused, which makes the wait return. Returns ``(reason, timed_out)``.
        """
        if not timeout or timeout <= 0:
            return wait_fn(), False

        box: dict[str, Any] = {}
        done = threading.Event()

        def worker():
            try:
                box["reason"] = wait_fn()
            except Exception as e:  # surfaced to the caller below
                box["error"] = e
            finally:
                done.set()

        threading.Thread(target=worker, daemon=True, name="bn-debug-wait").start()

        if done.wait(timeout):
            if "error" in box:
                raise box["error"]
            return box["reason"], False

        # Timed out: force the target to stop so the wait returns.
        try:
            self.controller.pause()
        except Exception as e:
            bn.log_warn(f"Debugger: pause after timeout failed: {e}")
        # Bounded wait for the paused stop to land; if it never does, report the
        # timeout anyway rather than blocking forever.
        if not done.wait(10):
            bn.log_warn("Debugger: target did not stop after pause; reporting timeout")
            return None, True
        if "error" in box:
            raise box["error"]
        return box.get("reason"), True

    def _begin_run(self) -> bool:
        """Claim the single run slot. Returns False if a run is already active."""
        with self._lock:
            if self._running:
                return False
            self._running = True
            return True

    def _end_run(self) -> None:
        with self._lock:
            self._running = False

    def _timeout_result(self) -> dict[str, Any]:
        """Result for a run/continue that was auto-paused after the timeout.

        The target is now stopped, so the full context is attached — the client
        can see exactly where it is (e.g. a hang) and then inspect, continue, or
        quit.
        """
        ctx = self.state_snapshot()
        addr = ctx.get("ip")
        return {
            "status": "paused",
            "stop_reason": "Timeout",
            "timed_out": True,
            "address": addr,
            "function": self._function_name(addr),
            "message": (
                f"Target still running after timeout; paused at {addr}. "
                "It may be hung or doing long work — inspect the backtrace, continue, or quit."
            ),
            "registers": ctx.get("registers"),
            "backtrace": ctx.get("backtrace"),
        }

    def _filter_stop(self, result: dict[str, Any]) -> dict[str, Any] | None:
        """Apply conditional-breakpoint filtering to a stop result.

        Returns the result to report, or ``None`` if this is a conditional
        breakpoint whose condition is false (meaning: keep running). Non-
        breakpoint stops (exit, crash, entry) always report.
        """
        if result["status"] != "breakpoint":
            return result
        bp = self._breakpoint_at(int(result["address"], 16))
        if bp is None or not bp.condition:
            return result
        try:
            hit = evaluate_condition(bp.condition, self._register_values())
        except Exception as e:
            # A broken condition shouldn't strand the client; stop and report.
            result["condition_error"] = f"{bp.condition!r}: {e}"
            return result
        return result if hit else None

    def _apply_launch_opts(self, opts: dict[str, Any]) -> None:
        mapping = {
            "cmd_line": "cmd_line",
            "working_directory": "working_directory",
            "adapter_type": "adapter_type",
        }
        for key, attr in mapping.items():
            value = opts.get(key)
            if value:
                try:
                    setattr(self.controller, attr, value)
                except Exception as e:
                    bn.log_warn(f"Debugger: failed to set {attr}={value!r}: {e}")

    # ---------- stop-result construction ----------

    def _resolve_stop(self, reason) -> dict[str, Any]:
        reason_name = _reason_name(reason)

        # 1. The process is gone — the exit code is the whole story.
        if reason_name in _EXIT_REASONS:
            code = _safe(lambda: self.controller.exit_code, default=None)
            return {
                "status": "exited",
                "stop_reason": reason_name,
                "exit_code": code,
                "message": f"Process exited with code {code}"
                if code is not None
                else "Process exited",
            }

        ip = _safe(lambda: self.controller.ip, default=None)
        addr_hex = hex(ip) if isinstance(ip, int) else None
        func = self._function_name(addr_hex)
        bp = self._breakpoint_at(ip) if isinstance(ip, int) else None

        # 2. Clean stop at a breakpoint the client set — self-explanatory.
        if reason_name == "Breakpoint" and bp is not None:
            where = f" in {func}" if func else ""
            return {
                "status": "breakpoint",
                "stop_reason": reason_name,
                "breakpoint_id": bp.id,
                "address": addr_hex,
                "function": func,
                "message": f"Stopped at breakpoint #{bp.id} ({addr_hex}){where}",
            }

        # 3. Other clean, expected stops (single step, requested entry stop).
        if reason_name in _CLEAN_STOP_REASONS:
            return {
                "status": "stopped",
                "stop_reason": reason_name,
                "address": addr_hex,
                "function": func,
                "message": f"Stopped ({reason_name}) at {addr_hex}",
            }

        # 4. EVERYTHING else is unexpected — a signal, an exception, a
        # breakpoint we did not set, or a reason we never anticipated
        # (including UnknownReason). Always attach full context so the client
        # can see why the target stopped and never has to guess.
        ctx = self.state_snapshot()
        ctx_addr = ctx.get("ip") or addr_hex
        is_fatal = reason_name in _FATAL_REASONS
        is_signal = reason_name.startswith("Signal") or reason_name.startswith("Exc")
        status = "crashed" if is_fatal else ("signal" if is_signal else "stopped")
        if is_fatal:
            headline = f"Target crashed ({reason_name})"
        elif is_signal:
            headline = f"Target stopped on signal {reason_name}"
        else:
            headline = f"Target stopped unexpectedly ({reason_name})"
        return {
            "status": status,
            "stop_reason": reason_name,
            "signal": reason_name if is_signal or is_fatal else None,
            "address": ctx_addr,
            "function": self._function_name(ctx_addr),
            "message": f"{headline} at {ctx_addr}",
            "registers": ctx.get("registers"),
            "backtrace": ctx.get("backtrace"),
        }

    # ---------- inspection ----------

    def get_registers(self) -> list[dict[str, Any]]:
        with self._lock:
            self._require_halted()
            regs = self.controller.regs
            out = []
            for name, reg in regs.regs.items():
                out.append(
                    {
                        "name": name,
                        "value": hex(reg.value),
                        "width": reg.width,
                        "hint": reg.hint or None,
                    }
                )
            return out

    def get_backtrace(self) -> list[dict[str, Any]]:
        with self._lock:
            self._require_halted()
            thread = self.controller.active_thread
            frames = self.controller.frames_of_thread(thread.tid)
            out = []
            for f in frames:
                out.append(
                    {
                        "index": f.index,
                        "pc": hex(f.pc),
                        "sp": hex(f.sp),
                        "fp": hex(f.fp),
                        "function": f.func_name or None,
                        "func_start": hex(f.func_start) if f.func_start else None,
                        "module": f.module or None,
                    }
                )
            return out

    def read_memory(self, address: int, size: int) -> bytes:
        with self._lock:
            self._require_halted()
            buf = self.controller.read_memory(address, size)
            return bytes(buf) if buf is not None else b""

    def state_snapshot(self) -> dict[str, Any]:
        """Registers + backtrace + ip, best-effort (used by the crash path)."""
        ip = _safe(lambda: self.controller.ip, default=None)
        return {
            "ip": hex(ip) if isinstance(ip, int) else None,
            "registers": _safe(self._register_dicts, default=None),
            "backtrace": _safe(self._backtrace_dicts, default=None),
        }

    # ---------- lifecycle ----------

    def quit(self) -> dict[str, Any]:
        if not self.is_live:
            return {"status": "ok", "message": "No live target."}
        # Non-blocking: it signals termination without holding the session lock,
        # so it works even while a run/continue is blocked on a hung target. The
        # in-flight run then returns with a ProcessExited result.
        try:
            self.controller.quit()
        except Exception as e:
            return {"status": "error", "message": f"Failed to quit: {e}"}
        return {"status": "ok", "message": "Termination requested."}

    @property
    def is_live(self) -> bool:
        # `connected` is true while a target exists; `live_view` is deprecated
        # and returns a static view even with no process, so it can't be used.
        return bool(_safe(lambda: self.controller.connected, default=False))

    # ---------- helpers ----------

    def _require_halted(self) -> None:
        if not self.is_live:
            raise DebuggerError("No live target. Run the program first.")
        if _safe(lambda: self.controller.running, default=False):
            raise DebuggerError("Target is running. It must be stopped to inspect state.")

    def _register_values(self) -> dict[str, int]:
        regs = self.controller.regs
        return {name: reg.value for name, reg in regs.regs.items()}

    def _register_dicts(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "value": hex(reg.value), "width": reg.width, "hint": reg.hint or None}
            for name, reg in self.controller.regs.regs.items()
        ]

    def _backtrace_dicts(self) -> list[dict[str, Any]]:
        thread = self.controller.active_thread
        return [
            {
                "index": f.index,
                "pc": hex(f.pc),
                "sp": hex(f.sp),
                "function": f.func_name or None,
                "module": f.module or None,
            }
            for f in self.controller.frames_of_thread(thread.tid)
        ]

    def _function_name(self, addr_hex: str | None) -> str | None:
        if not addr_hex:
            return None
        try:
            funcs = self.bv.get_functions_containing(int(addr_hex, 16))
            if funcs:
                return funcs[0].name
        except Exception:
            pass
        return None


class DebuggerError(Exception):
    """Raised for debugger-state errors that map to a 400 response."""


def _busy_result() -> dict[str, Any]:
    return {
        "status": "error",
        "message": "A run/continue is already in progress. Pause it before starting another.",
    }


def _reason_name(reason) -> str:
    return getattr(reason, "name", str(reason))


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


class DebuggerOperations:
    """Mixin giving BinaryOperations a debugger session for the current view."""

    def get_debugger(self, create: bool = True) -> DebuggerSession | None:
        """Return the DebuggerSession bound to the current view, creating it lazily.

        The session is rebound if the current view changed.
        """
        bv = self.current_view
        if bv is None:
            raise DebuggerError("No binary loaded")
        session = getattr(self, "_debugger_session", None)
        if session is not None and session.bv is bv:
            return session
        if not create:
            return session
        session = DebuggerSession(bv)
        self._debugger_session = session
        return session

    def shutdown_debugger(self) -> None:
        """Terminate any live target; called on server stop / view close."""
        session = getattr(self, "_debugger_session", None)
        if session is not None:
            try:
                session.quit()
            except Exception:
                pass
            self._debugger_session = None
