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
import os
import re
import threading
from typing import Any

import binaryninja as bn
from binaryninja.settings import Settings

from .condition import evaluate_condition

# Parses one LLDB `memory region` output line, e.g.
#   [0x0000000000401000-0x0000000000402000) r-x /path/to/exe PT_LOAD[1]
#   [0x00007ffffffde000-0x00007ffffffff000) rw- [stack]
_LLDB_REGION_RE = re.compile(r"\[0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)\)\s*(\S+)?\s*(.*)")

# Some adapters do not populate a module's size (they report a garbage value).
# Only use a module's size for range containment when it is plausibly real, so a
# bogus size can never misattribute an unrelated address (e.g. a stack pointer)
# to an image.
_MAX_IMAGE_SIZE = 1 << 34  # 16 GiB

# LLDB colorizes disassembly with ANSI escape codes; strip them from captured text.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

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
        # Whether the current run attaches the full context (thread + registers +
        # stack telescope + disasm-at-PC + backtrace) to its stop result. Set per
        # run; safe as a plain attribute because only one run is active at a time.
        self._include_context = True

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
        context: bool = True,
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

        ``context=True`` (default) attaches the full context to the stop result.

        launch_opts may include: cmd_line (str), working_directory (str),
        adapter_type (str).
        """
        if not self._begin_run():
            return _busy_result()
        self._include_context = context
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

    def resume(
        self, timeout: float | None = DEFAULT_RUN_TIMEOUT, context: bool = True
    ) -> dict[str, Any]:
        """Continue a running target until the next stop (see launch_and_run)."""
        if not self.is_live:
            return {"status": "error", "message": "No live target. Run the program first."}
        if not self._begin_run():
            return _busy_result()
        self._include_context = context
        try:
            return self._continue_loop(timeout)
        finally:
            self._end_run()

    def step_into(
        self, timeout: float | None = DEFAULT_RUN_TIMEOUT, context: bool = True
    ) -> dict[str, Any]:
        """Execute a single instruction, stepping into calls."""
        return self._step_control(self.controller.step_into_and_wait, timeout, context)

    def step_over(
        self, timeout: float | None = DEFAULT_RUN_TIMEOUT, context: bool = True
    ) -> dict[str, Any]:
        """Execute a single instruction, stepping over calls."""
        return self._step_control(self.controller.step_over_and_wait, timeout, context)

    def step_out(
        self, timeout: float | None = DEFAULT_RUN_TIMEOUT, context: bool = True
    ) -> dict[str, Any]:
        """Run until the current function returns to its caller (finish)."""
        return self._step_control(self.controller.step_return_and_wait, timeout, context)

    def run_to(
        self, address: int, timeout: float | None = DEFAULT_RUN_TIMEOUT, context: bool = True
    ) -> dict[str, Any]:
        """Resume until the target reaches ``address`` (advance/until)."""
        return self._step_control(
            lambda: self.controller.run_to_and_wait(address), timeout, context
        )

    def _step_control(self, wait_fn, timeout: float | None, context: bool = True) -> dict[str, Any]:
        """Run one blocking step/advance op and report where it stopped.

        Reuses the run machinery (single-run guard, timeout auto-pause,
        stop-result contract) but does not loop past conditional breakpoints:
        a step is a single action, so we report wherever it lands.
        """
        if not self.is_live:
            return {"status": "error", "message": "No live target. Run the program first."}
        if not self._begin_run():
            return _busy_result()
        self._include_context = context
        try:
            reason, timed_out = self._wait(wait_fn, timeout)
            if timed_out:
                return self._timeout_result()
            return self._resolve_stop(reason)
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

    def status(self) -> dict[str, Any]:
        """Session/adapter status, queryable at any time (no live target needed).

        Reports the backend ``adapter`` — the command dialect to use with
        :meth:`execute_backend_command` — and, when a target is live, whether it
        is running and where it is halted. Lets a client learn the dialect before
        issuing its first backend command.
        """
        live = self.is_live
        running = bool(_safe(lambda: self.controller.running, default=False)) if live else False
        ip_hex = None
        func = None
        if live and not running:
            ip = _safe(lambda: self.controller.ip, default=None)
            ip_hex = hex(ip) if isinstance(ip, int) else None
            func = self._function_name(ip_hex)
        with self._lock:
            bp_count = len(self._breakpoints)
        return {
            "adapter": _safe(lambda: self.controller.adapter_type, default=None),
            "live": live,
            "running": running,
            "ip": ip_hex,
            "function": func,
            "breakpoints": bp_count,
        }

    def execute_backend_command(self, command: str) -> dict[str, Any]:
        """Run a raw command in the underlying debug adapter's console.

        Escape hatch to the LLDB/WinDbg backend: any command the adapter accepts
        (e.g. LLDB ``watchpoint set ...`` / ``memory region``, WinDbg ``ba``)
        runs and its printed output is returned, along with which adapter is
        active so the caller knows the command dialect. Not run under the session
        lock, so it stays responsive. Prefer the structured debug_* tools for
        execution control — commands that change execution state here bypass this
        session's stop tracking.
        """
        if not self.is_live:
            return {"status": "error", "message": "No live target. Run the program first."}
        adapter = _safe(lambda: self.controller.adapter_type, default=None)
        try:
            output = self.controller.execute_backend_command(command)
        except Exception as e:
            return {
                "status": "error",
                "adapter": adapter,
                "command": command,
                "message": f"Backend command failed: {e}",
            }
        return {"status": "ok", "adapter": adapter, "command": command, "output": output}

    # ---------- address / memory-map inspection ----------

    def list_modules(self) -> list[dict[str, Any]]:
        """List the images loaded in the target (executable + shared libraries)."""
        if not self.is_live:
            raise DebuggerError("No live target. Run the program first.")
        out = []
        for m in self.controller.modules:
            base = getattr(m, "address", None)
            size = getattr(m, "size", None)
            # Some adapters report a garbage size; only surface a plausible one.
            plausible_size = isinstance(size, int) and 0 < size < _MAX_IMAGE_SIZE
            out.append(
                {
                    "name": getattr(m, "short_name", None) or _basename(getattr(m, "name", "")),
                    "path": getattr(m, "name", None),
                    "base": hex(base) if isinstance(base, int) else None,
                    "size": hex(size) if plausible_size else None,
                }
            )
        return out

    def resolve_address(self, address: int) -> dict[str, Any]:
        """Resolve a runtime address to its memory mapping and backing image.

        Finds the memory region (page mapping) containing ``address`` and, when
        that region is backed by a loaded image, reports the image's load base
        and the address's offset within the image, such that
        ``image_base + image_offset == address``. Purely descriptive — no
        static/analysis translation is performed.
        """
        if not self.is_live:
            return {"status": "error", "message": "No live target. Run the program first."}

        region = self._query_memory_region(address)
        if region is None:
            return {
                "status": "error",
                "address": hex(address),
                "message": "Could not query the memory map for this adapter.",
            }
        if not region.get("mapped"):
            return {
                "status": "unmapped",
                "address": hex(address),
                "message": "Address is not in any mapped region.",
            }
        # LLDB reports inter-mapping gaps as regions with no access permissions
        # ("---"); that is not a real mapping, so report it as unmapped.
        perms = region.get("perms")
        if perms and set(perms) <= {"-"}:
            return {
                "status": "unmapped",
                "address": hex(address),
                "mmap_base": hex(region["start"]),
                "mmap_end": hex(region["end"]),
                "message": "Address is in an inaccessible gap between mappings.",
            }

        result: dict[str, Any] = {
            "status": "ok",
            "address": hex(address),
            "mmap_base": hex(region["start"]),
            "mmap_end": hex(region["end"]),
            "permissions": region.get("perms"),
            "region_label": region.get("label"),
            "image_name": None,
            "image_base": None,
            "image_offset": None,
        }
        image = self._image_for_region(address, region)
        if image is not None:
            name, base = image
            result["image_name"] = name
            result["image_base"] = hex(base)
            result["image_offset"] = hex(address - base)
        return result

    def _query_memory_region(self, address: int) -> dict[str, Any] | None:
        """Ask the adapter for the memory region containing ``address``.

        Returns a parsed region dict, ``{"mapped": False}`` when the address is
        unmapped, or ``None`` when the adapter/output is not understood.
        """
        adapter = (_safe(lambda: self.controller.adapter_type, default="") or "").upper()
        if "DBGENG" in adapter or "WINDBG" in adapter:
            return None  # WinDbg (!address) parsing not implemented yet
        try:
            output = self.controller.execute_backend_command(f"memory region {hex(address)}")
        except Exception:
            return None
        return self._parse_lldb_region(output)

    @staticmethod
    def _parse_lldb_region(output: str) -> dict[str, Any] | None:
        text = (output or "").strip()
        if not text or text.lower().startswith("error"):
            # LLDB prints an error for an unmapped address.
            return {"mapped": False}
        m = _LLDB_REGION_RE.search(text)
        if not m:
            return None
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        perms = m.group(3)
        rest = (m.group(4) or "").strip()
        # Strip a trailing "PT_LOAD[n]" segment tag.
        seg = re.search(r"\bPT_LOAD\[(\d+)\]", rest)
        segment = int(seg.group(1)) if seg else None
        rest = re.sub(r"\s*\bPT_LOAD\[\d+\]", "", rest).strip()
        label = None
        file_path = None
        if rest.startswith("[") and rest.endswith("]"):
            label = rest  # e.g. [stack], [heap], [vdso]
        elif rest:
            file_path = rest
        return {
            "mapped": True,
            "start": start,
            "end": end,
            "perms": perms,
            "label": label,
            "file": file_path,
            "segment": segment,
        }

    def _image_for_region(self, address: int, region: dict[str, Any]):
        """Return ``(image_name, image_base)`` for the region, or None.

        Prefers matching the region's backing file to a loaded image; falls back
        to any loaded image whose reported range contains the address (covers
        anonymous segments such as .bss that carry no file label).
        """
        modules = list(_safe(lambda: self.controller.modules, default=[]) or [])
        file_path = region.get("file")
        if file_path:
            target = _basename(file_path)
            for m in modules:
                if (
                    getattr(m, "name", None) == file_path
                    or _basename(getattr(m, "name", "")) == target
                ):
                    return (getattr(m, "short_name", None) or target, m.address)
        for m in modules:
            base = getattr(m, "address", None)
            size = getattr(m, "size", None)
            if (
                isinstance(base, int)
                and isinstance(size, int)
                and 0 < size < _MAX_IMAGE_SIZE
                and base <= address < base + size
            ):
                return (getattr(m, "short_name", None) or _basename(getattr(m, "name", "")), base)
        return None

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
        ip = _safe(lambda: self.controller.ip, default=None)
        addr = hex(ip) if isinstance(ip, int) else None
        result = {
            "status": "paused",
            "stop_reason": "Timeout",
            "timed_out": True,
            "address": addr,
            "function": self._function_name(addr),
            "message": (
                f"Target still running after timeout; paused at {addr}. "
                "It may be hung or doing long work — inspect the backtrace, continue, or quit."
            ),
        }
        # A timeout-pause is an unexpected halt: always keep at least regs+bt.
        return self._attach_context(result, expected=False)

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

        # 1. The process is gone — the exit code is the whole story (no context).
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
            result = {
                "status": "breakpoint",
                "stop_reason": reason_name,
                "breakpoint_id": bp.id,
                "address": addr_hex,
                "function": func,
                "message": f"Stopped at breakpoint #{bp.id} ({addr_hex}){where}",
            }
            return self._attach_context(result, expected=True)

        # 3. Other clean, expected stops (single step, requested entry stop).
        if reason_name in _CLEAN_STOP_REASONS:
            result = {
                "status": "stopped",
                "stop_reason": reason_name,
                "address": addr_hex,
                "function": func,
                "message": f"Stopped ({reason_name}) at {addr_hex}",
            }
            return self._attach_context(result, expected=True)

        # 4. EVERYTHING else is unexpected — a signal, an exception, a breakpoint
        # we did not set, or a reason we never anticipated (including
        # UnknownReason). These always carry at least registers + backtrace so
        # the client never has to guess why the target stopped.
        is_fatal = reason_name in _FATAL_REASONS
        is_signal = reason_name.startswith("Signal") or reason_name.startswith("Exc")
        status = "crashed" if is_fatal else ("signal" if is_signal else "stopped")
        if is_fatal:
            headline = f"Target crashed ({reason_name})"
        elif is_signal:
            headline = f"Target stopped on signal {reason_name}"
        else:
            headline = f"Target stopped unexpectedly ({reason_name})"
        result = {
            "status": status,
            "stop_reason": reason_name,
            "signal": reason_name if is_signal or is_fatal else None,
            "address": addr_hex,
            "function": func,
            "message": f"{headline} at {addr_hex}",
        }
        return self._attach_context(result, expected=False)

    def _attach_context(self, result: dict[str, Any], expected: bool) -> dict[str, Any]:
        """Attach state to a halted stop result.

        With context enabled (default), attaches the full context (thread,
        registers, stack telescope, disasm-at-PC, backtrace). With it disabled,
        expected stops stay lean, but UNEXPECTED stops still get registers +
        backtrace — the visibility guarantee is never traded away.
        """
        if self._include_context:
            result.update(self._build_context())
        elif not expected:
            snap = self.state_snapshot()
            result["registers"] = snap.get("registers")
            result["backtrace"] = snap.get("backtrace")
        return result

    # ---------- inspection ----------

    def get_registers(self, full: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            self._require_halted()
            return self._format_registers(full=full)

    def _format_registers(self, full: bool = False) -> list[dict[str, Any]]:
        """Format the target's registers.

        By default returns only the important registers for the detected
        architecture (general-purpose + pc/sp/flags), curating out the dozens of
        sub-registers and vector/FPU registers. ``full=True`` returns them all.
        For an unrecognized architecture we return everything rather than risk
        hiding something.
        """
        regs = self.controller.regs
        all_regs = [
            {"name": name, "value": hex(reg.value), "width": reg.width, "hint": reg.hint or None}
            for name, reg in regs.regs.items()
        ]
        if full:
            return all_regs
        important = _important_registers(regs.regs.keys())
        if important is None:
            return all_regs
        by_name = {r["name"]: r for r in all_regs}
        return [by_name[name] for name in important if name in by_name]

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

    # ---------- context view ----------

    def context(self) -> dict[str, Any]:
        """The full halted-state context, on demand (requires a stopped target)."""
        with self._lock:
            self._require_halted()
            ip = _safe(lambda: self.controller.ip, default=None)
            addr = hex(ip) if isinstance(ip, int) else None
            result = {"status": "ok", "address": addr, "function": self._function_name(addr)}
            result.update(self._build_context())
            return result

    def _build_context(self) -> dict[str, Any]:
        """Assemble the pwndbg-style context of the halted target."""
        return {
            "thread": _safe(self._active_thread_info, default=None),
            "registers": _safe(self._register_dicts, default=None),
            "stack": _safe(self._stack_telescope, default=None),
            "disassembly": _safe(self._disasm_at_pc, default=None),
            "backtrace": _safe(self._backtrace_dicts, default=None),
        }

    def _active_thread_info(self) -> dict[str, Any] | None:
        t = self.controller.active_thread
        rip = getattr(t, "rip", None)
        return {"tid": getattr(t, "tid", None), "rip": hex(rip) if isinstance(rip, int) else None}

    def _stack_pointer(self) -> int | None:
        regs = self.controller.regs.regs
        for name in ("rsp", "esp", "sp"):
            if name in regs:
                return regs[name].value
        return None

    def _stack_telescope(self, count: int = 8) -> list[dict[str, Any]] | None:
        """Dump ``count`` pointer-sized words from the stack pointer, annotating
        any slot that points at a readable string."""
        sp = self._stack_pointer()
        if not isinstance(sp, int):
            return None
        out = []
        for i in range(count):
            addr = sp + i * 8
            raw = _safe(lambda a=addr: self.controller.read_memory(a, 8), default=None)
            if raw is None:
                break
            b = bytes(raw)
            if len(b) < 8:
                break
            value = int.from_bytes(b[:8], "little")
            entry = {"address": hex(addr), "value": hex(value)}
            s = self._maybe_string(value)
            if s is not None:
                entry["points_to"] = s
            out.append(entry)
        return out or None

    def _maybe_string(self, pointer: int, maxlen: int = 48) -> str | None:
        """If ``pointer`` points at a run of printable bytes, return that string."""
        if not isinstance(pointer, int) or pointer == 0:
            return None
        raw = _safe(lambda: self.controller.read_memory(pointer, maxlen), default=None)
        if raw is None:
            return None
        chars = []
        for ch in bytes(raw):
            if ch == 0:
                break
            if 32 <= ch <= 126:
                chars.append(chr(ch))
            else:
                return None
        text = "".join(chars)
        return text if len(text) >= 4 else None

    def _disasm_at_pc(self, count: int = 8) -> str | None:
        """Disassemble ``count`` instructions at the runtime PC via the adapter.

        Uses the adapter's own disassembler (live memory), so it is correct
        regardless of ASLR/PIE. Returns the adapter's raw text.
        """
        ip = _safe(lambda: self.controller.ip, default=None)
        if not isinstance(ip, int):
            return None
        adapter = (_safe(lambda: self.controller.adapter_type, default="") or "").upper()
        if "DBGENG" in adapter or "WINDBG" in adapter:
            cmd = f"u {hex(ip)} L{count}"
        else:
            cmd = f"disassemble -s {hex(ip)} -c {count}"
        out = _safe(lambda: self.controller.execute_backend_command(cmd), default=None)
        if not isinstance(out, str):
            return None
        out = _ANSI_RE.sub("", out).strip()
        return out or None

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
        # Concise set for auto-attached stop context; use get_registers(full=True)
        # for the complete register file.
        return self._format_registers(full=False)

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


# Important registers per architecture, in display order: general-purpose plus
# pc/sp/flags. Detected from the register names present so we curate the right
# set; an unrecognized architecture falls back to showing every register.
_ARCH_IMPORTANT_REGS: dict[str, list[str]] = {
    "x86_64": [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags",
    ],
    "x86": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"],
    "aarch64": [f"x{i}" for i in range(31)] + ["sp", "pc", "cpsr", "pstate"],
    "armv7": [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"],
}  # fmt: skip


def _important_registers(names) -> list[str] | None:
    """Return the important-register list for the arch implied by ``names``,
    or None when the architecture is unrecognized (caller shows all)."""
    present = set(names)
    if "rip" in present:
        arch = "x86_64"
    elif "eip" in present:
        arch = "x86"
    elif "pc" in present and "x0" in present:
        arch = "aarch64"
    elif "pc" in present and "r0" in present:
        arch = "armv7"
    else:
        return None
    return _ARCH_IMPORTANT_REGS[arch]


def _busy_result() -> dict[str, Any]:
    return {
        "status": "error",
        "message": "A run/continue is already in progress. Pause it before starting another.",
    }


def _basename(path: str) -> str:
    return os.path.basename(path) if path else ""


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
