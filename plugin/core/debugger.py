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

from .condition import ConditionError, evaluate, evaluate_condition

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

# Parse the adapter's watchpoint number from an LLDB `watchpoint set` line:
#   Watchpoint created: Watchpoint 1: addr = 0x... size = 8 ...
_LLDB_WP_SET_RE = re.compile(r"Watchpoint\s+(\d+):")
# Parse the stop reason from LLDB `thread info` (ANSI already stripped):
#   thread #1: ... stop reason = watchpoint 1
_LLDB_STOP_REASON_RE = re.compile(r"stop reason = (.+?)\s*$", re.MULTILINE)

# LLDB `-w` access-type keyword per watchpoint type.
_LLDB_WATCH_ACCESS = {"read": "read", "write": "write", "readwrite": "read_write"}

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


# Breakpoint-type names for the values Binary Ninja's controller reports. The
# value arrives as a plain int from the core, so map by int rather than by enum.
_BP_TYPE_NAMES = {
    0: "Software",
    1: "HardwareExecute",
    2: "HardwareRead",
    3: "HardwareWrite",
    4: "HardwareAccess",
}


def _bp_type_name(raw) -> str | None:
    if raw is None:
        return None
    try:
        return _BP_TYPE_NAMES.get(int(raw), str(raw))
    except (TypeError, ValueError):
        return str(raw)


class Breakpoint:
    """A user breakpoint tracked by the session (id, address, symbol, condition)."""

    def __init__(
        self,
        bp_id: int,
        address: int,
        condition: str | None = None,
        symbol: str | None = None,
    ):
        self.id = bp_id
        self.address = address
        self.condition = condition
        self.symbol = symbol
        self.enabled = True
        # True when this entry was adopted from Binary Ninja's own breakpoint
        # list (placed in the UI) rather than created through this server.
        self.adopted = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "address": hex(self.address),
            "symbol": self.symbol,
            "condition": self.condition,
            "enabled": self.enabled,
        }


class Watchpoint:
    """A hardware watchpoint tracked by the session.

    ``adapter_num`` is the underlying adapter's own watchpoint number (used to
    delete/enable/disable it and to attribute a stop to it).
    """

    def __init__(self, wp_id: int, address: int, size: int, wtype: str, adapter_num: int):
        self.id = wp_id
        self.address = address
        self.size = size
        self.wtype = wtype  # "read" | "write" | "readwrite"
        self.adapter_num = adapter_num
        self.enabled = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "address": hex(self.address),
            "size": self.size,
            "type": self.wtype,
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
        self._watchpoints: dict[int, Watchpoint] = {}
        self._next_wp_id = 1
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
        # Currently selected stack frame for inspection (0 = innermost). Persists
        # across inspection calls; reset to 0 on each run (a new stop starts at 0).
        self._selected_frame = 0

    # ---------- breakpoints ----------

    def resolve_location(self, ident: str) -> tuple[int, str | None]:
        """Resolve a breakpoint location (address or symbol/function name).

        Returns ``(address, symbol)`` where ``symbol`` is the resolved name (or
        None when an address was given). Raises DebuggerError if unresolved.
        """
        s = (ident or "").strip()
        if not s:
            raise DebuggerError("Empty breakpoint location.")
        # Numeric address (0x-prefixed or bare hex).
        try:
            if s.lower().startswith("0x"):
                return int(s, 16), None
            if all(c in "0123456789abcdefABCDEF" for c in s):
                return int(s, 16), None
        except ValueError:
            pass
        # Function by name.
        try:
            getter = getattr(self.bv, "get_functions_by_name", None)
            funcs = getter(s) if callable(getter) else None
            if funcs:
                return int(funcs[0].start), funcs[0].name
        except Exception:
            pass
        # Symbol by raw, then pretty, name.
        for getter_name in ("get_symbol_by_raw_name", "get_symbol_by_name"):
            try:
                getter = getattr(self.bv, getter_name, None)
                sym = getter(s) if callable(getter) else None
                if sym and hasattr(sym, "address"):
                    return int(sym.address), getattr(sym, "name", s)
            except Exception:
                pass
        raise DebuggerError(f"Could not resolve breakpoint location: {ident!r}")

    def add_breakpoint(
        self, address: int, condition: str | None = None, symbol: str | None = None
    ) -> Breakpoint:
        with self._lock:
            # Reuse an existing breakpoint at this address; update its metadata.
            for bp in self._breakpoints.values():
                if bp.address == address:
                    bp.condition = condition
                    if symbol:
                        bp.symbol = symbol
                    return bp
            bp = Breakpoint(self._next_bp_id, address, condition, symbol)
            self._next_bp_id += 1
            self._breakpoints[bp.id] = bp
            self.controller.add_breakpoint(address)
            return bp

    def add_breakpoint_at(self, ident: str, condition: str | None = None) -> Breakpoint:
        """Add a breakpoint by address or symbol/function name."""
        address, symbol = self.resolve_location(ident)
        return self.add_breakpoint(address, condition, symbol)

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

    def set_breakpoint_enabled(self, bp_id: int, enabled: bool) -> Breakpoint:
        """Enable or disable a breakpoint by id."""
        with self._lock:
            bp = self._breakpoints.get(bp_id)
            if bp is None:
                raise DebuggerError(f"No breakpoint with id {bp_id}")
            try:
                if enabled:
                    self.controller.enable_breakpoint(bp.address)
                else:
                    self.controller.disable_breakpoint(bp.address)
            except Exception as e:
                raise DebuggerError(
                    f"Failed to {'enable' if enabled else 'disable'} breakpoint: {e}"
                )
            bp.enabled = enabled
            return bp

    def list_breakpoints(self) -> list[dict[str, Any]]:
        """Every breakpoint of this view, merged from both registries.

        ``self._breakpoints`` holds the ones this server created: they carry an
        ``id`` and, when conditional, a condition evaluated by this plugin's own
        expression evaluator (see ``core.condition``). Binary Ninja's controller
        holds *all* of them, the ones placed in the UI included, with the
        module/offset it stores them under and the condition that BN's own
        expression parser evaluates. Those are two different engines, so the
        conditions are reported separately: ``condition_engine`` says which one
        owns ``condition``, and ``native_condition`` is set whenever BN holds a
        condition of its own.

        A native breakpoint that already has an absolute address and is not in
        the registry is adopted into it, so it gets an ``id`` and the
        delete/enable/disable tools act on it like any other. One that is still
        relative (module+offset, no address yet because no target is live)
        cannot be addressed that way, so it is reported with ``id: null`` and
        ``pending: true``.
        """
        # Queried before taking the lock: this is BN's own state, and the lock
        # guards only the registry.
        native = _safe(lambda: list(self.controller.breakpoints), default=None)
        synced = native is not None
        native = native or []
        native_addrs = {int(getattr(n, "address", 0) or 0) for n in native}

        with self._lock:
            if synced:
                # Drop adopted entries BN no longer reports (e.g. the target was
                # relaunched at a different ASLR base), so they cannot pile up.
                for bp_id in [
                    i
                    for i, bp in self._breakpoints.items()
                    if bp.adopted and bp.address not in native_addrs
                ]:
                    del self._breakpoints[bp_id]

            entries: dict[int, dict[str, Any]] = {}
            for bp in sorted(self._breakpoints.values(), key=lambda b: b.id):
                entry = bp.to_dict()
                entry["source"] = "ui" if bp.adopted else "mcp"
                entry["condition_engine"] = "mcp" if bp.condition else None
                entries[bp.address] = entry
            pending: list[dict[str, Any]] = []

            for nbp in native:
                offset = int(getattr(nbp, "offset", 0) or 0)
                address = int(getattr(nbp, "address", 0) or 0)
                condition = (getattr(nbp, "condition", "") or "").strip()
                shared: dict[str, Any] = {
                    "module": getattr(nbp, "module", "") or None,
                    "offset": hex(offset),
                    "enabled": bool(getattr(nbp, "enabled", True)),
                    "type": _bp_type_name(getattr(nbp, "type", None)),
                }
                if shared["type"] not in (None, "Software"):
                    shared["size"] = int(getattr(nbp, "size", 1) or 1)

                entry = entries.get(address) if address else None
                if entry is not None:
                    # Known to both sides: BN owns module/offset/enabled/type.
                    was_adopted = entry["source"] == "ui"
                    entry.update(shared)
                    entry["source"] = "ui" if was_adopted else "mcp+ui"
                    if condition:
                        entry["native_condition"] = condition
                        if not entry.get("condition"):
                            entry["condition"] = condition
                            entry["condition_engine"] = "binaryninja"
                        elif entry["condition"] != condition:
                            entry["condition_engine"] = "mcp+binaryninja"
                    continue

                entry = dict(shared)
                entry["address"] = hex(address) if address else None
                entry["symbol"] = self._function_name(entry["address"])
                entry["condition"] = condition or None
                entry["native_condition"] = condition or None
                entry["condition_engine"] = "binaryninja" if condition else None
                entry["source"] = "ui"
                if address:
                    adopted = Breakpoint(self._next_bp_id, address, None, entry["symbol"])
                    adopted.enabled = entry["enabled"]
                    adopted.adopted = True
                    self._next_bp_id += 1
                    self._breakpoints[adopted.id] = adopted
                    entry["id"] = adopted.id
                    entries[address] = entry
                else:
                    entry["id"] = None
                    entry["pending"] = True
                    pending.append(entry)

            merged = sorted(entries.values(), key=lambda e: e["id"]) + pending

        for entry in merged:
            for key in ("module", "offset", "type", "native_condition"):
                entry.setdefault(key, None)
        return merged

    def _breakpoint_at(self, address: int, enabled_only: bool = False) -> Breakpoint | None:
        with self._lock:
            for bp in self._breakpoints.values():
                if bp.address == address and (bp.enabled or not enabled_only):
                    return bp
        return None

    # ---------- watchpoints ----------

    def add_watchpoint(self, address: int, size: int = 8, wtype: str = "write") -> Watchpoint:
        """Set a hardware watchpoint that stops when ``address`` is accessed.

        ``wtype`` is "read", "write", or "readwrite". Hardware watchpoints are a
        limited resource; exceeding the adapter's count raises DebuggerError.
        Implemented via the adapter's own command (LLDB); the client does not
        need to know the adapter dialect.
        """
        if not self.is_live:
            raise DebuggerError("No live target. Run the program first.")
        wtype = wtype.lower()
        if wtype not in ("read", "write", "readwrite"):
            raise DebuggerError(f"Invalid watchpoint type {wtype!r} (use read/write/readwrite).")
        if size not in (1, 2, 4, 8):
            raise DebuggerError(f"Invalid watchpoint size {size} (use 1, 2, 4, or 8).")

        adapter = (_safe(lambda: self.controller.adapter_type, default="") or "").upper()
        if "DBGENG" not in adapter and "WINDBG" not in adapter:
            access = _LLDB_WATCH_ACCESS[wtype]
            cmd = f"watchpoint set expression -w {access} -s {size} -- {hex(address)}"
        else:
            raise DebuggerError("Watchpoints are only wired for the LLDB adapter so far.")

        with self._lock:
            output = _safe(lambda: self.controller.execute_backend_command(cmd), default="") or ""
            clean = _ANSI_RE.sub("", output)
            m = _LLDB_WP_SET_RE.search(clean)
            if not m:
                # Surface the adapter's own error (e.g. no more HW watchpoint resources).
                raise DebuggerError(f"Failed to set watchpoint: {clean.strip() or 'unknown error'}")
            adapter_num = int(m.group(1))
            wp = Watchpoint(self._next_wp_id, address, size, wtype, adapter_num)
            self._next_wp_id += 1
            self._watchpoints[wp.id] = wp
            return wp

    def list_watchpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            return [wp.to_dict() for wp in sorted(self._watchpoints.values(), key=lambda w: w.id)]

    def delete_watchpoint(self, wp_id: int) -> bool:
        with self._lock:
            wp = self._watchpoints.pop(wp_id, None)
            if not wp:
                return False
            self._watchpoint_command(f"watchpoint delete {wp.adapter_num}")
            return True

    def set_watchpoint_enabled(self, wp_id: int, enabled: bool) -> Watchpoint:
        with self._lock:
            wp = self._watchpoints.get(wp_id)
            if wp is None:
                raise DebuggerError(f"No watchpoint with id {wp_id}")
            verb = "enable" if enabled else "disable"
            self._watchpoint_command(f"watchpoint {verb} {wp.adapter_num}")
            wp.enabled = enabled
            return wp

    def _watchpoint_command(self, cmd: str) -> None:
        try:
            self.controller.execute_backend_command(cmd)
        except Exception as e:
            raise DebuggerError(f"Watchpoint command failed: {e}")

    def _watchpoint_by_adapter_num(self, num: int) -> Watchpoint | None:
        with self._lock:
            for wp in self._watchpoints.values():
                if wp.adapter_num == num:
                    return wp
        return None

    def _adapter_stop_reason(self) -> str | None:
        """The adapter's own stop reason (e.g. 'watchpoint 1'), via ``thread info``.

        Binary Ninja reports a watchpoint hit as UnknownReason; the adapter knows
        the true reason, so we ask it. Returns the reason text or None.
        """
        out = _safe(lambda: self.controller.execute_backend_command("thread info"), default=None)
        if not isinstance(out, str):
            return None
        m = _LLDB_STOP_REASON_RE.search(_ANSI_RE.sub("", out))
        return m.group(1).strip() if m else None

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
        # Watchpoints live on the process, not the analysis, so a fresh launch
        # starts with none (breakpoints, by contrast, are re-applied by BN).
        with self._lock:
            self._watchpoints.clear()
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

    def write_stdin(self, data: str) -> dict[str, Any]:
        """Write ``data`` to the target's standard input (Linux/macOS).

        Non-blocking and does NOT take the session lock, so it can feed input to
        a target that is blocked reading stdin while a run/continue is in flight
        in another request — the way a human types at a prompt. Add a trailing
        newline yourself if the program reads a line.
        """
        if not self.is_live:
            return {"status": "error", "message": "No live target. Run the program first."}
        try:
            self.controller.write_stdin(data)
        except Exception as e:
            return {"status": "error", "message": f"Failed to write stdin: {e}"}
        return {"status": "ok", "bytes_written": len(data.encode("utf-8", errors="replace"))}

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
        # Merged count: breakpoints placed in the UI count too.
        bp_count = len(self.list_breakpoints())
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
            # A new run/stop starts inspection at the innermost frame.
            self._selected_frame = 0
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
        bp = self._breakpoint_at(int(result["address"], 16), enabled_only=True)
        if bp is None or not bp.condition:
            return result
        try:
            hit = evaluate_condition(bp.condition, self._register_values(), self._read_mem_or_none)
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
        # Only an ENABLED breakpoint claims a stop; a disabled one falls through.
        bp = self._breakpoint_at(ip, enabled_only=True) if isinstance(ip, int) else None

        # 2. Clean stop at a breakpoint the client set — self-explanatory.
        if reason_name == "Breakpoint" and bp is not None:
            label = bp.symbol or func
            where = f" in {label}" if label else ""
            result = {
                "status": "breakpoint",
                "stop_reason": reason_name,
                "breakpoint_id": bp.id,
                "address": addr_hex,
                "function": func,
                "symbol": bp.symbol,
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

        # 3b. A watchpoint hit surfaces from Binary Ninja as UnknownReason. If we
        # have watchpoints, ask the adapter for the true reason and attribute it.
        if self._watchpoints:
            wp_result = self._resolve_watchpoint_stop(addr_hex, func)
            if wp_result is not None:
                return wp_result

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

    def _resolve_watchpoint_stop(
        self, addr_hex: str | None, func: str | None
    ) -> dict[str, Any] | None:
        """If the current stop is a watchpoint hit, build its stop result.

        Asks the adapter for the true stop reason (Binary Ninja reports the hit
        as UnknownReason) and, when it is one of our watchpoints, reports it as a
        first-class ``watchpoint`` stop instead of an anonymous one.
        """
        reason = self._adapter_stop_reason()
        if not reason:
            return None
        m = re.match(r"watchpoint\s+(\d+)", reason, re.IGNORECASE)
        if not m:
            return None
        wp = self._watchpoint_by_adapter_num(int(m.group(1)))
        if wp is None:
            return None
        where = f" in {func}" if func else ""
        result = {
            "status": "watchpoint",
            "stop_reason": "Watchpoint",
            "watchpoint_id": wp.id,
            "watch_address": hex(wp.address),
            "watch_type": wp.wtype,
            "watch_size": wp.size,
            "address": addr_hex,
            "function": func,
            "message": (
                f"Watchpoint #{wp.id} ({wp.wtype}, {wp.size} bytes at {hex(wp.address)}) "
                f"hit at {addr_hex}{where}"
            ),
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
            # A selected caller frame reports its recoverable unwound registers.
            if self._selected_frame != 0:
                return self._frame_registers(self._selected_frame) or []
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

    def get_backtrace(self, tid: int | None = None) -> list[dict[str, Any]]:
        """Backtrace of the given thread, or the active thread when ``tid`` is None."""
        with self._lock:
            self._require_halted()
            if tid is None:
                tid = self.controller.active_thread.tid
            frames = self.controller.frames_of_thread(tid)
            # Mark the selected frame only for the active thread's backtrace.
            active = tid == _safe(lambda: self.controller.active_thread.tid, default=None)
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
                        "selected": active and f.index == self._selected_frame,
                    }
                )
            return out

    def list_threads(self) -> list[dict[str, Any]]:
        """List the target's threads, flagging the active one."""
        with self._lock:
            self._require_halted()
            active_tid = _safe(lambda: self.controller.active_thread.tid, default=None)
            out = []
            for t in self.controller.threads:
                rip = getattr(t, "rip", None)
                rip_hex = hex(rip) if isinstance(rip, int) else None
                out.append(
                    {
                        "tid": t.tid,
                        "rip": rip_hex,
                        "function": self._function_name(rip_hex),
                        "active": t.tid == active_tid,
                    }
                )
            return out

    def select_thread(self, tid: int) -> dict[str, Any]:
        """Make ``tid`` the active thread (subsequent inspection targets it)."""
        with self._lock:
            self._require_halted()
            target = None
            for t in self.controller.threads:
                if t.tid == tid:
                    target = t
                    break
            if target is None:
                raise DebuggerError(f"No thread with tid {tid}")
            try:
                self.controller.active_thread = target
            except Exception as e:
                raise DebuggerError(f"Failed to select thread {tid}: {e}")
            rip = getattr(target, "rip", None)
            rip_hex = hex(rip) if isinstance(rip, int) else None
            return {
                "status": "ok",
                "tid": tid,
                "rip": rip_hex,
                "function": self._function_name(rip_hex),
            }

    # ---------- stack frames ----------

    def _frames(self) -> list:
        tid = self.controller.active_thread.tid
        return list(self.controller.frames_of_thread(tid))

    def select_frame(self, index: int) -> dict[str, Any]:
        """Select stack frame ``index`` (0 = innermost) as the inspection context.

        Persists across inspection calls (registers, backtrace, context, stack,
        disassembly) until changed or the target runs again. For a caller frame
        the pc/sp/fp are reliably unwound by Binary Ninja; a full register set is
        NOT available (the callee clobbered most registers), so only the
        recoverable/callee-saved registers are reported.
        """
        with self._lock:
            self._require_halted()
            frames = self._frames()
            if index < 0 or index >= len(frames):
                raise DebuggerError(f"No frame #{index}; backtrace has {len(frames)} frame(s).")
            # Keep the adapter's selected frame in sync (used for unwound registers).
            _safe(
                lambda: self.controller.execute_backend_command(f"frame select {index}"),
                default=None,
            )
            self._selected_frame = index
            return self._frame_context(index, frames)

    def frame_up(self) -> dict[str, Any]:
        """Move one frame toward the caller (older frame)."""
        with self._lock:
            return self.select_frame(self._selected_frame + 1)

    def frame_down(self) -> dict[str, Any]:
        """Move one frame toward the callee (newer frame)."""
        with self._lock:
            if self._selected_frame == 0:
                raise DebuggerError("Already at the innermost frame (#0).")
            return self.select_frame(self._selected_frame - 1)

    def _frame_context(self, index: int, frames: list) -> dict[str, Any]:
        f = frames[index]
        pc_hex = hex(f.pc)
        return {
            "status": "ok",
            "selected_frame": index,
            "address": pc_hex,
            "function": f.func_name or self._function_name(pc_hex),
            "frame": {
                "index": index,
                "pc": pc_hex,
                "sp": hex(f.sp),
                "fp": hex(f.fp),
                "module": f.module or None,
            },
            "thread": _safe(self._active_thread_info, default=None),
            "registers": _safe(lambda: self._frame_registers(index), default=None),
            "stack": _safe(lambda: self._stack_telescope(sp=f.sp), default=None),
            "disassembly": _safe(lambda: self._disasm_at_pc(pc=f.pc), default=None),
            "backtrace": _safe(self._backtrace_dicts, default=None),
            "note": None
            if index == 0
            else "Caller frame: pc/sp/fp are unwound; clobbered registers are unavailable.",
        }

    def _frame_registers(self, index: int) -> list[dict[str, Any]] | None:
        """Registers for a frame: full live set for #0, the recoverable unwound
        subset (via the adapter) for caller frames."""
        if index == 0:
            return self._format_registers(full=False)
        _safe(
            lambda: self.controller.execute_backend_command(f"frame select {index}"), default=None
        )
        out = _safe(lambda: self.controller.execute_backend_command("register read"), default=None)
        if not isinstance(out, str):
            return None
        regs = []
        for line in _ANSI_RE.sub("", out).splitlines():
            # "     rbx = 0x0000...". Clobbered regs read "= error: unavailable"
            # and simply do not match, so they are honestly omitted.
            m = re.match(r"\s*([a-z][a-z0-9]*)\s*=\s*(0x[0-9a-fA-F]+)\b", line)
            if m:
                regs.append({"name": m.group(1), "value": m.group(2), "hint": None})
        return regs or None

    def read_memory(self, address: int, size: int) -> bytes:
        with self._lock:
            self._require_halted()
            buf = self.controller.read_memory(address, size)
            data = bytes(buf) if buf is not None else b""
            if len(data) < size:
                # Short/empty read: classify why so the client can react.
                perms = self._region_perms(address)
                if _is_unmapped(perms):
                    raise DebuggerError(f"Memory at {hex(address)} is unmapped.")
                if perms is not None and "r" not in perms:
                    raise DebuggerError(
                        f"Memory at {hex(address)} is not readable (permissions {perms!r})."
                    )
                if not data:
                    raise DebuggerError(
                        f"Could not read memory at {hex(address)} (unmapped or inaccessible)."
                    )
            return data

    def evaluate_expression(self, expr: str) -> dict[str, Any]:
        """Evaluate an expression over registers and memory.

        Supports registers, integer/hex literals, arithmetic/comparison/boolean
        operators, and memory dereference (``[expr]``, ``deref(expr)``,
        ``u8/u16/u32/u64`` and signed ``i8..i64``). Returns the value in several
        forms; for a non-boolean result that looks like a pointer, annotates what
        it points at.
        """
        with self._lock:
            self._require_halted()
            regs = self._register_values()
            try:
                value = evaluate(expr, regs, self._read_mem_or_none)
            except ConditionError as e:
                raise DebuggerError(f"Cannot evaluate {expr!r}: {e}")

            result: dict[str, Any] = {"status": "ok", "expression": expr}
            if isinstance(value, bool):
                result["type"] = "bool"
                result["value"] = value
                return result
            # Normalize to an unsigned 64-bit view for hex display.
            u64 = value & 0xFFFFFFFFFFFFFFFF
            result["type"] = "int"
            result["value"] = hex(u64)
            result["decimal"] = value
            points_to = self._maybe_string(u64)
            if points_to is not None:
                result["points_to"] = points_to
            func = self._function_name(hex(u64))
            if func is not None:
                result["symbol"] = func
            return result

    def set_register(self, name: str, value: int) -> dict[str, Any]:
        """Set a register's value, verifying the write by reading it back."""
        with self._lock:
            self._require_halted()
            regs = self.controller.regs.regs
            if name not in regs:
                raise DebuggerError(f"Unknown register: {name!r}")
            old = regs[name].value
            ok = _safe(lambda: self.controller.set_reg_value(name, value), default=False)
            new = _safe(lambda: self.controller.regs.regs[name].value, default=None)
            if not ok and new != value:
                raise DebuggerError(f"Failed to set register {name!r}.")
            if new != value:
                # The adapter accepted the write but the value did not stick.
                raise DebuggerError(
                    f"Register {name!r} did not take the value "
                    f"({hex(value)} requested, reads {hex(new) if isinstance(new, int) else new})."
                )
            return {
                "status": "ok",
                "register": name,
                "old_value": hex(old),
                "new_value": hex(new),
            }

    def write_memory(self, address: int, data: bytes) -> dict[str, Any]:
        """Write bytes to the target's memory, guarding non-writable regions.

        Checks the region permissions first for a clear error, then verifies the
        write by reading the bytes back (so a silently-failed write is caught).
        """
        with self._lock:
            self._require_halted()
            if not data:
                raise DebuggerError("No data to write.")
            perms = self._region_perms(address)
            if _is_unmapped(perms):
                raise DebuggerError(f"Memory at {hex(address)} is unmapped.")
            if perms is not None and "w" not in perms:
                raise DebuggerError(
                    f"Memory at {hex(address)} is not writable (permissions {perms!r})."
                )
            ok = _safe(lambda: self.controller.write_memory(address, data), default=False)
            if not ok:
                raise DebuggerError(
                    f"Failed to write {len(data)} byte(s) at {hex(address)}"
                    + (f" (permissions {perms!r})." if perms else " (unmapped or inaccessible).")
                )
            # Verify by reading back.
            readback = _safe(lambda: self.controller.read_memory(address, len(data)), default=None)
            verified = readback is not None and bytes(readback)[: len(data)] == data
            return {
                "status": "ok",
                "address": hex(address),
                "bytes_written": len(data),
                "verified": bool(verified),
                "data": data.hex(),
            }

    def _region_perms(self, address: int) -> str | None:
        """Return the permission string (e.g. "rw-") for the region containing
        ``address``, or None when the adapter/output is not understood."""
        region = self._query_memory_region(address)
        if region is None or not region.get("mapped"):
            return None
        return region.get("perms")

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
        """The full halted-state context, on demand (requires a stopped target).

        Reflects the currently selected stack frame (see select_frame); defaults
        to the innermost frame.
        """
        with self._lock:
            self._require_halted()
            if self._selected_frame != 0:
                frames = self._frames()
                if self._selected_frame < len(frames):
                    return self._frame_context(self._selected_frame, frames)
                self._selected_frame = 0  # frame list changed; fall back to #0
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

    def _stack_telescope(
        self, count: int = 8, sp: int | None = None
    ) -> list[dict[str, Any]] | None:
        """Dump ``count`` pointer-sized words from ``sp`` (default: the live stack
        pointer), annotating any slot that points at a readable string."""
        if sp is None:
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

    def _disasm_at_pc(self, count: int = 8, pc: int | None = None) -> str | None:
        """Disassemble ``count`` instructions at ``pc`` (default: the runtime PC).

        Uses the adapter's own disassembler (live memory), so it is correct
        regardless of ASLR/PIE. Returns the adapter's raw text.
        """
        ip = pc if pc is not None else _safe(lambda: self.controller.ip, default=None)
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
        # Respect the selected frame so debug_evaluate is consistent with
        # debug_get_registers / debug_context. A caller frame exposes only its
        # recoverable registers (clobbered ones are absent, and referencing one
        # in an expression fails with "unknown register" — honestly).
        if self._selected_frame != 0:
            out: dict[str, int] = {}
            for r in self._frame_registers(self._selected_frame) or []:
                try:
                    out[r["name"]] = int(r["value"], 16)
                except (ValueError, TypeError):
                    continue
            return out
        regs = self.controller.regs
        return {name: reg.value for name, reg in regs.regs.items()}

    def _read_mem_or_none(self, address: int, size: int) -> bytes | None:
        """Memory reader for the expression evaluator: bytes, or None on failure."""
        buf = _safe(lambda: self.controller.read_memory(address, size), default=None)
        if buf is None:
            return None
        data = bytes(buf)
        return data if len(data) >= size else None

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
                "selected": f.index == self._selected_frame,
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


def _is_unmapped(perms: str | None) -> bool:
    """True when a region has no access at all (LLDB reports gaps as '---'),
    i.e. the address is effectively unmapped."""
    return bool(perms) and set(perms) <= {"-"}


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
