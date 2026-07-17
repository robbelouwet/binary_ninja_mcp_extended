"""Interactive debugging routes.

Breakpoint management, blocking run/continue, and halted-state inspection.
All routes require a loaded binary; the debugger session is bound to it.
"""

from ...core.debugger import DEFAULT_RUN_TIMEOUT, DebuggerError
from ...utils.hexdump import format_hexdump
from ...utils.string_utils import parse_address
from ..router import HTTPError, Request, route


def _session(req: Request):
    try:
        return req.binary_ops.get_debugger()
    except DebuggerError as e:
        raise HTTPError(400, str(e))


def _address(req: Request, *names: str, help: str | None = None) -> int:
    raw = req.require(*names, help=help)
    try:
        return parse_address(raw)
    except ValueError:
        raise HTTPError(400, f"Invalid address format: {raw!r}")


@route("/debug/breakpoint", methods=("GET", "POST", "DELETE"))
def breakpoint_route(req: Request):
    """List (GET), add (POST) or delete (DELETE) a breakpoint.

    POST params: address, optional condition (e.g. "rdi == 0x10").
    DELETE params: id.
    """
    session = _session(req)

    if req.method == "GET":
        return {"breakpoints": session.list_breakpoints()}

    if req.method == "DELETE":
        bp_id = req.require("id", help="Required: id of the breakpoint to delete")
        try:
            bp_id = int(bp_id)
        except (ValueError, TypeError):
            raise HTTPError(400, f"Invalid breakpoint id: {bp_id!r}")
        if session.delete_breakpoint(bp_id):
            return {"status": "ok", "message": f"Deleted breakpoint #{bp_id}"}
        raise HTTPError(404, f"No breakpoint with id {bp_id}")

    # POST
    address = _address(req, "address", "addr", help="Required: address (hex like 0x401000)")
    condition = req.param("condition") or None
    bp = session.add_breakpoint(address, condition)
    return {"status": "ok", "breakpoint": bp.to_dict()}


def _timeout_param(req: Request) -> float | None:
    """Parse the run/continue timeout: absent -> default, <=0 -> wait forever."""
    raw = req.param("timeout", "timeout_seconds")
    if raw is None or raw == "":
        return DEFAULT_RUN_TIMEOUT
    try:
        value = float(raw)
    except (ValueError, TypeError):
        raise HTTPError(400, f"Invalid timeout: {raw!r}")
    return None if value <= 0 else value


def _context_param(req: Request) -> bool:
    """Whether to attach the full context to the stop result (default true)."""
    raw = req.param("context", default="")
    return str(raw).lower() not in ("0", "false", "no")


@route("/debug/run", methods=("GET", "POST"))
def run_route(req: Request):
    """Launch the target and run until the next stop (blocking, bounded).

    By default runs to the first user breakpoint (the automatic entry-point stop
    is suppressed). Pass stop_at_entry=1 to halt at the program entry point.

    Blocks up to 'timeout' seconds (default 30); if the target has not stopped it
    is paused and returned with its location, so a hung target is never fatal.
    timeout<=0 waits indefinitely (interruptible only via /debug/pause).

    Optional params: stop_at_entry (bool), timeout (seconds), cmd_line,
    working_directory, adapter_type. Returns the normalized stop result.
    """
    session = _session(req)
    stop_at_entry = str(req.param("stop_at_entry", default="")).lower() in ("1", "true", "yes")
    timeout = _timeout_param(req)
    opts = {
        key: req.params.get(key)
        for key in ("cmd_line", "working_directory", "adapter_type")
        if req.params.get(key)
    }
    try:
        return session.launch_and_run(
            stop_at_entry=stop_at_entry, timeout=timeout, context=_context_param(req), **opts
        )
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/continue", methods=("GET", "POST"))
def continue_route(req: Request):
    """Continue a running target until the next stop (blocking, bounded).

    Same timeout semantics as /debug/run.
    """
    session = _session(req)
    timeout = _timeout_param(req)
    try:
        return session.resume(timeout=timeout, context=_context_param(req))
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/context")
def context_route(req: Request):
    """The full halted-state context (thread, registers, stack, disasm, backtrace)."""
    session = _session(req)
    try:
        return session.context()
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/pause", methods=("GET", "POST"))
def pause_route(req: Request):
    """Break into a running target so it can be inspected.

    Non-blocking: signals the target to stop. A concurrent run/continue then
    returns with the stop location. Useful for a target that is hung or looping.
    """
    session = _session(req)
    return session.pause()


@route("/debug/status")
def status_route(req: Request):
    """Session status: backend adapter (dialect), live/running, ip/function, bp count."""
    return _session(req).status()


@route("/debug/backend", methods=("GET", "POST"))
def backend_route(req: Request):
    """Run a raw command in the underlying debug adapter's (LLDB/WinDbg) console.

    Escape hatch for capabilities not yet wrapped as structured tools. Check
    /debug/status first to learn which adapter (dialect) is active. POST is
    preferred for commands with spaces/special characters.
    """
    session = _session(req)
    command = req.require("command", "cmd", help="Required: command (a raw adapter command)")
    return session.execute_backend_command(command)


@route("/debug/modules")
def modules_route(req: Request):
    """List the images loaded in the target (executable + shared libraries)."""
    session = _session(req)
    try:
        return {"modules": session.list_modules()}
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/resolve")
def resolve_route(req: Request):
    """Resolve a runtime address to its memory mapping and backing image."""
    session = _session(req)
    address = _address(req, "address", "addr", help="Required: address to resolve")
    return session.resolve_address(address)


@route("/debug/step", methods=("GET", "POST"))
def step_route(req: Request):
    """Execute a single instruction, stepping into calls (blocking, bounded)."""
    session = _session(req)
    try:
        return session.step_into(timeout=_timeout_param(req), context=_context_param(req))
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/stepover", methods=("GET", "POST"))
def step_over_route(req: Request):
    """Execute a single instruction, stepping over calls (blocking, bounded)."""
    session = _session(req)
    try:
        return session.step_over(timeout=_timeout_param(req), context=_context_param(req))
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/stepout", methods=("GET", "POST"))
def step_out_route(req: Request):
    """Run until the current function returns to its caller (blocking, bounded)."""
    session = _session(req)
    try:
        return session.step_out(timeout=_timeout_param(req), context=_context_param(req))
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/runto", methods=("GET", "POST"))
def run_to_route(req: Request):
    """Resume until the target reaches a given address (advance/until)."""
    session = _session(req)
    address = _address(req, "address", "addr", help="Required: address to run to")
    try:
        return session.run_to(address, timeout=_timeout_param(req), context=_context_param(req))
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/registers")
def registers_route(req: Request):
    """Read registers of the halted target.

    Returns the important registers by default; pass full=1 for the complete
    register file (sub-registers, segment, FPU/vector).
    """
    session = _session(req)
    full = str(req.param("full", "all", default="")).lower() in ("1", "true", "yes")
    try:
        return {"registers": session.get_registers(full=full)}
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/backtrace")
def backtrace_route(req: Request):
    session = _session(req)
    try:
        return {"backtrace": session.get_backtrace()}
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/memory")
def memory_route(req: Request):
    """Read memory from the halted target as a hexdump (plain text via ?raw=0)."""
    session = _session(req)
    address = _address(req, "address", "addr", help="Required: address to read from")
    try:
        size = int(req.param("size", "length", default=64))
    except (ValueError, TypeError):
        raise HTTPError(400, "Invalid size")
    try:
        data = session.read_memory(address, size)
    except DebuggerError as e:
        raise HTTPError(400, str(e))
    return {
        "address": hex(address),
        "size": len(data),
        "hexdump": format_hexdump(address, data),
    }


@route("/debug/setRegister", methods=("GET", "POST"))
def set_register_route(req: Request):
    """Set a register in the halted target. Params: name, value."""
    session = _session(req)
    name = req.require("name", "register", help="Required: name (register name)")
    value_raw = req.require("value", help="Required: value (hex like 0x10 or decimal)")
    try:
        value = parse_address(value_raw, bare_hex=False)
    except ValueError:
        raise HTTPError(400, f"Invalid value: {value_raw!r}")
    try:
        return session.set_register(name, value)
    except DebuggerError as e:
        raise HTTPError(400, str(e))


@route("/debug/writeMemory", methods=("GET", "POST"))
def write_memory_route(req: Request):
    """Write bytes to the halted target. Params: address, data (hex string)."""
    session = _session(req)
    address = _address(req, "address", "addr", help="Required: address to write to")
    data_str = req.require("data", "bytes", help="Required: data (hex, e.g. '90 90' or '9090')")
    try:
        data = _parse_hex_bytes(data_str)
    except ValueError as e:
        raise HTTPError(400, str(e))
    try:
        return session.write_memory(address, data)
    except DebuggerError as e:
        raise HTTPError(400, str(e))


def _parse_hex_bytes(text: str) -> bytes:
    """Parse a hex byte string like '90 90', '9090', or '0x90 0x90'."""
    cleaned = text.replace("0x", "").replace("0X", "").replace(",", " ")
    tokens = cleaned.split()
    if not tokens:
        raise ValueError("No data to write.")
    # Multiple whitespace-separated tokens are individual bytes (each 1 byte).
    if len(tokens) > 1:
        try:
            return bytes(int(tok, 16) for tok in tokens)
        except ValueError:
            raise ValueError(f"Invalid hex bytes: {text!r}")
    # A single token: a compact hex string (an even number of hex digits).
    compact = tokens[0]
    if len(compact) % 2 != 0:
        raise ValueError(f"Hex string must have an even number of digits: {text!r}")
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise ValueError(f"Invalid hex bytes: {text!r}")


@route("/debug/quit", methods=("GET", "POST"))
def quit_route(req: Request):
    """Terminate the live target."""
    session = _session(req)
    return session.quit()
