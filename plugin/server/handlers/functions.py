"""Function routes: listing, search, decompilation, IL, call graph, renaming."""

import binaryninja as bn
from binaryninja.settings import Settings

from ...utils.string_utils import parse_address
from ..router import HTTPError, Request, route


def _extract_identifiers(req: Request) -> list[str]:
    """Normalize identifier-bearing params into a list of names/addresses."""
    candidates = []
    for key in (
        "identifiers",
        "identifier",
        "functions",
        "function",
        "names",
        "name",
        "addresses",
        "address",
    ):
        value = req.params.get(key)
        if value:
            candidates.append(value)
    identifiers = []
    for raw in candidates:
        tokens = [tok.strip() for tok in raw.replace(";", ",").split(",")]
        identifiers.extend(tok for tok in tokens if tok)
    return identifiers


def _function_not_found(req: Request, identifier) -> HTTPError:
    return HTTPError(
        404,
        {
            "error": "Function not found",
            "requested": identifier,
            "available_functions": req.binary_ops.get_function_names(0, 10),
        },
    )


@route("/functions", "/methods")
def list_functions(req: Request):
    return {"functions": req.binary_ops.get_function_names(req.offset, req.limit)}


@route("/classes")
def list_classes(req: Request):
    return {"classes": req.binary_ops.get_class_names(req.offset, req.limit)}


@route("/namespaces")
def list_namespaces(req: Request):
    return {"namespaces": req.endpoints.get_namespaces(req.offset, req.limit)}


@route("/searchFunctions")
def search_functions(req: Request):
    matches = req.endpoints.search_functions(req.params.get("query", ""), req.offset, req.limit)
    return {"matches": matches}


@route("/entryPoints")
def entry_points(req: Request):
    return {"entry_points": req.endpoints.get_entry_points()}


@route("/getCallers")
def get_callers(req: Request):
    identifiers = _extract_identifiers(req)
    if not identifiers:
        raise HTTPError(
            400,
            {
                "error": "Missing identifier parameter",
                "help": "Provide ?identifier=<name|address> or comma-separated ?identifiers=a,b",
            },
        )
    return req.binary_ops.get_callers(identifiers)


@route("/getCallees")
def get_callees(req: Request):
    identifiers = _extract_identifiers(req)
    if not identifiers:
        raise HTTPError(
            400,
            {
                "error": "Missing identifier parameter",
                "help": "Provide ?identifier=<name|address> or comma-separated ?identifiers=a,b",
            },
        )
    return req.binary_ops.get_callees(identifiers)


@route("/decompile")
def decompile(req: Request):
    """Decompile a function to pseudo-C by name or address."""
    function_name = req.param("name", "functionName")
    if not function_name:
        raise HTTPError(
            400,
            "Missing function name parameter. Use ?name=function_name or ?functionName=function_name",
        )

    func_info = req.binary_ops.get_function_info(function_name)
    if not func_info:
        raise _function_not_found(req, function_name)

    decompiled = req.binary_ops.decompile_function(function_name)
    if decompiled is None:
        raise HTTPError(
            500,
            {
                "error": "Decompilation failed",
                "function": func_info,
                "reason": "Function could not be decompiled. This might be due to missing debug information or unsupported function type.",
            },
        )
    return {"decompiled": decompiled, "function": func_info}


@route("/assembly")
def assembly(req: Request):
    """Get annotated disassembly for a function."""
    function_name = req.param("name", "functionName")
    if not function_name:
        raise HTTPError(
            400,
            "Missing function name parameter. Use ?name=function_name or ?functionName=function_name",
        )

    func_info = req.binary_ops.get_function_info(function_name)
    if not func_info:
        raise _function_not_found(req, function_name)

    result = req.binary_ops.get_assembly_function(function_name)
    if result is None:
        raise HTTPError(
            500,
            {
                "error": "Assembly retrieval failed",
                "function": func_info,
                "reason": "Function assembly could not be retrieved. Check the Binary Ninja log for detailed error information.",
            },
        )
    return {"assembly": result, "function": func_info}


@route("/il")
def il(req: Request):
    """Get a function's IL (hlil/mlil/llil), optionally in SSA form."""
    ident = req.param("name", "functionName", "address")
    if not ident:
        raise HTTPError(
            400,
            {
                "error": "Missing function identifier",
                "help": "Use ?name=<func> or ?address=<hex> with optional &view=hlil|mlil|llil&ssa=0|1",
                "received": req.params,
            },
        )

    view = (req.param("view", "il") or "hlil").strip()
    ssa = (req.param("ssa", "isSSA") or "0").strip().lower() in ("1", "true", "yes", "on")

    func_info = req.binary_ops.get_function_info(ident)
    if not func_info:
        raise _function_not_found(req, ident)

    il_text = req.binary_ops.get_function_il(ident, view=view, ssa=ssa)
    if il_text is None:
        raise HTTPError(
            500,
            {
                "error": "Failed to get IL",
                "function": func_info,
                "view": view,
                "ssa": ssa,
                "reason": "Unsupported IL view or unavailable instructions",
            },
        )
    return {"il": il_text, "function": func_info, "view": view, "ssa": ssa}


@route("/functionAt")
def function_at(req: Request):
    """List function(s) containing the given instruction address."""
    address_str = req.require(
        "address",
        help="Required parameter: address (in hex format, e.g., 0x41d100) the address of an insruction",
    )
    try:
        address = parse_address(address_str, bare_hex=False)
    except ValueError:
        raise HTTPError(
            400,
            {
                "error": "Invalid address format",
                "help": "Address must be a valid hexadecimal (0x...) or decimal number",
                "received": address_str,
            },
        )
    function_names = req.binary_ops.get_functions_containing_address(address)
    return {"address": hex(address), "functions": function_names}


@route("/getStackFrameVars")
def get_stack_frame_vars(req: Request):
    """Get stack frame variable layout for a function."""
    ident = req.param("name", "address")
    if not ident:
        raise HTTPError(
            400,
            {"error": "Missing required parameter: name or address", "received": req.params},
        )
    return {"stack_frame_vars": req.endpoints.get_stack_frame_vars(ident)}


@route("/makeFunctionAt")
def make_function_at(req: Request):
    """Create a function at an address (no-op if one already exists)."""
    address_str = req.param("address", "addr")
    if not address_str:
        raise HTTPError(
            400,
            {
                "error": "Missing address parameter",
                "help": "Required: address (hex like 0x401000 or decimal). Optional: platform (e.g., linux-x86_64; use 'default' for view default)",
            },
        )
    arch = req.param("platform", "arch", "architecture")
    result = req.endpoints.make_function_at(address_str, arch)
    if isinstance(result, dict) and result.get("error"):
        return result, 400
    return result


@route("/setFunctionPrototype", methods=("GET", "POST"))
def set_function_prototype(req: Request):
    """Set a function's prototype; POST supports long prototypes."""
    ident = req.param("address", "functionAddress", "addr", "name")
    proto = req.param("prototype", "signature", "type")
    if not ident or proto is None:
        raise HTTPError(
            400,
            {
                "error": "Missing parameters",
                "help": "Required: address (or functionAddress/addr) and prototype (or signature/type)",
                "received": req.params,
            },
        )
    return req.endpoints.set_function_prototype(ident, proto)


@route("/rename/function", "/renameFunction", methods=("POST",))
def rename_function(req: Request):
    """Rename a function, applying the configured rename prefix."""
    old_name = req.param("oldName", "old_name")
    new_name = req.param("newName", "new_name")
    if not old_name or not new_name:
        raise HTTPError(
            400,
            {
                "error": "Missing parameters",
                "help": "Required parameters: oldName (or old_name) and newName (or new_name)",
                "received": req.params,
            },
        )

    # Accept addresses (0x... or decimal) as the old name
    if isinstance(old_name, str):
        if old_name.startswith("0x"):
            try:
                old_name = int(old_name, 16)
            except ValueError:
                pass
        elif old_name.isdigit():
            old_name = int(old_name)

    prefix = Settings().get_string("mcp.renamePrefix")
    if prefix and not new_name.startswith(prefix):
        new_name = prefix + new_name

    func_info = req.binary_ops.get_function_info(old_name)
    if not func_info:
        raise HTTPError(
            404,
            {
                "error": "Function not found",
                "requested": old_name,
                "help": "Make sure the function exists. You can use either the function name or its address.",
                "available_functions": req.binary_ops.get_function_names(0, 10),
            },
        )

    if req.binary_ops.rename_function(old_name, new_name):
        bn.log_info(f"Renamed function {old_name} -> {new_name}")
        return {
            "success": True,
            "message": f"Successfully renamed function from {old_name} to {new_name}",
            "function": func_info,
        }
    raise HTTPError(
        500,
        {
            "error": "Failed to rename function",
            "message": "The function was found but could not be renamed. This might be due to permissions or binary restrictions.",
            "function": func_info,
        },
    )
