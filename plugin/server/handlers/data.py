"""Data routes: segments, sections, symbols, strings, hexdumps, patching."""

import json

from ...utils.hexdump import format_hexdump
from ...utils.string_utils import c_escape, parse_address, parse_int_or_default
from ..router import HTTPError, PlainTextResponse, Request, route

_ALL = 2147483647  # "no pagination" limit for string listings


@route("/segments")
def list_segments(req: Request):
    return {"segments": req.binary_ops.get_segments(req.offset, req.limit)}


@route("/sections")
def list_sections(req: Request):
    return {"sections": req.binary_ops.get_sections(req.offset, req.limit)}


@route("/imports")
def list_imports(req: Request):
    return {"imports": req.endpoints.get_imports(req.offset, req.limit)}


@route("/exports")
def list_exports(req: Request):
    return {"exports": req.endpoints.get_exports(req.offset, req.limit)}


@route("/data")
def list_data(req: Request):
    """List defined data variables with a value preview.

    'length' (or 'previewLen') controls how many bytes are read per item;
    negative means "read the exact defined size".
    """
    length = req.param("length", "previewLen")
    read_len = parse_int_or_default(length, 32) if length is not None else -1
    return {"data": req.binary_ops.get_defined_data(req.offset, req.limit, read_len)}


@route("/strings")
def list_strings(req: Request):
    return {"strings": req.binary_ops.get_strings(req.offset, req.limit)}


@route("/allStrings")
def list_all_strings(req: Request):
    return {"strings": req.binary_ops.get_strings(0, _ALL)}


@route("/strings/filter")
def filter_strings(req: Request):
    """Case-insensitive substring filter over all strings, then paginate."""
    pattern = req.params.get("filter", "")
    all_strings = req.binary_ops.get_strings(0, _ALL)
    if pattern:
        needle = pattern.lower()
        filtered = [
            s
            for s in all_strings
            if isinstance(s.get("value"), str) and needle in s["value"].lower()
        ]
    else:
        filtered = all_strings
    page = filtered[req.offset : req.offset + req.limit]
    return {"strings": page, "total": len(filtered)}


def _resolve_read_length(req: Request, address: int, default: int = 64) -> int:
    """Resolve the byte count to read: explicit 'length' param, else the
    defined data size at the address, else ``default``."""
    try:
        length = int(req.params["length"]) if req.params.get("length") is not None else -1
    except (ValueError, TypeError):
        length = -1
    if length < 0:
        try:
            inferred = req.binary_ops.infer_data_size(address)
            if inferred is not None and inferred > 0:
                length = int(inferred)
        except Exception:
            pass
    return length if length >= 0 else default


def _read_bytes(req: Request, address: int, length: int) -> bytes:
    try:
        return req.binary_ops.current_view.read(address, length) or b""
    except Exception:
        return b""


@route("/hexdump")
def hexdump(req: Request):
    """Hexdump memory at an address (plain text response)."""
    address_str = req.params.get("address")
    if not address_str:
        return PlainTextResponse("Missing address parameter\n", 400)
    try:
        address = parse_address(address_str)
    except ValueError:
        return PlainTextResponse("Invalid address format; use hex like 0x401000\n", 400)

    data = _read_bytes(req, address, _resolve_read_length(req, address))

    label = None
    try:
        sym = req.binary_ops.current_view.get_symbol_at(address)
        if sym and hasattr(sym, "name"):
            label = sym.name
    except Exception:
        label = None

    return PlainTextResponse(format_hexdump(address, data, label))


@route("/hexdumpByName")
def hexdump_by_name(req: Request):
    """Hexdump a named symbol's data (plain text response)."""
    name = req.param("name", "symbol", "raw_name")
    if not name:
        return PlainTextResponse("Missing name parameter\n", 400)

    address, label = req.binary_ops.resolve_symbol(name)
    if address is None:
        return PlainTextResponse("Symbol not found\n", 404)

    data = _read_bytes(req, address, _resolve_read_length(req, address))
    return PlainTextResponse(format_hexdump(address, data, label))


@route("/getDataDecl")
def get_data_decl(req: Request):
    """Best-effort C declaration plus hexdump for a data symbol."""
    ident = req.param("name", "symbol", "raw_name", "address")
    if not ident:
        raise HTTPError(
            400,
            {
                "error": "Missing name/address parameter",
                "help": "Provide name, symbol, raw_name, or address",
            },
        )
    address, label = req.binary_ops.resolve_symbol(ident)
    if address is None:
        raise HTTPError(404, {"error": "Symbol not found", "ident": ident})

    # Determine exact size and type of the data variable
    size = None
    type_text = None
    try:
        bv = req.binary_ops.current_view
        dv = bv.get_data_var_at(address) if hasattr(bv, "get_data_var_at") else None
        type_obj = (
            dv.type
            if (dv is not None and hasattr(dv, "type"))
            else (bv.get_type_at(address) if hasattr(bv, "get_type_at") else None)
        )
        if type_obj is not None:
            type_text = str(type_obj)
            if hasattr(type_obj, "width") and type_obj.width:
                size = int(type_obj.width)
    except Exception:
        pass
    if size is None:
        try:
            inferred = req.binary_ops.infer_data_size(address)
            if inferred and inferred > 0:
                size = int(inferred)
        except Exception:
            pass
    if size is None:
        size = 64

    raw = _read_bytes(req, address, size)

    # Prefer explicit char[] initialization when the data is a string
    lowered = (type_text or "").lower()
    is_char_array = lowered.startswith("char") or "char [" in lowered
    if is_char_array and raw:
        escaped = c_escape(raw.rstrip(b"\x00"))
        decl = f"{type_text} {label} = {escaped};"
    elif type_text:
        decl = f"{type_text} {label};"
    else:
        decl = f"/* size={size} */ {label};"

    return {
        "address": hex(address),
        "name": label,
        "size": size,
        "type": type_text,
        "decl": decl,
        "hexdump": format_hexdump(address, raw, label),
    }


@route("/rename/data", "/renameData", methods=("POST",))
def rename_data(req: Request):
    """Rename a data variable at an address."""
    address = req.params.get("address")
    new_name = req.param("newName", "new_name")
    if not address or not new_name:
        raise HTTPError(400, "Missing parameters")
    try:
        address_int = parse_address(address)
    except ValueError:
        raise HTTPError(400, "Invalid address format")
    return {"success": req.binary_ops.rename_data(address_int, new_name)}


@route("/patch", "/patchBytes", methods=("GET", "POST"))
def patch_bytes(req: Request):
    """Patch bytes at an address; optionally persist the change to disk."""
    address = req.param("address", "addr")
    data = req.param("data", "bytes")

    save_to_file_param = req.params.get("save_to_file", True)
    if isinstance(save_to_file_param, bool):
        save_to_file = save_to_file_param
    else:
        save_to_file = str(save_to_file_param).lower() not in ("false", "0", "no")

    if not address:
        raise HTTPError(
            400,
            {
                "error": "Missing address parameter",
                "help": "Required: address (hex like 0x401000 or decimal). Optional: data (hex string like '90 90' or '9090'), save_to_file (bool, default true)",
                "received": req.params,
            },
        )
    if not data:
        raise HTTPError(
            400,
            {
                "error": "Missing data parameter",
                "help": "Required: data (hex string like '90 90' or '9090', or list of integers)",
                "received": req.params,
            },
        )

    # A JSON array passed as a string becomes a list of byte values
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
            if isinstance(parsed, list):
                data = parsed
        except (json.JSONDecodeError, ValueError):
            pass  # not JSON, treat as hex string

    return req.endpoints.patch_bytes(address, data, save_to_file)
