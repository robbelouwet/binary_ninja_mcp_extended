"""Type system routes: listing, search, definition, and inspection."""

import binaryninja as bn

from ..router import HTTPError, Request, route


def _include_libraries(req: Request) -> bool:
    return req.params.get("includeLibraries") in ("1", "true", "True")


@route("/localTypes")
def local_types(req: Request):
    """List local (user-defined) types, optionally including library types."""
    types = req.binary_ops.list_local_types(
        req.offset, req.limit, include_libraries=_include_libraries(req)
    )
    return {"types": types}


@route("/searchTypes")
def search_types(req: Request):
    """Substring search over local types; count=-1 returns all matches."""
    term = req.param("query", "q")
    if not term:
        raise HTTPError(400, {"error": "Missing query parameter", "help": "Required: query or q"})

    limit = req.limit
    if req.params.get("count") == "-1" or req.params.get("limit") == "-1":
        limit = -1
    include_libs = _include_libraries(req)

    all_matches = req.binary_ops.search_local_types(term, 0, -1, include_libraries=include_libs)
    offset = req.offset
    page = all_matches[offset:] if limit < 0 else all_matches[offset : offset + limit]
    return {
        "types": page,
        "query": term,
        "total": len(all_matches),
        "offset": offset,
        "limit": limit,
        "includeLibraries": include_libs,
    }


@route("/defineTypes")
def define_types(req: Request):
    """Define types from a block of C source."""
    c_code = req.require("cCode")
    return req.endpoints.define_types(c_code)


@route("/declareCType")
def declare_c_type(req: Request):
    """Create or update a local type from a single C declaration."""
    c_decl = req.param("declaration", "cDecl", "cDeclaration", "decl")
    if not c_decl:
        raise HTTPError(
            400,
            {
                "error": "Missing declaration parameter",
                "help": "Use 'declaration' with a single C type declaration",
            },
        )
    return req.endpoints.declare_c_type(c_decl)


@route("/getTypeInfo")
def get_type_info(req: Request):
    """Get detailed information about a named type."""
    type_name = req.require("name", "type", "typeName", help="Required: name (or type/typeName)")
    return req.binary_ops.get_type_info(type_name)


@route("/getUserDefinedType")
def get_user_defined_type(req: Request):
    """Get the definition of a user-defined type by name."""
    type_name = req.require(
        "name", help="Required parameter: name (name of the user-defined type to retrieve)"
    )
    type_info = req.binary_ops.get_user_defined_type(type_name)
    if type_info:
        return type_info

    # Type not found: list available user types to help the client recover
    available_types = {}
    try:
        container = getattr(req.binary_ops.current_view, "user_type_container", None)
        if container:
            for type_id in container.types.keys():
                current_type = container.types[type_id]
                available_types[current_type[0]] = (
                    str(current_type[1].type) if hasattr(current_type[1], "type") else "unknown"
                )
    except Exception as e:
        bn.log_error(f"Error listing available types: {e}")

    raise HTTPError(
        404,
        {
            "error": "Type not found",
            "requested_type": type_name,
            "available_types": available_types,
        },
    )
