"""Cross-reference routes: xrefs to addresses, struct fields, and types."""

from ..router import Request, route


@route("/getXrefsTo")
def xrefs_to_address(req: Request):
    address = req.require(
        "address", help="Required parameter: address (hex like 0x401000 or decimal)"
    )
    return req.binary_ops.get_xrefs_to_address(address)


@route("/getXrefsToField")
def xrefs_to_field(req: Request):
    struct_name = req.require("struct", "structName", help="Required: struct (or structName)")
    field_name = req.require("field", "fieldName", help="Required: field (or fieldName)")
    refs = req.binary_ops.get_xrefs_to_field(struct_name, field_name)
    return {"struct": struct_name, "field": field_name, "references": refs}


@route("/getXrefsToStruct")
def xrefs_to_struct(req: Request):
    struct_name = req.require(
        "name", "struct", "structName", help="Required: name (or struct/structName)"
    )
    return req.binary_ops.get_xrefs_to_struct(struct_name)


@route("/getXrefsToType")
def xrefs_to_type(req: Request):
    type_name = req.require("name", "type", "typeName", help="Required: name (or type/typeName)")
    return req.binary_ops.get_xrefs_to_type(type_name)


@route("/getXrefsToEnum")
def xrefs_to_enum(req: Request):
    enum_name = req.require("name", "enum", "enumName", help="Required: name (or enum/enumName)")
    return req.binary_ops.get_xrefs_to_enum(enum_name)


@route("/getXrefsToUnion")
def xrefs_to_union(req: Request):
    union_name = req.require(
        "name", "union", "unionName", help="Required: name (or union/unionName)"
    )
    return req.binary_ops.get_xrefs_to_union(union_name)
