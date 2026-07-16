"""Local variable routes: rename and retype."""

import json

from ..router import HTTPError, Request, route

_FUNCTION_IDENT_PARAMS = ("functionAddress", "address", "function", "functionName", "name")


@route("/renameVariable")
def rename_variable(req: Request):
    """Rename a single local variable in a function."""
    function_name = req.params.get("functionName")
    if not function_name:
        raise HTTPError(400, "Missing function name parameter")
    variable_name = req.params.get("variableName")
    if not variable_name:
        raise HTTPError(400, "Missing variable name parameter")
    new_name = req.params.get("newName")
    if not new_name:
        raise HTTPError(400, "Missing new name parameter")
    return req.endpoints.rename_variable(function_name, variable_name, new_name)


@route("/renameVariables", methods=("GET", "POST"))
def rename_variables(req: Request):
    """Batch rename local variables in a function.

    Accepts 'renames' (list of {old,new}), 'mapping' (JSON object old->new),
    or 'pairs' (compact "old1:new1,old2:new2" string).
    """
    fn_ident = req.param(*_FUNCTION_IDENT_PARAMS)
    if not fn_ident:
        raise HTTPError(
            400,
            {
                "error": "Missing function identifier",
                "help": "Provide functionAddress/address or functionName/name",
                "received": req.params,
            },
        )

    raw_renames = None
    if "renames" in req.params:
        raw_renames = req.params.get("renames")
    if raw_renames is None and "mapping" in req.params:
        try:
            mapping = req.params.get("mapping")
            raw_renames = json.loads(mapping) if isinstance(mapping, str) else mapping
        except Exception:
            raw_renames = None
    if raw_renames is None and "pairs" in req.params:
        mapping = {}
        for item in (req.params.get("pairs") or "").split(","):
            if item.strip() and ":" in item:
                old, new = item.split(":", 1)
                mapping[old.strip()] = new.strip()
        raw_renames = mapping

    if raw_renames is None:
        raise HTTPError(
            400,
            {
                "error": "Missing renames payload",
                "help": "Provide 'renames' (array of {old,new}) or 'mapping' (JSON object old->new) or 'pairs' (old:new,...)",
                "received": req.params,
            },
        )

    return req.endpoints.rename_variables(fn_ident, raw_renames)


@route("/retypeVariable")
def retype_variable(req: Request):
    """Retype a local variable in a function."""
    function_name = req.params.get("functionName")
    if not function_name:
        raise HTTPError(400, "Missing function name parameter")
    variable_name = req.params.get("variableName")
    if not variable_name:
        raise HTTPError(400, "Missing variable name parameter")
    type_str = req.params.get("type")
    if not type_str:
        raise HTTPError(400, "Missing type parameter")
    return req.endpoints.retype_variable(function_name, variable_name, type_str)


@route("/setLocalVariableType")
def set_local_variable_type(req: Request):
    """Set a local variable's type from a C type string."""
    fn_ident = req.param(*_FUNCTION_IDENT_PARAMS)
    var_name = req.param("variableName", "variable", "nameOrVar")
    new_type = req.param("newType", "type", "signature")
    if not fn_ident or not var_name or new_type is None:
        raise HTTPError(
            400,
            {
                "error": "Missing parameters",
                "help": "Required: functionAddress (or address/name), variableName, newType (or type/signature)",
                "received": req.params,
            },
        )
    return req.endpoints.set_local_variable_type(fn_ident, var_name, new_type)
