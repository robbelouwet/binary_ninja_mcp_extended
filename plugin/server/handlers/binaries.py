"""Binary/view management routes: status, listing, selection, loading."""

from ..router import HTTPError, Request, route


@route("/status", requires_binary=False)
def status(req: Request):
    """Report whether a binary is loaded and its filename."""
    return req.endpoints.get_status()


@route("/binaries", "/views", requires_binary=False)
def list_binaries(req: Request):
    """List managed/open binaries."""
    return req.endpoints.list_binaries()


@route("/selectBinary", requires_binary=False)
def select_binary(req: Request):
    """Select the active binary by id or filename."""
    ident = req.param("view", "binary", "id", "file")
    if not ident:
        raise HTTPError(400, {"error": "Missing parameter", "help": "Use ?view=<id|filename>"})
    return req.endpoints.select_binary(ident)


@route("/platforms", requires_binary=False)
def list_platforms(req: Request):
    """List all platform names known to Binary Ninja."""
    return req.endpoints.list_platforms()


@route("/load", methods=("POST",), requires_binary=False)
def load_binary(req: Request):
    """Load a binary from a file path."""
    filepath = req.require("filepath")
    req.binary_ops.load_binary(filepath)
    return {"success": True, "message": f"Binary loaded: {filepath}"}
