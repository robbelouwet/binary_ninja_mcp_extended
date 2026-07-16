"""Comment routes: address and function comments (get/set/delete)."""

from ...utils.string_utils import parse_address
from ..router import HTTPError, Request, route


def _parse_comment_address(req: Request) -> int:
    address = req.require("address")
    try:
        return parse_address(address)
    except ValueError:
        raise HTTPError(400, "Invalid address format")


def _get_address_comment(req: Request) -> dict:
    address = _parse_comment_address(req)
    comment = req.binary_ops.get_comment(address)
    response = {"success": True, "address": hex(address), "comment": comment}
    if comment is None:
        response["message"] = "No comment found at this address"
    return response


def _get_function_comment(req: Request) -> dict:
    function_name = req.require(
        "name", "functionName", help="Required parameter: name (or functionName)"
    )
    comment = req.binary_ops.get_function_comment(function_name)
    response = {"success": True, "function": function_name, "comment": comment}
    if comment is None:
        response["message"] = "No comment found for this function"
    return response


@route("/comment", methods=("GET", "POST", "DELETE"))
def comment(req: Request):
    """Get (GET), set (POST) or delete (DELETE) a comment at an address."""
    if req.method == "GET":
        return _get_address_comment(req)

    if req.method == "DELETE":
        address = _parse_comment_address(req)
        if req.binary_ops.delete_comment(address):
            return {
                "success": True,
                "message": f"Successfully deleted comment at {hex(address)}",
            }
        raise HTTPError(
            500,
            {
                "error": "Failed to delete comment",
                "message": "The comment could not be deleted at the specified address.",
            },
        )

    # POST
    address = _parse_comment_address(req)
    text = req.params.get("comment")
    if text is None:
        raise HTTPError(
            400,
            {
                "error": "Missing parameters",
                "help": "Required parameters: address and comment",
                "received": req.params,
            },
        )
    if req.binary_ops.set_comment(address, text):
        return {
            "success": True,
            "message": f"Successfully set comment at {hex(address)}",
            "comment": text,
        }
    raise HTTPError(
        500,
        {
            "error": "Failed to set comment",
            "message": "The comment could not be set at the specified address.",
        },
    )


@route("/comment/function", methods=("GET", "POST", "DELETE"))
def function_comment(req: Request):
    """Get (GET), set (POST) or delete (DELETE) a function comment."""
    if req.method == "GET":
        return _get_function_comment(req)

    function_name = req.require(
        "name", "functionName", help="Required parameter: name (or functionName)"
    )

    if req.method == "DELETE":
        if req.binary_ops.delete_function_comment(function_name):
            return {
                "success": True,
                "message": f"Successfully deleted comment for function {function_name}",
            }
        raise HTTPError(
            500,
            {
                "error": "Failed to delete function comment",
                "message": "The comment could not be deleted for the specified function.",
            },
        )

    # POST
    text = req.params.get("comment")
    if text is None:
        raise HTTPError(
            400,
            {
                "error": "Missing parameters",
                "help": "Required parameters: name (or functionName) and comment",
                "received": req.params,
            },
        )
    if req.binary_ops.set_function_comment(function_name, text):
        return {
            "success": True,
            "message": f"Successfully set comment for function {function_name}",
            "comment": text,
        }
    raise HTTPError(
        500,
        {
            "error": "Failed to set function comment",
            "message": "The comment could not be set for the specified function.",
        },
    )


@route("/getComment", methods=("GET", "POST"))
def get_comment(req: Request):
    """Read-only alias for fetching an address comment."""
    return _get_address_comment(req)


@route("/getFunctionComment", methods=("GET", "POST"))
def get_function_comment(req: Request):
    """Read-only alias for fetching a function comment."""
    return _get_function_comment(req)
