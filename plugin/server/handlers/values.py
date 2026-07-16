"""Number/string conversion routes."""

from ...utils.number_utils import convert_number
from ...utils.string_utils import parse_address
from ..router import HTTPError, Request, route


@route("/convertNumber", requires_binary=False)
def convert_number_route(req: Request):
    """Compute number/string representations (bases, LE/BE, C literals)."""
    text = req.params.get("text")
    if text is None:
        raise HTTPError(
            400,
            {
                "error": "Missing text parameter",
                "help": "Required: text. Optional: size (1,2,4,8 or 0 for auto)",
                "received": req.params,
            },
        )
    return convert_number(text, req.params.get("size"))


@route("/formatValue")
def format_value(req: Request):
    """Convert a value and annotate the binary with the result as a comment."""
    text = req.params.get("text")
    address_str = req.params.get("address")
    if not text or not address_str:
        raise HTTPError(
            400,
            {
                "error": "Missing parameters",
                "help": "Required: address, text. Optional: size",
                "received": req.params,
            },
        )
    try:
        address = parse_address(address_str, bare_hex=False)
    except ValueError:
        raise HTTPError(400, "Invalid address format")

    conv = convert_number(text, req.params.get("size"))

    # Build a concise annotation from the conversion result
    bases = conv.get("bases", {})
    parts = []
    if "hex" in bases:
        parts.append(f"hex={bases['hex']}")
    if "dec" in bases:
        parts.append(f"dec={bases['dec']}")
    if conv.get("c_literal"):
        parts.append(f"char={conv['c_literal']}")
    if conv.get("c_string"):
        s = conv["c_string"]
        if len(s) > 64:
            s = s[:61] + '"…'
        parts.append(f"str={s}")
    annotation = "Converted: " + ", ".join(parts) if parts else f"Converted: {conv}"

    applied = req.binary_ops.set_comment(address, annotation)
    return {
        "address": hex(address),
        "converted": conv,
        "applied_comment": bool(applied),
        "comment": annotation,
    }
