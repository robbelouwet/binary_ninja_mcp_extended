def escape_non_ascii(input_str: str) -> str:
    """Escape non-ASCII characters in a string"""
    if input_str is None:
        return ""
    result = ""
    for c in input_str:
        if 32 <= ord(c) < 127:
            result += c
        else:
            result += f"\\x{ord(c):02x}"
    return result


def parse_int_or_default(val: str, default: int) -> int:
    """Parse an integer from a string or return a default value"""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def parse_address(value: str | int, bare_hex: bool = True) -> int:
    """Parse an address given as int, "0x..." hex, bare hex, or decimal.

    With ``bare_hex=True`` (default), digit-only strings are interpreted as
    hexadecimal; with ``bare_hex=False`` they are interpreted as decimal.
    Raises ValueError for unparseable input.
    """
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if bare_hex and s and all(c in "0123456789abcdefABCDEF" for c in s):
        return int(s, 16)
    return int(s)


def c_escape(raw: bytes, limit: int | None = None) -> str:
    """Escape bytes as a double-quoted C string literal."""
    data = raw if limit is None else raw[:limit]
    out = []
    for ch in data:
        if ch == 0x22:  # '"'
            out.append('\\"')
        elif ch == 0x5C:  # '\\'
            out.append("\\\\")
        elif 32 <= ch <= 126:
            out.append(chr(ch))
        elif ch == 0x0A:
            out.append("\\n")
        elif ch == 0x0D:
            out.append("\\r")
        elif ch == 0x09:
            out.append("\\t")
        else:
            out.append(f"\\x{ch:02x}")
    return '"' + "".join(out) + '"'
