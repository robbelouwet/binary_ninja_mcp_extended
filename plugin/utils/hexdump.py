"""Classic 16-bytes-per-line hexdump formatting."""


def _printable(byte: int) -> str:
    return chr(byte) if 32 <= byte <= 126 else "."


def format_hexdump(address: int, data: bytes, label: str | None = None) -> str:
    """Format ``data`` starting at ``address`` as a hexdump.

    The first line is a header (``<addr>  <label>:`` when a label is given);
    the first data line is padded so byte columns stay aligned to 16-byte
    boundaries even for unaligned start addresses.
    """
    addr_hex = format(address, "x")
    lines = [f"{addr_hex}  {label}:" if label else f"{addr_hex}:"]

    total = len(data)
    offset = 0

    # First line may be unaligned
    first_pad = address % 16
    if first_pad != 0 and total > 0:
        take = min(16 - first_pad, total)
        chunk = data[:take]
        hex_area = ("   " * first_pad) + "".join(f"{b:02x} " for b in chunk)
        hex_area += "   " * (16 - first_pad - take)
        ascii_area = (" " * first_pad) + "".join(_printable(b) for b in chunk)
        ascii_area += " " * (16 - first_pad - take)
        lines.append(f"{addr_hex}  {hex_area} {ascii_area}")
        offset += take

    # Full lines
    while offset < total:
        line_addr = address + offset
        take = min(16, total - offset)
        chunk = data[offset : offset + take]
        hex_area = "".join(f"{b:02x} " for b in chunk) + ("   " * (16 - take))
        ascii_area = "".join(_printable(b) for b in chunk) + (" " * (16 - take))
        lines.append(f"{format(line_addr, 'x')}  {hex_area} {ascii_area}")
        offset += take

    return "\n".join(lines) + "\n"
