"""Data operations: segments, sections, defined data, strings, byte patching."""

import platform
import re
import subprocess
from typing import Any

import binaryninja as bn

from ..utils.string_utils import escape_non_ascii


class DataOperations:
    """Mixin for reading and modifying data in the binary."""

    def get_segments(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Get list of segments with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        segments = []
        for segment in self._current_view.segments:
            segment_info = {
                "start": hex(segment.start),
                "end": hex(segment.end),
                "name": "",
                "flags": [],
            }

            # Try to get segment name if available
            if hasattr(segment, "name"):
                segment_info["name"] = segment.name
            elif hasattr(segment, "data_name"):
                segment_info["name"] = segment.data_name

            # Try to get segment flags safely
            if hasattr(segment, "flags"):
                try:
                    if isinstance(segment.flags, (list, tuple)):
                        segment_info["flags"] = list(segment.flags)
                    else:
                        segment_info["flags"] = [str(segment.flags)]
                except (AttributeError, TypeError, ValueError):
                    pass

            # Add segment permissions if available
            if hasattr(segment, "readable"):
                segment_info["readable"] = bool(segment.readable)
            if hasattr(segment, "writable"):
                segment_info["writable"] = bool(segment.writable)
            if hasattr(segment, "executable"):
                segment_info["executable"] = bool(segment.executable)

            segments.append(segment_info)

        return segments[offset : offset + limit]

    def get_sections(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Get list of sections with pagination.

        Returns per-section fields when available:
        - name: section name
        - start/end: hex strings
        - size: integer number of bytes (end - start)
        - type: stringified section type (if exposed by BN)
        - semantics: stringified semantics (if exposed by BN)
        - linked_section: related/paired section name if exposed
        - alignment: alignment in bytes if exposed
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: list[dict[str, Any]] = []

        # Binary Ninja has exposed sections across versions either as an
        # iterable of Section objects or a dict-like object. Handle both.
        try:
            sec_container = getattr(self._current_view, "sections", None)
        except Exception:
            sec_container = None
        if not sec_container:
            return []

        def _iter_sections(container):
            try:
                # If it's a dict-like {name: Section}
                if hasattr(container, "items"):
                    for _name, _sec in list(container.items()):
                        yield _sec
                    return
            except Exception:
                pass
            # Otherwise assume it's iterable of Section objects
            try:
                for _sec in list(container):
                    yield _sec
            except Exception:
                return

        for sec in _iter_sections(sec_container):
            try:
                start = getattr(sec, "start", None)
                end = getattr(sec, "end", None)
                if start is None or end is None:
                    continue
                name = None
                try:
                    name = getattr(sec, "name", None)
                except Exception:
                    name = None
                try:
                    size = int(end) - int(start)
                except Exception:
                    size = None

                entry: dict[str, Any] = {
                    "name": name or "",
                    "start": hex(int(start)),
                    "end": hex(int(end)),
                    "size": size,
                }

                # Optional attributes: type, semantics, linked_section, alignment
                for attr, key in (
                    ("type", "type"),
                    ("semantics", "semantics"),
                    ("linked_section", "linked_section"),
                    ("align", "alignment"),
                    ("alignment", "alignment"),
                ):
                    try:
                        val = getattr(sec, attr, None)
                        if val is not None:
                            entry[key] = str(val)
                    except Exception:
                        pass

                results.append(entry)
            except Exception:
                continue

        return results[offset : offset + limit]

    def rename_data(self, address: int, new_name: str) -> bool:
        """Rename data at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.define_user_symbol(
                    bn.Symbol(bn.SymbolType.DataSymbol, address, new_name)
                )
                return True
        except Exception as e:
            bn.log_error(f"Failed to rename data: {e}")
        return False

    def get_defined_data(
        self, offset: int = 0, limit: int = 100, read_len: int = 32
    ) -> list[dict[str, Any]]:
        """Get list of defined data variables with lightweight previews and sizes.

        Returns per-item fields:
        - address: hex string
        - name/raw_name: label info if available
        - type: string if available
        - size: exact defined size in bytes if known (from BN type)
        - width: alias of size for backward compatibility
        - value: small integer value when width<=8 and readable; otherwise None
        - bytes_hex: hex string of up to preview_len bytes
        - ascii_preview: printable ASCII representation for the same bytes
        - repr: concise, human-friendly summary for LLMs (value/ASCII/hex)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self._current_view.data_vars:
            data_type = None  # may be a BN Type or a DataVariable
            value = None
            width = None
            bytes_hex = None
            ascii_preview = None
            typ_obj = None

            try:
                # Prefer DataVariable (carries underlying Type)
                dv = None
                if hasattr(self._current_view, "get_data_var_at"):
                    try:
                        dv = self._current_view.get_data_var_at(var)
                    except Exception:
                        dv = None
                if dv is not None and hasattr(dv, "type") and dv.type is not None:
                    typ_obj = dv.type
                    data_type = dv  # keep for fallback string formatting
                else:
                    # Fall back to direct type lookup
                    if hasattr(self._current_view, "get_type_at"):
                        try:
                            typ_obj = self._current_view.get_type_at(var)
                            data_type = typ_obj
                        except Exception:
                            typ_obj = None

                # Exact defined size if available
                if typ_obj is not None and hasattr(typ_obj, "width"):
                    try:
                        width = int(typ_obj.width)
                    except Exception:
                        width = None

                # Best-effort numeric read for small integers (<= 8 bytes)
                if width is not None and width <= 8:
                    try:
                        value = str(self._current_view.read_int(var, width))
                    except (ValueError, RuntimeError):
                        value = None

                # Provide bytes + ASCII preview for all cases
                # Determine effective read length
                try:
                    requested = int(read_len)
                except Exception:
                    requested = 32
                # If requested < 0 and width known, treat as "read exact size"
                if requested < 0 and width is not None:
                    eff_len = max(0, int(width))
                else:
                    eff_len = max(0, requested if requested >= 0 else 32)
                if width is not None:
                    eff_len = min(eff_len, int(width))

                try:
                    raw = self._current_view.read(var, eff_len)
                    if raw is not None:
                        try:
                            bytes_hex = raw.hex()
                        except Exception:
                            bytes_hex = None
                        try:
                            ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
                        except Exception:
                            ascii_preview = None
                except (ValueError, RuntimeError, TypeError):
                    pass
            except (AttributeError, TypeError, ValueError, RuntimeError):
                value = None
                data_type = None
                typ_obj = None

            # If BN doesn't expose a width, try to infer size from call sites
            if width is None:
                try:
                    inferred = self.infer_data_size(int(var))
                    if isinstance(inferred, int) and inferred > 0:
                        width = inferred
                except Exception:
                    pass

            # Get symbol information
            sym = self._current_view.get_symbol_at(var)
            # Choose a concise repr for LLMs
            if value is not None:
                short_repr = f"int:{value}"
            elif ascii_preview:
                short_repr = f'ascii:"{ascii_preview}"'
            elif bytes_hex:
                short_repr = f"hex:{bytes_hex}"
            else:
                short_repr = None

            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name if sym and hasattr(sym, "raw_name") else None,
                    # Prefer clean type string (avoid "<var ...>" envelope when possible)
                    "type": (
                        str(typ_obj)
                        if typ_obj is not None
                        else (str(data_type) if data_type else None)
                    ),
                    "size": width,
                    "width": width,
                    "value": value,
                    "bytes_hex": bytes_hex,
                    "ascii_preview": ascii_preview,
                    "bytes_read": len(bytes_hex) // 2 if bytes_hex else 0,
                    "repr": short_repr,
                }
            )

        return data_items[offset : offset + limit]

    def infer_data_size(self, address: int) -> int | None:
        """Infer size for data at address when BN hasn't defined a type width.

        Strategy:
        - Prefer BN's DataVariable.type.width or get_type_at().width if available.
        - Otherwise scan HLIL for calls like memcmp/strncmp/memcpy/strncpy where
          an argument equals this address and extract the last numeric argument
          as a best-effort length. Returns the maximum constant seen.
        """
        if not self._current_view:
            return None

        # 1) BN-provided width if available
        try:
            dv = None
            if hasattr(self._current_view, "get_data_var_at"):
                dv = self._current_view.get_data_var_at(address)
            t = None
            if dv is not None and hasattr(dv, "type"):
                t = dv.type
            elif hasattr(self._current_view, "get_type_at"):
                t = self._current_view.get_type_at(address)
            if t is not None and hasattr(t, "width") and t.width:
                return int(t.width)
        except Exception:
            pass

        # 2) HLIL heuristic
        try:
            addr_hex = hex(address)
            candidates: list[int] = []
            names = ("memcmp", "strncmp", "memcpy", "strncpy")
            for func in list(self._current_view.functions):
                try:
                    il = getattr(func, "hlil", None)
                    if not il:
                        continue
                    for ins in il.instructions:
                        try:
                            text = str(ins)
                            if addr_hex not in text:
                                continue
                            if not any(n in text for n in names):
                                continue
                            # Extract all numeric constants
                            nums = re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", text)
                            vals: list[int] = []
                            for n in nums:
                                try:
                                    v = int(n, 16) if n.startswith("0x") else int(n)
                                    vals.append(v)
                                except Exception:
                                    continue
                            if vals:
                                # Heuristic: last constant in call string is likely the size
                                candidates.append(vals[-1])
                        except Exception:
                            continue
                except Exception:
                    continue
            if candidates:
                # Use the maximum plausible size
                best = max(c for c in candidates if c > 0)
                if best > 0:
                    return best
        except Exception:
            pass
        return None

    def get_strings(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Get list of strings in the current binary view with pagination.

        Returns a list of dictionaries containing:
        - address: start address of the string (hex)
        - length: length in bytes (int if available)
        - type: Binary Ninja string type (str if available)
        - value: best-effort decoded and escaped string value
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: list[dict[str, Any]] = []

        try:
            # Prefer modern API if available
            strings_iter = None
            if hasattr(self._current_view, "get_strings"):
                try:
                    strings_iter = self._current_view.get_strings()
                except TypeError:
                    strings_iter = None

            if strings_iter is None and hasattr(self._current_view, "strings"):
                try:
                    strings_iter = list(self._current_view.strings)
                except Exception:
                    strings_iter = []

            if strings_iter is None:
                strings_iter = []

            for s in strings_iter:
                try:
                    addr = None
                    length = None
                    stype = None
                    value = None

                    # Common attributes on StringReference
                    addr = getattr(s, "start", getattr(s, "address", None))
                    length = getattr(s, "length", None)
                    stype = getattr(s, "type", None)
                    if stype is not None:
                        try:
                            stype = str(stype)
                        except Exception:
                            stype = str(stype)

                    value = getattr(s, "value", None)

                    # Best-effort read/decode if value is not present
                    if value is None and addr is not None and length is not None:
                        try:
                            raw = self._current_view.read(addr, length)
                            # Stop at first null byte if present
                            nul = raw.find(b"\x00")
                            if nul != -1:
                                raw = raw[:nul]
                            try:
                                value = raw.decode("utf-8", errors="ignore")
                            except Exception:
                                value = raw.decode("latin-1", errors="ignore")
                        except Exception:
                            value = None

                    # Ensure value is a string and escape non-ASCII
                    if value is None:
                        value = ""
                    value = escape_non_ascii(str(value))

                    results.append(
                        {
                            "address": hex(addr)
                            if isinstance(addr, int)
                            else (str(addr) if addr is not None else None),
                            "length": int(length)
                            if isinstance(length, (int,))
                            else (None if length is None else int(length)),
                            "type": stype,
                            "value": value,
                        }
                    )
                except Exception as e:
                    # Keep collecting even if one entry fails
                    bn.log_debug(f"Error processing string entry: {e}")
                    continue

            return results[offset : offset + limit]
        except Exception as e:
            bn.log_error(f"Error getting strings: {e}")
            return []

    def patch_bytes(
        self, address: str | int, data: str | bytes | list[int], save_to_file: bool = True
    ) -> dict[str, Any]:
        """Patch bytes at a given address in the binary.

        Args:
            address: Address to patch (hex string like "0x401000" or integer)
            data: Bytes to write. Can be:
                - Hex string: "90 90" or "9090" or "0x90 0x90"
                - List of integers: [0x90, 0x90]
                - Bytes object: b"\x90\x90"
            save_to_file: If True (default), save the patched binary to disk

        Returns:
            Dictionary with status, address, original bytes, and patched bytes

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If address or data format is invalid
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Parse address
        # Only treat as hex if it has "0x" prefix or contains a-f/A-F characters
        # This avoids ambiguity where "123" would be treated as hex instead of decimal
        if isinstance(address, str):
            address = address.strip()
            if address.startswith("0x") or address.startswith("0X"):
                addr = int(address, 16)
            elif any(c in "abcdefABCDEF" for c in address):
                # Contains hex letters, treat as hex
                addr = int(address, 16)
            else:
                # Pure digits, treat as decimal
                addr = int(address, 10)
        else:
            addr = int(address)

        # Parse data into bytes
        patch_bytes = None
        if isinstance(data, bytes):
            patch_bytes = data
        elif isinstance(data, str):
            # Try to parse as hex string
            data_str = data.strip()
            # Remove "0x" prefix if present
            if data_str.startswith("0x"):
                data_str = data_str[2:]
            # Remove spaces
            data_str = data_str.replace(" ", "").replace("\n", "").replace("\t", "")
            # Convert hex string to bytes
            try:
                patch_bytes = bytes.fromhex(data_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}")
        elif isinstance(data, list):
            # List of integers
            try:
                patch_bytes = bytes(data)
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid byte list: {e}")
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

        if not patch_bytes:
            raise ValueError("Empty patch data")

        # Read original bytes for comparison
        try:
            original_bytes = self._current_view.read(addr, len(patch_bytes))
            if original_bytes is None:
                original_bytes = b""
        except Exception as e:
            bn.log_warn(f"Could not read original bytes at {hex(addr)}: {e}")
            original_bytes = b""

        # Write the patch
        try:
            written = self._current_view.write(addr, patch_bytes)

            # Determine status based on whether all bytes were written
            if written != len(patch_bytes):
                bn.log_warn(f"Only wrote {written} of {len(patch_bytes)} bytes at {hex(addr)}")
                status = "partial"
            else:
                status = "ok"

            result = {
                "status": status,
                "address": hex(addr),
                "original_bytes": original_bytes.hex() if original_bytes else "",
                "patched_bytes": patch_bytes.hex(),
                "bytes_written": written,
                "bytes_requested": len(patch_bytes),
                "saved_to_file": False,
            }

            # Add warning message if partial write
            if status == "partial":
                result["warning"] = f"Only wrote {written} of {len(patch_bytes)} bytes"

            # Save to file if requested
            if save_to_file:
                try:
                    # Get the original file path
                    original_file = self._current_view.file.filename
                    if original_file:
                        # Save the patched binary back to the original file
                        if self._current_view.save(original_file):
                            result["saved_to_file"] = True
                            result["saved_path"] = original_file
                            bn.log_info(f"Patched binary saved to: {original_file}")

                            # On macOS, re-sign the binary to avoid "killed" error
                            if platform.system() == "Darwin":
                                result["codesign"] = self._codesign_binary(original_file)
                        else:
                            bn.log_warn(f"Failed to save patched binary to: {original_file}")
                            result["save_error"] = "save() returned False"
                    else:
                        bn.log_warn("No original file path available for saving")
                        result["save_error"] = "No original file path"
                except Exception as save_e:
                    bn.log_warn(f"Failed to save patched binary: {save_e}")
                    result["save_error"] = str(save_e)

            return result
        except Exception as e:
            raise ValueError(f"Failed to patch bytes at {hex(addr)}: {e!s}")

    def _codesign_binary(self, file_path: str) -> dict[str, Any]:
        """Re-sign a binary on macOS after patching.

        On macOS, modifying a binary invalidates its code signature, causing the
        system to kill the process when executed. This method removes the old
        signature and applies an ad-hoc signature to make the binary executable.

        Args:
            file_path: Path to the binary file to sign

        Returns:
            Dictionary with codesign status and any error messages
        """
        result = {
            "attempted": True,
            "success": False,
            "platform": "macOS",
        }

        try:
            # Step 1: Remove existing signature (optional, codesign -f will overwrite anyway)
            remove_result = subprocess.run(
                ["codesign", "--remove-signature", file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if remove_result.returncode != 0:
                # It's okay if removal fails (binary might not have been signed)
                bn.log_info(
                    f"codesign --remove-signature returned {remove_result.returncode}: {remove_result.stderr}"
                )

            # Step 2: Apply ad-hoc signature with force flag
            sign_result = subprocess.run(
                ["codesign", "-f", "-s", "-", file_path], capture_output=True, text=True, timeout=30
            )

            if sign_result.returncode == 0:
                result["success"] = True
                result["message"] = "Binary re-signed with ad-hoc signature"
                bn.log_info(f"Successfully re-signed binary: {file_path}")
            else:
                result["error"] = (
                    sign_result.stderr or f"codesign failed with code {sign_result.returncode}"
                )
                bn.log_warn(f"Failed to re-sign binary: {result['error']}")

        except FileNotFoundError:
            result["error"] = "codesign command not found"
            bn.log_warn("codesign command not found - is Xcode Command Line Tools installed?")
        except subprocess.TimeoutExpired:
            result["error"] = "codesign command timed out"
            bn.log_warn("codesign command timed out")
        except Exception as e:
            result["error"] = str(e)
            bn.log_warn(f"Error during codesign: {e}")

        return result
