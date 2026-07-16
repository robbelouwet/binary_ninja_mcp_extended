"""Function operations: lookup, metadata, decompilation, IL, call graph."""

from typing import Any

import binaryninja as bn


class FunctionOperations:
    """Mixin with function-level analysis and modification operations."""

    def get_function_by_name_or_address(self, identifier: str | int) -> bn.Function | None:
        """Get a function by either its name or address.

        Args:
            identifier: Function name or address (can be int, hex string, or decimal string)

        Returns:
            Function object if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Handle address-based lookup
        try:
            if isinstance(identifier, str) and identifier.startswith("0x"):
                addr = int(identifier, 16)
            elif isinstance(identifier, (int, str)):
                addr = int(identifier) if isinstance(identifier, str) else identifier

            func = self._current_view.get_function_at(addr)
            if func:
                bn.log_info(f"Found function at address {hex(addr)}: {func.name}")
                return func
        except ValueError:
            pass

        # Handle name-based lookup with case sensitivity
        for func in self._current_view.functions:
            if func.name == identifier:
                bn.log_info(f"Found function by name: {func.name}")
                return func

        # Try case-insensitive match as fallback
        for func in self._current_view.functions:
            if func.name.lower() == str(identifier).lower():
                bn.log_info(f"Found function by case-insensitive name: {func.name}")
                return func

        # Try symbol table lookup as last resort
        symbol = self._current_view.get_symbol_by_raw_name(str(identifier))
        if symbol and symbol.address:
            func = self._current_view.get_function_at(symbol.address)
            if func:
                bn.log_info(f"Found function through symbol lookup: {func.name}")
                return func

        bn.log_error(f"Could not find function: {identifier}")
        return None

    def _normalize_identifier_list(self, identifiers: Any) -> list[Any]:
        """Normalize comma-delimited strings or iterables into a list of identifiers."""
        if identifiers is None:
            return []
        if isinstance(identifiers, (list, tuple, set)):
            raw_items = list(identifiers)
        else:
            raw_items = [identifiers]
        normalized: list[Any] = []
        for item in raw_items:
            if item is None:
                continue
            if isinstance(item, str):
                # Allow comma or semicolon separation for convenience
                tokens = [tok.strip() for tok in item.replace(";", ",").split(",")]
                normalized.extend([tok for tok in tokens if tok])
            else:
                normalized.append(item)
        return normalized

    def _format_function_reference(self, func: bn.Function | None) -> dict[str, Any] | None:
        if not func:
            return None
        try:
            return {
                "name": getattr(func, "name", None),
                "address": hex(int(func.start)) if hasattr(func, "start") else None,
            }
        except Exception:
            return {
                "name": getattr(func, "name", None),
                "address": None,
            }

    def _collect_related_functions(
        self, func: bn.Function, relation_attr: str
    ) -> list[dict[str, Any]]:
        related: list[dict[str, Any]] = []
        seen: set[int] = set()
        try:
            rel_iter = getattr(func, relation_attr, None)
        except Exception:
            rel_iter = None
        if rel_iter is None:
            return related
        try:
            for rel_func in list(rel_iter):
                if not rel_func:
                    continue
                addr = None
                try:
                    addr = int(rel_func.start)
                except Exception:
                    addr = None
                if addr is not None and addr in seen:
                    continue
                if addr is not None:
                    seen.add(addr)
                ref = self._format_function_reference(rel_func)
                if ref:
                    related.append(ref)
        except Exception:
            pass
        return related

    def _summarize_call_sites(self, func: bn.Function, relation: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        attr = "caller_sites" if relation == "callers" else "call_sites"
        try:
            sites = getattr(func, attr, None)
        except Exception:
            sites = None
        if not sites:
            return entries

        def _extract_function(site: Any, names: tuple[str, ...]) -> bn.Function | None:
            for name in names:
                try:
                    value = getattr(site, name, None)
                except Exception:
                    value = None
                if value:
                    return value
            return None

        for site in list(sites):
            try:
                entry: dict[str, Any] = {}
                addr = getattr(site, "address", None)
                if isinstance(addr, int):
                    entry["address"] = hex(addr)
                elif isinstance(addr, str) and addr:
                    entry["address"] = addr

                if relation == "callers":
                    caller_func = _extract_function(site, ("function", "source_function", "caller"))
                    ref = self._format_function_reference(caller_func)
                    if ref:
                        entry["caller"] = ref
                else:
                    callee_func = _extract_function(
                        site, ("callee", "dest_function", "target_function")
                    )
                    ref = self._format_function_reference(callee_func)
                    if ref:
                        entry["callee"] = ref
                    else:
                        # Fall back to raw destination address when available
                        dest = None
                        for attr_name in ("dest", "target", "constant"):
                            try:
                                dest = getattr(site, attr_name)
                            except Exception:
                                dest = None
                            if dest is not None:
                                break
                        if isinstance(dest, int):
                            entry["callee"] = {"name": None, "address": hex(dest)}

                # Attach textual representation for quick context
                summary_text = None
                for attr_name in ("hlil", "il"):
                    try:
                        val = getattr(site, attr_name, None)
                    except Exception:
                        val = None
                    if val is not None:
                        summary_text = str(val)
                        break
                if summary_text is None:
                    summary_text = str(site)
                entry["il"] = summary_text

                entries.append(entry)
            except Exception:
                continue
        return entries

    def get_callers(self, identifiers: Any) -> dict[str, Any]:
        """Collect caller information for the given function identifiers."""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        items = self._normalize_identifier_list(identifiers)
        if not items:
            raise ValueError("No function identifiers provided")

        results: list[dict[str, Any]] = []
        errors: list[str] = []
        for ident in items:
            try:
                func = self.get_function_by_name_or_address(ident)
            except Exception as exc:
                func = None
                errors.append(f"{ident}: {exc}")
            if not func:
                errors.append(f"Function not found: {ident}")
                continue
            entry = {
                "identifier": str(ident),
                "function": self._format_function_reference(func),
                "callers": self._collect_related_functions(func, "callers"),
                "caller_sites": self._summarize_call_sites(func, "callers"),
            }
            results.append(entry)

        return {"results": results, "errors": errors}

    def get_callees(self, identifiers: Any) -> dict[str, Any]:
        """Collect callee information for the given function identifiers."""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        items = self._normalize_identifier_list(identifiers)
        if not items:
            raise ValueError("No function identifiers provided")

        results: list[dict[str, Any]] = []
        errors: list[str] = []
        for ident in items:
            try:
                func = self.get_function_by_name_or_address(ident)
            except Exception as exc:
                func = None
                errors.append(f"{ident}: {exc}")
            if not func:
                errors.append(f"Function not found: {ident}")
                continue
            entry = {
                "identifier": str(ident),
                "function": self._format_function_reference(func),
                "callees": self._collect_related_functions(func, "callees"),
                "call_sites": self._summarize_call_sites(func, "callees"),
            }
            results.append(entry)

        return {"results": results, "errors": errors}

    def get_function_names(self, offset: int = 0, limit: int = 100) -> list[dict[str, str]]:
        """Get list of function names with addresses"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        functions = []
        for func in self._current_view.functions:
            functions.append(
                {
                    "name": func.name,
                    "address": hex(func.start),
                    "raw_name": func.raw_name if hasattr(func, "raw_name") else func.name,
                }
            )

        return functions[offset : offset + limit]

    def get_class_names(self, offset: int = 0, limit: int = 100) -> list[str]:
        """Get list of class names with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        class_names = set()

        try:
            # Try different methods to identify classes
            for type_obj in self._current_view.types.values():
                try:
                    # Skip None or invalid types
                    if not type_obj or not hasattr(type_obj, "name"):
                        continue

                    # Method 1: Check type_class attribute
                    if hasattr(type_obj, "type_class"):
                        class_names.add(type_obj.name)
                        continue

                    # Method 2: Check structure attribute
                    if hasattr(type_obj, "structure") and type_obj.structure:
                        structure = type_obj.structure

                        # Check various attributes that indicate a class
                        if any(
                            hasattr(structure, attr)
                            for attr in [
                                "vtable",
                                "base_structures",
                                "members",
                                "functions",
                            ]
                        ):
                            class_names.add(type_obj.name)
                            continue

                        # Check type attribute if available
                        if hasattr(structure, "type"):
                            type_str = str(structure.type).lower()
                            if "class" in type_str or "struct" in type_str:
                                class_names.add(type_obj.name)
                                continue

                except Exception as e:
                    bn.log_debug(
                        f"Error processing type {getattr(type_obj, 'name', '<unknown>')}: {e}"
                    )
                    continue

            bn.log_info(f"Found {len(class_names)} classes")
            sorted_names = sorted(list(class_names))
            return sorted_names[offset : offset + limit]

        except Exception as e:
            bn.log_error(f"Error getting class names: {e}")
            return []

    def rename_function(self, old_name: str, new_name: str) -> bool:
        """Rename a function using multiple fallback methods.

        Args:
            old_name: Current function name or address
            new_name: New name for the function

        Returns:
            True if rename succeeded, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(old_name)
            if not func:
                bn.log_error(f"Function not found: {old_name}")
                return False

            bn.log_info(f"Found function to rename: {func.name} at {hex(func.start)}")

            if not new_name or not isinstance(new_name, str):
                bn.log_error(f"Invalid new name: {new_name}")
                return False

            if not hasattr(func, "name") or not hasattr(func, "__setattr__"):
                bn.log_error(f"Function {func.name} cannot be renamed (read-only)")
                return False

            try:
                # Try direct name assignment first
                old_name = func.name
                func.name = new_name

                if func.name == new_name:
                    bn.log_info(f"Successfully renamed function from {old_name} to {new_name}")
                    return True

                # Try symbol-based renaming if direct assignment fails
                if hasattr(func, "symbol") and func.symbol:
                    try:
                        new_symbol = bn.Symbol(
                            func.symbol.type,
                            func.start,
                            new_name,
                            namespace=func.symbol.namespace
                            if hasattr(func.symbol, "namespace")
                            else None,
                        )
                        self._current_view.define_user_symbol(new_symbol)
                        bn.log_info("Successfully renamed function using symbol table")
                        return True
                    except Exception as e:
                        bn.log_error(f"Symbol-based rename failed: {e}")

                # Try function update method as last resort
                if hasattr(self._current_view, "update_function"):
                    try:
                        func_copy = func
                        func_copy.name = new_name
                        self._current_view.update_function(func)
                        bn.log_info("Successfully renamed function using update method")
                        return True
                    except Exception as e:
                        bn.log_error(f"Function update rename failed: {e}")

                bn.log_error(f"All rename methods failed - function name unchanged: {func.name}")
                return False

            except Exception as e:
                bn.log_error(f"Error during rename operation: {e}")
                return False

        except Exception as e:
            bn.log_error(f"Error in rename_function: {e}")
            return False

    def get_function_info(self, identifier: str | int) -> dict[str, Any] | None:
        """Get detailed information about a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        bn.log_info(f"Found function: {func.name} at {hex(func.start)}")

        info = {
            "name": func.name,
            "raw_name": func.raw_name if hasattr(func, "raw_name") else func.name,
            "address": hex(func.start),
            "symbol": None,
        }

        if func.symbol:
            info["symbol"] = {
                "type": str(func.symbol.type),
                "full_name": func.symbol.full_name
                if hasattr(func.symbol, "full_name")
                else func.symbol.name,
            }

        return info

    def decompile_function(self, identifier: str | int) -> str | None:
        """Decompile a function and include addresses per statement.

        Args:
            identifier: Function name or address

        Returns:
            Decompiled HLIL-like code with address prefixes per line
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        # analyze func in case it was skipped
        func.analysis_skipped = False
        self._current_view.update_analysis_and_wait()

        try:
            il = getattr(func, "hlil", None)
            if il and hasattr(il, "instructions"):
                lines: list[str] = []
                last_addr: int | None = None
                for ins in il.instructions:
                    try:
                        addr = getattr(ins, "address", None)
                    except Exception:
                        addr = None
                    if addr is None:
                        addr = last_addr if last_addr is not None else func.start
                    last_addr = addr
                    addr_str = f"{int(addr):08x}"
                    text = str(ins)
                    lines.append(f"{addr_str}        {text}")
                return "\n".join(lines)
            # Fall back to MLIL with addresses
            mil = getattr(func, "mlil", None)
            if mil and hasattr(mil, "instructions"):
                lines: list[str] = []
                last_addr: int | None = None
                for ins in mil.instructions:
                    try:
                        addr = getattr(ins, "address", None)
                    except Exception:
                        addr = None
                    if addr is None:
                        addr = last_addr if last_addr is not None else func.start
                    last_addr = addr
                    addr_str = f"{int(addr):08x}"
                    text = str(ins)
                    lines.append(f"{addr_str}        {text}")
                return "\n".join(lines)
            # Last resort
            return str(func)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {e!s}")
            return None

    def get_function_il(
        self, identifier: str | int, view: str = "hlil", ssa: bool = False
    ) -> str | None:
        """Return IL for a function with selectable view and optional SSA form.

        Args:
            identifier: Function name or address
            view: One of 'hlil', 'mlil', 'llil' (case-insensitive). Aliases: 'il' -> 'llil'.
            ssa: When True, use SSA form if available (MLIL/LLIL only)

        Returns:
            Concatenated string with one instruction per line prefixed by address.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        # Ensure analysis has run for this function
        try:
            func.analysis_skipped = False
            self._current_view.update_analysis_and_wait()
        except Exception:
            pass

        v = (view or "").strip().lower()
        if v in ("il", "llil", "low", "lowlevel", "low-level", "low_level"):
            prop = "llil"
        elif v in ("mlil", "medium", "mediumlevel", "medium-level", "medium_level"):
            prop = "mlil"
        else:
            # Default to HLIL when unknown
            prop = "hlil"

        try:
            il_func = getattr(func, prop, None)
            if il_func is None:
                return None

            # Only MLIL/LLIL support SSA form in practice
            if ssa and hasattr(il_func, "ssa_form") and il_func.ssa_form is not None:
                il_func = il_func.ssa_form

            if not hasattr(il_func, "instructions"):
                # As a last resort, stringify the object
                return str(il_func)

            lines: list[str] = []
            last_addr: int | None = None
            for ins in il_func.instructions:
                try:
                    addr = getattr(ins, "address", None)
                except Exception:
                    addr = None
                if addr is None:
                    addr = last_addr if last_addr is not None else func.start
                last_addr = addr
                addr_str = f"{int(addr):08x}"
                text = str(ins)
                lines.append(f"{addr_str}        {text}")
            return "\n".join(lines)
        except Exception as e:
            bn.log_error(
                f"Error getting {prop}{' SSA' if ssa else ''} for function {identifier}: {e!s}"
            )
            return None

    def make_function_at(
        self, address: str | int, architecture: str | None = None
    ) -> dict[str, Any]:
        """Create a function at the given address (no-op if it already exists).

        Args:
            address: Hex string (e.g., 0x401000) or integer address.
            architecture: Optional architecture name (e.g., "x86_64", "x86", "armv7").

        Returns:
            Dict with keys: status (ok|exists), address, name (if found), architecture (if resolved).

        Raises:
            RuntimeError if no binary is loaded.
            ValueError on invalid address or creation failure.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Parse address
        try:
            if isinstance(address, str) and address.lower().startswith("0x"):
                addr = int(address, 16)
            else:
                addr = int(address)
        except Exception:
            raise ValueError(f"Invalid address: {address}")

        bv = self._current_view

        # If a function already exists, return info
        try:
            existing = bv.get_function_at(addr)
            if existing:
                return {
                    "status": "exists",
                    "address": hex(addr),
                    "name": existing.name,
                    "architecture": str(getattr(existing, "arch", getattr(bv, "arch", ""))) or None,
                }
        except Exception:
            pass

        # Resolve platform if provided; otherwise use view/platform default.
        # Note: BinaryView.create_user_function expects a Platform, not an Architecture.
        plat_obj = None
        arch_token = None
        if isinstance(architecture, str):
            arch_token = architecture.strip().lower()
        if architecture and arch_token not in (None, "", "default", "auto", "platform"):
            try:
                P = getattr(__import__("binaryninja", fromlist=["Platform"]), "Platform", None)
            except Exception:
                P = None
            if P is not None:
                try:
                    plat_obj = P[architecture]
                except Exception:
                    try:
                        getp = getattr(P, "get_by_name", None)
                        if callable(getp):
                            plat_obj = getp(architecture)
                    except Exception:
                        plat_obj = None
            # If user explicitly provided an architecture/platform name and we couldn't resolve it,
            # return an error with suggestions instead of silently using the default.
            if plat_obj is None:
                import re as _re
                from difflib import get_close_matches as _gcm

                names: list[str] = []
                # Prefer dynamic enumeration via binaryninja.Platform
                try:
                    import binaryninja as _bn  # type: ignore

                    try:
                        names = [
                            str(getattr(p, "name", str(p))) for p in list(getattr(_bn, "Platform"))
                        ]
                    except Exception:
                        names = []
                except Exception:
                    names = []
                # Fallback: try iterating via imported P if available
                if not names and P is not None:
                    try:
                        names = [str(getattr(p, "name", str(p))) for p in list(P)]
                    except Exception:
                        names = []
                # Last resort: static catalog (kept up-to-date best-effort)
                if not names:
                    names = [
                        "decree-x86",
                        "efi-x86",
                        "efi-windows-x86",
                        "efi-x86_64",
                        "efi-windows-x86_64",
                        "efi-aarch64",
                        "efi-windows-aarch64",
                        "efi-armv7",
                        "efi-thumb2",
                        "freebsd-x86",
                        "freebsd-x86_64",
                        "freebsd-aarch64",
                        "freebsd-armv7",
                        "freebsd-thumb2",
                        "ios-aarch64",
                        "ios-armv7",
                        "ios-thumb2",
                        "ios-kernel-aarch64",
                        "ios-kernel-armv7",
                        "ios-kernel-thumb2",
                        "linux-ppc32",
                        "linux-ppcvle32",
                        "linux-ppc64",
                        "linux-ppc32_le",
                        "linux-ppc64_le",
                        "linux-rv32gc",
                        "linux-rv64gc",
                        "linux-x86",
                        "linux-x86_64",
                        "linux-x32",
                        "linux-aarch64",
                        "linux-armv7",
                        "linux-thumb2",
                        "linux-armv7eb",
                        "linux-thumb2eb",
                        "linux-mipsel",
                        "linux-mips",
                        "linux-mips3",
                        "linux-mipsel3",
                        "linux-mips64",
                        "linux-cnmips64",
                        "linux-mipsel64",
                        "mac-x86",
                        "mac-x86_64",
                        "mac-aarch64",
                        "mac-armv7",
                        "mac-thumb2",
                        "mac-kernel-x86",
                        "mac-kernel-x86_64",
                        "mac-kernel-aarch64",
                        "mac-kernel-armv7",
                        "mac-kernel-thumb2",
                        "windows-x86",
                        "windows-x86_64",
                        "windows-aarch64",
                        "windows-armv7",
                        "windows-thumb2",
                        "windows-kernel-x86",
                        "windows-kernel-x86_64",
                        "windows-kernel-windows-aarch64",
                    ]
                # Build ranked suggestions
                tl = (arch_token or "").lower()

                def _score(n: str) -> float:
                    nl = n.lower()
                    s = 0.0
                    if tl and tl in nl:
                        s += 2.0
                    # remove non-alnum for loose matching
                    tlr = _re.sub(r"[^a-z0-9]", "", tl)
                    nlr = _re.sub(r"[^a-z0-9]", "", nl)
                    if tlr and tlr in nlr:
                        s += 1.0
                    return s

                base = sorted(names)
                # Start with substring matches, then extend with close matches
                substr = [n for n in base if tl in n.lower()]
                # Use difflib for additional candidates if needed
                extra = _gcm(tl, base, n=10, cutoff=0.3) if tl else []
                cand = []
                seen = set()
                for n in substr + extra:
                    if n not in seen:
                        seen.add(n)
                        cand.append(n)
                cand.sort(key=_score, reverse=True)
                cand[:10]
                raise ValueError(f"Unknown platform/architecture '{architecture}'")
        # Default/platform fallback when no explicit architecture provided
        if plat_obj is None:
            try:
                plat_obj = getattr(bv, "platform", None)
            except Exception:
                plat_obj = None

        # Create the function
        try:
            if hasattr(bv, "create_user_function"):
                if plat_obj is not None:
                    bv.create_user_function(addr, plat_obj)
                else:
                    bv.create_user_function(addr)
            elif hasattr(bv, "add_function"):
                if plat_obj is not None:
                    bv.add_function(addr, plat_obj)
                else:
                    bv.add_function(addr)
            else:
                raise ValueError("BinaryView does not support function creation")
        except Exception as e:
            raise ValueError(f"Failed to create function: {e!s}")

        # Fetch created function info
        try:
            fn = bv.get_function_at(addr)
        except Exception:
            fn = None
        return {
            "status": "ok",
            "address": hex(addr),
            "name": fn.name if fn else None,
            "platform": str(plat_obj) if plat_obj is not None else None,
            "architecture": str(getattr(plat_obj, "arch", None))
            if plat_obj is not None
            else (
                str(getattr(bv, "arch", None)) if getattr(bv, "arch", None) is not None else None
            ),
        }

    def get_assembly_function(self, identifier: str | int) -> str | None:
        """Get the assembly representation of a function with practical annotations.

        Args:
            identifier: Function name or address

        Returns:
            Assembly code as string, or None if the function cannot be found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None

            bn.log_info(f"Found function: {func.name} at {hex(func.start)}")

            var_map = {}  # TODO: Implement this functionality (issues with var.storage not returning the correst sp offset)
            assembly_blocks = {}

            if not hasattr(func, "basic_blocks") or not func.basic_blocks:
                bn.log_error(f"Function {func.name} has no basic blocks")
                # Try alternate approach with linear disassembly
                start_addr = func.start
                try:
                    func_length = func.total_bytes
                    if func_length <= 0:
                        func_length = 1024  # Use a reasonable default if length not available
                except Exception:
                    func_length = 1024  # Use a reasonable default if error

                try:
                    # Create one big block for the entire function
                    block_lines = []
                    current_addr = start_addr
                    end_addr = start_addr + func_length

                    while current_addr < end_addr:
                        try:
                            # Get instruction length
                            instr_len = self._current_view.get_instruction_length(current_addr)
                            if instr_len <= 0:
                                instr_len = 4  # Default to a reasonable instruction length

                            # Get disassembly for this instruction
                            line = self._get_instruction_with_annotations(
                                current_addr, instr_len, var_map
                            )
                            if line:
                                block_lines.append(line)

                            current_addr += instr_len
                        except Exception as e:
                            bn.log_error(f"Error processing address {hex(current_addr)}: {e!s}")
                            block_lines.append(f"# Error at {hex(current_addr)}: {e!s}")
                            current_addr += 1  # Skip to next byte

                    assembly_blocks[start_addr] = [
                        f"# Block at {hex(start_addr)}",
                        *block_lines,
                        "",
                    ]

                except Exception as e:
                    bn.log_error(f"Linear disassembly failed: {e!s}")
                    return None
            else:
                for i, block in enumerate(func.basic_blocks):
                    try:
                        block_lines = []

                        # Process each address in the block
                        addr = block.start
                        while addr < block.end:
                            try:
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    instr_len = 4  # Default to a reasonable instruction length

                                # Get disassembly for this instruction
                                line = self._get_instruction_with_annotations(
                                    addr, instr_len, var_map
                                )
                                if line:
                                    block_lines.append(line)

                                addr += instr_len
                            except Exception as e:
                                bn.log_error(f"Error processing address {hex(addr)}: {e!s}")
                                block_lines.append(f"# Error at {hex(addr)}: {e!s}")
                                addr += 1  # Skip to next byte

                        # Store block with its starting address as key
                        assembly_blocks[block.start] = [
                            f"# Block {i + 1} at {hex(block.start)}",
                            *block_lines,
                            "",
                        ]

                    except Exception as e:
                        bn.log_error(f"Error processing block {i + 1} at {hex(block.start)}: {e!s}")
                        assembly_blocks[block.start] = [
                            f"# Error processing block {i + 1} at {hex(block.start)}: {e!s}",
                            "",
                        ]

            # Sort blocks by address and concatenate them
            sorted_blocks = []
            for addr in sorted(assembly_blocks.keys()):
                sorted_blocks.extend(assembly_blocks[addr])

            return "\n".join(sorted_blocks)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function {identifier}: {e!s}")
            import traceback

            bn.log_error(traceback.format_exc())
            return None

    def _get_instruction_with_annotations(
        self, addr: int, instr_len: int, var_map: dict[int, str]
    ) -> str | None:
        """Get a single instruction with practical annotations.

        Args:
            addr: Address of the instruction
            instr_len: Length of the instruction
            var_map: Dictionary mapping offsets to variable names

        Returns:
            Formatted instruction string with annotations
        """
        if not self._current_view:
            return None

        try:
            # Get raw bytes for fallback
            try:
                raw_bytes = self._current_view.read(addr, instr_len)
                hex_bytes = " ".join(f"{b:02x}" for b in raw_bytes)
            except Exception:
                hex_bytes = "??"

            # Get basic disassembly
            disasm_text = ""
            try:
                if hasattr(self._current_view, "get_disassembly"):
                    disasm = self._current_view.get_disassembly(addr)
                    if disasm:
                        disasm_text = disasm
            except Exception:
                disasm_text = hex_bytes + " ; [Raw bytes]"

            if not disasm_text:
                disasm_text = hex_bytes + " ; [Raw bytes]"

            # Check if this is a call instruction and try to get target function name
            if "call" in disasm_text.lower():
                try:
                    # Extract the address from the call instruction
                    import re

                    addr_pattern = r"0x[0-9a-fA-F]+"
                    match = re.search(addr_pattern, disasm_text)
                    if match:
                        call_addr_str = match.group(0)
                        call_addr = int(call_addr_str, 16)

                        # Look up the target function name
                        sym = self._current_view.get_symbol_at(call_addr)
                        if sym and hasattr(sym, "name"):
                            # Replace the address with the function name
                            disasm_text = disasm_text.replace(call_addr_str, sym.name)
                except Exception:
                    pass

            # Try to annotate memory references with variable names
            try:
                # Look for memory references like [reg+offset]
                import re

                mem_ref_pattern = r"\[([^\]]+)\]"
                mem_refs = re.findall(mem_ref_pattern, disasm_text)

                # For each memory reference, check if it's a known variable
                for mem_ref in mem_refs:
                    # Parse for ebp relative references
                    offset_pattern = r"(ebp|rbp)(([+-]0x[0-9a-fA-F]+)|([+-]\d+))"
                    offset_match = re.search(offset_pattern, mem_ref)
                    if offset_match:
                        # Extract base register and offset
                        offset_match.group(1)
                        offset_str = offset_match.group(2)

                        # Convert offset to integer
                        try:
                            offset = (
                                int(offset_str, 16)
                                if offset_str.startswith("0x") or offset_str.startswith("-0x")
                                else int(offset_str)
                            )

                            # Try to find variable name
                            var_name = var_map.get(offset)

                            # If found, add it to the memory reference
                            if var_name:
                                old_ref = f"[{mem_ref}]"
                                new_ref = f"[{mem_ref} {{{var_name}}}]"
                                disasm_text = disasm_text.replace(old_ref, new_ref)
                        except Exception:
                            pass
            except Exception:
                pass

            # Get comment if any
            comment = None
            try:
                comment = self._current_view.get_comment_at(addr)
            except Exception:
                pass

            # Format the final line
            addr_str = f"{addr:08x}"
            # Include hex bytes column padded for readability
            bytes_col = f"{hex_bytes}".ljust(16)
            line = f"{addr_str}  {bytes_col} {disasm_text}"

            # Add comment at the end if any
            if comment:
                line += f"  ; {comment}"

            return line
        except Exception as e:
            bn.log_error(f"Error annotating instruction at {hex(addr)}: {e!s}")
            return f"{addr:08x}  {hex_bytes} ; [Error: {e!s}]"

    def get_functions_containing_address(self, address: int) -> list:
        """Get functions containing a specific address.

        Args:
            address: The instruction address to find containing functions for

        Returns:
            List of function names containing the address
        """
        if not self.current_view:
            raise RuntimeError("No binary loaded")

        try:
            functions = list(self.current_view.get_functions_containing(address))
            return [func.name for func in functions]
        except Exception as e:
            bn.log_error(f"Error getting functions containing address {hex(address)}: {e}")
            return []

    def get_entry_points(self) -> list[dict[str, Any]]:
        """Return entry point(s) for the current binary view.

        Primarily uses `bv.entry_point`. Also includes common startup symbols like
        `_start` when resolvable.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        bv = self._current_view
        results: list[dict[str, Any]] = []

        def _append(addr: int):
            try:
                if addr is None:
                    return
                name = None
                try:
                    sym = bv.get_symbol_at(addr)
                    if sym and getattr(sym, "name", None):
                        name = sym.name
                except Exception:
                    pass
                if name is None:
                    try:
                        func = bv.get_function_at(addr)
                        if func and getattr(func, "name", None):
                            name = func.name
                    except Exception:
                        pass
                results.append(
                    {
                        "address": hex(int(addr)),
                        "name": name,
                    }
                )
            except Exception:
                pass

        # Primary entry point
        try:
            ep = getattr(bv, "entry_point", None)
            if isinstance(ep, int) and ep >= 0:
                _append(ep)
        except Exception:
            pass

        # Common startup symbol fallback
        for sname in ("_start", "entry", "start", "WinMain", "mainCRTStartup"):
            try:
                sym = bv.get_symbol_by_name(sname) if hasattr(bv, "get_symbol_by_name") else None
                if sym and hasattr(sym, "address"):
                    addr = int(sym.address)
                    if not any(r.get("address") == hex(addr) for r in results):
                        _append(addr)
            except Exception:
                continue

        return results

    # Removed: get_function_code_references() in favor of address-based get_xrefs_to_* helpers
