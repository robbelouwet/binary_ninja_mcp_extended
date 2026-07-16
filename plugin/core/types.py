"""Type operations: listing, searching, and inspecting local types."""

from typing import Any

import binaryninja as bn
from binaryninja.enums import StructureVariant, TypeClass


class TypeOperations:
    """Mixin for querying the type system of the current view."""

    def list_local_types(
        self, offset: int = 0, limit: int = 100, include_libraries: bool = False
    ) -> list[dict[str, Any]]:
        """List local types (Types view) in the current database.

        Returns a list of dictionaries with:
        - name: type name
        - kind: struct/union/class/enum/typedef/unknown
        - decl: string form of the type (when available)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: list[dict[str, Any]] = []
        seen_keys = set()
        try:

            def add_type_entry(name, tobj):
                # Normalize name to string to avoid BN QualifiedName in JSON
                try:
                    name_str = str(name) if name is not None else None
                except Exception:
                    name_str = None
                if not name_str:
                    return
                # Fallback: try to resolve missing type object by querying BV / libraries
                if tobj is None:
                    try:
                        if hasattr(self._current_view, "get_type_by_name"):
                            t2 = self._current_view.get_type_by_name(name_str)
                            if t2 is not None:
                                tobj = t2
                    except Exception:
                        pass
                    if tobj is None:
                        try:
                            plat = getattr(self._current_view, "platform", None)
                            libs = list(getattr(plat, "type_libraries", []) or []) if plat else []
                            for lib in libs:
                                get_t = getattr(lib, "get_type_by_name", None)
                                if not callable(get_t):
                                    continue
                                t3 = None
                                try:
                                    # Try QualifiedName if available
                                    try:
                                        t3 = get_t(bn.QualifiedName(name_str))
                                    except Exception:
                                        t3 = get_t(name_str)
                                except Exception:
                                    t3 = None
                                if t3 is not None:
                                    tobj = t3
                                    break
                        except Exception:
                            pass

                tc = getattr(tobj, "type_class", None)
                kind = "unknown"
                if tc == TypeClass.VoidTypeClass:
                    kind = "void"
                elif tc == TypeClass.BoolTypeClass:
                    kind = "bool"
                elif tc == TypeClass.IntegerTypeClass:
                    kind = "int"
                elif tc == TypeClass.FloatTypeClass:
                    kind = "float"
                elif tc == TypeClass.StructureTypeClass:
                    try:
                        if getattr(tobj, "type", None) == StructureVariant.StructStructureType:
                            kind = "struct"
                        elif getattr(tobj, "type", None) == StructureVariant.UnionStructureType:
                            kind = "union"
                        elif getattr(tobj, "type", None) == StructureVariant.ClassStructureType:
                            kind = "class"
                        else:
                            kind = "struct"
                    except Exception:
                        kind = "struct"
                elif tc == TypeClass.EnumerationTypeClass:
                    kind = "enum"
                elif tc == TypeClass.NamedTypeReferenceClass:
                    kind = "typedef"
                elif tc == TypeClass.FunctionTypeClass:
                    kind = "function"
                elif tc == TypeClass.WideCharTypeClass:
                    kind = "wchar"
                elif tc == TypeClass.PointerTypeClass:
                    kind = "pointer"
                elif tc == TypeClass.ArrayTypeClass:
                    kind = "array"

                decl = None
                try:
                    decl = str(tobj)
                except Exception:
                    try:
                        decl = str(getattr(tobj, "type", None))
                    except Exception:
                        decl = None

                # If kind is unknown or a named typedef, try to infer underlying from declaration text
                try:
                    dlow = (decl or "").strip().lower()
                    if dlow:
                        if dlow.startswith("struct ") or " struct " in dlow:
                            kind = "struct"
                        elif dlow.startswith("union ") or " union " in dlow:
                            kind = "union"
                        elif dlow.startswith("enum ") or " enum " in dlow:
                            kind = "enum"
                except Exception:
                    pass

                key = (name_str, decl or "")
                if key in seen_keys:
                    return
                results.append(
                    {
                        "name": name_str,
                        "kind": kind,
                        "type_class": str(tc) if tc is not None else None,
                        "decl": decl,
                    }
                )
                seen_keys.add(key)

            # Source 1: user_type_container (explicit local/user types)
            try:
                utc = getattr(self._current_view, "user_type_container", None)
                if utc and getattr(utc, "types", None):
                    for type_id in list(utc.types.keys()):
                        try:
                            entry = utc.types[type_id]
                            name = (
                                entry[0]
                                if isinstance(entry, (tuple, list))
                                else getattr(entry, "name", None)
                            )
                            tobj = (
                                entry[1]
                                if isinstance(entry, (tuple, list))
                                else getattr(entry, "type", entry)
                            )
                            add_type_entry(name, tobj)
                        except Exception:
                            continue
            except Exception:
                pass

            # Source 2: view.types (BN view-local types)
            for k, v in self._current_view.types.items():
                try:
                    if isinstance(v, (tuple, list)) and len(v) >= 2:
                        name = str(v[0])
                        tobj = v[1]
                    else:
                        tobj = v
                        name = getattr(v, "name", None)
                        if not name:
                            name = str(k)
                    add_type_entry(name, tobj)
                except Exception:
                    continue

            # Source 3: platform type libraries (optional; can be heavy)
            if include_libraries:
                try:
                    plat = getattr(self._current_view, "platform", None)
                    libs = []
                    try:
                        libs = list(getattr(plat, "type_libraries", []) or [])
                    except Exception:
                        libs = []
                    for lib in libs:
                        # Try multiple ways to enumerate names in this library
                        names = []
                        try:
                            nt = getattr(lib, "named_types", None)
                            if isinstance(nt, dict):
                                names = list(nt.keys())
                        except Exception:
                            pass
                        if not names:
                            try:
                                tmap = getattr(lib, "types", None)
                                if isinstance(tmap, dict):
                                    names = list(tmap.keys())
                            except Exception:
                                pass
                        if not names:
                            try:
                                get_names = getattr(lib, "get_type_names", None)
                                if callable(get_names):
                                    names = list(get_names())
                            except Exception:
                                pass
                        # Fetch each type object if possible
                        for nm in names:
                            try:
                                tobj = None
                                try:
                                    g = getattr(lib, "get_type_by_name", None)
                                    if callable(g):
                                        tobj = g(nm)
                                except Exception:
                                    tobj = None
                                add_type_entry(nm, tobj)
                            except Exception:
                                continue
                except Exception:
                    pass
        except Exception as e:
            bn.log_error(f"Error listing local types: {e}")
        return results[offset : offset + limit]

    def search_local_types(
        self, query: str, offset: int = 0, limit: int = 100, include_libraries: bool = False
    ) -> list[dict[str, Any]]:
        """Search local/view types whose name or declaration contains the substring.

        Returns entries with {name, kind, type_class, decl}.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
        if not query:
            return []
        ql = str(query).lower()
        # Only local types by default (fast). Optionally include libraries.
        all_types = self.list_local_types(0, 1_000_000, include_libraries=include_libraries)
        matches: list[dict[str, Any]] = []
        for t in all_types:
            try:
                name = t.get("name") or ""
                decl = t.get("decl") or ""
                if (ql in str(name).lower()) or (ql in str(decl).lower()):
                    matches.append(t)
            except Exception:
                continue
        if isinstance(limit, int) and limit < 0:
            return matches[offset:]
        return matches[offset : offset + limit]

    def get_type_info(self, name: str) -> dict[str, Any]:
        """Resolve a type by name and return detailed information.

        Returns a dictionary with:
        - name: type name
        - kind: struct/union/class/enum/typedef/... (best-effort)
        - decl: declaration string
        - members: for struct/union [{name, type, offset}]
        - enum_members: for enums [{name, value}]
        - underlying: for typedefs, best-effort underlying declaration
        - source: local | library | unknown
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        type_name = str(name)
        tobj = None
        source = "unknown"

        # 1) Try view local resolution first
        try:
            if hasattr(self._current_view, "get_type_by_name"):
                t = self._current_view.get_type_by_name(type_name)
                if t is not None:
                    tobj = t
                    source = "local"
        except Exception:
            pass

        # 2) Fall back to platform type libraries
        if tobj is None:
            try:
                plat = getattr(self._current_view, "platform", None)
                libs = list(getattr(plat, "type_libraries", []) or []) if plat else []
                for lib in libs:
                    get_t = getattr(lib, "get_type_by_name", None)
                    if not callable(get_t):
                        continue
                    try:
                        # Try with QualifiedName if available
                        try:
                            t = get_t(bn.QualifiedName(type_name))
                        except Exception:
                            t = get_t(type_name)
                    except Exception:
                        t = None
                    if t is not None:
                        tobj = t
                        source = "library"
                        break
            except Exception:
                pass

        # Prepare defaults
        kind = "unknown"
        decl = None
        members: list[dict[str, Any]] = []
        enum_members: list[dict[str, Any]] = []
        underlying = None

        # Extract details from type object
        if tobj is not None:
            try:
                decl = str(tobj)
            except Exception:
                try:
                    decl = str(getattr(tobj, "type", None))
                except Exception:
                    decl = None

            tc = getattr(tobj, "type_class", None)
            if tc == TypeClass.StructureTypeClass:
                # structure variant
                try:
                    v = getattr(tobj, "type", None)
                    if v == StructureVariant.UnionStructureType:
                        kind = "union"
                    elif v == StructureVariant.ClassStructureType:
                        kind = "class"
                    else:
                        kind = "struct"
                except Exception:
                    kind = "struct"

                # collect members
                try:
                    for m in getattr(
                        tobj, "members", getattr(getattr(tobj, "structure", None), "members", [])
                    ):
                        try:
                            members.append(
                                {
                                    "name": getattr(m, "name", None),
                                    "type": str(getattr(m, "type", ""))
                                    if hasattr(m, "type")
                                    else None,
                                    "offset": int(getattr(m, "offset", 0))
                                    if hasattr(m, "offset")
                                    else None,
                                }
                            )
                        except Exception:
                            continue
                except Exception:
                    pass

            elif tc == TypeClass.EnumerationTypeClass:
                kind = "enum"
                try:
                    for em in getattr(tobj, "members", []):
                        try:
                            enum_members.append(
                                {
                                    "name": getattr(em, "name", None),
                                    "value": getattr(em, "value", None),
                                }
                            )
                        except Exception:
                            continue
                except Exception:
                    pass

            elif tc == TypeClass.NamedTypeReferenceClass:
                kind = "typedef"
                # best-effort underlying from decl text
                try:
                    dlow = (decl or "").lower()
                    if dlow:
                        if dlow.startswith("struct ") or " struct " in dlow:
                            underlying = "struct"
                        elif dlow.startswith("union ") or " union " in dlow:
                            underlying = "union"
                        elif dlow.startswith("enum ") or " enum " in dlow:
                            underlying = "enum"
                except Exception:
                    pass

            elif tc == TypeClass.IntegerTypeClass:
                kind = "int"
            elif tc == TypeClass.FloatTypeClass:
                kind = "float"
            elif tc == TypeClass.BoolTypeClass:
                kind = "bool"
            elif tc == TypeClass.VoidTypeClass:
                kind = "void"
            elif tc == TypeClass.PointerTypeClass:
                kind = "pointer"
            elif tc == TypeClass.ArrayTypeClass:
                kind = "array"
            elif tc == TypeClass.FunctionTypeClass:
                kind = "function"

            # Infer kind from decl if still unknown
            if kind == "unknown" and decl:
                try:
                    dl = decl.lower()
                    if dl.startswith("struct ") or " struct " in dl:
                        kind = "struct"
                    elif dl.startswith("union ") or " union " in dl:
                        kind = "union"
                    elif dl.startswith("enum ") or " enum " in dl:
                        kind = "enum"
                except Exception:
                    pass

        return {
            "name": type_name,
            "kind": kind,
            "decl": decl,
            "members": members if members else None,
            "enum_members": enum_members if enum_members else None,
            "underlying": underlying,
            "source": source,
        }

    def get_user_defined_type(self, type_name: str) -> dict[str, Any] | None:
        """Get the definition of a user-defined type (struct, enum, etc.)

        Args:
            type_name: Name of the user-defined type to retrieve

        Returns:
            Dictionary with type information and definition, or None if not found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            # Check if we have a user type container
            if (
                not hasattr(self._current_view, "user_type_container")
                or not self._current_view.user_type_container
            ):
                bn.log_info("No user type container available")
                return None

            # Search for the requested type by name
            found_type = None
            found_type_id = None

            for type_id in self._current_view.user_type_container.types.keys():
                current_type = self._current_view.user_type_container.types[type_id]
                type_name_from_container = current_type[0]

                if type_name_from_container == type_name:
                    found_type = current_type
                    found_type_id = type_id
                    break

            if not found_type or not found_type_id:
                bn.log_info(f"Type not found: {type_name}")
                return None

            # Determine the type category (struct, enum, etc.)
            type_category = "unknown"
            type_object = found_type[1]
            bn.log_info("Stage1")
            bn.log_info(f"Stage1.5 {type_object.type_class} {StructureVariant.StructStructureType}")
            if type_object.type_class == TypeClass.EnumerationTypeClass:
                type_category = "enum"
            elif type_object.type_class == TypeClass.StructureTypeClass:
                if type_object.type == StructureVariant.StructStructureType:
                    type_category = "struct"
                elif type_object.type == StructureVariant.UnionStructureType:
                    type_category = "union"
                elif type_object.type == StructureVariant.ClassStructureType:
                    type_category = "class"
            elif type_object.type_class == TypeClass.NamedTypeReferenceClass:
                type_category = "typedef"

            # Generate the C++ style definition
            definition_lines = []

            try:
                if (
                    type_category == "struct"
                    or type_category == "class"
                    or type_category == "union"
                ):
                    definition_lines.append(f"{type_category} {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "type"):
                            definition_lines.append(f"    {member.type} {member.name};")
                    definition_lines.append("};")
                elif type_category == "enum":
                    definition_lines.append(f"enum {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "value"):
                            definition_lines.append(f"    {member.name} = {member.value},")
                    definition_lines.append("};")
                elif type_category == "typedef":
                    str_type_object = str(type_object)
                    definition_lines.append(f"typedef {str_type_object};")
            except Exception as e:
                bn.log_error(f"Error getting type lines: {e}")

            # Construct the final definition string
            definition = "\n".join(definition_lines)

            return {"name": type_name, "type": type_category, "definition": definition}
        except Exception as e:
            bn.log_error(f"Error getting user-defined type {type_name}: {e}")
            return None
