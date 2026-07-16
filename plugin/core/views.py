"""BinaryView lifecycle: loading binaries, tracking open views, selection."""

import re
import weakref

import binaryninja as bn


class ViewOperations:
    """Mixin managing the current BinaryView and the registry of open views."""

    def load_binary(self, filepath: str) -> bn.BinaryView:
        """Load a binary file using the appropriate method based on the Binary Ninja API version"""
        try:
            if hasattr(bn, "open_view"):
                bn.log_info("Using bn.open_view method")
                self._current_view = bn.open_view(filepath)
            elif hasattr(bn, "BinaryViewType") and hasattr(bn.BinaryViewType, "get_view_of_file"):
                bn.log_info("Using BinaryViewType.get_view_of_file method")
                file_metadata = bn.FileMetadata()
                try:
                    if hasattr(bn.BinaryViewType, "get_default_options"):
                        options = bn.BinaryViewType.get_default_options()
                        self._current_view = bn.BinaryViewType.get_view_of_file(
                            filepath, file_metadata, options
                        )
                    else:
                        self._current_view = bn.BinaryViewType.get_view_of_file(
                            filepath, file_metadata
                        )
                except TypeError:
                    self._current_view = bn.BinaryViewType.get_view_of_file(filepath)
            else:
                bn.log_info("Using legacy method")
                file_metadata = bn.FileMetadata()
                binary_view_type = bn.BinaryViewType.get_view_of_file_with_options(
                    filepath, file_metadata
                )
                if binary_view_type:
                    self._current_view = binary_view_type.open()
                else:
                    raise Exception("No view type available for this file")

            try:
                if self._current_view is not None:
                    view = self._current_view
                    self._register_view(view)
                    # Re-assert: _register_view prunes stale views and clears a
                    # current view that was not yet in the registry.
                    self._current_view = view
            except Exception:
                pass
            return self._current_view
        except Exception as e:
            bn.log_error(f"Failed to load binary: {e}")
            raise

    # ---------------- Multi-binary helpers ----------------
    def _prune_views(self) -> None:
        """Remove entries for BinaryViews that no longer exist and rebuild filename map."""
        with self._registry_lock:
            self._prune_views_locked()

    def _prune_views_locked(self) -> None:
        alive: dict[str, weakref.ReferenceType] = {}
        new_fn_map: dict[str, str] = {}
        alive_objs: list[object] = []
        for vid, w in list(self._views_by_id.items()):
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is None:
                continue
            alive[vid] = w
            alive_objs.append(vb)
            try:
                fn = str(getattr(vb.file, "filename", None)) if getattr(vb, "file", None) else None
            except Exception:
                fn = None
            if fn and fn not in new_fn_map:
                new_fn_map[fn] = vid
        self._views_by_id = alive
        self._id_by_filename = new_fn_map
        # If current_view no longer exists among alive views, clear it
        try:
            if self._current_view is not None and all(
                obj is not self._current_view for obj in alive_objs
            ):
                self._current_view = None
        except Exception:
            self._current_view = None

    def _register_view(self, bv: bn.BinaryView) -> str:
        """Add a view to the managed list if not present, return its id."""
        with self._registry_lock:
            return self._register_view_locked(bv)

    def _register_view_locked(self, bv: bn.BinaryView) -> str:
        self._prune_views()
        # Reuse existing id if the exact object is already tracked
        for vid, w in list(self._views_by_id.items()):
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is bv:
                return vid
        # Prefer deduplication by canonical filename
        fn = None
        try:
            fn = str(getattr(bv.file, "filename", None)) if getattr(bv, "file", None) else None
        except Exception:
            fn = None
        if fn:
            # If a view for this filename already exists, reuse its id and update the view
            existing_id = self._id_by_filename.get(fn)
            if existing_id and existing_id in self._views_by_id:
                # Always store weak references so closed views can be pruned
                self._views_by_id[existing_id] = weakref.ref(bv)
                return existing_id
        # Assign a new id
        vid = str(self._next_view_id)
        self._next_view_id += 1
        self._views_by_id[vid] = weakref.ref(bv)
        if fn:
            self._id_by_filename[fn] = vid
        return vid

    def register_view(self, bv: bn.BinaryView) -> str:
        """Public wrapper to register a BinaryView and return its id."""
        return self._register_view(bv)

    def unregister_by_filename(self, filename: str) -> int:
        """Remove all tracked views that match the given absolute filename.

        Returns number of entries removed.
        """
        if not filename:
            return 0
        with self._registry_lock:
            return self._unregister_by_filename_locked(filename)

    def _unregister_by_filename_locked(self, filename: str) -> int:
        self._prune_views()
        to_delete: list[str] = []
        for vid, w in list(self._views_by_id.items()):
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is None:
                continue
            try:
                fn = getattr(vb.file, "filename", None)
            except Exception:
                fn = None
            if fn == filename:
                to_delete.append(vid)
        for vid in to_delete:
            self._views_by_id.pop(vid, None)
        # Rebuild filename map and clear current_view if it matched
        try:
            cur_fn = None
            if self._current_view and getattr(self._current_view, "file", None):
                cur_fn = getattr(self._current_view.file, "filename", None)
            if cur_fn == filename:
                self._current_view = None
        except Exception:
            self._current_view = None
        self._prune_views()
        return len(to_delete)

    def list_open_binaries(self) -> list[dict[str, str]]:
        """Return a list of managed/open binaries with ids.

        Note: Tracks binaries opened via this plugin or explicitly registered as current_view.
        """
        items: list[dict[str, str]] = []
        # Cleanup first
        self._prune_views()
        # Do NOT auto-register current_view here; UI monitor handles discovery.
        # This avoids re-introducing closed views via a stale strong reference.
        # Deduplicate by canonical filename; prefer the id mapped in _id_by_filename
        entries: list[tuple[str, str, bool]] = []  # (id, filename, active)
        seen: set[str] = set()
        for vid, w in self._views_by_id.items():
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is None:
                continue
            try:
                fn = vb.file.filename
            except Exception:
                fn = "(unknown)"
            key = fn
            if key in seen:
                continue
            seen.add(key)
            # Resolve canonical id for this filename when available
            canonical_id = self._id_by_filename.get(fn, vid)
            try:
                vb_canon_ref = self._views_by_id.get(canonical_id)
                vb_canon = vb_canon_ref() if vb_canon_ref else vb
            except Exception:
                vb_canon = vb
            entries.append((canonical_id, fn, bool(vb_canon is self._current_view)))
        # Sort by filename for stable ordering
        entries.sort(key=lambda t: t[1] or "")
        for cid, fn, active in entries:
            items.append({"id": cid, "filename": fn, "active": active})
        return items

    def select_view(self, ident: str) -> dict[str, str] | None:
        """Select active BinaryView by id or filename/basename.

        Returns selection info on success, None on failure.
        """
        s = (ident or "").strip()
        if not s:
            return None
        self._prune_views()
        # Try id
        w = self._views_by_id.get(s)
        vb = None
        if w is not None:
            try:
                vb = w()
            except Exception:
                vb = None
        # If user passed a 1-based ordinal (from /binaries), map it to filename
        if vb is None and s.isdigit():
            try:
                idx = int(s)
                if idx >= 1:
                    lst = self.list_open_binaries()  # sorted order
                    if 1 <= idx <= len(lst):
                        fname = lst[idx - 1].get("filename")
                        if fname:
                            map_id = self._id_by_filename.get(fname)
                            if map_id:
                                wmap = self._views_by_id.get(map_id)
                                vb = wmap() if wmap else None
            except Exception:
                vb = None
        # Try direct filename mapping
        if vb is None:
            try:
                # Exact filename
                map_id = self._id_by_filename.get(s)
                if map_id:
                    wmap = self._views_by_id.get(map_id)
                    vb = wmap() if wmap else None
            except Exception:
                vb = None
        if vb is None:
            # Try match by full filename or basename
            for vid, w2 in self._views_by_id.items():
                try:
                    v = w2()
                except Exception:
                    v = None
                if v is None:
                    continue
                try:
                    fn = v.file.filename
                except Exception:
                    fn = None
                if not fn:
                    continue
                import os as _os

                if s == fn or s == _os.path.basename(fn):
                    vb = v
                    break
        if vb is None:
            return None
        self.current_view = vb
        vid = None
        for k, wv in self._views_by_id.items():
            try:
                vv = wv()
            except Exception:
                vv = None
            if vv is vb:
                vid = k
                break
        return {"id": vid or "", "filename": getattr(vb.file, "filename", "(unknown)")}

    def resolve_symbol(self, ident: str) -> tuple[int | None, str | None]:
        """Resolve a symbol name or address string to ``(address, label)``.

        Tries, in order: hex address parsing (with or without 0x), raw and
        pretty symbol names, Binary Ninja auto-generated data labels
        (data_/byte_/word_/...), and finally a scan over data variable symbols.
        Returns ``(None, None)`` when nothing matches.
        """
        bv = self.current_view
        if not bv:
            return None, None
        s = (ident or "").strip()
        # Hex address (with or without 0x prefix)
        try:
            if s.lower().startswith("0x"):
                return int(s, 16), s
            if s and all(c in "0123456789abcdefABCDEF" for c in s):
                return int(s, 16), s
        except Exception:
            pass
        # Raw name, then pretty name
        for getter_name in ("get_symbol_by_raw_name", "get_symbol_by_name"):
            try:
                getter = getattr(bv, getter_name, None)
                sym = getter(s) if callable(getter) else None
                if sym and hasattr(sym, "address"):
                    return int(sym.address), getattr(sym, "name", s)
            except Exception:
                pass
        # BN auto-generated data labels like data_100003f66, byte_..., off_...
        try:
            m = re.match(
                r"^(?:data|byte|word|dword|qword|off|unk)_(?:0x)?([0-9a-fA-F]+)$",
                s,
                re.IGNORECASE,
            )
            if m:
                return int(m.group(1), 16), s
        except Exception:
            pass
        # Scan data vars for a matching symbol name
        try:
            for var in list(bv.data_vars):
                try:
                    sym = bv.get_symbol_at(var)
                    if sym and s in (getattr(sym, "name", None), getattr(sym, "raw_name", None)):
                        return int(var), getattr(sym, "name", s)
                except Exception:
                    continue
        except Exception:
            pass
        return None, None
