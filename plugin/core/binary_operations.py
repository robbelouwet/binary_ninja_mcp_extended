"""Facade composing every Binary Ninja operation used by the MCP server.

The actual logic lives in domain-specific mixins (views, functions, data,
types, comments, xrefs); this class only holds shared state and wires the
mixins together so callers keep a single ``BinaryOperations`` interface.
"""

import weakref

import binaryninja as bn

from .comments import CommentOperations
from .config import BinaryNinjaConfig
from .data import DataOperations
from .functions import FunctionOperations
from .types import TypeOperations
from .views import ViewOperations
from .xrefs import XrefOperations


class BinaryOperations(
    ViewOperations,
    FunctionOperations,
    DataOperations,
    TypeOperations,
    CommentOperations,
    XrefOperations,
):
    def __init__(self, config: BinaryNinjaConfig):
        self.config = config
        self._current_view: bn.BinaryView | None = None
        # Multi-binary support
        # Store weak references so closed views are auto-pruned
        self._views_by_id: dict[str, weakref.ReferenceType] = {}
        self._next_view_id: int = 1
        self._id_by_filename: dict[str, str] = {}

    @property
    def current_view(self) -> bn.BinaryView | None:
        return self._current_view

    @current_view.setter
    def current_view(self, bv: bn.BinaryView | None):
        if bv:
            bn.log_info(f"Set current binary view: {bv.file.filename}")
            # Register before assigning: _register_view prunes stale views and
            # would clear a current view that is not yet in the registry.
            try:
                self._register_view(bv)
            except Exception:
                pass
        else:
            bn.log_info("Cleared current binary view")
        self._current_view = bv
