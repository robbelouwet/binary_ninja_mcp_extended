"""UI integration: status bar indicator, notifications, and view tracking.

Everything here is best-effort — the plugin must keep working headless or on
Binary Ninja versions whose UI APIs differ, so UI failures only log.
Call :func:`install` once at plugin load with the plugin instance.
"""

import binaryninja as bn
from binaryninja import Settings

# Set by install()
_plugin = None
_autostart = None

_status_button = None
_status_container = None
_indicator_timer = None
_bv_monitor_timer = None


def notify(title: str, text: str):
    """Log a user-facing status message (UI popups are intentionally disabled)."""
    try:
        bn.log_info(f"{title}: {text}")
    except Exception:
        pass


def show_no_bv_popup():
    """Show a focused popup for the 'no BinaryView' case only."""
    msg = "No BinaryView is active, please open a binary first"
    try:
        from binaryninja.interaction import (
            MessageBoxButtonSet,
            MessageBoxIcon,
            show_message_box,
        )

        show_message_box(
            "Binary Ninja MCP Max",
            msg,
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.WarningIcon,
        )
    except Exception:
        # Fall back to log if UI interaction is unavailable
        try:
            bn.log_warn(msg)
        except Exception:
            pass


def _active_binary_view():
    """Return the BinaryView of the active UI view frame, if any."""
    try:
        from binaryninjaui import UIContext

        ctx = UIContext.activeContext()
        if ctx:
            vf = ctx.getCurrentViewFrame()
            if vf and hasattr(vf, "getCurrentBinaryView"):
                return vf.getCurrentBinaryView()
    except Exception:
        pass
    return None


def _sidebar_icon_margin_default() -> int:
    """Return a reasonable UI icon size to use as horizontal margin.

    Tries to query the Qt style's toolbar icon size (commonly 24). Falls back to 24 on failure.
    """
    try:
        import binaryninjaui as ui
        from PySide6.QtWidgets import QStyle

        ctx = ui.UIContext.activeContext()
        mw = getattr(ctx, "mainWindow", None)
        mw = mw() if callable(mw) else mw
        if mw and hasattr(mw, "style"):
            st = mw.style()
            if st:
                val = int(st.pixelMetric(QStyle.PM_ToolBarIconSize))
                if val > 0:
                    return val
    except Exception:
        pass
    return 24


def ensure_status_indicator():
    """Create the status bar button once the UI is available."""
    global _status_button
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QHBoxLayout, QPushButton, QWidget

        if not Settings().get_bool("mcp.showStatusButton"):
            return

        def _create():
            global _status_button, _status_container
            if _status_button is not None:
                return
            ctx = ui.UIContext.activeContext()
            if not ctx:
                return
            mw = getattr(ctx, "mainWindow", None)
            mw = mw() if callable(mw) else mw
            if mw is None or not hasattr(mw, "statusBar"):
                return
            sb = mw.statusBar()
            if sb is None:
                return
            # Tighten status bar spacing
            try:
                sb.setContentsMargins(0, 0, 0, 0)
                if sb.layout():
                    sb.layout().setContentsMargins(0, 0, 0, 0)
                    sb.layout().setSpacing(0)
                sb.setStyleSheet(
                    "QStatusBar{padding:0;margin:0;} QStatusBar::item{margin:0;padding:0;border:0;}"
                )
            except Exception:
                pass

            # Create a flat button as the indicator and control
            _status_button = QPushButton()
            _status_button.setObjectName("mcpStatusButton")
            _status_button.setFlat(True)
            _status_button.setCursor(Qt.PointingHandCursor)
            _status_button.setToolTip("Click to start/stop MCP server")
            _status_button.setContentsMargins(0, 0, 0, 0)
            _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")

            # Wrap the button in a container with side margins so the margin area is unclickable
            m = _sidebar_icon_margin_default()
            container = QWidget()
            container.setObjectName("mcpStatusContainer")
            lay = QHBoxLayout(container)
            lay.setContentsMargins(m, 0, 3, 0)  # left margin = icon size + 1; right margin = 3px
            lay.setSpacing(0)
            lay.addWidget(_status_button)
            _status_container = container

            # Set initial visible state so the indicator shows up immediately
            _apply_indicator_state(_plugin is not None and _plugin.is_running)

            # Click handler to toggle server state
            def _on_click():
                try:
                    if _plugin.is_running:
                        _plugin.stop_server(None)
                    else:
                        bv = _active_binary_view()
                        if not bv:
                            show_no_bv_popup()
                            return
                        _plugin.start_server(bv)
                finally:
                    set_status_indicator(_plugin.is_running)

            _status_button.clicked.connect(_on_click)

            # Place slightly to the right (not the far-right): index 1
            try:
                sb.insertWidget(1, container, 0)
            except Exception:
                try:
                    sb.addWidget(container)
                except Exception:
                    sb.addPermanentWidget(container)

        # Ensure we run on UI thread if available
        try:
            ui.execute_on_main_thread(_create)
        except Exception:
            _create()
    except Exception:
        pass


def _apply_indicator_state(running: bool):
    if _status_button is None:
        return
    _status_button.setText("🟢 MCP: Running" if running else "🔴 MCP: Stopped")
    _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")


def set_status_indicator(running: bool):
    """Update the status bar button to reflect the server state."""
    try:
        import binaryninjaui as ui

        if not Settings().get_bool("mcp.showStatusButton"):
            return

        def _update():
            ensure_status_indicator()
            _apply_indicator_state(running)

        try:
            ui.execute_on_main_thread(_update)
        except Exception:
            _update()
    except Exception:
        pass


def _refresh_indicator():
    ensure_status_indicator()
    set_status_indicator(_plugin is not None and _plugin.is_running)


def _start_indicator_watcher():
    """Periodically ensure the indicator exists after UI becomes ready.

    Some environments initialize UI context late; this watcher is a light
    safety net that creates and updates the indicator shortly after load.
    It stops itself once the indicator exists.
    """
    global _indicator_timer
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        if _indicator_timer is not None:
            return

        def _tick():
            try:
                _refresh_indicator()
                if _status_button is not None and hasattr(_indicator_timer, "stop"):
                    _indicator_timer.stop()
            except Exception:
                pass

        _indicator_timer = QTimer()
        _indicator_timer.setInterval(500)
        _indicator_timer.timeout.connect(_tick)

        def _start():
            try:
                _tick()
                _indicator_timer.start()
            except Exception:
                pass

        try:
            ui.execute_on_main_thread(_start)
        except Exception:
            _start()
    except Exception:
        pass


def _schedule_status_init():
    """Ensure the status control appears ASAP on app load."""
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        try:
            ui.execute_on_main_thread(_refresh_indicator)
        except Exception:
            _refresh_indicator()

        # Attempt again with several short delays to catch late UI init
        for delay in (200, 500, 1000, 1500, 2000):
            try:
                ui.execute_on_main_thread(lambda d=delay: QTimer.singleShot(d, _refresh_indicator))
            except Exception:
                pass
    except Exception:
        pass


def _start_bv_monitor():
    """Start a lightweight UI timer that keeps the server's BinaryView list in sync.

    - Registers any newly opened views discovered via UI contexts
    - Prunes closed views so /binaries reflects current state without user interaction
    """
    global _bv_monitor_timer
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        if _bv_monitor_timer is not None:
            return

        def _discover_all_open_bvs(ops):
            """Heuristically discover all open BinaryViews from UI and sync registry.

            Attempts multiple UI paths defensively; safe if some APIs are unavailable.
            """
            try:
                from binaryninjaui import UIContext
            except Exception:
                UIContext = None

            found_bvs: list = []
            contexts = []
            try:
                if UIContext and hasattr(UIContext, "allContexts"):
                    contexts = list(UIContext.allContexts())
            except Exception:
                contexts = []
            if not contexts and UIContext:
                try:
                    ctx = UIContext.activeContext()
                    if ctx:
                        contexts = [ctx]
                except Exception:
                    contexts = []

            def _collect_from_frame(vf):
                for getter in ("getCurrentBinaryView", "getBinaryView"):
                    try:
                        if vf and hasattr(vf, getter):
                            bv = getattr(vf, getter)()
                            if bv:
                                found_bvs.append(bv)
                    except Exception:
                        pass

            for ctx in contexts:
                # Current frame
                try:
                    _collect_from_frame(ctx.getCurrentViewFrame())
                except Exception:
                    pass
                # Any additional frames if available
                for attr in ("getViewFrames", "viewFrames", "allViewFrames", "frames"):
                    try:
                        getter = getattr(ctx, attr, None)
                        frames = getter() if callable(getter) else getter
                        if frames:
                            for vf in list(frames):
                                _collect_from_frame(vf)
                    except Exception:
                        continue

            for bv in found_bvs:
                try:
                    ops.register_view(bv)
                except Exception:
                    continue

        def _tick():
            try:
                ops = _plugin.server.binary_ops if (_plugin and _plugin.server) else None
                if not ops:
                    return

                # Prune internal weakrefs of closed views
                try:
                    ops.list_open_binaries()
                except Exception:
                    pass

                # Discover all open BVs from UI and sync registry
                try:
                    _discover_all_open_bvs(ops)
                except Exception:
                    pass

                # Keep the MCP-selected active view independent of UI focus.
                # Only adopt the UI-active view when there is no current
                # selection (e.g. after the selected view was closed).
                try:
                    if ops.current_view is None:
                        bv = _active_binary_view()
                        ops.current_view = bv
                        if bv:
                            ops.register_view(bv)
                except Exception:
                    pass
            except Exception:
                # Never raise out of the timer
                pass

        _bv_monitor_timer = QTimer()
        _bv_monitor_timer.setInterval(1000)  # 1s; light periodic sync
        _bv_monitor_timer.timeout.connect(_tick)

        def _start():
            try:
                _tick()
                _bv_monitor_timer.start()
            except Exception:
                pass

        try:
            ui.execute_on_main_thread(_start)
        except Exception:
            _start()
    except Exception:
        pass


def _register_notifications():
    """Install UIContext notifications to track views and refresh the indicator."""
    import binaryninjaui as ui

    class _MCPUINotification(ui.UIContextNotification):
        def _on_view_event(self):
            bv = _active_binary_view()
            _refresh_indicator()
            _start_indicator_watcher()
            _start_bv_monitor()
            if bv:
                # Track the BinaryView for multi-binary support
                try:
                    _plugin.server.binary_ops.register_view(bv)
                except Exception:
                    pass
                _autostart(bv)

        def OnViewChange(self, *args):  # signature varies across versions
            try:
                self._on_view_event()
            except Exception as e:
                bn.log_error(f"MCP Max UI notification error: {e}")

        # Some versions provide OnAfterOpenFile; handle if present
        def OnAfterOpenFile(self, *args):  # type: ignore[override]
            try:
                self._on_view_event()
            except Exception as e:
                bn.log_error(f"MCP Max OnAfterOpenFile error: {e}")

        # Best-effort close notifications (may not be called on all versions)
        def OnBeforeCloseFile(self, *args):  # type: ignore[override]
            try:
                bv = _active_binary_view()
                if bv and _plugin and _plugin.server:
                    ops = _plugin.server.binary_ops
                    # Kill a debuggee bound to the view being closed
                    session = getattr(ops, "_debugger_session", None)
                    if session is not None and session.bv is bv:
                        ops.shutdown_debugger()
                    fn = getattr(bv.file, "filename", None)
                    if fn:
                        ops.unregister_by_filename(fn)
            except Exception:
                pass

        def OnAfterCloseFile(self, *args):  # type: ignore[override]
            try:
                # Force a prune after close
                if _plugin and _plugin.server:
                    _plugin.server.binary_ops.list_open_binaries()
            except Exception:
                pass

        # Ensure status indicator exists when a UI context opens
        def OnContextOpen(self, *args):  # type: ignore[override]
            try:
                _refresh_indicator()
                _start_indicator_watcher()
            except Exception:
                pass

    ui.UIContext.registerNotification(_MCPUINotification())
    bn.log_info("MCP Max UI notifications installed")


def _schedule_autostart_retries():
    """Attempt an immediate autostart if a BinaryView is already open, then retry
    a few times on the UI thread to catch late BV availability."""
    bv = _active_binary_view()
    if bv:
        _autostart(bv)

    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        def _kick_autostart():
            try:
                bv = _active_binary_view()
                if bv:
                    _autostart(bv)
                # Also ensure the status control exists after the UI is ready
                _schedule_status_init()
            except Exception as e:
                bn.log_debug(f"MCP Max auto-start retry error: {e}")

        for delay in (200, 500, 1000, 1500, 2000):
            ui.execute_on_main_thread(lambda d=delay: QTimer.singleShot(d, _kick_autostart))
    except Exception:
        pass


def install(plugin, autostart):
    """Wire up all UI integration for the given plugin instance.

    ``autostart`` is called with a BinaryView whenever one becomes active.
    No-op (logged) when the UI is unavailable, e.g. in headless mode.
    """
    global _plugin, _autostart
    _plugin = plugin
    _autostart = autostart

    try:
        _register_notifications()
        _schedule_status_init()
        _start_indicator_watcher()
        _start_bv_monitor()
        _schedule_autostart_retries()
    except Exception as e:
        # UI not available (headless) or API mismatch; ignore
        bn.log_debug(f"MCP Max UI integration not installed: {e}")
