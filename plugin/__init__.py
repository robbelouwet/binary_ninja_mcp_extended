"""Binary Ninja MCP plugin entry point: server lifecycle and menu commands."""

import binaryninja as bn

from . import ui
from .core.config import Config
from .server.http_server import MCPServer
from .settings import apply_settings, register_settings

# When true, suppress auto-start while a BinaryView is open until the user
# explicitly starts the server again. This prevents immediate re-start after stop.
_user_stopped = False


class BinaryNinjaMCP:
    """Owns the MCP server instance and its start/stop lifecycle."""

    def __init__(self):
        self.config = Config()
        self.server = MCPServer(self.config)

    @property
    def is_running(self) -> bool:
        try:
            return bool(self.server and self.server.server)
        except Exception:
            return False

    def start_server(self, bv):
        global _user_stopped
        try:
            # Apply latest settings from Binary Ninja configuration
            apply_settings(self.config)

            # Require an active BinaryView (match menu behavior)
            if bv is None:
                bn.log_debug("MCP Max start requested but no BinaryView is active; deferring")
                ui.show_no_bv_popup()
                return

            # Avoid duplicate starts
            if self.is_running:
                bn.log_info("MCP Max server already running; skip new start")
                if self.server.binary_ops.current_view is None:
                    self.server.binary_ops.current_view = bv
                else:
                    # Register any newly seen view even if server is already running
                    try:
                        self.server.binary_ops.register_view(bv)
                    except Exception:
                        pass
                ui.notify("MCP Server", "Server is already running.")
                return

            self.server.binary_ops.current_view = bv
            try:
                self.server.binary_ops.register_view(bv)
            except Exception:
                pass
            self.server.start()
            _user_stopped = False
            bn.log_info(
                f"MCP server started successfully on http://{self.config.server.host}:{self.config.server.port}"
            )
            ui.set_status_indicator(True)
            ui.notify(
                "MCP Server Started",
                f"Running at http://{self.config.server.host}:{self.config.server.port}",
            )
        except Exception as e:
            bn.log_error(f"Failed to start MCP server: {e!s}")
            ui.notify("MCP Server Error", f"Failed to start: {e}")

    def stop_server(self, bv):
        global _user_stopped
        try:
            if not self.is_running:
                bn.log_info("MCP Max server stop requested but server is not running")
                ui.notify("MCP Server", "Server is not running.")
                return
            _user_stopped = True
            self.server.binary_ops.current_view = None
            self.server.stop()
            bn.log_info("Binary Ninja MCP Max plugin stopped successfully")
            ui.set_status_indicator(False)
            ui.notify("MCP Server Stopped", "Server has been stopped.")
        except Exception as e:
            bn.log_error(f"Failed to stop server: {e!s}")
            ui.notify("MCP Server Error", f"Failed to stop: {e}")


def _try_autostart_for_bv(bv):
    """Start the server for a newly active BinaryView unless the user stopped it."""
    try:
        if _user_stopped:
            bn.log_debug("MCP Max autostart suppressed due to manual stop")
            return
        plugin.start_server(bv)
    except Exception as e:
        bn.log_error(f"MCP Max autostart failed: {e}")


def _register_bv_tracking():
    """Track BinaryViews opened outside the UI callbacks (e.g. headless analysis)."""
    try:
        from binaryninja.binaryview import BinaryViewType

        def _on_bv_event(bv):
            try:
                # Even if the server is not running, register the view for listing later
                if plugin.server and plugin.server.binary_ops:
                    plugin.server.binary_ops.register_view(bv)
            except Exception:
                pass

        try:
            BinaryViewType.add_binaryview_initial_analysis_completion_event(_on_bv_event)
            bn.log_info("Registered BinaryView initial analysis completion event for MCP Max")
        except Exception as e:
            bn.log_debug(f"Unable to register BV analysis completion event: {e}")
        # Also register finalized event to catch newly created/opened views early
        try:
            BinaryViewType.add_binaryview_finalized_event(_on_bv_event)
            bn.log_info("Registered BinaryView finalized event for MCP Max")
        except Exception as e:
            bn.log_debug(f"Unable to register BV finalized event: {e}")
    except Exception:
        pass


plugin = BinaryNinjaMCP()
register_settings()
ui.install(plugin, _try_autostart_for_bv)

bn.PluginCommand.register(
    "MCP Server\\Start MCP Server",
    "Start the Binary Ninja MCP server",
    plugin.start_server,
)
bn.PluginCommand.register(
    "MCP Server\\Stop MCP Server",
    "Stop the Binary Ninja MCP server",
    plugin.stop_server,
)

bn.log_info("Binary Ninja MCP plugin loaded successfully")

# One-time MCP client auto-setup: install bridge entry into popular MCP clients
try:
    from .utils.auto_setup import install_mcp_clients

    install_mcp_clients(quiet=True)
except Exception:
    # Best-effort; ignore failures to avoid disrupting plugin load
    pass

_register_bv_tracking()
