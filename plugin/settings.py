"""Binary Ninja settings for the MCP plugin."""

import binaryninja as bn
from binaryninja import Settings

from .core.config import Config


def register_settings():
    """Register the plugin's settings group with Binary Ninja."""
    settings = Settings()
    settings.register_group("mcp", "MCP Server")
    settings.register_setting(
        "mcp.renamePrefix",
        '{ "title": "Rename Prefix", "type": "string", "default": "mcp_", "description": "Prefix to prepend to renamed functions and variables (e.g. mcp_, mw_). Leave empty for no prefix." }',
    )
    settings.register_setting(
        "mcp.showStatusButton",
        '{ "title": "Show Status Button", "type": "boolean", "default": true, "description": "Show MCP server status button in the status bar." }',
    )
    settings.register_setting(
        "mcp.exposeToNetwork",
        '{ "title": "Expose to Network", "type": "boolean", "default": false, "description": "When enabled, the server binds to 0.0.0.0 and is accessible from other machines. When disabled, the server only binds to localhost for local-only access." }',
    )
    settings.register_setting(
        "mcp.port",
        '{"title": "Server Port", "type": "string", "default": "9009", "description": "Port number for the MCP server."}',
    )


def apply_settings(config: Config):
    """Copy the current Binary Ninja settings into the server config."""
    try:
        settings = Settings()

        expose_to_network = settings.get_bool("mcp.exposeToNetwork")
        config.server.host = "0.0.0.0" if expose_to_network else "localhost"

        port_str = settings.get_string("mcp.port")
        if port_str:
            try:
                config.server.port = int(port_str)
            except ValueError:
                pass
    except Exception as e:
        bn.log_error(f"Failed to apply settings to config: {e}")
