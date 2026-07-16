"""HTTP server for the Binary Ninja MCP plugin.

Requests are dispatched through the route registry in ``router``; the actual
endpoint logic lives in the ``handlers`` package.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import binaryninja as bn

from ..api.endpoints import BinaryNinjaEndpoints
from ..core.binary_operations import BinaryOperations
from ..core.config import Config
from . import handlers  # noqa: F401  (imports register all routes)
from .router import ROUTES, HTTPError, PlainTextResponse, Request


class MCPRequestHandler(BaseHTTPRequestHandler):
    binary_ops = None  # Set by MCPServer via a subclass attribute

    @property
    def endpoints(self) -> BinaryNinjaEndpoints:
        # Created on demand so binary_ops is guaranteed to be set
        if not hasattr(self, "_endpoints"):
            if not self.binary_ops:
                raise RuntimeError("binary_ops not initialized")
            self._endpoints = BinaryNinjaEndpoints(self.binary_ops)
        return self._endpoints

    def log_message(self, format, *args):
        bn.log_info(format % args)

    # ---------- Request parsing ----------

    def _parse_query_params(self) -> dict[str, str]:
        parsed_path = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed_path.query))

    def _parse_post_params(self) -> dict[str, Any]:
        """Parse a POST body (JSON, form data, or raw text)."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}

        content_type = (self.headers.get("Content-Type") or "").lower()
        post_data = self.rfile.read(content_length).decode("utf-8")

        if "application/json" in content_type:
            try:
                return json.loads(post_data)
            except json.JSONDecodeError as e:
                bn.log_error(f"Failed to parse JSON: {e}")
                return {"error": "Invalid JSON format"}

        if "application/x-www-form-urlencoded" in content_type:
            try:
                return dict(urllib.parse.parse_qsl(post_data))
            except Exception as e:
                bn.log_error(f"Failed to parse form data: {e}")
                return {"error": "Invalid form data format"}

        if "text/plain" in content_type or not content_type:
            return {"name": post_data.strip()}

        return {}

    # ---------- Response writing ----------

    def _set_headers(self, content_type="application/json", status_code=200):
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Access-Control-Allow-Origin", "*")
            # Encourage clients to close promptly; reduces BrokenPipe on abrupt disconnects
            self.send_header("Connection", "close")
            self.end_headers()
        except (BrokenPipeError, OSError):
            bn.log_warn("Client disconnected while sending headers")

    def _send_json_response(self, data: dict[str, Any], status_code: int = 200):
        try:
            body = json.dumps(data).encode("utf-8")
        except Exception:
            body = b"{}"
        self._write_response(body, "application/json", status_code)

    def _send_text_response(self, text: str, status_code: int = 200):
        self._write_response(text.encode("utf-8", errors="replace"), "text/plain", status_code)

    def _write_response(self, body: bytes, content_type: str, status_code: int):
        try:
            self._set_headers(content_type=content_type, status_code=status_code)
            try:
                self.wfile.write(body)
            except (BrokenPipeError, OSError):
                bn.log_warn("Client disconnected while sending body")
        except Exception:
            # Last-resort swallow to avoid cascading errors on disconnects
            bn.log_debug("Suppressed exception during response write")

    # ---------- Dispatch ----------

    def do_GET(self):
        self._dispatch("GET", self._parse_query_params())

    def do_DELETE(self):
        self._dispatch("DELETE", self._parse_query_params())

    def do_POST(self):
        params = self._parse_post_params()
        method = "POST"
        # Support method tunnelling for clients that can only POST
        if isinstance(params, dict) and str(params.get("_method", "")).upper() == "DELETE":
            params.pop("_method")
            method = "DELETE"
        self._dispatch(method, params)

    def _dispatch(self, method: str, params: dict[str, Any]):
        path = urllib.parse.urlparse(self.path).path

        entry = ROUTES.get((method, path))
        if entry is None:
            self._send_json_response({"error": "Not found"}, 404)
            return
        if entry.requires_binary and (not self.binary_ops or not self.binary_ops.current_view):
            self._send_json_response({"error": "No binary loaded"}, 400)
            return

        request = Request(method, params, self.binary_ops, self.endpoints)
        try:
            result = entry.handler(request)
        except HTTPError as e:
            self._send_json_response(e.payload, e.status)
        except ValueError as e:
            self._send_json_response({"error": str(e)}, 400)
        except Exception as e:
            bn.log_error(f"Error handling {method} {path}: {e}")
            self._send_json_response({"error": str(e)}, 500)
        else:
            if isinstance(result, PlainTextResponse):
                self._send_text_response(result.text, result.status)
            elif isinstance(result, tuple):
                payload, status = result
                self._send_json_response(payload, status)
            else:
                self._send_json_response(result)


class MCPServer:
    """Threaded HTTP server exposing the MCP REST API."""

    def __init__(self, config: Config):
        self.config = config
        self.server = None
        self.thread = None
        self.binary_ops = BinaryOperations(config.binary_ninja)

    def start(self):
        """Start the HTTP server in a background thread."""
        server_address = (self.config.server.host, self.config.server.port)

        # Create handler with access to binary operations
        handler_class = type(
            "MCPRequestHandlerWithOps",
            (MCPRequestHandler,),
            {"binary_ops": self.binary_ops},
        )

        # Threaded so a blocking request (e.g. a debugger "run until stop") does
        # not wedge the whole server; other requests, including a pause, still run.
        self.server = ThreadingHTTPServer(server_address, handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        bn.log_info(f"Server started on {self.config.server.host}:{self.config.server.port}")

    def stop(self):
        """Stop the HTTP server and clean up resources."""
        # Terminate any live debuggee before tearing down the server.
        try:
            self.binary_ops.shutdown_debugger()
        except Exception as e:
            bn.log_warn(f"Error shutting down debugger: {e}")
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self.thread:
                self.thread.join()
            # Clear references so callers can reliably detect stopped state
            self.thread = None
            self.server = None
            bn.log_info("Server stopped")
