"""Minimal route registry for the MCP HTTP server.

Handlers are plain functions registered with the ``@route`` decorator and
receive a :class:`Request`. They may return:

- a ``dict`` (sent as JSON with status 200)
- a ``(dict, status)`` tuple
- a :class:`PlainTextResponse`

Raising :class:`HTTPError` sends a JSON error with the given status code.
"""

from collections.abc import Callable
from typing import Any, NamedTuple

from ..utils.string_utils import parse_int_or_default


class HTTPError(Exception):
    """Error that maps directly to a JSON HTTP response."""

    def __init__(self, status: int, payload: dict[str, Any] | str):
        self.status = status
        self.payload = {"error": payload} if isinstance(payload, str) else payload
        super().__init__(self.payload.get("error", "HTTP error"))


class PlainTextResponse:
    """Handler return value for text/plain responses (e.g. hexdumps)."""

    def __init__(self, text: str, status: int = 200):
        self.text = text
        self.status = status


class Request:
    """Parsed request passed to handlers.

    ``params`` holds query parameters for GET/DELETE requests and the parsed
    body for POST requests, matching the pre-refactor behaviour.
    """

    def __init__(
        self,
        method: str,
        params: dict[str, Any],
        binary_ops,
        endpoints,
    ):
        self.method = method
        self.params = params
        self.binary_ops = binary_ops
        self.endpoints = endpoints

    def param(self, *names: str, default: Any = None) -> Any:
        """Return the first non-empty parameter among ``names``."""
        for name in names:
            value = self.params.get(name)
            if value is not None and value != "":
                return value
        return default

    def require(self, *names: str, help: str | None = None) -> Any:
        """Like :meth:`param` but raises a 400 error when missing."""
        value = self.param(*names)
        if value is None:
            payload: dict[str, Any] = {
                "error": f"Missing {names[0]} parameter",
                "received": self.params,
            }
            if help:
                payload["help"] = help
            raise HTTPError(400, payload)
        return value

    @property
    def offset(self) -> int:
        return parse_int_or_default(self.params.get("offset"), 0)

    @property
    def limit(self) -> int:
        """Pagination limit; ``count`` is accepted as an alias."""
        if self.params.get("count") is not None:
            return parse_int_or_default(self.params.get("count"), 100)
        return parse_int_or_default(self.params.get("limit"), 100)


class RouteEntry(NamedTuple):
    handler: Callable[[Request], Any]
    requires_binary: bool


# (method, path) -> RouteEntry
ROUTES: dict[tuple[str, str], RouteEntry] = {}


def route(*paths: str, methods: tuple[str, ...] = ("GET",), requires_binary: bool = True):
    """Register a handler for one or more paths and HTTP methods.

    ``requires_binary=True`` makes the server reject the request with a
    400 "No binary loaded" error before the handler runs.
    """

    def decorator(fn: Callable[[Request], Any]):
        for path in paths:
            for method in methods:
                ROUTES[(method, path)] = RouteEntry(fn, requires_binary)
        return fn

    return decorator
