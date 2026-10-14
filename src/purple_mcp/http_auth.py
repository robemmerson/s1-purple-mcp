"""Bearer API-key authentication for the HTTP transports.

The MCP endpoints (streamable-http and SSE) are wrapped in :class:`BearerAuth`, an ASGI
middleware that requires ``Authorization: Bearer <MCP_API_KEY>`` on every HTTP request
except a small set of open paths (``/health`` by default) used by container health checks.
"""

import hmac
from collections.abc import Iterable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

API_KEY_ENV = "MCP_API_KEY"
AUTH_REALM = "purple-mcp"
DEFAULT_OPEN_PATHS: frozenset[str] = frozenset({"/health"})


class BearerAuth:
    """ASGI middleware that rejects requests without a valid bearer API key.

    HTTP requests must carry ``Authorization: Bearer <key>``. The scheme is matched
    case-insensitively and the key is compared in constant time. Requests to an open path
    skip the check. Websocket connections are closed with code 1008 (the MCP transports are
    plain HTTP), and lifespan events pass through untouched so the wrapped app starts up
    normally.
    """

    def __init__(
        self, app: ASGIApp, api_key: str, open_paths: Iterable[str] = DEFAULT_OPEN_PATHS
    ) -> None:
        """Wrap *app* so it is only reachable with *api_key*.

        Args:
            app: The ASGI application to protect.
            api_key: The key clients must send as a bearer token.
            open_paths: Exact request paths that are served without authentication.

        Raises:
            ValueError: If *api_key* is empty.
        """
        if not api_key:
            raise ValueError("api_key cannot be empty")
        self.app = app
        self._key = api_key.encode()
        self._open_paths = frozenset(open_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle an ASGI connection."""
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return

        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        if scope.get("path") in self._open_paths or self._is_authorised(scope):
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            {"error": "unauthorized", "detail": f"send Authorization: Bearer <{API_KEY_ENV}>"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="{AUTH_REALM}"'},
        )
        await response(scope, receive, send)

    def _is_authorised(self, scope: Scope) -> bool:
        """Return True if the request carries the expected bearer key."""
        header = b""
        for name, value in scope.get("headers") or []:
            if name.lower() == b"authorization":
                header = value
                break
        scheme, _, supplied = header.partition(b" ")
        return scheme.lower() == b"bearer" and hmac.compare_digest(supplied.strip(), self._key)
