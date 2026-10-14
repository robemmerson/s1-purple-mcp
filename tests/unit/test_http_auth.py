"""Tests for purple_mcp.http_auth (bearer API-key middleware for the HTTP transports)."""

from collections.abc import Generator
from typing import Literal

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from purple_mcp.http_auth import BearerAuth
from purple_mcp.server import app as mcp_app

API_KEY = "test-key-123"
AZURE_HOST = "purple-mcp.happyriver-1234abcd.swedencentral.azurecontainerapps.io"
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def _build_client(
    transport: Literal["streamable-http", "sse"], stateless_http: bool = False
) -> TestClient:
    """Wrap the real Purple MCP HTTP app in BearerAuth and return a test client for it."""
    http_app: Starlette = mcp_app.http_app(transport=transport, stateless_http=stateless_http)
    return TestClient(BearerAuth(http_app, API_KEY), base_url=f"https://{AZURE_HOST}")


@pytest.fixture(params=[False, True], ids=["stateful", "stateless"])
def mcp_client(request: pytest.FixtureRequest) -> Generator[TestClient, None, None]:
    """Streamable-HTTP client (lifespan running) in both stateful and stateless mode."""
    with _build_client("streamable-http", stateless_http=request.param) as client:
        yield client


@pytest.fixture()
def sse_client() -> Generator[TestClient, None, None]:
    """SSE transport client with lifespan running."""
    with _build_client("sse") as client:
        yield client


class TestBearerAuthStreamableHttp:
    """Bearer authentication in front of the streamable-http MCP endpoint."""

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="no-header"),
            pytest.param({"Authorization": f"Basic {API_KEY}"}, id="wrong-scheme"),
            pytest.param({"Authorization": API_KEY}, id="no-scheme"),
            pytest.param({"Authorization": "Bearer wrong-key"}, id="wrong-key"),
            pytest.param({"Authorization": "Bearer "}, id="empty-key"),
            pytest.param({"Authorization": f"Bearer {API_KEY}x"}, id="key-with-suffix"),
        ],
    )
    def test_mcp_request_without_valid_key_returns_401(
        self, mcp_client: TestClient, headers: dict[str, str]
    ) -> None:
        """Requests without a valid bearer key are rejected before reaching the MCP app."""
        response = mcp_client.post("/mcp", json=INITIALIZE, headers={**MCP_HEADERS, **headers})

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Bearer realm="purple-mcp"'
        assert response.json()["error"] == "unauthorized"
        assert API_KEY not in response.text

    @pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
    def test_mcp_request_with_valid_key_reaches_mcp_app(
        self, mcp_client: TestClient, scheme: str
    ) -> None:
        """A valid key (any scheme casing) reaches the MCP app, even with an Azure ingress Host."""
        response = mcp_client.post(
            "/mcp",
            json=INITIALIZE,
            headers={**MCP_HEADERS, "Authorization": f"{scheme} {API_KEY}"},
        )

        assert response.status_code == 200
        assert "PurpleAIMCP" in response.text
        assert "serverInfo" in response.text

    def test_health_is_open_without_key(self, mcp_client: TestClient) -> None:
        """GET /health stays reachable without a key for container health checks."""
        response = mcp_client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_websocket_is_closed_with_policy_violation(self, mcp_client: TestClient) -> None:
        """Websocket connections are closed with code 1008, key or no key."""
        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            mcp_client.websocket_connect("/mcp", headers={"Authorization": f"Bearer {API_KEY}"}),
        ):
            pass

        assert exc_info.value.code == 1008


class TestBearerAuthSse:
    """Bearer authentication in front of the SSE MCP endpoints."""

    @pytest.mark.parametrize("path", ["/sse", "/messages/"])
    def test_sse_endpoints_without_key_return_401(self, sse_client: TestClient, path: str) -> None:
        """Both SSE endpoints reject unauthenticated requests."""
        if path == "/sse":
            response = sse_client.get(path)
        else:
            response = sse_client.post(path, json=INITIALIZE)

        assert response.status_code == 401

    def test_sse_messages_with_key_reaches_mcp_app(self, sse_client: TestClient) -> None:
        """With a valid key the request reaches the SSE transport (which rejects the bad session)."""
        response = sse_client.post(
            "/messages/?session_id=not-a-real-session",
            json=INITIALIZE,
            headers={"Authorization": f"Bearer {API_KEY}"},
        )

        assert response.status_code != 401

    def test_health_is_open_without_key(self, sse_client: TestClient) -> None:
        """GET /health stays open on the SSE app as well."""
        assert sse_client.get("/health").status_code == 200


class TestBearerAuthInit:
    """Construction-time validation."""

    def test_empty_key_is_rejected(self) -> None:
        """An empty key would make every request fail, so it is refused outright."""
        with pytest.raises(ValueError, match=r"api_key cannot be empty"):
            BearerAuth(Starlette(), "")

    def test_open_paths_can_be_customised(self) -> None:
        """Only the configured open paths bypass authentication."""
        with TestClient(BearerAuth(Starlette(), API_KEY, open_paths=["/ping"])) as client:
            assert client.get("/ping").status_code == 404  # reached the app, no such route
            assert client.get("/health").status_code == 401
