"""REST client for SentinelOne response actions (management API v2.1).

Every write goes to an endpoint that takes ``{"filter": {"ids": [...]}}``. The client only ever
sends an explicit ID list, never a broader filter: an empty or wider filter would apply the action
to every agent or threat the token can see.
"""

import logging
from collections.abc import Sequence
from http import HTTPStatus
from typing import Any, Final

import httpx

from purple_mcp.libs.response.exceptions import (
    ResponseAPIError,
    ResponseAuthenticationError,
    ResponseNetworkError,
)
from purple_mcp.user_agent import get_user_agent

logger = logging.getLogger(__name__)

API_PREFIX: Final[str] = "/web/api/v2.1"


class ResponseClient:
    """Client for the agent and threat action endpoints of the SentinelOne management API.

    Write requests are never retried: a timeout can leave the action applied, and the caller
    should check state before trying again.
    """

    def __init__(self, base_url: str, api_token: str, timeout: float = 30.0) -> None:
        """Initialize the client.

        Args:
            base_url: Console base URL (HTTPS origin, no trailing slash).
            api_token: Response (write) API token.
            timeout: Request timeout in seconds.

        Raises:
            ValueError: If base_url is not HTTPS or api_token is empty.
        """
        if not base_url.startswith("https://"):
            raise ValueError("base_url must use HTTPS protocol")
        if not api_token:
            raise ValueError("api_token cannot be empty")
        self._base_url = base_url.rstrip("/") + API_PREFIX
        self._api_token = api_token
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ResponseClient":
        """Enter async context manager."""
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"ApiToken {self._api_token}",
                "Content-Type": "application/json",
                "User-Agent": get_user_agent(),
            },
            timeout=httpx.Timeout(self._timeout),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit async context manager."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(
        self, method: str, path: str, *, json: Any = None, params: Any = None
    ) -> dict[str, Any]:
        """Send a request and return the decoded JSON body.

        Raises:
            ResponseAuthenticationError: On 401 or 403.
            ResponseAPIError: On any other non-2xx status or an undecodable body.
            ResponseNetworkError: If the request could not be completed.
        """
        if self._client is None:
            raise ResponseAPIError("Client not initialized. Use async context manager.")
        try:
            response = await self._client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            raise ResponseNetworkError(f"Request to {path} failed: {type(exc).__name__}") from exc

        if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
            raise ResponseAuthenticationError(
                "Response token rejected or lacks permission for this action",
                status_code=response.status_code,
            )
        if response.is_error:
            raise ResponseAPIError(
                f"Management API error on {path}: {_error_detail(response)}",
                status_code=response.status_code,
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise ResponseAPIError(f"Management API returned non-JSON from {path}") from exc
        if not isinstance(body, dict):
            raise ResponseAPIError(f"Management API returned unexpected body from {path}")
        return body

    async def _get_by_ids(self, path: str, ids: Sequence[str]) -> list[dict[str, Any]]:
        body = await self._request("GET", path, params={"ids": ",".join(ids), "limit": len(ids)})
        data = body.get("data")
        return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []

    async def _post_action(
        self, path: str, ids: Sequence[str], data: dict[str, Any] | None = None
    ) -> int:
        if not ids:
            raise ValueError("At least one ID is required")
        payload: dict[str, Any] = {"filter": {"ids": list(ids)}}
        if data is not None:
            payload["data"] = data
        body = await self._request("POST", path, json=payload)
        affected = (body.get("data") or {}).get("affected", 0)
        return affected if isinstance(affected, int) else 0

    async def get_agents(self, agent_ids: Sequence[str]) -> list[dict[str, Any]]:
        """Return the agents with the given IDs that the token can see."""
        return await self._get_by_ids("/agents", agent_ids)

    async def get_threats(self, threat_ids: Sequence[str]) -> list[dict[str, Any]]:
        """Return the threats with the given IDs that the token can see."""
        return await self._get_by_ids("/threats", threat_ids)

    async def disconnect_agents(self, agent_ids: Sequence[str]) -> int:
        """Network-isolate agents. Returns the number of agents affected."""
        return await self._post_action("/agents/actions/disconnect", agent_ids)

    async def initiate_scan(self, agent_ids: Sequence[str]) -> int:
        """Start a full disk scan on agents. Returns the number of agents affected."""
        return await self._post_action("/agents/actions/initiate-scan", agent_ids, data={})

    async def mitigate_threats(self, threat_ids: Sequence[str], action: str) -> int:
        """Apply a mitigation action to threats. Returns the number of threats affected."""
        return await self._post_action(f"/threats/mitigate/{action}", threat_ids)

    async def set_analyst_verdict(self, threat_ids: Sequence[str], verdict: str) -> int:
        """Set the analyst verdict on threats. Returns the number of threats affected."""
        return await self._post_action(
            "/threats/analyst-verdict", threat_ids, data={"analystVerdict": verdict}
        )

    async def set_incident_status(self, threat_ids: Sequence[str], status: str) -> int:
        """Set the incident status on threats. Returns the number of threats affected."""
        return await self._post_action(
            "/threats/incident", threat_ids, data={"incidentStatus": status}
        )


def _error_detail(response: httpx.Response) -> str:
    """Extract the management API's error text, falling back to the status phrase."""
    try:
        errors = response.json().get("errors")
    except (ValueError, AttributeError):
        errors = None
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            return str(first.get("detail") or first.get("title") or first)
    return response.reason_phrase or "unknown error"
