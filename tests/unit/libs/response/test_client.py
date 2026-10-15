"""Tests for the response-action REST client."""

import json

import httpx
import pytest
import respx

from purple_mcp.libs.response import (
    ResponseAPIError,
    ResponseAuthenticationError,
    ResponseClient,
    ResponseNetworkError,
)

BASE = "https://console.example.test"
API = f"{BASE}/web/api/v2.1"
AGENT_IDS = ["111111111111111111", "222222222222222222"]


def _client() -> ResponseClient:
    return ResponseClient(BASE, "write-token")


def test_rejects_non_https_base_url() -> None:
    """Test: rejects non https base url."""
    with pytest.raises(ValueError, match="HTTPS"):
        ResponseClient("http://console.example.test", "write-token")


def test_rejects_empty_token() -> None:
    """Test: rejects empty token."""
    with pytest.raises(ValueError, match="api_token"):
        ResponseClient(BASE, "")


@pytest.mark.asyncio
@respx.mock
async def test_disconnect_sends_explicit_id_filter_with_api_token() -> None:
    """Test: disconnect sends explicit id filter with api token."""
    route = respx.post(f"{API}/agents/actions/disconnect").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 2}})
    )
    async with _client() as client:
        assert await client.disconnect_agents(AGENT_IDS) == 2

    request = route.calls.last.request
    assert request.headers["Authorization"] == "ApiToken write-token"
    assert json.loads(request.content) == {"filter": {"ids": AGENT_IDS}}


@pytest.mark.asyncio
@respx.mock
async def test_initiate_scan_posts_empty_data() -> None:
    """Test: initiate scan posts empty data."""
    route = respx.post(f"{API}/agents/actions/initiate-scan").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    async with _client() as client:
        assert await client.initiate_scan(AGENT_IDS[:1]) == 1
    assert json.loads(route.calls.last.request.content) == {
        "filter": {"ids": AGENT_IDS[:1]},
        "data": {},
    }


@pytest.mark.asyncio
@respx.mock
async def test_mitigate_uses_action_in_path() -> None:
    """Test: mitigate uses action in path."""
    route = respx.post(f"{API}/threats/mitigate/quarantine").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    async with _client() as client:
        assert await client.mitigate_threats(["333333333333333333"], "quarantine") == 1
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_verdict_and_status_payloads() -> None:
    """Test: verdict and status payloads."""
    verdict = respx.post(f"{API}/threats/analyst-verdict").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    status = respx.post(f"{API}/threats/incident").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    async with _client() as client:
        await client.set_analyst_verdict(["333333333333333333"], "true_positive")
        await client.set_incident_status(["333333333333333333"], "in_progress")
    assert json.loads(verdict.calls.last.request.content)["data"] == {
        "analystVerdict": "true_positive"
    }
    assert json.loads(status.calls.last.request.content)["data"] == {
        "incidentStatus": "in_progress"
    }


@pytest.mark.asyncio
async def test_post_action_refuses_empty_ids() -> None:
    """Test: post action refuses empty ids."""
    async with _client() as client:
        with pytest.raises(ValueError, match="At least one ID"):
            await client.disconnect_agents([])


@pytest.mark.asyncio
@respx.mock
async def test_get_agents_passes_ids_and_limit() -> None:
    """Test: get agents passes ids and limit."""
    route = respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(200, json={"data": [{"id": AGENT_IDS[0]}, "junk"]})
    )
    async with _client() as client:
        assert await client.get_agents(AGENT_IDS) == [{"id": AGENT_IDS[0]}]
    params = route.calls.last.request.url.params
    assert params["ids"] == ",".join(AGENT_IDS)
    assert params["limit"] == "2"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
@respx.mock
async def test_auth_errors(status: int) -> None:
    """Test: auth errors."""
    respx.post(f"{API}/agents/actions/disconnect").mock(return_value=httpx.Response(status))
    async with _client() as client:
        with pytest.raises(ResponseAuthenticationError) as exc:
            await client.disconnect_agents(AGENT_IDS)
    assert exc.value.status_code == status


@pytest.mark.asyncio
@respx.mock
async def test_api_error_includes_console_detail() -> None:
    """Test: api error includes console detail."""
    respx.post(f"{API}/threats/mitigate/kill").mock(
        return_value=httpx.Response(400, json={"errors": [{"detail": "bad filter"}]})
    )
    async with _client() as client:
        with pytest.raises(ResponseAPIError, match="bad filter"):
            await client.mitigate_threats(["333333333333333333"], "kill")


@pytest.mark.asyncio
@respx.mock
async def test_network_error() -> None:
    """Test: network error."""
    respx.post(f"{API}/agents/actions/disconnect").mock(side_effect=httpx.ConnectTimeout("t"))
    async with _client() as client:
        with pytest.raises(ResponseNetworkError):
            await client.disconnect_agents(AGENT_IDS)


@pytest.mark.asyncio
async def test_request_outside_context_manager() -> None:
    """Test: request outside context manager."""
    with pytest.raises(ResponseAPIError, match="not initialized"):
        await _client().disconnect_agents(AGENT_IDS)


@pytest.mark.asyncio
@respx.mock
async def test_reconnect_and_abort_scan_endpoints() -> None:
    """Reconnect posts to /connect with an ID filter; abort-scan posts empty data."""
    connect = respx.post(f"{API}/agents/actions/connect").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 2}})
    )
    abort = respx.post(f"{API}/agents/actions/abort-scan").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    async with _client() as client:
        assert await client.reconnect_agents(AGENT_IDS) == 2
        assert await client.abort_scan(AGENT_IDS[:1]) == 1
    assert json.loads(connect.calls.last.request.content) == {"filter": {"ids": AGENT_IDS}}
    assert json.loads(abort.calls.last.request.content) == {
        "filter": {"ids": AGENT_IDS[:1]},
        "data": {},
    }
