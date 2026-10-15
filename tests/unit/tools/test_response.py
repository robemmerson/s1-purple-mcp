"""Tests for the opt-in response-action tools."""

import json
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import fastmcp
import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

import purple_mcp.tools.response as response_tools
from purple_mcp.tools.response import (
    MAX_TARGETS,
    RESPONSE_TOOL_NAMES,
    disconnect_agents_from_network,
    initiate_agent_scan,
    mitigate_threats,
    register_response_tools,
    update_threat_triage,
)

BASE = "https://console.example.test"
API = f"{BASE}/web/api/v2.1"
AGENT = "111111111111111111"
AGENT2 = "222222222222222222"
THREAT = "333333333333333333"
REASON = "ransomware behaviour on host"


@pytest.fixture(autouse=True)
def writes_enabled(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    """Point the tools at stub settings with writes enabled and a fresh token store."""
    settings = SimpleNamespace(
        allow_writes=True,
        response_token="write-token",
        sentinelone_console_base_url=BASE,
        agent_confirmable_actions=(),
    )
    monkeypatch.setattr(response_tools, "get_settings", lambda: settings)
    response_tools._spent.clear()
    yield settings
    response_tools._spent.clear()


def _agents(*ids: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": [
                {"id": i, "computerName": f"host-{i[-1]}", "networkStatus": "connected"}
                for i in ids
            ]
        },
    )


def _threats(*ids: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": [
                {
                    "id": i,
                    "threatInfo": {"threatName": "evil.exe", "mitigationStatus": "not_mitigated"},
                    "agentRealtimeInfo": {"agentComputerName": "host-1", "agentId": AGENT},
                }
                for i in ids
            ]
        },
    )


async def _preview(tool: Any, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(await tool(**kwargs))
    assert result["sent"] is False
    return result


# --------------------------------------------------------------------------- two-step flow


@pytest.mark.asyncio
@respx.mock
async def test_disconnect_preview_then_confirm() -> None:
    """Test: disconnect preview then confirm."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT, AGENT2))
    action = respx.post(f"{API}/agents/actions/disconnect").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 2}})
    )

    preview = await _preview(
        disconnect_agents_from_network, agent_ids=[AGENT2, AGENT, AGENT], reason=REASON
    )
    assert not action.called
    assert [t["computerName"] for t in preview["targets"]] == ["host-1", "host-2"]
    assert preview["arguments"]["agent_ids"] == [AGENT, AGENT2]  # de-duplicated and sorted

    done = json.loads(
        await disconnect_agents_from_network(
            agent_ids=[AGENT, AGENT2],
            reason=REASON,
            confirm=True,
            confirmation_token=preview["confirmation_token"],
        )
    )
    assert done == {
        "sent": True,
        "action": "disconnect_agents_from_network",
        "affected": {"disconnected": 2},
    }
    assert json.loads(action.calls.last.request.content) == {"filter": {"ids": [AGENT, AGENT2]}}


@pytest.mark.asyncio
@respx.mock
async def test_confirm_without_token_is_refused() -> None:
    """Test: confirm without token is refused."""
    action = respx.post(f"{API}/agents/actions/disconnect")
    with pytest.raises(ToolError, match="needs the confirmation_token"):
        await disconnect_agents_from_network(agent_ids=[AGENT], reason=REASON, confirm=True)
    assert not action.called


@pytest.mark.asyncio
@respx.mock
async def test_token_is_single_use() -> None:
    """Test: token is single use."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT))
    respx.post(f"{API}/agents/actions/initiate-scan").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    token = (await _preview(initiate_agent_scan, agent_ids=[AGENT], reason=REASON))[
        "confirmation_token"
    ]
    kwargs = {"agent_ids": [AGENT], "reason": REASON, "confirm": True, "confirmation_token": token}
    await initiate_agent_scan(**kwargs)
    with pytest.raises(ToolError, match="already used"):
        await initiate_agent_scan(**kwargs)


@pytest.mark.asyncio
@respx.mock
async def test_token_bound_to_targets_and_action() -> None:
    """Test: token bound to targets and action."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT))
    disconnect = respx.post(f"{API}/agents/actions/disconnect")
    token = (await _preview(initiate_agent_scan, agent_ids=[AGENT], reason=REASON))[
        "confirmation_token"
    ]

    # A scan preview cannot authorise a disconnect of the same agent ...
    with pytest.raises(ToolError, match="doesn't match"):
        await disconnect_agents_from_network(
            agent_ids=[AGENT], reason=REASON, confirm=True, confirmation_token=token
        )
    # ... nor a scan of a different agent.
    with pytest.raises(ToolError, match="doesn't match"):
        await initiate_agent_scan(
            agent_ids=[AGENT2], reason=REASON, confirm=True, confirmation_token=token
        )
    assert not disconnect.called


@pytest.mark.asyncio
@respx.mock
async def test_token_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test: token expires."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT))
    now = 1_000_000_000.0
    monkeypatch.setattr("purple_mcp.tools.response.time.time", lambda: now)
    token = (await _preview(initiate_agent_scan, agent_ids=[AGENT], reason=REASON))[
        "confirmation_token"
    ]
    now += 2 * response_tools.CONFIRM_TTL + 1
    with pytest.raises(ToolError, match="doesn't match"):
        await initiate_agent_scan(
            agent_ids=[AGENT], reason=REASON, confirm=True, confirmation_token=token
        )


@pytest.mark.asyncio
@respx.mock
async def test_preview_refuses_unknown_targets() -> None:
    """Test: preview refuses unknown targets."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT))
    with pytest.raises(ValueError, match=f"outside the response token's scope: \\['{AGENT2}'\\]"):
        await disconnect_agents_from_network(agent_ids=[AGENT, AGENT2], reason=REASON)


@pytest.mark.asyncio
@respx.mock
async def test_affected_mismatch_is_flagged() -> None:
    """Test: affected mismatch is flagged."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT, AGENT2))
    respx.post(f"{API}/agents/actions/disconnect").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    token = (
        await _preview(disconnect_agents_from_network, agent_ids=[AGENT, AGENT2], reason=REASON)
    )["confirmation_token"]
    done = json.loads(
        await disconnect_agents_from_network(
            agent_ids=[AGENT, AGENT2], reason=REASON, confirm=True, confirmation_token=token
        )
    )
    assert "warning" in done


@pytest.mark.asyncio
@respx.mock
async def test_mitigate_preview_and_confirm() -> None:
    """Test: mitigate preview and confirm."""
    respx.get(f"{API}/threats").mock(return_value=_threats(THREAT))
    action = respx.post(f"{API}/threats/mitigate/kill").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    preview = await _preview(mitigate_threats, threat_ids=[THREAT], action="kill", reason=REASON)
    assert preview["targets"][0]["threatName"] == "evil.exe"
    await mitigate_threats(
        threat_ids=[THREAT],
        action="kill",
        reason=REASON,
        confirm=True,
        confirmation_token=preview["confirmation_token"],
    )
    assert action.called


@pytest.mark.asyncio
@respx.mock
async def test_triage_sets_both_fields() -> None:
    """Test: triage sets both fields."""
    respx.get(f"{API}/threats").mock(return_value=_threats(THREAT))
    verdict = respx.post(f"{API}/threats/analyst-verdict").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    status = respx.post(f"{API}/threats/incident").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    kwargs: dict[str, Any] = {
        "threat_ids": [THREAT],
        "reason": REASON,
        "analyst_verdict": "true_positive",
        "incident_status": "in_progress",
    }
    token = (await _preview(update_threat_triage, **kwargs))["confirmation_token"]
    done = json.loads(await update_threat_triage(**kwargs, confirm=True, confirmation_token=token))
    assert done["affected"] == {"analyst_verdict": 1, "incident_status": 1}
    assert verdict.called and status.called


# --------------------------------------------------------------------------- approval guidance

# The preview guidance shipped before PURPLEMCP_AGENT_CONFIRMABLE_ACTIONS existed. It must stay
# verbatim for every action that is not configured as agent-confirmable.
HUMAN_NEXT = (
    "Show this preview to the user. Only after they explicitly approve it, call again with the "
    "same arguments, confirm=true and this confirmation_token."
)
AGENT_NEXT = (
    "Check that every target (hostnames, sites, statuses) matches what you intended. If it "
    "does and your operating policy authorises this action, call again with the same "
    "arguments, confirm=true and this confirmation_token. If anything is unexpected, don't "
    "confirm: escalate to a human."
)
AGENT_CONFIRMABLE = ("initiate_agent_scan", "disconnect_agents_from_network")


async def _preview_all() -> dict[str, dict[str, Any]]:
    """Preview each of the four response actions and return the previews by action name."""
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT))
    respx.get(f"{API}/threats").mock(return_value=_threats(THREAT))
    previews = [
        await _preview(disconnect_agents_from_network, agent_ids=[AGENT], reason=REASON),
        await _preview(initiate_agent_scan, agent_ids=[AGENT], reason=REASON),
        await _preview(mitigate_threats, threat_ids=[THREAT], action="kill", reason=REASON),
        await _preview(
            update_threat_triage,
            threat_ids=[THREAT],
            reason=REASON,
            incident_status="in_progress",
        ),
    ]
    return {p["action"]: p for p in previews}


@pytest.mark.asyncio
@respx.mock
async def test_previews_default_to_human_approval_with_unchanged_text() -> None:
    """With the setting unset, every preview asks for human approval in the original words."""
    previews = await _preview_all()
    assert set(previews) == set(RESPONSE_TOOL_NAMES)
    for preview in previews.values():
        assert preview["approval"] == "human"
        assert preview["next"] == HUMAN_NEXT


@pytest.mark.asyncio
@respx.mock
async def test_configured_actions_get_agent_policy_guidance(
    writes_enabled: SimpleNamespace,
) -> None:
    """Only the configured actions tell the agent it may confirm under its own policy."""
    writes_enabled.agent_confirmable_actions = AGENT_CONFIRMABLE
    previews = await _preview_all()
    for name, preview in previews.items():
        if name in AGENT_CONFIRMABLE:
            assert preview["approval"] == "agent_policy"
            assert preview["next"] == AGENT_NEXT
        else:
            assert preview["approval"] == "human"
            assert preview["next"] == HUMAN_NEXT


@pytest.mark.asyncio
@pytest.mark.parametrize("confirmable", [(), AGENT_CONFIRMABLE])
@respx.mock
async def test_confirmation_token_still_required_in_every_mode(
    writes_enabled: SimpleNamespace, confirmable: tuple[str, ...]
) -> None:
    """Agent-confirmable actions still need a matching, unused token from a preview."""
    writes_enabled.agent_confirmable_actions = confirmable
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT, AGENT2))
    action = respx.post(f"{API}/agents/actions/disconnect").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )

    with pytest.raises(ToolError, match="needs the confirmation_token"):
        await disconnect_agents_from_network(agent_ids=[AGENT], reason=REASON, confirm=True)

    token = (await _preview(disconnect_agents_from_network, agent_ids=[AGENT], reason=REASON))[
        "confirmation_token"
    ]
    with pytest.raises(ToolError, match="doesn't match"):
        await disconnect_agents_from_network(
            agent_ids=[AGENT2], reason=REASON, confirm=True, confirmation_token=token
        )
    assert not action.called

    kwargs = {"agent_ids": [AGENT], "reason": REASON, "confirm": True, "confirmation_token": token}
    await disconnect_agents_from_network(**kwargs)
    with pytest.raises(ToolError, match="already used"):
        await disconnect_agents_from_network(**kwargs)
    assert action.call_count == 1


# --------------------------------------------------------------------------- input validation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ids", "match"),
    [
        ([], "At least one"),
        (["  "], "At least one"),
        (["123"], "Invalid agent"),
        (["11111111111111111a"], "Invalid agent"),
        ([str(10**17 + i) for i in range(MAX_TARGETS + 1)], f"At most {MAX_TARGETS}"),
    ],
)
async def test_invalid_ids_rejected(ids: list[str], match: str) -> None:
    """Test: invalid ids rejected."""
    with pytest.raises(ValueError, match=match):
        await disconnect_agents_from_network(agent_ids=ids, reason=REASON)


@pytest.mark.asyncio
async def test_reason_required() -> None:
    """Test: reason required."""
    with pytest.raises(ValueError, match="reason"):
        await initiate_agent_scan(agent_ids=[AGENT], reason="   ")


@pytest.mark.asyncio
async def test_triage_needs_a_field() -> None:
    """Test: triage needs a field."""
    with pytest.raises(ValueError, match="analyst_verdict, incident_status, or both"):
        await update_threat_triage(threat_ids=[THREAT], reason=REASON)


@pytest.mark.asyncio
async def test_invalid_mitigation_action() -> None:
    """Test: invalid mitigation action."""
    with pytest.raises(ValueError, match="action must be one of"):
        await mitigate_threats(threat_ids=[THREAT], action="delete", reason=REASON)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_refuses_when_writes_disabled(writes_enabled: SimpleNamespace) -> None:
    """Test: refuses when writes disabled."""
    writes_enabled.allow_writes = False
    with pytest.raises(ToolError, match="disabled"):
        await initiate_agent_scan(agent_ids=[AGENT], reason=REASON)


# --------------------------------------------------------------------------- registration


@pytest.mark.asyncio
async def test_register_response_tools_with_annotations() -> None:
    """Test: register response tools with annotations."""
    mcp: fastmcp.FastMCP[None] = fastmcp.FastMCP("test")
    register_response_tools(mcp)
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert set(tools) == set(RESPONSE_TOOL_NAMES)
    for tool in tools.values():
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is False
    assert tools["disconnect_agents_from_network"].annotations.destructiveHint is True
    assert tools["mitigate_threats"].annotations.destructiveHint is True
    schema = tools["disconnect_agents_from_network"].inputSchema
    assert schema["properties"]["agent_ids"]["maxItems"] == MAX_TARGETS
    assert set(schema["required"]) == {"agent_ids", "reason"}


# --------------------------------------------------------------------------- agent-facing wording

# Phrases that send the agent to a human. None may reach an agent for an agent-confirmable action.
HUMAN_PHRASES = ("to the user", "user's approval", "user approved", "they explicitly approve")


async def _listed_tools(agent_confirmable: tuple[str, ...]) -> dict[str, Any]:
    """Register the tools with the given agent-confirmable set and return them by name."""
    mcp: fastmcp.FastMCP[None] = fastmcp.FastMCP("test")
    register_response_tools(mcp, agent_confirmable)
    async with Client(mcp) as client:
        return {t.name: t for t in await client.list_tools()}


@pytest.mark.asyncio
async def test_default_registration_asks_for_human_approval() -> None:
    """Without agent-confirmable actions every description and confirm parameter asks a human."""
    for tool in (await _listed_tools(())).values():
        assert "Show that preview to the user" in (tool.description or "")
        assert tool.inputSchema["properties"]["confirm"]["description"] == (
            "Perform the action. Only after the user approved the preview"
        )


@pytest.mark.asyncio
async def test_registration_wording_follows_agent_confirmable_actions() -> None:
    """Configured tools describe agent confirmation; the others still ask for a human."""
    tools = await _listed_tools(AGENT_CONFIRMABLE)
    for name, tool in tools.items():
        description = tool.description or ""
        confirm = tool.inputSchema["properties"]["confirm"]["description"]
        if name in AGENT_CONFIRMABLE:
            assert "no human approval is" in description
            assert "escalate to a human" in description
            assert "no human approval is needed" in confirm
            assert not any(p in description + confirm for p in HUMAN_PHRASES)
        else:
            assert "Show that preview to the user" in description
            assert "user approved" in confirm


@pytest.mark.asyncio
@respx.mock
async def test_agent_confirmable_actions_never_tell_the_agent_to_wait_for_a_human(
    writes_enabled: SimpleNamespace,
) -> None:
    """Description, schema, preview and every confirmation error avoid human-approval wording."""
    writes_enabled.agent_confirmable_actions = AGENT_CONFIRMABLE
    respx.get(f"{API}/agents").mock(return_value=_agents(AGENT))
    respx.post(f"{API}/agents/actions/disconnect").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    respx.post(f"{API}/agents/actions/initiate-scan").mock(
        return_value=httpx.Response(200, json={"data": {"affected": 1}})
    )
    tools = await _listed_tools(AGENT_CONFIRMABLE)

    for tool_fn in (disconnect_agents_from_network, initiate_agent_scan):
        listed = tools[tool_fn.__name__]
        texts = [listed.description or "", json.dumps(listed.inputSchema)]

        preview = await _preview(tool_fn, agent_ids=[AGENT], reason=REASON)
        texts.append(json.dumps(preview))
        token = preview["confirmation_token"]

        for kwargs in (
            {"agent_ids": [AGENT], "reason": REASON, "confirm": True},  # no token
            {
                "agent_ids": [AGENT2],
                "reason": REASON,
                "confirm": True,
                "confirmation_token": token,
            },
        ):
            with pytest.raises(ToolError) as exc:
                await tool_fn(**kwargs)
            texts.append(str(exc.value))

        done = await tool_fn(
            agent_ids=[AGENT], reason=REASON, confirm=True, confirmation_token=token
        )
        texts.append(done)
        with pytest.raises(ToolError, match="already used") as exc:
            await tool_fn(agent_ids=[AGENT], reason=REASON, confirm=True, confirmation_token=token)
        texts.append(str(exc.value))

        for text in texts:
            assert not any(p in text for p in HUMAN_PHRASES), text


@pytest.mark.asyncio
async def test_confirmation_errors_keep_human_wording_by_default() -> None:
    """Without the setting, confirmation errors still send the agent to the user."""
    with pytest.raises(ToolError, match="show the preview to the user"):
        await initiate_agent_scan(agent_ids=[AGENT], reason=REASON, confirm=True)
    with pytest.raises(ToolError, match="get the user's approval"):
        await initiate_agent_scan(
            agent_ids=[AGENT], reason=REASON, confirm=True, confirmation_token="bad.token"
        )
