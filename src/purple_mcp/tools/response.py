"""Opt-in response-action tools: network isolation, scans and threat mitigation/triage.

These are the only tools that change anything in the SentinelOne console, so they are guarded
more tightly than the read tools:

- They are registered only when ``PURPLEMCP_ALLOW_WRITES=true``, and they authenticate with their
  own ``PURPLEMCP_RESPONSE_TOKEN`` rather than the read token.
- Each takes an explicit list of at most ``MAX_TARGETS`` agent or threat IDs, never a filter.
- Each runs in two steps. Without ``confirm`` it looks the targets up and returns a preview plus a
  ``confirmation_token``. With ``confirm=true`` and that token it performs the action. The token is
  an HMAC over the exact action and parameters, valid for ``CONFIRM_TTL`` seconds, usable once,
  and tied to this server process.
- Every executed action is logged with the caller's stated reason.
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Awaitable, Callable, Iterable
from textwrap import dedent
from typing import Annotated, Any, Final, Literal, get_args

import fastmcp
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from purple_mcp.config import RESPONSE_ACTION_NAMES, get_settings
from purple_mcp.libs.response import ResponseClient

logger = logging.getLogger(__name__)

MAX_TARGETS: Final = 10
CONFIRM_TTL: Final = 1800  # seconds a preview's confirmation token stays valid
_ID_DIGITS: Final = range(15, 21)  # SentinelOne object IDs are 18-19 digit integers

MitigationAction = Literal[
    "kill", "quarantine", "remediate", "rollback-remediation", "un-quarantine"
]
AnalystVerdict = Literal["true_positive", "false_positive", "suspicious", "undefined"]
IncidentStatus = Literal["unresolved", "in_progress", "resolved"]

_WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)

_Ids = Annotated[
    list[str],
    Field(
        min_length=1,
        max_length=MAX_TARGETS,
        description=f"1-{MAX_TARGETS} numeric SentinelOne IDs",
    ),
]
_Reason = Annotated[
    str,
    Field(
        min_length=5,
        max_length=500,
        description="Why this action is needed; recorded in the server's audit log",
    ),
]
_Confirm = Annotated[
    bool,
    Field(description="Perform the action. Only after the user approved the preview"),
]
_Token = Annotated[
    str | None,
    Field(description="The confirmation_token returned by the preview of this exact action"),
]

# Agent-facing guidance comes in two variants. PURPLEMCP_AGENT_CONFIRMABLE_ACTIONS chooses, per
# action, whether the tool description, the confirm parameter, each preview and each confirmation
# error tell the agent to wait for a human or to confirm under its own operating policy. It only
# chooses text: confirming still needs the token from a matching preview either way.
_AGENT_CONFIRM_DESCRIPTION: Final = (
    "Perform the action. Only after checking the preview's targets; no human approval is "
    "needed if your operating policy authorises this action"
)
_HUMAN_APPROVAL_NEXT: Final = (
    "Show this preview to the user. Only after they explicitly approve it, call "
    "again with the same arguments, confirm=true and this confirmation_token."
)
_AGENT_POLICY_NEXT: Final = (
    "Check that every target (hostnames, sites, statuses) matches what you intended. If it "
    "does and your operating policy authorises this action, call again with the same "
    "arguments, confirm=true and this confirmation_token. If anything is unexpected, don't "
    "confirm: escalate to a human."
)

_CONFIRM_KEY: Final = secrets.token_bytes(32)
_spent: dict[str, float] = {}  # nonce -> when it can be forgotten; each token confirms one action

_TWO_STEP_NOTE: Final = dedent(
    """
    This is a write action and runs in two steps:
    1. Call with confirm=false (the default). Nothing changes; the response lists the targets
       and includes a confirmation_token.
    2. Show that preview to the user. Only after they explicitly approve it, call again with the
       same arguments, confirm=true and the confirmation_token. Each token is valid for 30
       minutes and for one call.
    """
).strip()

_AGENT_TWO_STEP_NOTE: Final = dedent(
    """
    This is a write action and runs in two steps:
    1. Call with confirm=false (the default). Nothing changes; the response lists the targets
       and includes a confirmation_token.
    2. This server lets an authorised agent confirm this action itself; no human approval is
       needed. Check that every target in the preview (hostnames, sites, statuses) matches what
       you intended. If it does and your operating policy authorises this action, call again
       with the same arguments, confirm=true and the confirmation_token. If anything is
       unexpected, don't confirm: escalate to a human. Each token is valid for 30 minutes and
       for one call.
    """
).strip()

_DISCONNECT_AGENTS_BASE: Final[str] = dedent(
    f"""
Disconnect SentinelOne agents from the network (network quarantine / isolation).

The endpoints lose all network access except to the SentinelOne management console, so
analysts can keep investigating and reconnect them later from the console. Use this to
contain a host where an active threat is suspected.

Args:
    agent_ids: 1-{MAX_TARGETS} agent IDs (the numeric agent ID, not the UUID).
    reason: Why the hosts must be isolated.
    confirm: false to preview, true to perform.
    confirmation_token: Token from the preview.

Returns:
    JSON. Preview: target agents (name, site, current network status) and a
    confirmation_token. Confirmed: the number of agents affected.
"""
).strip()

_INITIATE_SCAN_BASE: Final[str] = dedent(
    f"""
Start a full disk scan on SentinelOne agents.

Args:
    agent_ids: 1-{MAX_TARGETS} agent IDs (the numeric agent ID, not the UUID).
    reason: Why the scan is needed.
    confirm: false to preview, true to perform.
    confirmation_token: Token from the preview.

Returns:
    JSON. Preview: target agents and a confirmation_token. Confirmed: the number of agents
    affected.
"""
).strip()

_MITIGATE_THREATS_BASE: Final[str] = dedent(
    f"""
Apply a mitigation action to SentinelOne threats.

Actions:
    kill: Kill the threat's processes.
    quarantine: Quarantine the threat's files.
    remediate: Kill, quarantine and undo the threat's changes to the system.
    rollback-remediation: Roll the system back to before the threat (Windows, VSS).
    un-quarantine: Restore files previously quarantined.

Args:
    threat_ids: 1-{MAX_TARGETS} threat IDs.
    action: One of the actions above.
    reason: Why the mitigation is needed.
    confirm: false to preview, true to perform.
    confirmation_token: Token from the preview.

Returns:
    JSON. Preview: target threats (name, endpoint, current mitigation status) and a
    confirmation_token. Confirmed: the number of threats affected.
"""
).strip()

_UPDATE_THREAT_TRIAGE_BASE: Final[str] = dedent(
    f"""
Set the analyst verdict and/or incident status of SentinelOne threats.

Args:
    threat_ids: 1-{MAX_TARGETS} threat IDs.
    analyst_verdict: true_positive, false_positive, suspicious or undefined (optional).
    incident_status: unresolved, in_progress or resolved (optional).
    reason: Why the triage is being changed.
    confirm: false to preview, true to perform.
    confirmation_token: Token from the preview.

At least one of analyst_verdict and incident_status is required.

Returns:
    JSON. Preview: target threats with their current verdict and status, and a
    confirmation_token. Confirmed: the number of threats affected per field.
"""
).strip()


def _description(base: str, agent_may_confirm: bool) -> str:
    """Return a tool description with the two-step note for the configured approval mode."""
    return f"{base}\n\n{_AGENT_TWO_STEP_NOTE if agent_may_confirm else _TWO_STEP_NOTE}"


# Default (human-approval) descriptions.
DISCONNECT_AGENTS_DESCRIPTION: Final[str] = _description(_DISCONNECT_AGENTS_BASE, False)
INITIATE_SCAN_DESCRIPTION: Final[str] = _description(_INITIATE_SCAN_BASE, False)
MITIGATE_THREATS_DESCRIPTION: Final[str] = _description(_MITIGATE_THREATS_BASE, False)
UPDATE_THREAT_TRIAGE_DESCRIPTION: Final[str] = _description(_UPDATE_THREAT_TRIAGE_BASE, False)


# --------------------------------------------------------------------------- confirmation tokens


def _token_mac(action: str, params: dict[str, Any], nonce: str, bucket: int) -> str:
    msg = json.dumps([action, params, nonce, bucket], sort_keys=True).encode()
    return hmac.new(_CONFIRM_KEY, msg, hashlib.sha256).hexdigest()[:32]


def _confirmation_token(action: str, params: dict[str, Any]) -> str:
    nonce = secrets.token_hex(8)
    return f"{nonce}.{_token_mac(action, params, nonce, int(time.time() // CONFIRM_TTL))}"


def _check_confirmation(
    action: str, params: dict[str, Any], token: str | None, agent_may_confirm: bool = False
) -> None:
    """Accept *token* once if it was issued for exactly this action and these parameters.

    Args:
        action: The response action being confirmed.
        params: The normalised arguments the token must have been issued for.
        token: The confirmation_token supplied by the caller.
        agent_may_confirm: Word the errors for an agent allowed to confirm this action itself.

    Raises:
        ToolError: If the token is missing, reused, expired, or for a different action.
    """
    re_preview = (
        "Preview again and check what it shows before confirming."
        if agent_may_confirm
        else "Preview again and get the user's approval for what it shows."
    )
    if not token:
        raise ToolError(
            "confirm=true needs the confirmation_token from a preview of this exact action. "
            + (
                "Call without confirm first, check the targets it lists, and confirm with its "
                "token if they match what you intended."
                if agent_may_confirm
                else "Call without confirm first, show the preview to the user, and confirm only "
                "after they approve it."
            )
        )
    now = time.time()
    for nonce in [n for n, until in _spent.items() if until < now]:
        del _spent[nonce]
    nonce, _, mac = token.strip().partition(".")
    if nonce in _spent:
        raise ToolError(
            f"This confirmation_token was already used: each preview approves one action. {re_preview}"
        )
    bucket = int(now // CONFIRM_TTL)
    for b in (bucket, bucket - 1):
        if hmac.compare_digest(mac.encode(), _token_mac(action, params, nonce, b).encode()):
            _spent[nonce] = now + 2 * CONFIRM_TTL
            return
    raise ToolError(
        "confirmation_token doesn't match this action (different arguments, expired, or the "
        f"server restarted). {re_preview}"
    )


# --------------------------------------------------------------------------- helpers


def _normalise_ids(ids: Iterable[str], label: str) -> list[str]:
    """Strip, de-duplicate and sort IDs, rejecting anything that is not a SentinelOne ID.

    Raises:
        ValueError: If the list is empty, too long, or contains a non-numeric ID.
    """
    cleaned = sorted({str(i).strip() for i in ids if str(i).strip()})
    if not cleaned:
        raise ValueError(f"At least one {label} ID is required")
    if len(cleaned) > MAX_TARGETS:
        raise ValueError(f"At most {MAX_TARGETS} {label} IDs per call, got {len(cleaned)}")
    bad = [i for i in cleaned if not (i.isdigit() and len(i) in _ID_DIGITS)]
    if bad:
        raise ValueError(f"Invalid {label} ID(s), expected numeric SentinelOne IDs: {bad}")
    return cleaned


def _normalise_reason(reason: str) -> str:
    cleaned = " ".join(reason.split())
    if len(cleaned) < 5:
        raise ValueError("reason must say why the action is needed (at least 5 characters)")
    return cleaned[:500]


def _response_client() -> ResponseClient:
    """Return a client authenticated with the response token.

    Raises:
        ToolError: If response actions are disabled or not configured.
    """
    settings = get_settings()
    if not settings.allow_writes or not settings.response_token:
        raise ToolError("Response actions are disabled on this server.")
    if settings.sentinelone_console_base_url is None:
        raise ToolError("Console base URL not configured.")
    return ResponseClient(settings.sentinelone_console_base_url, settings.response_token)


def _agent_summary(agent: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": agent.get("id"),
        "computerName": agent.get("computerName"),
        "siteName": agent.get("siteName"),
        "groupName": agent.get("groupName"),
        "osName": agent.get("osName"),
        "networkStatus": agent.get("networkStatus"),
        "isActive": agent.get("isActive"),
        "infected": agent.get("infected"),
        "lastActiveDate": agent.get("lastActiveDate"),
    }


def _threat_summary(threat: dict[str, Any]) -> dict[str, Any]:
    info = threat.get("threatInfo") or {}
    agent = threat.get("agentRealtimeInfo") or {}
    return {
        "id": threat.get("id"),
        "threatName": info.get("threatName"),
        "classification": info.get("classification"),
        "confidenceLevel": info.get("confidenceLevel"),
        "mitigationStatus": info.get("mitigationStatus"),
        "analystVerdict": info.get("analystVerdict"),
        "incidentStatus": info.get("incidentStatus"),
        "agentId": agent.get("agentId"),
        "agentComputerName": agent.get("agentComputerName"),
        "siteName": agent.get("siteName"),
    }


def _require_all_found(requested: list[str], found: list[dict[str, Any]], label: str) -> None:
    missing = sorted(set(requested) - {str(item.get("id")) for item in found})
    if missing:
        raise ValueError(
            f"{label} ID(s) not found or outside the response token's scope: {missing}. "
            "Nothing was changed."
        )


async def _two_step(
    *,
    action: str,
    params: dict[str, Any],
    preview: Callable[[ResponseClient], Awaitable[list[dict[str, Any]]]],
    execute: Callable[[ResponseClient], Awaitable[dict[str, int]]],
    confirm: bool,
    confirmation_token: str | None,
) -> str:
    """Preview or perform a response action, enforcing the confirmation token."""
    agent_may_confirm = action in get_settings().agent_confirmable_actions
    if confirm:
        _check_confirmation(action, params, confirmation_token, agent_may_confirm)
        async with _response_client() as client:
            affected = await execute(client)
        logger.warning(
            "Response action executed",
            extra={"response_action": action, "response_params": params, "affected": affected},
        )
        result: dict[str, Any] = {"sent": True, "action": action, "affected": affected}
        targets = len(params.get("agent_ids") or params.get("threat_ids") or [])
        if any(count != targets for count in affected.values()):
            result["warning"] = (
                f"{targets} target(s) requested but the console reports a different count "
                "affected. Check their state before retrying."
            )
        return json.dumps(result, indent=2)

    async with _response_client() as client:
        targets_found = await preview(client)
    return json.dumps(
        {
            "sent": False,
            "action": action,
            "arguments": params,
            "targets": targets_found,
            "confirmation_token": _confirmation_token(action, params),
            "approval": "agent_policy" if agent_may_confirm else "human",
            "next": _AGENT_POLICY_NEXT if agent_may_confirm else _HUMAN_APPROVAL_NEXT,
        },
        indent=2,
    )


# --------------------------------------------------------------------------- tools


async def disconnect_agents_from_network(
    agent_ids: _Ids,
    reason: _Reason,
    confirm: _Confirm = False,
    confirmation_token: _Token = None,
) -> str:
    """Network-isolate agents (two-step: preview, then confirm)."""
    ids = _normalise_ids(agent_ids, "agent")
    params = {"agent_ids": ids, "reason": _normalise_reason(reason)}

    async def preview(client: ResponseClient) -> list[dict[str, Any]]:
        agents = await client.get_agents(ids)
        _require_all_found(ids, agents, "Agent")
        return [_agent_summary(a) for a in agents]

    async def execute(client: ResponseClient) -> dict[str, int]:
        return {"disconnected": await client.disconnect_agents(ids)}

    return await _two_step(
        action="disconnect_agents_from_network",
        params=params,
        preview=preview,
        execute=execute,
        confirm=confirm,
        confirmation_token=confirmation_token,
    )


async def initiate_agent_scan(
    agent_ids: _Ids,
    reason: _Reason,
    confirm: _Confirm = False,
    confirmation_token: _Token = None,
) -> str:
    """Start a full disk scan on agents (two-step: preview, then confirm)."""
    ids = _normalise_ids(agent_ids, "agent")
    params = {"agent_ids": ids, "reason": _normalise_reason(reason)}

    async def preview(client: ResponseClient) -> list[dict[str, Any]]:
        agents = await client.get_agents(ids)
        _require_all_found(ids, agents, "Agent")
        return [_agent_summary(a) for a in agents]

    async def execute(client: ResponseClient) -> dict[str, int]:
        return {"scans_started": await client.initiate_scan(ids)}

    return await _two_step(
        action="initiate_agent_scan",
        params=params,
        preview=preview,
        execute=execute,
        confirm=confirm,
        confirmation_token=confirmation_token,
    )


async def mitigate_threats(
    threat_ids: _Ids,
    action: MitigationAction,
    reason: _Reason,
    confirm: _Confirm = False,
    confirmation_token: _Token = None,
) -> str:
    """Apply a mitigation action to threats (two-step: preview, then confirm)."""
    if action not in get_args(MitigationAction):
        raise ValueError(f"action must be one of {list(get_args(MitigationAction))}")
    ids = _normalise_ids(threat_ids, "threat")
    params = {"threat_ids": ids, "action": action, "reason": _normalise_reason(reason)}

    async def preview(client: ResponseClient) -> list[dict[str, Any]]:
        threats = await client.get_threats(ids)
        _require_all_found(ids, threats, "Threat")
        return [_threat_summary(t) for t in threats]

    async def execute(client: ResponseClient) -> dict[str, int]:
        return {"mitigated": await client.mitigate_threats(ids, action)}

    return await _two_step(
        action="mitigate_threats",
        params=params,
        preview=preview,
        execute=execute,
        confirm=confirm,
        confirmation_token=confirmation_token,
    )


async def update_threat_triage(
    threat_ids: _Ids,
    reason: _Reason,
    analyst_verdict: AnalystVerdict | None = None,
    incident_status: IncidentStatus | None = None,
    confirm: _Confirm = False,
    confirmation_token: _Token = None,
) -> str:
    """Set analyst verdict and/or incident status on threats (two-step: preview, then confirm)."""
    if analyst_verdict is None and incident_status is None:
        raise ValueError("Set analyst_verdict, incident_status, or both")
    if analyst_verdict is not None and analyst_verdict not in get_args(AnalystVerdict):
        raise ValueError(f"analyst_verdict must be one of {list(get_args(AnalystVerdict))}")
    if incident_status is not None and incident_status not in get_args(IncidentStatus):
        raise ValueError(f"incident_status must be one of {list(get_args(IncidentStatus))}")
    ids = _normalise_ids(threat_ids, "threat")
    params = {
        "threat_ids": ids,
        "analyst_verdict": analyst_verdict,
        "incident_status": incident_status,
        "reason": _normalise_reason(reason),
    }

    async def preview(client: ResponseClient) -> list[dict[str, Any]]:
        threats = await client.get_threats(ids)
        _require_all_found(ids, threats, "Threat")
        return [_threat_summary(t) for t in threats]

    async def execute(client: ResponseClient) -> dict[str, int]:
        affected: dict[str, int] = {}
        if analyst_verdict is not None:
            affected["analyst_verdict"] = await client.set_analyst_verdict(ids, analyst_verdict)
        if incident_status is not None:
            affected["incident_status"] = await client.set_incident_status(ids, incident_status)
        return affected

    return await _two_step(
        action="update_threat_triage",
        params=params,
        preview=preview,
        execute=execute,
        confirm=confirm,
        confirmation_token=confirmation_token,
    )


RESPONSE_TOOL_NAMES: Final[tuple[str, ...]] = RESPONSE_ACTION_NAMES


def register_response_tools(
    app: fastmcp.FastMCP[None], agent_confirmable: Iterable[str] = ()
) -> None:
    """Register the response-action tools on *app*.

    Only call this when ``PURPLEMCP_ALLOW_WRITES`` is enabled; the tools also refuse to run if
    it is not.

    Args:
        app: The server to register the tools on.
        agent_confirmable: Names of actions whose description and ``confirm`` parameter tell the
            agent it may confirm them itself (``PURPLEMCP_AGENT_CONFIRMABLE_ACTIONS``). All
            others ask for human approval.
    """
    confirmable = frozenset(agent_confirmable)
    tools: tuple[tuple[Callable[..., Awaitable[str]], str, ToolAnnotations], ...] = (
        (disconnect_agents_from_network, _DISCONNECT_AGENTS_BASE, _DESTRUCTIVE),
        (initiate_agent_scan, _INITIATE_SCAN_BASE, _WRITE),
        (mitigate_threats, _MITIGATE_THREATS_BASE, _DESTRUCTIVE),
        (update_threat_triage, _UPDATE_THREAT_TRIAGE_BASE, _WRITE),
    )
    for fn, base, annotations in tools:
        agent_may_confirm = fn.__name__ in confirmable
        tool = app.tool(
            description=_description(base, agent_may_confirm), annotations=annotations
        )(fn)
        if agent_may_confirm:
            tool.parameters["properties"]["confirm"]["description"] = _AGENT_CONFIRM_DESCRIPTION
