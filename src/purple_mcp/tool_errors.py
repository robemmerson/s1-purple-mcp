"""Opt-in "tool errors as text" mode.

Some MCP clients (notably Microsoft Foundry Agent Service) abort the whole agent run when a tool
result has ``isError: true``, so the model never sees the error and cannot correct its arguments.
With ``MCP_TOOL_ERRORS_AS_TEXT=true`` every error result from ``tools/call`` is rewritten as an
ordinary result (``isError: false``) whose single text block is ``ERROR: <original message>``.

The rewrite wraps the ``tools/call`` request handler, so it covers every error source in one
place: ``ToolError`` raised by tool code, unexpected exceptions, argument validation failures and
unknown tool names. Tools that declare an ``outputSchema`` also get ``structuredContent`` that
satisfies it, so strict clients that validate structured output still accept the result.

The mode is off by default, and when off nothing is installed.
"""

import logging
import os
from typing import Any

import fastmcp
import jsonschema
from fastmcp.exceptions import NotFoundError
from mcp import types
from pydantic import TypeAdapter, ValidationError

logger = logging.getLogger(__name__)

TOOL_ERRORS_AS_TEXT_ENV = "MCP_TOOL_ERRORS_AS_TEXT"
ERROR_PREFIX = "ERROR: "


def tool_errors_as_text_enabled() -> bool:
    """Return True if ``MCP_TOOL_ERRORS_AS_TEXT`` is set to a true value.

    The value is parsed like the other boolean settings (``true``/``1``/``yes``/``on``,
    case-insensitive). Unset, empty or unparseable values mean off.

    Returns:
        Whether tool errors should be returned as text.
    """
    raw = os.environ.get(TOOL_ERRORS_AS_TEXT_ENV, "").strip()
    if not raw:
        return False
    try:
        return TypeAdapter(bool).validate_python(raw)
    except ValidationError:
        logger.warning(
            "Ignoring invalid %s value; tool errors keep isError=true", TOOL_ERRORS_AS_TEXT_ENV
        )
        return False


def _structured_error(output_schema: dict[str, Any], text: str) -> dict[str, Any] | None:
    """Return a structuredContent object for *text* that satisfies *output_schema*, if any."""
    for candidate in ({"result": text}, {"error": text}, {}):
        try:
            jsonschema.validate(instance=candidate, schema=output_schema)
        except jsonschema.ValidationError:
            continue
        return candidate
    return None


def install_tool_errors_as_text(app: fastmcp.FastMCP[Any]) -> None:
    """Rewrite ``isError: true`` tool results from *app* as ``ERROR: ...`` text results.

    Args:
        app: The FastMCP server whose ``tools/call`` handler is wrapped.
    """
    server = app._mcp_server
    call_tool = server.request_handlers[types.CallToolRequest]

    async def call_tool_errors_as_text(req: types.CallToolRequest) -> types.ServerResult:
        response: types.ServerResult = await call_tool(req)
        result = response.root
        if not isinstance(result, types.CallToolResult) or not result.isError:
            return response

        tool_name = req.params.name
        message = "\n".join(
            block.text for block in result.content if isinstance(block, types.TextContent)
        )
        text = f"{ERROR_PREFIX}{message}"

        structured: dict[str, Any] | None = None
        try:
            output_schema = (await app.get_tool(tool_name)).output_schema
        except NotFoundError:
            output_schema = None
        if output_schema is not None:
            structured = _structured_error(output_schema, text)
            if structured is None:
                logger.warning(
                    "No structuredContent fits the outputSchema of tool %r; returning text only",
                    tool_name,
                )

        logger.warning("Tool %r failed; returning the error as text (isError=false)", tool_name)
        return types.ServerResult(
            types.CallToolResult(
                content=[types.TextContent(type="text", text=text)],
                structuredContent=structured,
                isError=False,
            )
        )

    server.request_handlers[types.CallToolRequest] = call_tool_errors_as_text
