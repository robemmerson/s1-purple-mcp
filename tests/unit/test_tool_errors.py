"""Tests for purple_mcp.tool_errors (opt-in "tool errors as text" mode)."""

import logging
from typing import Any

import fastmcp
import pytest
from fastmcp.exceptions import ToolError
from mcp import types

from purple_mcp.tool_errors import (
    TOOL_ERRORS_AS_TEXT_ENV,
    install_tool_errors_as_text,
    tool_errors_as_text_enabled,
)
from purple_mcp.tools.purple_utils import iso_to_unix_timestamp

SECRET_ARGUMENT = "s3cr3t-argument-value"


def _build_app(errors_as_text: bool) -> fastmcp.FastMCP[None]:
    """Build a small server with tools that fail in each of the ways a tool call can fail."""
    app: fastmcp.FastMCP[None] = fastmcp.FastMCP("tool-errors-test")

    @app.tool
    def raises_tool_error(value: str) -> str:
        """Raise a ToolError with a recovery hint."""
        raise ToolError(f"Unknown field {value!r}; did you mean ObjectId?")

    @app.tool
    def raises_unexpected(value: str) -> str:
        """Raise an unexpected exception."""
        raise RuntimeError("database connection reset")

    @app.tool
    def succeeds(count: int) -> str:
        """Return a normal result."""
        return f"count={count}"

    @app.tool
    def returns_mapping(value: str) -> dict[str, str]:
        """Return a mapping (its outputSchema is not the wrapped-result shape)."""
        raise ToolError("mapping failed")

    @app.tool(
        output_schema={
            "type": "object",
            "properties": {"n": {"type": "integer"}},
            "required": ["n"],
        }
    )
    def strict_schema(value: str) -> dict[str, int]:
        """Declare an outputSchema no error object can satisfy."""
        raise ToolError("strict failed")

    app.tool(iso_to_unix_timestamp)

    if errors_as_text:
        install_tool_errors_as_text(app)
    return app


async def _call(
    app: fastmcp.FastMCP[None], name: str, arguments: dict[str, Any]
) -> types.CallToolResult:
    """Call a tool through a real MCP client session (which validates structured output)."""
    async with fastmcp.Client(app) as client:
        result: types.CallToolResult = await client.call_tool_mcp(name, arguments)
    return result


def _text(result: types.CallToolResult) -> str:
    """Return the single text block of *result*."""
    assert len(result.content) == 1
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


FAILING_CALLS = [
    pytest.param(
        "raises_tool_error", {"value": "objectid"}, "did you mean ObjectId?", id="tool-error"
    ),
    pytest.param(
        "raises_unexpected", {"value": "x"}, "database connection reset", id="unexpected-exception"
    ),
    pytest.param("succeeds", {}, "Missing required argument", id="missing-argument"),
    pytest.param(
        "succeeds", {"count": "many"}, "Input should be a valid integer", id="wrong-type"
    ),
    pytest.param(
        "iso_to_unix_timestamp", {}, "Missing required argument", id="real-tool-missing-argument"
    ),
    pytest.param("no_such_tool", {}, "Unknown tool: no_such_tool", id="unknown-tool"),
]


class TestFlagOff:
    """Without the flag, error results are untouched."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("tool", "arguments", "message"), FAILING_CALLS)
    async def test_failing_tool_still_returns_is_error(
        self, tool: str, arguments: dict[str, Any], message: str
    ) -> None:
        """Every failure keeps isError=true and the plain message."""
        result = await _call(_build_app(errors_as_text=False), tool, arguments)

        assert result.isError is True
        assert message in _text(result)
        assert not _text(result).startswith("ERROR: ")


class TestFlagOn:
    """With the flag, error results become ordinary ``ERROR: ...`` text results."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("tool", "arguments", "message"), FAILING_CALLS)
    async def test_error_is_returned_as_text(
        self, tool: str, arguments: dict[str, Any], message: str
    ) -> None:
        """The client sees isError=false and the exact message it would otherwise have seen."""
        original = await _call(_build_app(errors_as_text=False), tool, arguments)

        result = await _call(_build_app(errors_as_text=True), tool, arguments)

        assert result.isError is False
        assert _text(result) == f"ERROR: {_text(original)}"
        assert message in _text(result)

    @pytest.mark.asyncio
    async def test_success_is_unchanged(self) -> None:
        """Successful calls are returned exactly as without the flag."""
        original = await _call(_build_app(errors_as_text=False), "succeeds", {"count": 3})

        result = await _call(_build_app(errors_as_text=True), "succeeds", {"count": 3})

        assert result == original
        assert result.structuredContent == {"result": "count=3"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("tool", "arguments"),
        [
            pytest.param("raises_tool_error", {"value": "x"}, id="wrapped-result-schema"),
            pytest.param("returns_mapping", {"value": "x"}, id="mapping-schema"),
            pytest.param("iso_to_unix_timestamp", {"iso_datetime": "not-a-date"}, id="real-tool"),
        ],
    )
    async def test_output_schema_tool_returns_matching_structured_content(
        self, tool: str, arguments: dict[str, Any]
    ) -> None:
        """Tools with an outputSchema get structuredContent a strict client accepts.

        ``fastmcp.Client`` validates structuredContent against the tool's outputSchema whenever
        isError is false, so reaching the assertions means a strict client accepted the result.
        """
        app = _build_app(errors_as_text=True)
        assert (await app.get_tool(tool)).output_schema is not None

        async with fastmcp.Client(app) as client:
            result = await client.call_tool(tool, arguments, raise_on_error=False)

        assert result.is_error is False
        assert isinstance(result.structured_content, dict)
        assert list(result.structured_content.values()) == [result.content[0].text]
        assert result.content[0].text.startswith("ERROR: ")

    @pytest.mark.asyncio
    async def test_unsatisfiable_output_schema_falls_back_to_text_only(self) -> None:
        """If no error object fits the schema, structuredContent is omitted."""
        app = _build_app(errors_as_text=True)
        handler = app._mcp_server.request_handlers[types.CallToolRequest]
        request = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="strict_schema", arguments={"value": "x"}),
        )

        result = (await handler(request)).root

        assert isinstance(result, types.CallToolResult)
        assert result.isError is False
        assert result.structuredContent is None
        assert _text(result) == "ERROR: strict failed"

    @pytest.mark.asyncio
    async def test_converted_error_is_logged_without_arguments(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Each conversion logs a warning naming the tool, never the argument values."""
        with caplog.at_level(logging.WARNING, logger="purple_mcp.tool_errors"):
            await _call(
                _build_app(errors_as_text=True), "raises_unexpected", {"value": SECRET_ARGUMENT}
            )

        records = [r for r in caplog.records if r.name == "purple_mcp.tool_errors"]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING
        assert "raises_unexpected" in records[0].getMessage()
        assert SECRET_ARGUMENT not in caplog.text


class TestToolErrorsAsTextEnabled:
    """Parsing of MCP_TOOL_ERRORS_AS_TEXT."""

    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "YES", "on", " true "])
    def test_true_values(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        """True-ish values enable the mode, case-insensitively."""
        monkeypatch.setenv(TOOL_ERRORS_AS_TEXT_ENV, value)

        assert tool_errors_as_text_enabled() is True

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off", "", "   "])
    def test_false_values(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        """False-ish and empty values leave the mode off."""
        monkeypatch.setenv(TOOL_ERRORS_AS_TEXT_ENV, value)

        assert tool_errors_as_text_enabled() is False

    def test_unset_is_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The mode is off by default."""
        monkeypatch.delenv(TOOL_ERRORS_AS_TEXT_ENV, raising=False)

        assert tool_errors_as_text_enabled() is False

    def test_invalid_value_is_off_with_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An unparseable value leaves the mode off and says so."""
        monkeypatch.setenv(TOOL_ERRORS_AS_TEXT_ENV, "maybe")

        with caplog.at_level(logging.WARNING, logger="purple_mcp.tool_errors"):
            assert tool_errors_as_text_enabled() is False

        assert TOOL_ERRORS_AS_TEXT_ENV in caplog.text
