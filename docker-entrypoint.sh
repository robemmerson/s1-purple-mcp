#!/bin/sh
set -eu

if [ "${PURPLEMCP_AUTH_TOKEN:-}" = "your-secure-token-here" ]; then
    echo "ERROR: Default placeholder token detected!" >&2
    echo "The PURPLEMCP_AUTH_TOKEN environment variable is set to 'your-secure-token-here'," >&2
    echo "which is the default placeholder value and must not be used in a release environment." >&2
    echo "" >&2
    echo "Please generate a strong random token:" >&2
    echo "  openssl rand -base64 32" >&2
    echo "" >&2
    echo "And set it in your environment or .env file:" >&2
    echo "  PURPLEMCP_AUTH_TOKEN=<your-generated-token>" >&2
    exit 1
fi

MCP_MODE="${MCP_MODE:-stdio}"
MCP_HOST="${MCP_HOST:-0.0.0.0}"
MCP_PORT="${MCP_PORT:-8000}"

set -- python -u -m purple_mcp.cli --mode "$MCP_MODE" --host "$MCP_HOST" --port "$MCP_PORT"

ALLOW_REMOTE_ACCESS=false

# Conditionally add --allow-remote-access for HTTP modes binding to non-loopback addresses
case "$MCP_MODE" in
    sse|streamable-http)
        # Check explicitly for loopback addresses first
        case "$MCP_HOST" in
            localhost|127.0.0.1|::1)
                # Loopback addresses - no remote access flag needed
                ;;
            *)
                # All other addresses (0.0.0.0 and remote IPs) need remote access
                set -- "$@" --allow-remote-access
                ALLOW_REMOTE_ACCESS=true
                ;;
        esac
        ;;
    stdio)
        ;;
    *)
        # For other modes, check for loopback
        if [ "$MCP_HOST" != "localhost" ] && [ "$MCP_HOST" != "127.0.0.1" ] && [ "$MCP_HOST" != "::1" ]; then
            set -- "$@" --allow-remote-access
            ALLOW_REMOTE_ACCESS=true
        fi
        ;;
esac

if [ "$ALLOW_REMOTE_ACCESS" = "true" ] && [ -z "${MCP_API_KEY:-}" ]; then
    echo "ERROR: Purple MCP is binding to non-loopback address ($MCP_HOST) but MCP_API_KEY is not set." >&2
    echo "Set MCP_API_KEY to a strong random value (e.g. openssl rand -base64 32); clients must then" >&2
    echo "send 'Authorization: Bearer <MCP_API_KEY>'. The server will refuse to start without it." >&2
    echo "" >&2
fi

exec "$@"
