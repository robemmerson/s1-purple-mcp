# Deployment Configurations

This directory contains deployment and infrastructure configurations.

## Using nginx

Reverse proxy configuration for release deployments. See
[nginx.conf.template](nginx/nginx.conf.template) for:

- Bearer token authentication
- HTTPS/TLS configuration
- Security headers
- Rate limiting
- Streaming support for MCP

Used by the `purple-mcp-proxy` service in [docker-compose.yml](../docker-compose.yml).

### Using Docker

```bash
# Build the image
docker build -t purple-mcp:latest .

# Run with your credentials
export PURPLEMCP_CONSOLE_TOKEN="your_token"
export PURPLEMCP_CONSOLE_BASE_URL="https://your-console.sentinelone.net"
# API key clients must send as "Authorization: Bearer <key>" (required for HTTP modes on 0.0.0.0)
export MCP_API_KEY="$(openssl rand -base64 32)"

docker run -p 8000:8000 \
  -e PURPLEMCP_CONSOLE_TOKEN \
  -e PURPLEMCP_CONSOLE_BASE_URL \
  -e MCP_API_KEY \
  -e MCP_MODE=streamable-http \
  purple-mcp:latest

# Health check (no key needed)
curl http://localhost:8000/health

# MCP requests need the key
curl -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

In `sse`/`streamable-http` mode the container binds `0.0.0.0` by default, so `MCP_API_KEY` is
required: without it the server refuses to start. Only `/health` is served without the key. When
running behind the bundled nginx proxy (`docker compose --profile proxy`), which forwards the
`Authorization` header, set `MCP_API_KEY` to the same value as `PURPLEMCP_AUTH_TOKEN`.

Follow more detailed instructions Docker Deployment [here](docker/DOCKER.md)

## Using Amazon Bedrock AgentCore

```bash
# Subscribe to Purple AI MCP Server via AWS Marketplace

#Prepare Environment Variables
PURPLEMCP_CONSOLE_BASE_URL=https://your-console.sentinelone.net
PURPLEMCP_CONSOLE_TOKEN=your-token
MCP_API_KEY=your-api-key
MCP_MODE=streamable-http
PURPLEMCP_STATELESS_HTTP=True
```

Follow mode detailed instructions for Amazon Bedrock AgentCore Deployment
[here](aws_agentcore/BEDROCK_AGENTCORE_DEPLOYMENT.md)

### Using Amazon Elastic Container Service (ECS)

```bash
# Subscribe to Purple AI MCP Server via AWS Marketplace

#Prepare Environment Variables
PURPLEMCP_CONSOLE_BASE_URL=https://your-console.sentinelone.net
PURPLEMCP_CONSOLE_TOKEN=your-token
MCP_API_KEY=your-api-key
MCP_MODE=streamable-http
PURPLEMCP_STATELESS_HTTP=True
```

Follow more detailed instructions for Amazon Elastic Container Service Deployment
[here](aws_ecs/AMAZON_ECS_DEPLOYMENT.md)

### Using Azure Container Apps

Azure's ingress terminates TLS in front of the container. Store the key as a Container Apps secret
and expose it as `MCP_API_KEY`; MCP clients (for example a Microsoft Foundry agent) then send
`Authorization: Bearer <key>`.

```bash
#Prepare Environment Variables
PURPLEMCP_CONSOLE_BASE_URL=https://your-console.sentinelone.net
PURPLEMCP_CONSOLE_TOKEN=secretref:console-token
MCP_API_KEY=secretref:mcp-api-key
MCP_MODE=streamable-http
MCP_HOST=0.0.0.0
PURPLEMCP_STATELESS_HTTP=true
MCP_TOOL_ERRORS_AS_TEXT=true
```

Foundry Agent Service ends the agent run with `tool_user_error` whenever a tool result has
`isError: true`. `MCP_TOOL_ERRORS_AS_TEXT=true` returns those errors as ordinary `ERROR: ...` text
results instead, so the model can read the message, fix its arguments and retry. Leave it unset for
clients that handle `isError` themselves.

Point the ingress health probes at `GET /health` (no key needed) and the MCP client at
`https://<app>.<env>.<region>.azurecontainerapps.io/mcp`.

To let agents run [response actions](../README.md#response-actions-opt-in), add a separate token.
`PURPLEMCP_AGENT_CONFIRMABLE_ACTIONS` lists the actions an autonomous agent (for example a
webhook-driven Foundry agent with no human present) may confirm itself:

```bash
PURPLEMCP_ALLOW_WRITES=true
PURPLEMCP_RESPONSE_TOKEN=secretref:response-token
PURPLEMCP_AGENT_CONFIRMABLE_ACTIONS=initiate_agent_scan,disconnect_agents_from_network
```

This only changes the guidance in each preview: the agent still has to preview and confirm with
the token it gets back. It is not an approval mechanism. Enforce human approval for the riskier
actions (`mitigate_threats`, `update_threat_triage`) in Foundry's MCP tool approval settings, and
use `allowed_tools` to give each agent only the tools it needs.

### Cloud Native Setup

For more detailed cloud setup instructions, see [CLOUD_SETUP.md](cloud/CLOUD_SETUP.md).
