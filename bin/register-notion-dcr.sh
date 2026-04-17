#!/usr/bin/env bash
# Register an OAuth client with Notion's MCP server via Dynamic Client Registration (RFC 7591).
#
# Notion's MCP server (mcp.notion.com) is a separate OAuth 2.1 authorization server
# from the Notion API (api.notion.com). Credentials MUST be obtained via DCR against
# mcp.notion.com — the Notion Developer Dashboard (My Integrations) issues credentials
# for api.notion.com only and will NOT work.
#
# Usage:
#   bin/register-notion-dcr.sh                  # print credentials
#   bin/register-notion-dcr.sh --env            # also append to .env
#   bin/register-notion-dcr.sh --export         # print as export statements
#
# Prerequisites: curl, jq

set -euo pipefail

MCP_SERVER="https://mcp.notion.com/mcp"
CLIENT_NAME="${CLIENT_NAME:-AgentCore Gateway}"
# Placeholder — replaced with the real AgentCore callback URL after first deploy.
REDIRECT_URI="${REDIRECT_URI:-https://placeholder.example.com/callback}"

# ── Discovery ──

echo "Discovering OAuth endpoints from ${MCP_SERVER}..." >&2

# RFC 9728: Protected Resource Metadata URL uses path-suffix format:
#   https://host/.well-known/oauth-protected-resource/path
# For mcp.notion.com/mcp → https://mcp.notion.com/.well-known/oauth-protected-resource/mcp
# We also try the WWW-Authenticate header as a fallback.
MCP_PATH="${MCP_SERVER#https://}"  # e.g. mcp.notion.com/mcp
MCP_HOST="${MCP_PATH%%/*}"         # e.g. mcp.notion.com
MCP_SUFFIX="${MCP_PATH#*/}"        # e.g. mcp

PRM_URL="https://${MCP_HOST}/.well-known/oauth-protected-resource/${MCP_SUFFIX}"

PROTECTED_RESOURCE=$(curl -sf "$PRM_URL") || {
  # Fallback: parse resource_metadata from WWW-Authenticate header
  PRM_URL=$(curl -s -D- -o /dev/null "${MCP_SERVER}" 2>&1 \
    | grep -oi 'resource_metadata="[^"]*"' | head -1 | sed 's/resource_metadata="//;s/"$//')
  if [ -n "$PRM_URL" ]; then
    PROTECTED_RESOURCE=$(curl -sf "$PRM_URL") || { echo "Error: Failed to fetch protected resource metadata" >&2; exit 1; }
  else
    echo "Error: Failed to fetch protected resource metadata" >&2; exit 1
  fi
}

AUTH_SERVER=$(echo "$PROTECTED_RESOURCE" | jq -r '.authorization_servers[0]')
if [ -z "$AUTH_SERVER" ] || [ "$AUTH_SERVER" = "null" ]; then
  echo "Error: No authorization server found in protected resource metadata" >&2; exit 1
fi

AS_METADATA=$(curl -sf "${AUTH_SERVER}/.well-known/oauth-authorization-server") || {
  echo "Error: Failed to fetch authorization server metadata from ${AUTH_SERVER}" >&2; exit 1
}

REG_ENDPOINT=$(echo "$AS_METADATA" | jq -r '.registration_endpoint')
if [ -z "$REG_ENDPOINT" ] || [ "$REG_ENDPOINT" = "null" ]; then
  echo "Error: No registration_endpoint in authorization server metadata" >&2; exit 1
fi

echo "Registration endpoint: ${REG_ENDPOINT}" >&2

# ── DCR ──

RESPONSE=$(curl -sf -X POST "$REG_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"${CLIENT_NAME}\",
    \"redirect_uris\": [\"${REDIRECT_URI}\"],
    \"grant_types\": [\"authorization_code\", \"refresh_token\"],
    \"response_types\": [\"code\"],
    \"token_endpoint_auth_method\": \"client_secret_basic\"
  }") || {
  echo "Error: DCR request failed" >&2; exit 1
}

CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret // empty')

if [ -z "$CLIENT_ID" ] || [ "$CLIENT_ID" = "null" ]; then
  echo "Error: No client_id in DCR response:" >&2
  echo "$RESPONSE" | jq . >&2
  exit 1
fi

echo "" >&2
echo "Registration successful." >&2

# ── Output ──

case "${1:-}" in
  --env)
    ENV_FILE="${2:-.env}"
    {
      echo ""
      echo "# Notion MCP OAuth (registered via DCR on $(date -u +%Y-%m-%dT%H:%M:%SZ))"
      echo "NOTION_OAUTH_CLIENT_ID=${CLIENT_ID}"
      [ -n "$CLIENT_SECRET" ] && echo "NOTION_OAUTH_CLIENT_SECRET=${CLIENT_SECRET}"
    } >> "$ENV_FILE"
    echo "Appended to ${ENV_FILE}" >&2
    ;;
  --export)
    echo "export NOTION_OAUTH_CLIENT_ID='${CLIENT_ID}'"
    [ -n "$CLIENT_SECRET" ] && echo "export NOTION_OAUTH_CLIENT_SECRET='${CLIENT_SECRET}'"
    ;;
  *)
    echo ""
    echo "NOTION_OAUTH_CLIENT_ID=${CLIENT_ID}"
    [ -n "$CLIENT_SECRET" ] && echo "NOTION_OAUTH_CLIENT_SECRET=${CLIENT_SECRET}"
    echo ""
    echo "Set these before running 'pnpm deploy':" >&2
    echo "  export NOTION_OAUTH_CLIENT_ID='${CLIENT_ID}'" >&2
    [ -n "$CLIENT_SECRET" ] && echo "  export NOTION_OAUTH_CLIENT_SECRET='${CLIENT_SECRET}'" >&2
    echo "" >&2
    echo "Or use: eval \$(bin/register-notion-dcr.sh --export)" >&2
    ;;
esac
