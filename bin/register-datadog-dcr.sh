#!/usr/bin/env bash
# Register an OAuth client with Datadog's MCP server via Dynamic Client Registration (RFC 7591).
#
# Datadog MCP (mcp.datadoghq.com) requires DCR — credentials cannot be created
# via the Datadog UI for the MCP OAuth server.
#
# Note: Datadog MCP requires PKCE (S256). AgentCore handles PKCE at runtime;
# no special handling is needed during client registration.
#
# Usage:
#   bin/register-datadog-dcr.sh                  # print credentials
#   bin/register-datadog-dcr.sh --env            # also append to .env
#   bin/register-datadog-dcr.sh --export         # print as export statements
#
# Prerequisites: curl, jq

set -euo pipefail

CLIENT_NAME="${CLIENT_NAME:-AgentCore Gateway}"
# Set MCP_HOST for non-US1 sites:
#   MCP_HOST=mcp.ap1.datadoghq.com bin/register-datadog-dcr.sh --export
MCP_HOST="${MCP_HOST:-mcp.ap1.datadoghq.com}"
REDIRECT_URI="${REDIRECT_URI:-https://placeholder.example.com/callback}"

REG_ENDPOINT="https://${MCP_HOST}/api/unstable/mcp-server/register"

echo "Registration endpoint: ${REG_ENDPOINT}" >&2
echo "redirect_uri: ${REDIRECT_URI}" >&2

# ── DCR ──

RESPONSE=$(curl -sf -X POST "$REG_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"${CLIENT_NAME}\",
    \"redirect_uris\": [\"${REDIRECT_URI}\"],
    \"grant_types\": [\"authorization_code\", \"refresh_token\"],
    \"response_types\": [\"code\"],
    \"token_endpoint_auth_method\": \"client_secret_post\",
    \"code_challenge_methods_supported\": [\"S256\"]
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
      echo "# Datadog MCP OAuth (registered via DCR on $(date -u +%Y-%m-%dT%H:%M:%SZ))"
      echo "DATADOG_OAUTH_CLIENT_ID=${CLIENT_ID}"
      [ -n "$CLIENT_SECRET" ] && echo "DATADOG_OAUTH_CLIENT_SECRET=${CLIENT_SECRET}"
    } >> "$ENV_FILE"
    echo "Appended to ${ENV_FILE}" >&2
    ;;
  --export)
    echo "export DATADOG_OAUTH_CLIENT_ID='${CLIENT_ID}'"
    [ -n "$CLIENT_SECRET" ] && echo "export DATADOG_OAUTH_CLIENT_SECRET='${CLIENT_SECRET}'"
    ;;
  *)
    echo ""
    echo "DATADOG_OAUTH_CLIENT_ID=${CLIENT_ID}"
    [ -n "$CLIENT_SECRET" ] && echo "DATADOG_OAUTH_CLIENT_SECRET=${CLIENT_SECRET}"
    echo ""
    echo "Set these before running 'pnpm deploy':" >&2
    echo "  export DATADOG_OAUTH_CLIENT_ID='${CLIENT_ID}'" >&2
    [ -n "$CLIENT_SECRET" ] && echo "  export DATADOG_OAUTH_CLIENT_SECRET='${CLIENT_SECRET}'" >&2
    echo "" >&2
    echo "Or use: eval \$(bin/register-datadog-dcr.sh --export)" >&2
    echo "" >&2
    echo "After first deploy, update redirect_uri:" >&2
    echo "  1. Get callback URL:" >&2
    echo "     aws bedrock-agentcore-control get-oauth2-credential-provider \\" >&2
    echo "       --name \$(aws cloudformation describe-stacks --stack-name GatewayStack \\" >&2
    echo "         --query 'Stacks[0].Outputs[?OutputKey==\`DatadogCredentialProviderName\`].OutputValue' \\" >&2
    echo "         --output text) --query callbackUrl --output text" >&2
    echo "  2. Re-register: REDIRECT_URI=<callback_url> bin/register-datadog-dcr.sh --export" >&2
    echo "  3. Re-deploy with new credentials" >&2
    ;;
esac
