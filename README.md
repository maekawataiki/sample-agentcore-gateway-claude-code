# Remote MCP Gateway CDK

Amazon Bedrock AgentCore Gateway for Claude Code MCP integration.
Single gateway with multiple targets (GitHub, Notion, Redash) — one Cognito login covers all tools.

## Why a Single Gateway

When AI agents call external APIs directly, credentials scatter, access control fragments, and audit becomes hard. A single AgentCore Gateway solves this:

- **Credential isolation** — The agent never holds OAuth tokens or API keys. Tokens stay in Token Vault; API keys stay in DynamoDB + Interceptor Lambda. A compromised agent cannot reach external credentials.
- **Unified audit trail** — Every call to GitHub, Notion, Redash flows through one gateway. Who called what, when, and with which parameters is logged in one place (CloudTrail / CloudWatch Logs).
- **Single login** — One Cognito authentication covers all SaaS targets. No per-service login.
- **Zero agent-side config changes** — Adding a new SaaS target means adding a gateway target, not touching `.mcp.json`.

## Architecture

![Architecture](docs/architecture.drawio.png)

- **3LO OAuth Flow** (GitHub / Notion): Claude Code → OAuth Proxy → Cognito → AgentCore Gateway → Token Vault → External API
- **API Key Swap Flow** (Redash): Claude Code → OAuth Proxy → AgentCore Gateway → REQUEST Interceptor (DynamoDB lookup) → External API

### Operation Flow

![Operation Flow](docs/flow.png)

- **Step 1**: Inbound Auth — Cognito login via OAuth Proxy
- **Step 2-a**: Outbound 3LO Auth — GitHub/Notion OAuth consent via Token Vault
- **Step 2-b**: API Key Exchange — Redash API Key injected transparently by REQUEST Interceptor

### Stacks

| Stack | Description |
|-------|-------------|
| `CognitoStack` | Shared Cognito User Pool + App Client (us-east-1) |
| `GatewayStack` | Unified Gateway + all targets + OAuth Proxy |

## Prerequisites

- AWS CDK v2, Node.js 18+
- An AWS account with Bedrock AgentCore access (us-east-1)
- GitHub OAuth App (optional)
- Notion Integration with OAuth (optional)

## Deployment

### 1. Set OAuth secrets (optional, enables 3LO targets)

```bash
export GITHUB_OAUTH_CLIENT_ID="..."
export GITHUB_OAUTH_CLIENT_SECRET="..."
export NOTION_OAUTH_CLIENT_ID="..."
export NOTION_OAUTH_CLIENT_SECRET="..."
```

### 2. Deploy

```bash
cd cdk
npm install
npx cdk deploy --all --require-approval never
```

### 3. Create a Cognito user

```bash
USER_POOL_ID=$(aws cloudformation describe-stacks --stack-name CognitoStack \
  --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' --output text)

aws cognito-idp admin-create-user \
  --user-pool-id $USER_POOL_ID \
  --username your-email@example.com \
  --user-attributes Name=email,Value=your-email@example.com Name=email_verified,Value=true \
  --temporary-password 'TempPassword123!' \
  --message-action SUPPRESS

aws cognito-idp admin-set-user-password \
  --user-pool-id $USER_POOL_ID \
  --username your-email@example.com \
  --password 'YourSecurePassword123!' \
  --permanent
```

### 4. Set OAuth App callback URLs

After deploy, get the credential provider callback URLs:

```bash
# GitHub
aws bedrock-agentcore-control get-oauth2-credential-provider \
  --name $(aws cloudformation describe-stacks --stack-name GatewayStack \
    --query 'Stacks[0].Outputs[?OutputKey==`GitHubCredentialProviderName`].OutputValue' --output text) \
  --query callbackUrl --output text

# Notion
aws bedrock-agentcore-control get-oauth2-credential-provider \
  --name $(aws cloudformation describe-stacks --stack-name GatewayStack \
    --query 'Stacks[0].Outputs[?OutputKey==`NotionCredentialProviderName`].OutputValue' --output text) \
  --query callbackUrl --output text
```

Set these URLs in your OAuth App settings:
- **GitHub**: Settings > Developer settings > OAuth Apps > Authorization callback URL
- **Notion**: My Integrations > OAuth > Redirect URI

> These URLs change when the credential provider is recreated (stack delete + create).

### 5. Configure `.mcp.json`

```bash
# Get the values
MCP_URL=$(aws cloudformation describe-stacks --stack-name GatewayStack \
  --query 'Stacks[0].Outputs[?OutputKey==`McpUrl`].OutputValue' --output text)
CLIENT_ID=$(aws cloudformation describe-stacks --stack-name CognitoStack \
  --query 'Stacks[0].Outputs[?OutputKey==`AppClientId`].OutputValue' --output text)

echo "MCP URL: $MCP_URL"
echo "Client ID: $CLIENT_ID"
```

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "remote-mcp": {
      "type": "http",
      "url": "<MCP_URL>",
      "oauth": {
        "clientId": "<CLIENT_ID>",
        "callbackPort": 9090
      }
    }
  }
}
```

One entry covers all tools (GitHub, Notion, Redash).

### 6. Update gateway target `defaultReturnUrl` (3LO only)

The 3LO targets are created with a placeholder `defaultReturnUrl`.
After deploy, update them to point to the proxy's `/3lo-callback` endpoint:

```bash
GATEWAY_ID=$(aws cloudformation describe-stacks --stack-name GatewayStack \
  --query 'Stacks[0].Outputs[?OutputKey==`GatewayId`].OutputValue' --output text)
PROXY_URL=$(aws cloudformation describe-stacks --stack-name GatewayStack \
  --query 'Stacks[0].Outputs[?OutputKey==`ProxyUrl`].OutputValue' --output text)

# List targets
aws bedrock-agentcore-control list-gateway-targets \
  --gateway-identifier $GATEWAY_ID \
  --query 'targets[].{name:name,targetId:targetId}' --output table

# For each 3LO target (github/notion), update defaultReturnUrl:
aws bedrock-agentcore-control update-gateway-target \
  --gateway-identifier $GATEWAY_ID \
  --target-id <TARGET_ID> \
  --name <TARGET_NAME> \
  --target-configuration '{"mcp":{"openApiSchema":{"inlinePayload":"..."}}}' \
  --credential-provider-configurations '[{
    "credentialProviderType": "OAUTH",
    "credentialProvider": {
      "oauthCredentialProvider": {
        "providerArn": "<PROVIDER_ARN>",
        "grantType": "AUTHORIZATION_CODE",
        "defaultReturnUrl": "'$PROXY_URL'/3lo-callback",
        "scopes": [...]
      }
    }
  }]'
```

## Key Files

| File | Description |
|------|-------------|
| `cdk/bin/mcp-3lo-runtime-stack.ts` | CDK app entry point |
| `cdk/bin/parameter.ts` | Deployment parameters |
| `cdk/lib/cognito-stack.ts` | Shared Cognito User Pool |
| `cdk/lib/gateway-stack.ts` | Unified Gateway + all targets + OAuth Proxy |
| `cdk/lib/constructs-3lo/` | 3LO credential provider constructs (GitHub, Notion) |
| `cdk/lib/constructs-apikey/` | API Key Swap constructs (DynamoDB, interceptor, Redash) |
| `cdk/lib/constructs/` | Shared constructs (Cognito callback registration) |
| `cdk/lambda/mcp_oauth_proxy.py` | OAuth proxy Lambda |
| `cdk/lambda/notion_elicitation_interceptor.py` | Response interceptor (passthrough) |
| `cdk/lambda/apikey_request_interceptor/` | API Key injection interceptor |
| `cdk/openapi/github-api.yaml` | GitHub API OpenAPI spec |
| `cdk/openapi/notion-api.yaml` | Notion API OpenAPI spec |
| `cdk/openapi/redash-api.yaml` | Redash API OpenAPI spec |

## Troubleshooting

### "Invalid or expired session" on 3LO callback
- Check DynamoDB session table (TTL: 10 min)
- Verify `defaultReturnUrl` points to `<PROXY_URL>/3lo-callback`
- Ensure the proxy Lambda has `secretsmanager:GetSecretValue` permission

### "invalid_scope" from Cognito
- AgentCore Gateway requests all OIDC scopes from Cognito discovery (including `phone`)
- The CDK Cognito stack includes all scopes; if using external Cognito, add `phone` scope

### "redirect_mismatch" from Cognito
- The proxy's `/callback` URL must be in Cognito's allowed callback URLs
- The CDK stack auto-registers this via a Custom Resource

### Credential provider callback URL changed
- Happens when the credential provider is recreated (stack delete + create)
- Update the OAuth App callback URL from the stack output `GitHubOAuthCallbackUrl` / `NotionOAuthCallbackUrl`

### Auth link not displayed in Claude Code
- The response interceptor must pass through `-32042` responses unchanged
- MCP protocol version must be `2025-11-25`

## License

MIT License
