#!/usr/bin/env python3
"""Manage MCP server targets outside of CloudFormation.

CloudFormation cannot handle MCP server targets with Authorization Code grant
because the target creation requires interactive OAuth consent from the gateway
owner (to discover tools via tools/list on the upstream MCP server).

This script bridges the gap:
  1. Reads GatewayStack outputs (gateway ID, credential provider ARNs)
  2. Creates/updates MCP server targets via the SDK
  3. Captures the authorization URL from the response
  4. Starts a local callback server and opens the browser for OAuth consent
  5. Completes session binding via CompleteResourceTokenAuth
  6. Polls until the target reaches READY
  7. Stores the target ID in SSM Parameter Store for idempotent re-runs

Usage:
    python bin/sync-mcp-targets.py create github
    python bin/sync-mcp-targets.py create notion
    python bin/sync-mcp-targets.py status github
    python bin/sync-mcp-targets.py delete github
    python bin/sync-mcp-targets.py list
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import sys
import threading
import time
import urllib.parse
import webbrowser

import boto3

REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
STACK_NAME = os.environ.get("STACK_NAME", "GatewayStack")
CALLBACK_PORT = int(os.environ.get("CALLBACK_PORT", "18080"))
CALLBACK_URL = f"http://localhost:{CALLBACK_PORT}/callback"
SESSION_TABLE_NAME = f"3lo-sessions-{STACK_NAME}"

SSM_PREFIX = f"/gateway/{STACK_NAME}/targets"

SERVICES = {
    "github": {
        "endpoint": "https://api.githubcopilot.com/mcp/",
        "scopes": ["repo", "read:org", "read:user", "user:email"],
        "provider_output": "GitHubCredentialProviderArn",
    },
    "notion": {
        "endpoint": "https://mcp.notion.com/mcp",
        "scopes": [],
        "provider_output": "NotionCredentialProviderArn",
    },
    "slack": {
        # Routed through the proxy's /slack-mcp handler (not directly to
        # mcp.slack.com) to shim resources/templates/list. See
        # handle_slack_mcp in mcp_oauth_proxy.py for details.
        # Endpoint is composed at runtime from the GatewayStack's ProxyUrl.
        "endpoint": "{ProxyUrl}/slack-mcp/mcp",
        "scopes": [
            "search:read.public", "search:read.private",
            "search:read.mpim", "search:read.im",
            "search:read.files", "search:read.users",
            "chat:write",
            "channels:history", "groups:history",
            "mpim:history", "im:history",
            "canvases:read", "canvases:write",
            "users:read", "users:read.email",
        ],
        "provider_output": "SlackCredentialProviderArn",
    },
    "github-bot": {
        # Machine-to-machine GitHub MCP access. The gateway calls the proxy's
        # IAM-protected /github-mcp route (SigV4 via its service role), and the
        # proxy injects `Authorization: Bearer <PAT>` from Secrets Manager
        # (GitHubBotPatSecretArn). IAM auth ensures only the gateway can reach
        # the PAT-injecting route. See handle_github_mcp in mcp_oauth_proxy.py.
        "endpoint": "{ProxyUrl}/github-mcp/mcp",
        "scopes": [],
        "auth": "iam",
        "provider_output": None,  # IAM outbound: no credential provider ARN
    },
    "datadog": {
        # Datadog MCP (AP1 site). Public client — no client_secret (PKCE-only).
        # Register via: MCP_HOST=mcp.ap1.datadoghq.com bin/register-datadog-dcr.sh --export
        # For other sites set DATADOG_MCP_HOST env var and update endpoint accordingly.
        "endpoint": os.environ.get(
            "DATADOG_MCP_ENDPOINT",
            "https://mcp.ap1.datadoghq.com/api/unstable/mcp-server/mcp",
        ),
        # Datadog MCP has scopes_supported:[] — the proxy's /datadog-authorize
        # route strips any scope= param before forwarding to Datadog.
        "scopes": [],
        "provider_output": "DatadogCredentialProviderArn",
    },
}


def _cfn():
    return boto3.client("cloudformation", region_name=REGION)


def _agentcore_cp():
    return boto3.client("bedrock-agentcore-control", region_name=REGION)


def _agentcore():
    return boto3.client("bedrock-agentcore", region_name=REGION)


def _ssm():
    return boto3.client("ssm", region_name=REGION)


def _get_stack_outputs() -> dict[str, str]:
    resp = _cfn().describe_stacks(StackName=STACK_NAME)
    outputs = resp["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _ssm_get(key: str) -> str | None:
    try:
        return _ssm().get_parameter(Name=f"{SSM_PREFIX}/{key}")["Parameter"]["Value"]
    except _ssm().exceptions.ParameterNotFound:
        return None


def _ssm_put(key: str, value: str) -> None:
    _ssm().put_parameter(Name=f"{SSM_PREFIX}/{key}", Value=value, Type="String", Overwrite=True)


def _dynamodb():
    return boto3.resource("dynamodb", region_name=REGION)


def _seed_admin_session(authorization_url: str, admin_user_id: str) -> None:
    """Pre-seed DynamoDB so the proxy's /3lo-callback can bind the admin
    session without needing a Cognito JWT (admin auth uses userId, not userToken).
    """
    parsed = urllib.parse.urlparse(authorization_url)
    qs = urllib.parse.parse_qs(parsed.query)
    request_uri_raw = (qs.get("request_uri") or [None])[0]
    if not request_uri_raw:
        print("  (admin session seed skipped: no request_uri in authorizationUrl)")
        return
    request_uri = urllib.parse.unquote(request_uri_raw)
    now = int(time.time())
    try:
        table = _dynamodb().Table(SESSION_TABLE_NAME)
        table.put_item(Item={
            "sessionUri": request_uri,
            "userId": admin_user_id,
            "cachedAt": now,
            "ttl": now + 600,
        })
        print(f"  seeded admin session in DynamoDB: {request_uri[:80]}")
    except Exception as e:
        print(f"  WARNING: failed to seed admin session in DynamoDB: {e}")


def _ssm_delete(key: str) -> None:
    try:
        _ssm().delete_parameter(Name=f"{SSM_PREFIX}/{key}")
    except Exception:
        pass


def _wait_for_callback(user_id: str) -> bool:
    """Start a local HTTP server that catches the OAuth callback and calls
    CompleteResourceTokenAuth, then returns."""
    result = {"done": False, "ok": False}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            session_uri = (params.get("session_id") or [None])[0]
            if parsed.path != "/callback" or not session_uri:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing session_id")
                return

            try:
                _agentcore().complete_resource_token_auth(
                    userIdentifier={"userId": user_id},
                    sessionUri=session_uri,
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<h1>Authorization complete</h1><p>You can close this tab.</p>")
                result["ok"] = True
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"<h1>Error</h1><p>{e}</p>".encode())
            finally:
                result["done"] = True

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("", CALLBACK_PORT), Handler)
    server.timeout = 300  # 5 min max

    while not result["done"]:
        server.handle_request()

    server.server_close()
    return result["ok"]


def _poll_target(gateway_id: str, target_id: str, timeout: int = 120) -> str:
    """Poll get_gateway_target until status is terminal."""
    cp = _agentcore_cp()
    terminal = {"READY", "FAILED", "SYNCHRONIZE_UNSUCCESSFUL", "UPDATE_UNSUCCESSFUL"}
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = cp.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        status = resp.get("status", "UNKNOWN")
        print(f"  target {target_id}: {status}")
        if status in terminal:
            return status
        time.sleep(5)
    return "TIMEOUT"


# ── Commands ──

def cmd_create(service: str) -> None:
    svc = SERVICES[service]
    outputs = _get_stack_outputs()
    gateway_id = outputs["GatewayId"]
    no_auth = svc["provider_output"] is None
    provider_arn = None if no_auth else outputs.get(svc["provider_output"])

    if not no_auth and not provider_arn:
        print(f"Error: {svc['provider_output']} not found in stack outputs.")
        print(f"Did you set the {service} OAuth client ID/secret in parameter.ts?")
        sys.exit(1)

    existing_id = _ssm_get(f"{service}/targetId")
    if existing_id:
        print(f"Target already exists: {existing_id}. Use 'status' or 'delete' first.")
        return

    proxy_url = outputs.get("ProxyUrl", "")
    if not proxy_url:
        print("Error: ProxyUrl not found in stack outputs. Deploy GatewayStack first.")
        sys.exit(1)

    cp = _agentcore_cp()
    target_name = f"{service}-mcp-{STACK_NAME}"

    # defaultReturnUrl: the proxy's /3lo-callback handles end-user
    # authorization. When an MCP client (e.g. Claude Code) first invokes a
    # tool on this target, the gateway returns an elicitation response; the
    # proxy caches the caller's JWT, and on the callback binds the session
    # with CompleteResourceTokenAuth(userIdentifier={userToken:...}).
    # No local server / browser bootstrap is needed.
    return_url = f"{proxy_url}/3lo-callback"
    endpoint = svc["endpoint"].format(ProxyUrl=proxy_url)
    print(f"Creating MCP target: {target_name}")
    print(f"  endpoint: {endpoint}")
    create_kwargs = {
        "gatewayIdentifier": gateway_id,
        "name": target_name,
        "description": f"{service.title()} MCP server target (managed by sync-mcp-targets.py)",
        "targetConfiguration": {"mcp": {"mcpServer": {"endpoint": endpoint}}},
    }
    if svc.get("auth") == "iam":
        # IAM (SigV4) outbound: the gateway signs calls to the IAM-protected
        # /github-mcp proxy route with its service role, so only the gateway can
        # reach it. The proxy then injects the bot PAT toward GitHub MCP.
        print("  authorization: IAM (gateway service role SigV4, execute-api)")
        create_kwargs["credentialProviderConfigurations"] = [{
            "credentialProviderType": "GATEWAY_IAM_ROLE",
            "credentialProvider": {
                "iamCredentialProvider": {"service": "execute-api"},
            },
        }]
    elif no_auth:
        print("  authorization: No-auth")
    else:
        print(f"  defaultReturnUrl: {return_url}")
        create_kwargs["credentialProviderConfigurations"] = [{
            "credentialProviderType": "OAUTH",
            "credentialProvider": {
                "oauthCredentialProvider": {
                    "providerArn": provider_arn,
                    "grantType": "AUTHORIZATION_CODE",
                    "defaultReturnUrl": return_url,
                    "scopes": svc["scopes"],
                },
            },
        }]
    resp = cp.create_gateway_target(**create_kwargs)

    target_id = resp["targetId"]
    status = resp.get("status", "UNKNOWN")
    print(f"Target created: {target_id} (status: {status})")

    # Dump full create_gateway_target response for debugging (auth URL, userId, etc.)
    debug_path = f"/tmp/sync-mcp-targets-{service}-create.json"
    try:
        with open(debug_path, "w") as f:
            json.dump(resp, f, indent=2, default=str)
        print(f"  full response: {debug_path}")
    except Exception as e:
        print(f"  (failed to write debug dump: {e})")

    _ssm_put(f"{service}/targetId", target_id)
    _ssm_put(f"{service}/targetName", target_name)

    if no_auth:
        # github-bot: the PAT is seeded at deploy (GITHUB_BOT_PAT). During
        # creation the gateway runs tools/list discovery via SigV4 against the
        # IAM-protected /github-mcp route, so a valid PAT must already be set.
        print()
        print(f"Target created (status={status}).")
        print("If status is not READY, verify GITHUB_BOT_PAT is valid and redeploy GatewayStack.")
    else:
        auth_data = resp.get("authorizationData", {}).get("oauth2", {})
        auth_url = auth_data.get("authorizationUrl")
        admin_user_id = auth_data.get("userId")

        if auth_url and admin_user_id and status == "CREATE_PENDING_AUTH":
            # AgentCore returned an admin auth URL — the gateway owner must
            # authorize once to enable tool discovery. Pre-seed DynamoDB so the
            # proxy's /3lo-callback uses the correct userId (not "default-user").
            _seed_admin_session(auth_url, admin_user_id)
            print()
            print("Admin authorization required to complete target setup.")
            print("Open this URL in your browser (valid for ~10 minutes):")
            print(f"  {auth_url}")
            print()
            print("After authorizing, this script will poll until the target is READY.")
            print("Press Ctrl+C to exit and poll manually with: python bin/sync-mcp-targets.py status " + service)
            webbrowser.open(auth_url)
            final_status = _poll_target(gateway_id, target_id, timeout=600)
            if final_status == "READY":
                print(f"Target {target_id} is READY.")
            else:
                print(f"Target {target_id} ended in status: {final_status}")
                print("If still pending, retry authorization or check Lambda logs.")
        else:
            # No admin auth URL in response — end-user authorization happens
            # lazily via the MCP elicitation flow when the first tool call is made.
            print()
            print(f"Target is pending end-user authorization (status={status}).")
            print(f"To complete setup, invoke any {service} tool from an MCP client")
            print(f"(Claude Code, etc.). The client will receive an elicitation")
            print(f"prompting the user to authorize {service}; the proxy's")
            print(f"/3lo-callback endpoint handles session binding automatically.")


def cmd_status(service: str) -> None:
    outputs = _get_stack_outputs()
    gateway_id = outputs["GatewayId"]
    target_id = _ssm_get(f"{service}/targetId")

    if not target_id:
        print(f"No target found for {service}. Run 'create' first.")
        return

    cp = _agentcore_cp()
    resp = cp.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    print(json.dumps({
        "targetId": resp["targetId"],
        "name": resp["name"],
        "status": resp["status"],
        "statusReasons": resp.get("statusReasons", []),
    }, indent=2, default=str))


def cmd_delete(service: str) -> None:
    outputs = _get_stack_outputs()
    gateway_id = outputs["GatewayId"]
    target_id = _ssm_get(f"{service}/targetId")

    if not target_id:
        print(f"No target found for {service}.")
        return

    cp = _agentcore_cp()
    print(f"Deleting target {target_id}...")
    cp.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)

    _ssm_delete(f"{service}/targetId")
    _ssm_delete(f"{service}/targetName")
    print("Deleted.")


def cmd_list() -> None:
    outputs = _get_stack_outputs()
    gateway_id = outputs["GatewayId"]
    cp = _agentcore_cp()
    resp = cp.list_gateway_targets(gatewayIdentifier=gateway_id, maxResults=100)
    for item in resp.get("items", []):
        print(f"  {item['targetId']}  {item['name']}  {item['status']}")


def main():
    parser = argparse.ArgumentParser(description="Manage MCP server targets")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a MCP server target with interactive OAuth")
    p_create.add_argument("service", choices=list(SERVICES.keys()))

    p_status = sub.add_parser("status", help="Get target status")
    p_status.add_argument("service", choices=list(SERVICES.keys()))

    p_delete = sub.add_parser("delete", help="Delete a target")
    p_delete.add_argument("service", choices=list(SERVICES.keys()))

    sub.add_parser("list", help="List all targets on the gateway")

    args = parser.parse_args()

    if args.command == "create":
        cmd_create(args.service)
    elif args.command == "status":
        cmd_status(args.service)
    elif args.command == "delete":
        cmd_delete(args.service)
    elif args.command == "list":
        cmd_list()


if __name__ == "__main__":
    main()
