# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Generic MCP OAuth Proxy Lambda.

Acts as an OAuth Authorization Server facade in front of an AgentCore Gateway,
enabling Claude Code (and other MCP clients) to authenticate via Cognito and
forward MCP requests to the gateway.

This Lambda handles:
  - OAuth metadata discovery (RFC 8414 / RFC 9728)
  - Dynamic Client Registration (DCR)
  - Authorization code flow (redirect to Cognito Hosted UI)
  - Token exchange (proxy to Cognito token endpoint)
  - MCP request forwarding to AgentCore Gateway

Environment variables:
  GATEWAY_URL        - AgentCore Gateway MCP endpoint URL
  COGNITO_DOMAIN     - Cognito Hosted UI domain (e.g. example.auth.us-east-1.amazoncognito.com)
  COGNITO_CLIENT_ID  - Cognito app client ID (public client, no secret)
  SESSION_TABLE_NAME - DynamoDB table for 3LO session→token mapping (optional)
"""

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

GATEWAY_URL = os.environ["GATEWAY_URL"]
COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"]
COGNITO_CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
SESSION_TABLE_NAME = os.environ.get("SESSION_TABLE_NAME", "")

# Allowed redirect_uri hosts for OAuth callback (prevent open redirect)
_ALLOWED_REDIRECT_HOSTS = {"127.0.0.1", "localhost"}


def lambda_handler(event, context):
    path = event.get("path", "") or event.get("rawPath", "/")
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method", "GET")
    )
    print(f"[REQ] {method} {path}")

    if method == "OPTIONS":
        return cors_ok()

    # ── OAuth metadata ──
    if path.startswith("/.well-known/oauth-authorization-server"):
        return handle_oauth_metadata(event)
    if path in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ):
        return handle_protected_resource_metadata(event)

    # ── OAuth flow ──
    if path == "/register" and method == "POST":
        return handle_dcr(event)
    if path == "/authorize":
        return handle_authorize(event)
    if path == "/callback":
        return handle_callback(event)
    if path == "/token" and method == "POST":
        return handle_token(event)

    # ── 3LO callback (CompleteResourceTokenAuth) ──
    if path == "/3lo-callback":
        return handle_3lo_callback(event)

    # ── Health check ──
    if path == "/ping":
        return json_response(200, {"status": "ok"})

    # ── Default: proxy MCP requests to AgentCore Gateway ──
    return proxy_to_gateway(event)


# ─── OAuth metadata endpoints ────────────────────────────────────────────────


def handle_oauth_metadata(event):
    """Serve OAuth Authorization Server Metadata (RFC 8414)."""
    api_url = get_api_url(event)
    return json_response(200, {
        "issuer": api_url,
        "authorization_endpoint": f"{api_url}/authorize",
        "token_endpoint": f"{api_url}/token",
        "registration_endpoint": f"{api_url}/register",
        "scopes_supported": ["openid", "email", "profile"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    })


def handle_protected_resource_metadata(event):
    """Serve OAuth Protected Resource Metadata (RFC 9728)."""
    api_url = get_api_url(event)
    return json_response(200, {
        "resource": f"{api_url}/mcp",
        "authorization_servers": [api_url],
        "bearer_methods_supported": ["header"],
    })


# ─── OAuth flow endpoints ────────────────────────────────────────────────────


def handle_dcr(event):
    """Dynamic Client Registration — return pre-registered Cognito client_id."""
    api_url = get_api_url(event)
    return json_response(200, {
        "client_id": COGNITO_CLIENT_ID,
        "client_name": "Claude Code MCP Client",
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": [f"{api_url}/callback"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })


def handle_authorize(event):
    """Redirect to Cognito Hosted UI with compound state encoding."""
    params = dict((event.get("queryStringParameters") or {}).items())
    api_url = get_api_url(event)

    # Encode original redirect_uri + state into compound state
    original_redirect_uri = params.pop("redirect_uri", "")
    original_state = params.pop("state", "")

    compound_state = base64.urlsafe_b64encode(
        json.dumps({
            "state": original_state,
            "redirect_uri": original_redirect_uri,
        }).encode()
    ).decode()

    params.update({
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": f"{api_url}/callback",
        "state": compound_state,
        "response_type": "code",
    })
    params.setdefault("scope", "openid email profile")

    cognito_url = (
        f"https://{COGNITO_DOMAIN}/oauth2/authorize?"
        f"{urllib.parse.urlencode(params)}"
    )
    return {"statusCode": 302, "headers": {"Location": cognito_url}, "body": ""}


def handle_callback(event):
    """Handle Cognito callback — forward authorization code to Claude Code."""
    params = event.get("queryStringParameters") or {}
    code = params.get("code", "")
    encoded_state = params.get("state", "")
    error = params.get("error", "")

    if error:
        return json_response(400, {"error": error})

    try:
        decoded = json.loads(
            base64.urlsafe_b64decode(encoded_state + "==").decode()
        )
        original_state = decoded.get("state", "")
        original_redirect_uri = decoded.get("redirect_uri", "")
    except Exception as e:
        print(f"[CALLBACK] State decode error: {e}")
        return json_response(400, {"error": "Invalid state parameter"})

    if not original_redirect_uri:
        return json_response(400, {"error": "Missing redirect_uri"})

    # Validate redirect_uri against allowlist to prevent open redirect
    try:
        parsed = urllib.parse.urlparse(original_redirect_uri)
        if parsed.hostname not in _ALLOWED_REDIRECT_HOSTS:
            print(f"[CALLBACK] Blocked redirect to disallowed host: {parsed.hostname}")
            return json_response(400, {"error": "Invalid redirect_uri"})
    except Exception:
        return json_response(400, {"error": "Invalid redirect_uri"})

    forward_params = urllib.parse.urlencode({
        "code": code,
        "state": original_state,
    })
    return {
        "statusCode": 302,
        "headers": {"Location": f"{original_redirect_uri}?{forward_params}"},
        "body": "",
    }


def handle_token(event):
    """Proxy token requests to Cognito token endpoint."""
    body = event.get("body", "")
    if event.get("isBase64Encoded") and body:
        body = base64.b64decode(body).decode()

    params = dict(urllib.parse.parse_qsl(body))
    api_url = get_api_url(event)

    # Rewrite redirect_uri to our callback
    if "redirect_uri" in params:
        params["redirect_uri"] = f"{api_url}/callback"

    # Force Cognito client_id
    params["client_id"] = COGNITO_CLIENT_ID

    data = urllib.parse.urlencode(params).encode()
    token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"

    req = urllib.request.Request(token_url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            token_data = json.loads(resp.read().decode())
            if "created_at" not in token_data:
                token_data["created_at"] = int(time.time() * 1000)
            return json_response(200, token_data)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[TOKEN] Cognito error {e.code}: {error_body}")
        # Return generic error to client; details are logged server-side
        return json_response(e.code, {"error": "token_exchange_failed"})


# ─── 3LO Callback (CompleteResourceTokenAuth) ───────────────────────────────


def handle_3lo_callback(event):
    """Complete the 3LO OAuth session binding via CompleteResourceTokenAuth.

    AgentCore redirects here after the IdP callback with session_id (and
    optionally user_id / user_token) as query parameters.

    The userIdentifier must match how the gateway identifies the user.
    With CUSTOM_JWT auth the gateway uses the JWT 'sub' claim; we accept
    either user_token (the Cognito access token) or user_id as query params.

    Reference: https://github.com/awslabs/agentcore-samples/issues/801
    """
    params = (event.get("queryStringParameters") or {})
    session_id = params.get("session_id")
    user_id = params.get("user_id")
    user_token = params.get("user_token")

    if not session_id:
        return html_response(400, "Missing session_id",
                             "The callback URL must include a session_id parameter.")

    region = os.environ.get("AWS_REGION", "us-east-1")
    api_url = f"https://bedrock-agentcore.{region}.amazonaws.com/identities/CompleteResourceTokenAuth"

    # Try to get cached token from DynamoDB
    cached_token = _get_cached_token(session_id)

    # Build userIdentifier — prefer cached/provided token over userId
    effective_token = user_token or cached_token
    if effective_token:
        user_identifier = {"userToken": effective_token}
    else:
        user_identifier = {"userId": user_id or "default-user"}
        print(f"[3LO-CALLBACK] WARNING: No token available, falling back to userId")

    body = json.dumps({
        "sessionUri": session_id,
        "userIdentifier": user_identifier,
    })

    print(f"[3LO-CALLBACK] sessionUri={session_id}")
    print(f"[3LO-CALLBACK] userIdentifier keys={list(user_identifier.keys())}")
    print(f"[3LO-CALLBACK] POST {api_url}")

    try:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.session import Session as BotocoreSession

        session = BotocoreSession()
        credentials = session.get_credentials().get_frozen_credentials()

        aws_request = AWSRequest(method="POST", url=api_url, data=body,
                                 headers={"Content-Type": "application/json"})
        SigV4Auth(credentials, "bedrock-agentcore", region).add_auth(aws_request)

        req = urllib.request.Request(api_url, data=body.encode(), method="POST")
        for k, v in dict(aws_request.headers).items():
            req.add_header(k, v)

        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode()
            print(f"[3LO-CALLBACK] CompleteResourceTokenAuth OK: {resp_body[:500]}")
            return html_response(200, "Authorization Complete!",
                                 "You can close this window and return to your agent session.")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[3LO-CALLBACK] CompleteResourceTokenAuth error {e.code}: {error_body}")
        return html_response(e.code, "Token exchange failed",
                             "Authorization could not be completed. Check server logs for details.")
    except Exception as exc:
        print(f"[3LO-CALLBACK] Error: {exc}")
        return html_response(500, "Token exchange failed",
                             "An unexpected error occurred. Check server logs for details.")


def html_response(code, title, detail):
    ok = code == 200
    color = "#28a745" if ok else "#dc3545"
    symbol = "&#10003;" if ok else "&#10007;"
    return {
        "statusCode": code,
        "headers": {"Content-Type": "text/html"},
        "body": (
            f"<!DOCTYPE html><html><head><title>{title}</title>"
            f"<style>body{{font-family:sans-serif;max-width:500px;margin:60px auto;text-align:center}}"
            f".t{{color:{color};font-size:1.4em}}code{{background:#f0f0f0;padding:2px 6px;word-break:break-all}}</style></head>"
            f"<body><p class='t'>{symbol} {title}</p><p><code>{detail}</code></p></body></html>"
        ),
    }


# ─── MCP Proxy ───────────────────────────────────────────────────────────────


def proxy_to_gateway(event):
    """Forward MCP requests to AgentCore Gateway."""
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method", "GET")
    )
    headers = event.get("headers") or {}
    body = event.get("body", "")
    if event.get("isBase64Encoded") and body:
        body = base64.b64decode(body)

    # Forward to gateway /mcp endpoint regardless of incoming path
    target_url = GATEWAY_URL

    req_headers = {
        "Content-Type": headers.get("content-type", "application/json"),
        "Accept": headers.get("accept", "application/json, text/event-stream"),
    }

    # Forward MCP headers from client
    for h in ("mcp-protocol-version", "mcp-session-id"):
        val = headers.get(h)
        if val:
            req_headers[h.title()] = val

    if method == "POST" and body:
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(target_url, data=data, method="POST")
    else:
        req = urllib.request.Request(target_url, method=method)

    for k, v in req_headers.items():
        req.add_header(k, v)

    auth = get_header(event, "Authorization")
    if auth:
        req.add_header("Authorization", auth)

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_body = resp.read().decode()
            print(f"[PROXY] Gateway {resp.status}: {resp_body[:500]}")

            # Cache user token when elicitation response detected
            _cache_elicitation_token(resp_body, auth)

            resp_headers = {
                "Content-Type": resp.headers.get("Content-Type", "application/json"),
            }
            session_id = resp.headers.get("Mcp-Session-Id")
            if session_id:
                resp_headers["Mcp-Session-Id"] = session_id
            return {
                "statusCode": resp.status,
                "headers": resp_headers,
                "body": resp_body,
            }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[PROXY] Gateway error {e.code}: {error_body[:500]}")
        resp_headers = {"Content-Type": "application/json"}
        session_id = e.headers.get("Mcp-Session-Id")
        if session_id:
            resp_headers["Mcp-Session-Id"] = session_id
        return {"statusCode": e.code, "headers": resp_headers, "body": error_body}
    except Exception as e:
        return json_response(502, {"error": {"code": -32603, "message": str(e)}})


# ─── Session Token Store (DynamoDB) ─────────────────────────────────────────

_dynamodb = None

def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _cache_elicitation_token(resp_body, auth_header):
    """Extract request_uri from elicitation response and store the user's JWT in DynamoDB."""
    if not auth_header or not SESSION_TABLE_NAME:
        return
    # Look for request_uri in the response body
    match = re.search(r'request_uri=(urn%3A[^&"\s]+|urn:[^&"\s]+)', resp_body)
    if not match:
        return

    request_uri = urllib.parse.unquote(match.group(1))
    token = auth_header.replace("Bearer ", "").replace("bearer ", "")

    try:
        table = _get_dynamodb().Table(SESSION_TABLE_NAME)
        table.put_item(Item={
            "sessionUri": request_uri,
            "userToken": token,
            "ttl": int(time.time()) + 600,  # 10 min TTL
        })
        print(f"[CACHE] Stored token in DynamoDB for session: {request_uri[:80]}...")
    except Exception as e:
        print(f"[CACHE] Failed to store token: {e}")


def _get_cached_token(session_uri):
    """Retrieve cached user token from DynamoDB."""
    if not SESSION_TABLE_NAME:
        return None
    try:
        table = _get_dynamodb().Table(SESSION_TABLE_NAME)
        resp = table.get_item(Key={"sessionUri": session_uri})
        item = resp.get("Item")
        if item:
            print(f"[CACHE] Found token in DynamoDB for session")
            return item.get("userToken")
    except Exception as e:
        print(f"[CACHE] Failed to get token: {e}")
    return None


# ─── Helpers ─────────────────────────────────────────────────────────────────


def get_header(event, name):
    """Case-insensitive header lookup."""
    headers = event.get("headers") or {}
    return (
        headers.get(name)
        or headers.get(name.lower())
        or headers.get(name.capitalize())
        or ""
    )


def get_api_url(event):
    """Extract API Gateway base URL from event."""
    ctx = event.get("requestContext", {})
    domain = ctx.get("domainName", "")
    stage = ctx.get("stage", "")
    if domain and stage and stage != "$default":
        return f"https://{domain}/{stage}"
    headers = event.get("headers") or {}
    host = headers.get("host") or headers.get("Host")
    if host:
        return f"https://{host}"
    if domain:
        return f"https://{domain}"
    return "http://localhost"


def json_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "http://localhost",
            "Access-Control-Allow-Headers": "Content-Type,Authorization,Mcp-Protocol-Version,Mcp-Session-Id",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body),
    }


def cors_ok():
    return {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": "http://localhost",
            "Access-Control-Allow-Headers": "Content-Type,Authorization,Mcp-Protocol-Version,Mcp-Session-Id",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": "",
    }
