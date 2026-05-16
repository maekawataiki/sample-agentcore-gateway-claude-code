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
"""

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import boto3

GATEWAY_URL = os.environ["GATEWAY_URL"]
COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"]
COGNITO_CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
SESSION_TABLE_NAME = os.environ.get("SESSION_TABLE_NAME", "")
GITHUB_BOT_PAT_SECRET_ARN = os.environ.get("GITHUB_BOT_PAT_SECRET_ARN", "")

# Allowed redirect_uri hosts for OAuth callback (prevent open redirect)
_ALLOWED_REDIRECT_HOSTS = {"127.0.0.1", "localhost"}


# ─── Structured audit logging ──────────────────────────────────────────────


def _extract_sub_from_jwt(auth_header):
    """Extract 'sub' claim from JWT without verification (for logging only)."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ", 1)[1]
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.b64decode(payload))
        return claims.get("sub") or claims.get("username")
    except Exception:
        return None


def audit_log(*, action, correlation_id, caller=None, path=None, status=None, detail=None):
    """Emit a structured JSON audit log entry."""
    entry = {
        "audit": True,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "correlationId": correlation_id,
        "action": action,
    }
    if caller:
        entry["caller"] = caller
    if path:
        entry["path"] = path
    if status is not None:
        entry["status"] = status
    if detail:
        entry["detail"] = detail
    print(json.dumps(entry, separators=(",", ":")))


def lambda_handler(event, context):
    path = event.get("path", "") or event.get("rawPath", "/")
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method", "GET")
    )
    # Correlation ID: use API Gateway request ID if available, else generate one
    correlation_id = (
        event.get("requestContext", {}).get("requestId")
        or str(uuid.uuid4())
    )
    # Extract caller identity for audit
    auth_header = get_header(event, "Authorization")
    caller = _extract_sub_from_jwt(auth_header)
    source_ip = (
        event.get("requestContext", {}).get("http", {}).get("sourceIp")
        or event.get("requestContext", {}).get("identity", {}).get("sourceIp")
    )

    audit_log(
        action="request",
        correlation_id=correlation_id,
        caller=caller,
        path=f"{method} {path}",
        detail=f"sourceIp={source_ip}" if source_ip else None,
    )

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

    # ── Slack MCP relay (AgentCore strict-mode workaround) ──
    # AgentCore marks the target FAILED when an MCP server returns -32601
    # (Method not found) for `resources/templates/list`, which Slack MCP does
    # because the method is optional in the spec. We intercept that one
    # method and synthesize an empty result; everything else passes through.
    if path.startswith("/slack-mcp"):
        return handle_slack_mcp(event)

    # ── GitHub MCP relay (PAT injection for machine-to-machine bots) ──
    # GitHub remote MCP only accepts OAuth (3LO) or PAT — there is no 2LO
    # path. For bot workloads we point the gateway target at this proxy
    # with No-auth and inject `Authorization: Bearer <PAT>` here, sourced
    # from Secrets Manager.
    if path.startswith("/github-mcp"):
        return handle_github_mcp(event)

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


# ─── 3LO Callback ───────────────────────────────────────────────────────────


def handle_3lo_callback(event):
    """Bind the AgentCore session via CompleteResourceTokenAuth using a
    Cognito JWT cached at elicitation-response time and keyed by the PAR
    request_uri returned in the elicitation body.
    """
    correlation_id = event.get("requestContext", {}).get("requestId", "")
    params = event.get("queryStringParameters") or {}
    session_id = params.get("session_id", "")
    error_param = params.get("error")
    src_ip = (
        event.get("requestContext", {}).get("http", {}).get("sourceIp")
        or event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        or ""
    )

    if session_id:
        from urllib.parse import unquote
        session_id = unquote(session_id)

    print(f"[3LO-CALLBACK] query params: {json.dumps(params)}")

    if error_param:
        audit_log(
            action="3lo_callback",
            correlation_id=correlation_id,
            status=400,
            detail=f"upstream_error={error_param}",
        )
        return html_response(
            400,
            "Authorization Failed",
            f"The upstream provider returned an error: {error_param}.",
        )

    if not session_id:
        audit_log(action="3lo_callback", correlation_id=correlation_id, status=400, detail="missing session_id")
        return html_response(400, "Missing session_id",
                             "The callback URL must include a session_id parameter.")

    # Look up the caller JWT cached at elicitation-response interception
    # time, keyed by the session URN in this callback.
    user_token = _get_cached_token(session_id)
    if user_token:
        user_identifier = {"userToken": user_token}
        identifier_type = "userToken"
    else:
        user_identifier = {"userId": "default-user"}
        identifier_type = "userId(fallback)"
        print("[3LO-CALLBACK] WARNING: no cached token; falling back to userId")

    region = os.environ.get("AWS_REGION", "us-east-1")
    api_url = f"https://bedrock-agentcore.{region}.amazonaws.com/identities/CompleteResourceTokenAuth"

    body = json.dumps({
        "sessionUri": session_id,
        "userIdentifier": user_identifier,
    })

    audit_log(
        action="3lo_callback",
        correlation_id=correlation_id,
        detail=f"sessionUri={session_id[:60]}... identifierType={identifier_type}",
    )

    try:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.session import Session as BotocoreSession

        session = BotocoreSession()
        credentials = session.get_credentials().get_frozen_credentials()

        aws_request = AWSRequest(
            method="POST",
            url=api_url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        SigV4Auth(credentials, "bedrock-agentcore", region).add_auth(aws_request)

        req = urllib.request.Request(api_url, data=body.encode(), method="POST")
        for k, v in dict(aws_request.headers).items():
            req.add_header(k, v)

        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
            audit_log(
                action="3lo_callback",
                correlation_id=correlation_id,
                status=200,
                detail="CompleteResourceTokenAuth OK",
            )
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[3LO-CALLBACK] CompleteResourceTokenAuth {e.code}: {error_body}")
        audit_log(
            action="3lo_callback",
            correlation_id=correlation_id,
            status=e.code,
            detail=f"CompleteResourceTokenAuth_error={error_body[:200]}",
        )
        # Intentionally swallow — AgentCore's internal resolver still
        # completes the binding in the background. Show success HTML.
    except Exception as exc:
        print(f"[3LO-CALLBACK] Unexpected error: {exc}")
        audit_log(
            action="3lo_callback",
            correlation_id=correlation_id,
            status=500,
            detail=f"exception={type(exc).__name__}",
        )

    return html_response(
        200,
        "Authorization Complete",
        "You can close this window and return to your agent client. "
        "Tool access will be available shortly. If your next tool call "
        "still asks you to authorize, wait a few seconds and retry.",
    )


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


def _parse_mcp_body(body_text, content_type):
    """Parse an MCP response body. Supports both application/json and
    text/event-stream (SSE). Returns the first JSON-RPC message found, or None.
    """
    if "text/event-stream" in (content_type or ""):
        for line in body_text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        return None
    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        return None


def _forward_one(body_bytes, req_headers, auth):
    """Send one MCP request to the gateway and return (status, raw_text, content_type, session_id)."""
    req = urllib.request.Request(GATEWAY_URL, data=body_bytes, method="POST")
    for k, v in req_headers.items():
        req.add_header(k, v)
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return (
                resp.status,
                resp.read().decode(),
                resp.headers.get("Content-Type", "application/json"),
                resp.headers.get("Mcp-Session-Id"),
            )
    except urllib.error.HTTPError as e:
        return (
            e.code,
            e.read().decode(),
            e.headers.get("Content-Type", "application/json"),
            e.headers.get("Mcp-Session-Id"),
        )


def _handle_tools_list_with_pagination(parsed_req, req_headers, auth, correlation_id, caller):
    """Work around Claude Code's lack of MCP tools/list pagination support
    (https://github.com/anthropics/claude-code/issues/24785). AgentCore Gateway
    paginates at 30 tools per page; we fetch every page server-side and return
    a single merged response with no nextCursor.
    """
    all_tools = []
    last_session_id = None
    last_status = 200
    last_content_type = "application/json"
    jsonrpc_id = parsed_req.get("id")
    base_params = dict(parsed_req.get("params") or {})
    max_pages = 20

    for page in range(max_pages):
        body = dict(parsed_req)
        body["params"] = base_params
        data = json.dumps(body).encode()

        status, text, ct, sid = _forward_one(data, req_headers, auth)
        last_status = status
        last_content_type = ct
        if sid:
            last_session_id = sid
            req_headers["Mcp-Session-Id"] = sid

        if status >= 400:
            audit_log(
                action="mcp_proxy",
                correlation_id=correlation_id,
                caller=caller,
                status=status,
                detail=f"mcp_method=tools/list page={page} error=true",
            )
            resp_headers = {"Content-Type": ct}
            if last_session_id:
                resp_headers["Mcp-Session-Id"] = last_session_id
            return {"statusCode": status, "headers": resp_headers, "body": text}

        msg = _parse_mcp_body(text, ct)
        if not msg or "result" not in msg:
            return {
                "statusCode": status,
                "headers": {"Content-Type": ct, **({"Mcp-Session-Id": last_session_id} if last_session_id else {})},
                "body": text,
            }

        result = msg["result"] or {}
        tools = result.get("tools") or []
        all_tools.extend(tools)
        next_cursor = result.get("nextCursor")
        if not next_cursor:
            break
        base_params["cursor"] = next_cursor
    else:
        audit_log(
            action="mcp_proxy",
            correlation_id=correlation_id,
            caller=caller,
            status=last_status,
            detail=f"mcp_method=tools/list max_pages_reached tools={len(all_tools)}",
        )

    merged = {
        "jsonrpc": "2.0",
        "id": jsonrpc_id,
        "result": {"tools": all_tools},
    }
    resp_headers = {"Content-Type": "application/json"}
    if last_session_id:
        resp_headers["Mcp-Session-Id"] = last_session_id

    audit_log(
        action="mcp_proxy",
        correlation_id=correlation_id,
        caller=caller,
        status=last_status,
        detail=f"mcp_method=tools/list pages={page + 1} tools={len(all_tools)}",
    )
    return {"statusCode": 200, "headers": resp_headers, "body": json.dumps(merged)}


def handle_slack_mcp(event):
    """Forward MCP requests to mcp.slack.com, but intercept
    `resources/templates/list` and return an empty result.

    AgentCore Gateway marks the target FAILED when an upstream MCP server
    responds with JSON-RPC -32601 (Method not found) for that method, even
    though the method is optional per the MCP spec. Slack MCP correctly
    returns -32601, so we shim the response here to keep the target healthy.
    """
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method", "POST")
    )
    body = event.get("body", "")
    if event.get("isBase64Encoded") and body:
        body = base64.b64decode(body)

    # Intercept resources/templates/list before forwarding.
    if method == "POST" and body:
        try:
            parsed = json.loads(body if isinstance(body, str) else body.decode())
            if parsed.get("method") == "resources/templates/list":
                return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "jsonrpc": "2.0",
                        "id": parsed.get("id"),
                        "result": {"resourceTemplates": []},
                    }),
                }
        except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
            pass

    headers_in = event.get("headers") or {}
    auth = headers_in.get("authorization") or headers_in.get("Authorization") or ""

    fwd_headers = {
        "Content-Type": headers_in.get("content-type") or headers_in.get("Content-Type") or "application/json",
        "Accept": headers_in.get("accept") or headers_in.get("Accept") or "application/json, text/event-stream",
    }
    if auth:
        fwd_headers["Authorization"] = auth
    for h in ("mcp-protocol-version", "mcp-session-id", "user-agent"):
        v = headers_in.get(h) or headers_in.get(h.title())
        if v:
            fwd_headers[h.title() if h != "user-agent" else "User-Agent"] = v

    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(
        "https://mcp.slack.com/mcp", data=data or None, method=method, headers=fwd_headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode()
            resp_headers = {"Content-Type": resp.headers.get("Content-Type", "application/json")}
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                resp_headers["Mcp-Session-Id"] = sid
            return {"statusCode": resp.status, "headers": resp_headers, "body": resp_body}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        resp_headers = {"Content-Type": e.headers.get("Content-Type", "application/json")}
        www_auth = e.headers.get("WWW-Authenticate", "")
        if www_auth:
            resp_headers["WWW-Authenticate"] = www_auth
        return {"statusCode": e.code, "headers": resp_headers, "body": err_body}
    except Exception as e:
        print(f"[SLACK-MCP] upstream exception {type(e).__name__}: {e}")
        return {"statusCode": 502, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": str(e)})}


# ─── GitHub MCP PAT-injection relay ────────────────────────────────────────

_GITHUB_PAT_CACHE = {"value": None, "expires_at": 0.0}
_GITHUB_PAT_TTL = 300  # seconds


def _get_github_bot_pat():
    """Return the GitHub bot PAT, cached for _GITHUB_PAT_TTL seconds.

    Lambda execution environments live ~15min idle so a short TTL is enough
    to avoid hitting Secrets Manager on every invocation while still letting
    rotation propagate within a few minutes.
    """
    now = time.time()
    if _GITHUB_PAT_CACHE["value"] and _GITHUB_PAT_CACHE["expires_at"] > now:
        return _GITHUB_PAT_CACHE["value"]
    if not GITHUB_BOT_PAT_SECRET_ARN:
        raise RuntimeError("GITHUB_BOT_PAT_SECRET_ARN env var is not set")
    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=GITHUB_BOT_PAT_SECRET_ARN)
    secret_str = resp.get("SecretString") or ""
    # Allow either a raw PAT or a JSON blob like {"pat": "ghp_..."} for ergonomics.
    pat = secret_str.strip()
    if pat.startswith("{"):
        try:
            pat = json.loads(pat).get("pat", "").strip()
        except json.JSONDecodeError:
            pass
    if not pat:
        raise RuntimeError("GitHub bot PAT secret is empty")
    _GITHUB_PAT_CACHE["value"] = pat
    _GITHUB_PAT_CACHE["expires_at"] = now + _GITHUB_PAT_TTL
    return pat


def handle_github_mcp(event):
    """Forward MCP requests to api.githubcopilot.com/mcp/, injecting a
    bot PAT in the Authorization header from Secrets Manager.

    The inbound caller is authenticated by AgentCore Gateway (CUSTOM_JWT)
    before requests reach this proxy via the No-auth MCP target, so the
    inbound Authorization is intentionally ignored here.
    """
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method", "POST")
    )
    body = event.get("body", "")
    if event.get("isBase64Encoded") and body:
        body = base64.b64decode(body)

    try:
        pat = _get_github_bot_pat()
    except Exception as e:
        print(f"[GITHUB-MCP] PAT resolution failed: {type(e).__name__}: {e}")
        return {"statusCode": 500, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "github_pat_unavailable"})}

    headers_in = event.get("headers") or {}
    fwd_headers = {
        "Authorization": f"Bearer {pat}",
        "Content-Type": headers_in.get("content-type") or headers_in.get("Content-Type") or "application/json",
        "Accept": headers_in.get("accept") or headers_in.get("Accept") or "application/json, text/event-stream",
    }
    for h in ("mcp-protocol-version", "mcp-session-id", "user-agent"):
        v = headers_in.get(h) or headers_in.get(h.title())
        if v:
            fwd_headers[h.title() if h != "user-agent" else "User-Agent"] = v

    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(
        "https://api.githubcopilot.com/mcp/", data=data or None, method=method, headers=fwd_headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode()
            resp_headers = {"Content-Type": resp.headers.get("Content-Type", "application/json")}
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                resp_headers["Mcp-Session-Id"] = sid
            return {"statusCode": resp.status, "headers": resp_headers, "body": resp_body}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        resp_headers = {"Content-Type": e.headers.get("Content-Type", "application/json")}
        www_auth = e.headers.get("WWW-Authenticate", "")
        if www_auth:
            resp_headers["WWW-Authenticate"] = www_auth
        # On 401/403 invalidate the cache so a rotated PAT is picked up next call.
        if e.code in (401, 403):
            _GITHUB_PAT_CACHE["value"] = None
            _GITHUB_PAT_CACHE["expires_at"] = 0.0
        return {"statusCode": e.code, "headers": resp_headers, "body": err_body}
    except Exception as e:
        print(f"[GITHUB-MCP] upstream exception {type(e).__name__}: {e}")
        return {"statusCode": 502, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": str(e)})}


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

    # Extract audit context
    correlation_id = event.get("requestContext", {}).get("requestId", "")
    auth = get_header(event, "Authorization")
    caller = _extract_sub_from_jwt(auth)
    source_ip = (
        event.get("requestContext", {}).get("http", {}).get("sourceIp")
        or event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        or ""
    )

    # Extract MCP method/tool for audit (e.g. "tools/call" with tool name)
    mcp_method = ""
    mcp_tool = ""
    parsed_req = None
    if isinstance(body, (str, bytes)):
        try:
            parsed_req = json.loads(body)
            mcp_method = parsed_req.get("method", "")
            mcp_tool = parsed_req.get("params", {}).get("name", "")
        except (json.JSONDecodeError, AttributeError):
            pass

    # Intercept tools/list and transparently aggregate all pages — Claude Code
    # does not follow nextCursor, so pagination must happen here.
    if method == "POST" and mcp_method == "tools/list" and parsed_req is not None:
        req_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        for h in ("mcp-protocol-version", "mcp-session-id"):
            val = headers.get(h)
            if val:
                req_headers[h.title()] = val
        return _handle_tools_list_with_pagination(parsed_req, req_headers, auth, correlation_id, caller)

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

    if auth:
        req.add_header("Authorization", auth)

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_body = resp.read().decode()

            audit_log(
                action="mcp_proxy",
                correlation_id=correlation_id,
                caller=caller,
                status=resp.status,
                detail=f"mcp_method={mcp_method} tool={mcp_tool}" if mcp_method else None,
            )

            # Cache the caller's JWT keyed by the PAR request_uri so that
            # /3lo-callback can later bind the session with userToken.
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
        audit_log(
            action="mcp_proxy",
            correlation_id=correlation_id,
            caller=caller,
            status=e.code,
            detail=f"mcp_method={mcp_method} tool={mcp_tool} error=true",
        )
        resp_headers = {"Content-Type": "application/json"}
        session_id = e.headers.get("Mcp-Session-Id")
        if session_id:
            resp_headers["Mcp-Session-Id"] = session_id
        return {"statusCode": e.code, "headers": resp_headers, "body": error_body}
    except Exception as e:
        audit_log(
            action="mcp_proxy",
            correlation_id=correlation_id,
            caller=caller,
            status=502,
            detail=f"mcp_method={mcp_method} exception={type(e).__name__}",
        )
        return json_response(502, {"error": {"code": -32603, "message": str(e)}})


# ─── Session token cache (DynamoDB) ─────────────────────────────────────────

_dynamodb = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _cache_elicitation_token(resp_body, auth_header):
    """When the gateway returns an elicitation response containing a PAR
    request_uri, store the caller's JWT keyed by that URN so /3lo-callback
    can later complete the session binding with userToken.
    """
    if not auth_header or not SESSION_TABLE_NAME:
        return
    match = re.search(r'request_uri=(urn%3A[^&"\s]+|urn:[^&"\s]+)', resp_body)
    if not match:
        return
    request_uri = urllib.parse.unquote(match.group(1))
    token = auth_header.replace("Bearer ", "").replace("bearer ", "")
    try:
        now = int(time.time())
        table = _get_dynamodb().Table(SESSION_TABLE_NAME)
        table.put_item(Item={
            "sessionUri": request_uri,
            "userToken": token,
            "cachedAt": now,
            "ttl": now + 600,
        })
        print(f"[CACHE] stored token for session: {request_uri}")
    except Exception as e:
        print(f"[CACHE] put_item failed: {e}")


def _get_cached_token(session_uri):
    if not SESSION_TABLE_NAME or not session_uri:
        return None
    try:
        table = _get_dynamodb().Table(SESSION_TABLE_NAME)
        resp = table.get_item(Key={"sessionUri": session_uri})
        item = resp.get("Item")
        if item:
            print(f"[CACHE] hit for session: {session_uri[:80]}")
            return item.get("userToken")
        print(f"[CACHE] miss for session: {session_uri[:80]}")
    except Exception as e:
        print(f"[CACHE] get_item failed: {e}")
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
