"""API Key Request Interceptor for AgentCore Gateway.

Extracts user identity from JWT Bearer token, looks up the user's API key
in DynamoDB, and injects it as a request header for the backend service.

Only injects API keys for tools matching the TARGET_PREFIX (e.g. "redash-target-").
Other tools (GitHub, Notion 3LO) are passed through without modification so
the Authorization header (Cognito JWT) is preserved for outbound OAuth.

Environment variables:
    APIKEY_TABLE_NAME: DynamoDB table name for user -> API key mapping
    TARGET_PREFIX:     Tool name prefix for API key injection (default: "redash-target-")
    REGION:            AWS region (default: us-east-1)
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import boto3

APIKEY_TABLE_NAME = os.environ["APIKEY_TABLE_NAME"]
TARGET_PREFIX = os.environ.get("TARGET_PREFIX", "redash-target-")
REGION = os.environ.get("REGION", "us-east-1")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
apikey_table = dynamodb.Table(APIKEY_TABLE_NAME)


def _extract_caller_id(req: dict[str, Any]) -> str:
    """Extract caller identity from JWT Bearer token."""
    headers = req.get("headers", {})
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")

    if auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ", 1)[1]
            payload = token.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            claims = json.loads(base64.b64decode(payload))
            return claims.get("username", "") or claims.get("sub", "")
        except Exception:
            pass
    return ""


def _get_api_key_info(user_id: str) -> dict[str, str]:
    """Look up API key from DynamoDB."""
    resp = apikey_table.get_item(Key={"userId": user_id})
    item = resp.get("Item")
    if not item:
        raise ValueError(f"No API key mapping found for user: {user_id}")
    return {
        "apiKey": item["apiKey"],
        "headerName": item.get("headerName", "X-API-Key"),
    }


def _build_error(message: str, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {"code": -32000, "message": message},
                },
            }
        },
    }


def _build_pass_through(body: dict[str, Any], extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {
                "headers": headers,
                "body": body,
            }
        },
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    print(f"[APIKEY_INTERCEPTOR] Event: {json.dumps(event, default=str)[:2000]}")

    mcp = event.get("mcp", {})
    req = mcp.get("gatewayRequest", {})
    body = req.get("body", {})
    method = body.get("method", "")

    caller_id = _extract_caller_id(req)
    print(f"[APIKEY_INTERCEPTOR] Method: {method}, Caller: {caller_id}")

    # Only inject API key for tools/call requests
    if method != "tools/call":
        return _build_pass_through(body)

    # Only inject for tools matching the target prefix (e.g. "redash-target-")
    tool_name = body.get("params", {}).get("name", "")
    if not tool_name.startswith(TARGET_PREFIX):
        print(f"[APIKEY_INTERCEPTOR] Tool '{tool_name}' not a {TARGET_PREFIX} tool, passing through")
        return _build_pass_through(body)

    if not caller_id:
        print("[APIKEY_INTERCEPTOR] No caller identity found")
        return _build_error("Cannot identify caller", body)

    try:
        key_info = _get_api_key_info(caller_id)
        print(f"[APIKEY_INTERCEPTOR] Injecting {key_info['headerName']} for user {caller_id}")

        return _build_pass_through(
            body,
            extra_headers={
                key_info["headerName"]: key_info["apiKey"],
            },
        )
    except ValueError:
        # No API key mapping — pass through without injection.
        # This happens for targets that use 3LO (GitHub, Notion) instead of
        # API key auth. Their credential provider handles authentication.
        print(f"[APIKEY_INTERCEPTOR] No key for {caller_id}, passing through (3LO target)")
        return _build_pass_through(body)
    except Exception as e:
        print(f"[APIKEY_INTERCEPTOR] Error: {e}")
        return _build_error(f"API key lookup failed: {e}", body)
