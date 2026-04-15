"""API Key Request Interceptor for AgentCore Gateway.

Resolves an API key for the incoming MCP tool call by matching JWT claims
against the admin table and injects it as a request header.

Schema (AdminTable):
    PK = "SERVICES",      SK = <serviceName>          → service metadata
    PK = "SVC#<service>", SK = "CLAIM#<key>#<value>"  → API key mapping

Resolution:
    1. Decode JWT (already verified by the gateway's CUSTOM_JWT authorizer).
    2. Resolve service from tool name prefix (e.g. "redash-target-foo" → "redash").
    3. Build candidate claim tuples from ALLOWED_CLAIM_KEYS (in priority order),
       plus the service-default wildcard ("*", "*").
    4. BatchGetItem for all candidates against PK="SVC#<service>".
    5. Return the first hit in candidate order. No hit → pass through unchanged.

Environment variables:
    ADMIN_TABLE_NAME:    DynamoDB table (required)
    ALLOWED_CLAIM_KEYS:  Comma-separated JWT claim keys in priority order
                         (default: "email,cognito:groups")
    REGION:              AWS region (default: us-east-1)
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import boto3

ADMIN_TABLE_NAME = os.environ["ADMIN_TABLE_NAME"]
ALLOWED_CLAIM_KEYS: list[str] = [
    k.strip() for k in os.environ.get("ALLOWED_CLAIM_KEYS", "email,cognito:groups").split(",") if k.strip()
]
REGION = os.environ.get("REGION", "us-east-1")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
admin_table = dynamodb.Table(ADMIN_TABLE_NAME)

# Cache: targetPrefix → serviceName (loaded once per container)
_service_map: dict[str, str] | None = None


def _load_service_map() -> dict[str, str]:
    """Query all active services once per cold start."""
    global _service_map
    if _service_map is not None:
        return _service_map

    _service_map = {}
    try:
        resp = admin_table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": "SERVICES"},
        )
        for item in resp.get("Items", []):
            if not item.get("isActive", True):
                continue
            prefix = item.get("targetPrefix", "")
            name = item.get("SK", "")
            if prefix and name:
                _service_map[prefix] = name
    except Exception as e:
        print(f"[APIKEY_INTERCEPTOR] Failed to load service map: {e}")

    return _service_map


def _resolve_service(tool_name: str) -> str | None:
    for prefix, service_name in _load_service_map().items():
        if tool_name.startswith(prefix):
            return service_name
    return None


def _decode_claims(req: dict[str, Any]) -> dict[str, Any]:
    """Decode the JWT payload (signature already verified by the gateway)."""
    headers = req.get("headers", {})
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return {}
    try:
        token = auth_header.split(" ", 1)[1]
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        print(f"[APIKEY_INTERCEPTOR] JWT decode error: {e}")
        return {}


def _claim_candidates(claims: dict[str, Any]) -> list[tuple[str, str]]:
    """Expand JWT claims into an ordered list of (key, value) candidates.

    Order reflects priority (earliest = most specific). Each allowed claim key
    is expanded into one or more candidates (list-valued claims yield one per
    element). A final ("*", "*") wildcard provides the service-default slot.
    """
    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(k: str, v: Any) -> None:
        if v is None or v == "":
            return
        pair = (k, str(v))
        if pair in seen:
            return
        seen.add(pair)
        candidates.append(pair)

    for key in ALLOWED_CLAIM_KEYS:
        value = claims.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for v in value:
                add(key, v)
        elif isinstance(value, str) and "," in value and key == "cognito:groups":
            # Cognito sometimes flattens groups to a comma-separated string.
            for v in value.split(","):
                add(key, v.strip())
        else:
            add(key, value)

    candidates.append(("*", "*"))
    return candidates


def _resolve_api_key(service: str, claims: dict[str, Any]) -> dict[str, str] | None:
    candidates = _claim_candidates(claims)
    pk = f"SVC#{service}"
    keys = [{"PK": pk, "SK": f"CLAIM#{k}#{v}"} for k, v in candidates]

    # BatchGetItem has a 100-key hard limit — we're nowhere near it.
    resp = dynamodb.batch_get_item(
        RequestItems={ADMIN_TABLE_NAME: {"Keys": keys}},
    )
    items_by_sk: dict[str, dict[str, Any]] = {
        item["SK"]: item for item in resp.get("Responses", {}).get(ADMIN_TABLE_NAME, [])
    }

    for k, v in candidates:
        sk = f"CLAIM#{k}#{v}"
        item = items_by_sk.get(sk)
        if item:
            print(f"[APIKEY_INTERCEPTOR] Resolved {service} via {sk}")
            return {
                "apiKey": item["apiKey"],
                "headerName": item.get("headerName", "X-API-Key"),
            }
    return None


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

    if method != "tools/call":
        return _build_pass_through(body)

    tool_name = body.get("params", {}).get("name", "")
    service = _resolve_service(tool_name)
    if service is None:
        print(f"[APIKEY_INTERCEPTOR] Tool '{tool_name}' not an API-key target, passing through")
        return _build_pass_through(body)

    claims = _decode_claims(req)
    if not claims:
        return _build_error("Cannot identify caller", body)

    try:
        key_info = _resolve_api_key(service, claims)
    except Exception as e:
        print(f"[APIKEY_INTERCEPTOR] Lookup error: {e}")
        return _build_error("API key lookup failed", body)

    if key_info is None:
        print(f"[APIKEY_INTERCEPTOR] No key for {service}, passing through")
        return _build_pass_through(body)

    return _build_pass_through(
        body,
        extra_headers={key_info["headerName"]: key_info["apiKey"]},
    )
