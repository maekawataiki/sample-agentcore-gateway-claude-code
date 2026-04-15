"""Admin Control Panel API — router and auth.

Routes all /admin/v1/* requests. Cognito Authorizer on API Gateway validates
the JWT; this handler additionally checks for admin group membership via the
cognito:groups claim in the authorizer context.

Environment variables:
    ADMIN_TABLE_NAME:  DynamoDB table (single-table)
    ADMIN_GROUP_NAME:  Cognito group required for access (default: admin)
"""

from __future__ import annotations

import json
import os
import re
import time
import traceback
from typing import Any

from mappings import delete_mapping, get_mapping, list_mappings, put_mapping
from services import create_service, delete_service, get_service, list_services, update_service

ADMIN_TABLE = os.environ["ADMIN_TABLE_NAME"]
ADMIN_GROUP = os.environ.get("ADMIN_GROUP_NAME", "admin")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    print(f"[ADMIN_API] Event: {json.dumps(event, default=str)[:2000]}")

    try:
        caller = _extract_caller(event)
        if not _is_admin(event):
            return _response(403, {"error": "Admin group membership required"})

        method = event.get("httpMethod", "")
        path = event.get("path", "")
        body = json.loads(event.get("body") or "{}") if event.get("body") else {}
        params = event.get("queryStringParameters") or {}

        route = re.sub(r"^/admin/v1", "", path)
        result = _route(method, route, body, params, caller)
        return _response(200, result)

    except ValueError as e:
        return _response(400, {"error": str(e)})
    except Exception:
        traceback.print_exc()
        return _response(500, {"error": "Internal server error"})


def _route(
    method: str,
    route: str,
    body: dict[str, Any],
    params: dict[str, str],
    caller: str,
) -> Any:
    # ── Services ──
    if route == "/services" and method == "GET":
        return {"services": list_services(ADMIN_TABLE)}
    if route == "/services" and method == "POST":
        result = create_service(ADMIN_TABLE, body)
        _audit("service_created", caller, {"serviceName": result["serviceName"]})
        return result

    m = re.match(r"^/services/([^/]+)$", route)
    if m:
        svc = m.group(1)
        if method == "GET":
            return get_service(ADMIN_TABLE, svc) or {}
        if method == "PUT":
            result = update_service(ADMIN_TABLE, svc, body)
            _audit("service_updated", caller, {"serviceName": svc})
            return result
        if method == "DELETE":
            delete_service(ADMIN_TABLE, svc)
            _audit("service_deleted", caller, {"serviceName": svc})
            return {"status": "deleted"}

    # ── Mappings (claim → API key) ──
    m = re.match(r"^/services/([^/]+)/mappings$", route)
    if m:
        svc = m.group(1)
        if method == "GET":
            return {"mappings": list_mappings(ADMIN_TABLE, svc)}
        if method == "PUT":
            result = put_mapping(ADMIN_TABLE, {**body, "serviceName": svc}, caller)
            _audit("mapping_upserted", caller, {
                "serviceName": svc,
                "claimKey": body.get("claimKey"),
                "claimValue": body.get("claimValue"),
            })
            return result
        if method == "DELETE":
            claim_key = params.get("claimKey", "")
            claim_value = params.get("claimValue", "")
            if not claim_key or not claim_value:
                raise ValueError("claimKey and claimValue query parameters are required")
            delete_mapping(ADMIN_TABLE, svc, claim_key, claim_value)
            _audit("mapping_deleted", caller, {
                "serviceName": svc,
                "claimKey": claim_key,
                "claimValue": claim_value,
            })
            return {"status": "deleted"}

    m = re.match(r"^/services/([^/]+)/mappings/lookup$", route)
    if m and method == "GET":
        svc = m.group(1)
        claim_key = params.get("claimKey", "")
        claim_value = params.get("claimValue", "")
        if not claim_key or not claim_value:
            raise ValueError("claimKey and claimValue query parameters are required")
        return get_mapping(ADMIN_TABLE, svc, claim_key, claim_value) or {}

    raise ValueError(f"Unknown route: {method} {route}")


def _extract_caller(event: dict[str, Any]) -> str:
    claims = event.get("requestContext", {}).get("authorizer", {}).get("claims", {})
    return claims.get("cognito:username", "") or claims.get("sub", "")


def _is_admin(event: dict[str, Any]) -> bool:
    claims = event.get("requestContext", {}).get("authorizer", {}).get("claims", {})
    groups_str = claims.get("cognito:groups", "")
    if not groups_str:
        return False
    groups = [g.strip() for g in groups_str.split(",")]
    return ADMIN_GROUP in groups


def _audit(action: str, caller: str, detail: dict[str, Any] | None = None) -> None:
    entry = {
        "audit": True,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "caller": caller,
    }
    if detail:
        entry["detail"] = detail
    print(json.dumps(entry, separators=(",", ":"), default=str))


def _response(status_code: int, body: Any) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
