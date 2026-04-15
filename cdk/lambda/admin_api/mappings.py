"""Claim → API key mapping CRUD on the single admin table.

Layout: PK="SVC#<service>", SK="CLAIM#<claimKey>#<claimValue>"
"""

from __future__ import annotations

import time
from typing import Any

import boto3

dynamodb = boto3.resource("dynamodb")


def _table(name: str):
    return dynamodb.Table(name)


def _pk(service: str) -> str:
    return f"SVC#{service}"


def _sk(claim_key: str, claim_value: str) -> str:
    return f"CLAIM#{claim_key}#{claim_value}"


def list_mappings(table_name: str, service: str) -> list[dict[str, Any]]:
    resp = _table(table_name).query(
        KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
        ExpressionAttributeValues={":pk": _pk(service), ":prefix": "CLAIM#"},
    )
    return [_strip(item) for item in resp.get("Items", [])]


def get_mapping(
    table_name: str,
    service: str,
    claim_key: str,
    claim_value: str,
) -> dict[str, Any] | None:
    resp = _table(table_name).get_item(
        Key={"PK": _pk(service), "SK": _sk(claim_key, claim_value)},
    )
    item = resp.get("Item")
    return _strip(item) if item else None


def put_mapping(table_name: str, body: dict[str, Any], performed_by: str) -> dict[str, Any]:
    service = body.get("serviceName", "")
    claim_key = body.get("claimKey", "")
    claim_value = body.get("claimValue", "")
    api_key = body.get("apiKey", "")

    if not all([service, claim_key, claim_value, api_key]):
        raise ValueError("serviceName, claimKey, claimValue, and apiKey are required")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    item = {
        "PK": _pk(service),
        "SK": _sk(claim_key, claim_value),
        "claimKey": claim_key,
        "claimValue": claim_value,
        "serviceName": service,
        "apiKey": api_key,
        "headerName": body.get("headerName", "X-API-Key"),
        "description": body.get("description", ""),
        "updatedAt": now,
        "updatedBy": performed_by,
    }
    _table(table_name).put_item(Item=item)
    return _strip(item)


def delete_mapping(
    table_name: str,
    service: str,
    claim_key: str,
    claim_value: str,
) -> None:
    _table(table_name).delete_item(
        Key={"PK": _pk(service), "SK": _sk(claim_key, claim_value)},
    )


def _strip(item: dict[str, Any]) -> dict[str, Any]:
    """Remove raw PK/SK keys; redact apiKey for safe return."""
    out = {k: v for k, v in item.items() if k not in ("PK", "SK")}
    if "apiKey" in out:
        out["apiKey"] = "***"
    return out
