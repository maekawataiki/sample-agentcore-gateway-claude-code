"""Service registry CRUD on the single admin table.

Layout: PK="SERVICES", SK=<serviceName>
"""

from __future__ import annotations

import time
from typing import Any

import boto3

dynamodb = boto3.resource("dynamodb")

_SERVICES_PK = "SERVICES"


def _table(name: str):
    return dynamodb.Table(name)


def list_services(table_name: str) -> list[dict[str, Any]]:
    resp = _table(table_name).query(
        KeyConditionExpression="PK = :pk",
        ExpressionAttributeValues={":pk": _SERVICES_PK},
    )
    return [_strip(item) for item in resp.get("Items", [])]


def get_service(table_name: str, service_name: str) -> dict[str, Any] | None:
    resp = _table(table_name).get_item(Key={"PK": _SERVICES_PK, "SK": service_name})
    item = resp.get("Item")
    return _strip(item) if item else None


def create_service(table_name: str, body: dict[str, Any]) -> dict[str, Any]:
    service_name = body.get("serviceName", "")
    if not service_name:
        raise ValueError("serviceName is required")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    item = {
        "PK": _SERVICES_PK,
        "SK": service_name,
        "displayName": body.get("displayName", service_name),
        "description": body.get("description", ""),
        "defaultHeaderName": body.get("defaultHeaderName", "X-API-Key"),
        "defaultHeaderPrefix": body.get("defaultHeaderPrefix", ""),
        "targetPrefix": body.get("targetPrefix", f"{service_name}-target-"),
        "isActive": True,
        "createdAt": now,
        "updatedAt": now,
    }
    _table(table_name).put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(PK)",
    )
    return _strip(item)


def update_service(table_name: str, service_name: str, body: dict[str, Any]) -> dict[str, Any]:
    allowed = ["displayName", "description", "defaultHeaderName", "defaultHeaderPrefix", "targetPrefix", "isActive"]
    update_parts: list[str] = []
    names: dict[str, str] = {}
    values: dict[str, Any] = {}

    for field in allowed:
        if field in body:
            ph = f"#{field}"
            vk = f":{field}"
            update_parts.append(f"{ph} = {vk}")
            names[ph] = field
            values[vk] = body[field]

    if not update_parts:
        raise ValueError("No updatable fields provided")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    update_parts.append("#updatedAt = :updatedAt")
    names["#updatedAt"] = "updatedAt"
    values[":updatedAt"] = now

    resp = _table(table_name).update_item(
        Key={"PK": _SERVICES_PK, "SK": service_name},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ConditionExpression="attribute_exists(PK)",
        ReturnValues="ALL_NEW",
    )
    return _strip(resp["Attributes"])


def delete_service(table_name: str, service_name: str) -> None:
    """Delete the service metadata. Does NOT cascade-delete mappings;
    mappings under PK=SVC#<name> remain and can be cleaned via mapping delete."""
    _table(table_name).delete_item(Key={"PK": _SERVICES_PK, "SK": service_name})


def _strip(item: dict[str, Any]) -> dict[str, Any]:
    """Remove raw PK/SK keys, surface serviceName in their place."""
    out = {k: v for k, v in item.items() if k not in ("PK", "SK")}
    out["serviceName"] = item.get("SK", "")
    return out
