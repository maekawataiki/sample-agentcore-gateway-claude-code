# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Gateway RESPONSE interceptor for 3LO gateways (GitHub, Notion, etc.).

Passes all responses through unchanged. The -32042 elicitation responses
are forwarded as-is to MCP clients (Claude Code natively supports URL
elicitation in MCP 2025-11-25).

This interceptor exists as a hook point for future response transformations
and for debug logging of gateway responses.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Interceptor event (truncated): %s", json.dumps(event, default=str)[:2000])

    mcp_data = event.get("mcp", {})
    gateway_response = mcp_data.get("gatewayResponse", {})
    body = gateway_response.get("body")
    status_code = gateway_response.get("statusCode", 200)

    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            body = {}
    if body is None:
        body = {}

    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "body": body,
                "statusCode": status_code,
            }
        },
    }
