"""Mock API backend for testing API key injection.

Returns request headers and body as the response, allowing verification
that the interceptor correctly injects API keys.
"""

import json


def lambda_handler(event, context):
    print(f"[MOCK_API] Event: {json.dumps(event, default=str)[:3000]}")

    headers = event.get("headers", {})
    body = event.get("body", "")
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")

    if isinstance(body, str) and body:
        try:
            body = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            pass

    response_body = {
        "service": "mock-api",
        "path": path,
        "method": method,
        "receivedHeaders": {
            k: v for k, v in (headers or {}).items()
            if k.lower() in ("x-api-key", "authorization", "content-type", "x-custom-key")
        },
        "allHeaderKeys": list((headers or {}).keys()),
        "body": body,
    }

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(response_body),
    }
