"""Bounded JSON state shared by task persistence and provider checkpoints."""

import json


def safe_task_state(value):
    forbidden = {"password", "secret", "secret_key", "secret_access_key", "access_token", "token",
                 "refresh_token", "session_token", "client_secret", "private_key", "authorization",
                 "api_key", "raw_content", "raw_secret", "text", "data"}
    def check(node):
        if isinstance(node, dict):
            if any(not isinstance(k, str) or k.lower() in forbidden for k in node):
                raise ValueError("TASK_PAYLOAD_CONTAINS_CONTENT_OR_CREDENTIALS")
            for child in node.values():
                check(child)
        elif isinstance(node, list):
            for child in node:
                check(child)
    check(value)
    encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode()) > 2_000_000:
        raise ValueError("TASK_STATE_LIMIT")
    return json.loads(encoded)
