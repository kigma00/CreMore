"""Notion's signed event envelope; event bodies are never persistence records."""

import hashlib
import hmac
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

MAX_BODY = 64 * 1024
PAGE_EVENTS = {"page.created", "page.content_updated", "page.properties_updated", "page.moved", "page.deleted", "page.undeleted"}
DATA_EVENTS = {"data_source.content_updated", "data_source.schema_updated", "data_source.deleted", "data_source.undeleted",
               "database.content_updated", "database.schema_updated", "database.deleted", "database.undeleted"}


class WebhookError(ValueError):
    pass


def token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", value):
        raise WebhookError("NOTION_WEBHOOK_TOKEN_INVALID")
    return value


def body(raw):
    if len(raw) > MAX_BODY:
        raise WebhookError("NOTION_WEBHOOK_BODY_LIMIT")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise WebhookError("NOTION_WEBHOOK_BODY_INVALID") from None
    if not isinstance(value, dict):
        raise WebhookError("NOTION_WEBHOOK_BODY_INVALID")
    return value


def event(raw, signature, verification_token, *, now=None):
    if len(raw) > MAX_BODY:
        raise WebhookError("NOTION_WEBHOOK_BODY_LIMIT")
    expected = "sha256=" + hmac.new(token(verification_token).encode(), raw, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature) or not hmac.compare_digest(expected, signature):
        raise WebhookError("NOTION_WEBHOOK_SIGNATURE_INVALID")
    value = body(raw)
    try:
        identity = {k: str(uuid.UUID(value[k])) for k in ("id", "workspace_id", "subscription_id", "integration_id")}
        entity = value["entity"]
        entity_id = str(uuid.UUID(entity["id"]))
        stamp = datetime.fromisoformat(value["timestamp"])
        now = now or datetime.now(UTC)
        if stamp.tzinfo is None or not now - timedelta(days=3) <= stamp <= now + timedelta(minutes=5):
            raise ValueError
        kind = value["type"]
        if not isinstance(kind, str) or len(kind) > 96:
            raise ValueError
    except (KeyError, ValueError, TypeError, AttributeError):
        raise WebhookError("NOTION_WEBHOOK_EVENT_INVALID") from None
    # Authors, changed text, arbitrary data and retry attempt are intentionally discarded.
    return {**identity, "entity_id": entity_id, "type": kind,
            "supported": kind in PAGE_EVENTS | DATA_EVENTS}


def targets(plan, event):
    """Only previously approved pages/rows. A new page event never expands scope."""
    identity = event["entity_id"].replace("-", "")
    for root in plan.roots:
        root_id = str(root["provider_resource_id"]).replace("-", "").lower()
        children = {str(v).replace("-", "").lower() for v in root.get("descendant_ids", [])} if root.get("page_mode") != "PAGE_ONLY" else set()
        if (root["resource_type"] == "NOTION_PAGE" and identity == root_id) or identity in children:
            yield {"resource_id": root["resource_id"], "page_ids": [event["entity_id"]]}
        elif root["resource_type"] == "NOTION_DATA_SOURCE" and identity == root_id and event["type"] in DATA_EVENTS:
            yield {"resource_id": root["resource_id"], "page_ids": []}
