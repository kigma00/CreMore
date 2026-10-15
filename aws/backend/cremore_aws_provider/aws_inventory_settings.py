"""Explicit, installation-scoped automatic AWS credential inventory settings."""

from __future__ import annotations

import re

KEY = "aws_credential_inventory"
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_REGION = re.compile(r"^[a-z]{2,4}(?:-[a-z]+)+-[0-9]+$")
_DEFAULTS = {"enabled": False, "interval_minutes": 1440, "account_ids": [],
             "cloudtrail_enabled": False, "regions": [], "window_days": 7,
             "cloudtrail_source": "event_history", "trail_bucket": "", "trail_prefixes": []}


def normalize(body, current=None):
    """Validate administrator input without silently broadening a selected scope."""
    if not isinstance(body, dict) or set(body) - set(_DEFAULTS):
        raise ValueError("AWS_INVENTORY_INVALID_SETTINGS")
    out = {**_DEFAULTS, **(current or {}), **body}
    for field in ("enabled", "cloudtrail_enabled"):
        if type(out[field]) is not bool:
            raise ValueError("AWS_INVENTORY_INVALID_" + field.upper())
    if out["cloudtrail_source"] not in ("event_history", "s3"):
        raise ValueError("AWS_INVENTORY_INVALID_CLOUDTRAIL_SOURCE")
    for field, lower, upper in (("interval_minutes", 5, 10080),
                                ("window_days", 1, 3650 if out["cloudtrail_source"] == "s3" else 90)):
        if type(out[field]) is not int or not lower <= out[field] <= upper:
            raise ValueError("AWS_INVENTORY_INVALID_" + field.upper())
    for field, pattern, limit in (("account_ids", _ACCOUNT, 10000), ("regions", _REGION, 50)):
        values = out[field]
        if (not isinstance(values, list) or len(values) > limit
                or any(not isinstance(value, str) or not pattern.fullmatch(value) for value in values)):
            raise ValueError("AWS_INVENTORY_INVALID_" + field.upper())
        out[field] = sorted(set(values))
    if out["cloudtrail_enabled"] and not out["regions"]:
        raise ValueError("AWS_INVENTORY_CLOUDTRAIL_REGIONS_REQUIRED")
    # Reuse the collection spec's scope validation; no parallel bucket/prefix contract.
    if out["cloudtrail_enabled"]:
        from cremore.coverage.models import ConnectionSpec
        ConnectionSpec(name="Inventory configuration", provider="aws_cloudtrail", account_id="000000000000",
                       regions=out["regions"], window_days=out["window_days"],
                       cloudtrail_source=out["cloudtrail_source"], trail_bucket=out["trail_bucket"],
                       trail_prefixes=out["trail_prefixes"])
    elif not isinstance(out["trail_bucket"], str) or not isinstance(out["trail_prefixes"], list):
        raise ValueError("AWS_INVENTORY_INVALID_TRAIL_SCOPE")
    return {key: out[key] for key in _DEFAULTS}


def config(settings, repo):
    record = repo.get_setting(KEY) or {}
    try:
        value = normalize(record.get("value") or {})
        reason = None
    except ValueError:
        # A corrupt scope must not become an enabled, unrestricted default.
        value, reason = dict(_DEFAULTS), "AWS_INVENTORY_INVALID_SETTINGS"
    return {**value, "installation_allows": bool(getattr(settings, "scan_schedules_allowed", False)),
            "updated_by": record.get("updated_by"), "updated_at": record.get("updated_at"),
            "reason": reason}


def effective(settings, repo):
    value = config(settings, repo)
    return value["enabled"] and value["installation_allows"]


def account_allowed(settings, repo, account_id):
    value = config(settings, repo)
    return bool(value["enabled"] and value["installation_allows"]
                and (not value["account_ids"] or account_id in value["account_ids"]))
