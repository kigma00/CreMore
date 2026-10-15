"""AWS Organizations account discovery, configured from the dashboard.

The sibling of ``cremore/aws_sso_settings.py`` and for the same reason: the person
who operates an installation is frequently not the person who can change its
deployment. Everything here is a value an administrator copies out of AWS --
the StackSet's shared ExternalId, the organizational units it targets, the
accounts to leave alone -- so all of it belongs in ``installation_settings``
rather than in the environment.

The environment keeps its usual role. ``AWS_ORG_DISCOVERY_MODE=disabled``
hard-locks the sweep off, and each of ``AWS_ORG_DISCOVERY_EXTERNAL_ID``,
``AWS_ORG_DISCOVERY_OU_IDS`` and ``AWS_ORG_DISCOVERY_EXCLUDE_ACCOUNTS``, when
set, pins that one field so the dashboard reports it as locked instead of
pretending to offer a choice.

The shared ExternalId is not a secret: it is a confused-deputy identifier that
already appears in each account's record and in the CloudFormation quick-create
link. Storing it here introduces no new handling requirement.

Discovery still cannot run without it. A registered account whose role was
deployed with a different ExternalId could never be assumed, so ``effective``
requires one -- the same guard ``reconcile_org_accounts`` has always had.
"""

from __future__ import annotations

import re

KEY = "aws_org_discovery"
# Organizations ids, as AWS documents them; anything else is dropped rather
# than sent to the API or stored.
OU_ID = re.compile(r"^ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}$|^r-[0-9a-z]{4,32}$")
ACCOUNT_ID = re.compile(r"^\d{12}$")
# The value the StackSet baked into every member role's trust policy.
EXTERNAL_ID = re.compile(r"^[A-Za-z0-9+=,.@:/_-]{2,1224}$")
REGION = re.compile(r"^[a-z]{2,4}(?:-[a-z]+)+-[0-9]+$")
CONTEXT_FIELDS = ("control_tower_enabled", "control_tower_region", "lifecycle_queue_url",
                  "lifecycle_queue_acknowledged")


def normalize_context(body, current=None):
    """Optional home-region metadata and a separately acknowledged event queue."""
    from cremore.scanning.trigger_settings import queue_url
    out = {"control_tower_enabled": False, "control_tower_region": "", "lifecycle_queue_url": "",
           "lifecycle_queue_acknowledged": False, **(current or {}),
           **{key: body[key] for key in CONTEXT_FIELDS if key in body}}
    for key in ("control_tower_enabled", "lifecycle_queue_acknowledged"):
        if type(out[key]) is not bool:
            raise ValueError("AWS_CONTROL_TOWER_INVALID_SETTING")
    region = out["control_tower_region"]
    if not isinstance(region, str) or (region and not REGION.fullmatch(region)):
        raise ValueError("AWS_CONTROL_TOWER_INVALID_REGION")
    if out["control_tower_enabled"] and not region:
        raise ValueError("AWS_CONTROL_TOWER_HOME_REGION_REQUIRED")
    out["lifecycle_queue_url"] = queue_url(out["lifecycle_queue_url"])
    if out["lifecycle_queue_url"]:
        from urllib.parse import urlsplit
        host = urlsplit(out["lifecycle_queue_url"]).hostname
        if not region or host != f"sqs.{region}.amazonaws.com" + (".cn" if region.startswith("cn-") else ""):
            raise ValueError("AWS_CONTROL_TOWER_QUEUE_REGION_MISMATCH")
    return {key: out[key] for key in CONTEXT_FIELDS}


def _stored(repo) -> tuple[dict, dict]:
    record = repo.get_setting(KEY) or {}
    return (record.get("value") or {}), record


def stored(repo) -> dict:
    """The saved document, so a caller can change one field and write it back."""
    return _stored(repo)[0]


def _pin(settings, name: str) -> str:
    return (getattr(settings, name, "") or "").strip()


def _csv(value: str, pattern: re.Pattern) -> list[str]:
    return sorted({item.strip() for item in value.split(",") if pattern.fullmatch(item.strip())})


def _listed(value, pattern: re.Pattern) -> list[str]:
    if isinstance(value, str):
        return _csv(value, pattern)
    if isinstance(value, list):
        return sorted({str(item).strip() for item in value if pattern.fullmatch(str(item).strip())})
    return []


def config(settings, repo) -> dict:
    """The effective configuration, and where each value came from."""
    stored, record = _stored(repo)
    external_pin = _pin(settings, "aws_org_discovery_external_id")
    ou_pin = _pin(settings, "aws_org_discovery_ou_ids")
    exclude_pin = _pin(settings, "aws_org_discovery_excludes")
    stored_external = str(stored.get("external_id") or "").strip()
    try:
        context = normalize_context(stored)
    except ValueError:
        context = normalize_context({})
    return {
        **context,
        # The switch is the dashboard's alone; configuration only allows or locks.
        "enabled": stored.get("enabled", False) is True,
        "installation_allows": bool(getattr(settings, "org_discovery_allowed", True)),
        "external_id": external_pin or (stored_external if EXTERNAL_ID.fullmatch(stored_external) else None) or None,
        "external_id_locked": bool(external_pin),
        "ou_ids": _csv(ou_pin, OU_ID) if ou_pin else _listed(stored.get("ou_ids"), OU_ID),
        "ou_ids_locked": bool(ou_pin),
        "excludes": _csv(exclude_pin, ACCOUNT_ID) if exclude_pin else _listed(stored.get("excludes"), ACCOUNT_ID),
        "excludes_locked": bool(exclude_pin),
        # Opt-in, unlike the Identity Center sweep: a member account's stack may
        # not be deployed yet, and checking now would only record a failure the
        # administrator has not had a chance to prevent.
        "auto_validate": stored.get("auto_validate", False) is True,
        "updated_by": record.get("updated_by") or None,
        "updated_at": record.get("updated_at"),
    }


def effective(settings, repo) -> bool:
    """Sweep now? Allowed, switched on, and an ExternalId to assume roles with."""
    current = config(settings, repo)
    return bool(current["installation_allows"] and current["enabled"] and current["external_id"])
