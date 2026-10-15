"""Explicit projections of documented Slack admin and audit log fields, with bounded omissions.

An approved app is one row per credential its scopes imply: its bot token, the tokens users grant
it and its incoming webhook. The approved list says an app may be installed, not that it is; the
audit log's installs and removals, when read, give the state, the install date and the installer.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import UTC, datetime

from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataFact,
    MetadataProvenance,
    OperationReport,
    RecordQuality,
    metadata_text,
)

from . import AUDIT_ACTIONS, CONTRACT_VERSION, INSTALLS, REMOVALS

APP_ID = re.compile(r"A[A-Z0-9]{2,30}")
ACTOR_ID = re.compile(r"[A-Z][A-Z0-9]{2,30}")
SCOPE_IDS = {"enterprise": re.compile(r"E[A-Z0-9]{2,30}"), "workspace": re.compile(r"T[A-Z0-9]{2,30}")}
SCOPE_NAME = re.compile(r"[a-z][a-z0-9_.:-]{0,79}")
WEBHOOK_SCOPE = "incoming-webhook"
# Row prefix -> the token_type fact.
KINDS = {"bot": "bot", "user": "user", "hook": "incoming_webhook"}
DEVELOPERS = ("internal", "third_party", "slack")
ITEM_FIELDS = {"app", "scopes", "date_updated", "last_resolved_by"}
APP_FIELDS = {"id", "name", "description", "help_url", "privacy_policy_url", "app_homepage_url", "app_directory_url",
              "is_app_directory_approved", "is_internal", "developer_type", "socket_mode_enabled", "icons",
              "additional_info"}
# Kept from an approved app; the rest (descriptions, links, icons) is not credential metadata.
KEPT_APP_FIELDS = {"id", "name", "is_internal", "developer_type"}
MAX_SCOPES = 200
# An app is installed per workspace (or for the whole organization): its state is kept per place.
MAX_PLACES = 20
PLACE = re.compile(r"[ET][A-Z0-9]{2,30}|org")
LIMITATIONS = ["TOKEN_VALUES_AND_WEBHOOK_URLS_NOT_RETURNED"]
BASIS = {"audit_events": "AUDIT_LOG_WINDOW", "approved_apps": "APPROVED_APPS_OF_DECLARED_SCOPE",
         "installed_apps": "AUDIT_LOG_INSTALLS_NOT_IN_APPROVED_LIST"}
ROW_FACTS = {"app_id", "name", "token_type", "scopes", "developer_type", "is_internal", "approved_at", "approved_by",
             "created_at", "added_by", "last_change", "last_change_at"}


def safe_text(value, *, bearer="", max_length=512):
    if not isinstance(value, str) or not value or len(value) > max_length or (bearer and bearer in value):
        raise ValueError("SLACK_UNSAFE_METADATA")
    return metadata_text(value)  # refuses control characters and anything shaped like a credential


def seconds(value):
    """Slack's times are Unix seconds."""
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
            or not 0 <= value <= 253402300799):
        raise ValueError("SLACK_INVALID_TIME")
    return int(value)


def iso(value):
    return datetime.fromtimestamp(seconds(value), UTC).isoformat(timespec="seconds")


def scope_id(scope):
    pattern = SCOPE_IDS.get(scope.kind)
    if pattern is None or not pattern.fullmatch(scope.id):
        raise ValueError("SLACK_SCOPE_INVALID")
    return scope.id


def operation(source):
    return "slack." + source


def resource(scope, source):
    return scope.kind + ":" + scope.id + "/" + source


def provenance(scope, source, observed_at):
    return MetadataProvenance(operation=operation(source), observed_at=observed_at,
                              resource_id=resource(scope, source), contract_version=CONTRACT_VERSION)


def _unknown(row, allowed, path):
    # Provider-controlled field names can themselves hold secrets: only their hash is kept.
    return [("field/" + hashlib.sha256((path + str(key)).encode()).hexdigest(), "UNAPPROVED_METADATA_FIELD")
            for key in sorted(map(str, row.keys() - allowed))]


def _scope_names(values, omitted, path):
    names = set()
    for value in values if isinstance(values, list) else []:
        if isinstance(value, str) and SCOPE_NAME.fullmatch(value):
            names.add(value)
        else:
            omitted.append((path, "INVALID_METADATA_VALUE"))
    return sorted(names)[:MAX_SCOPES]


def approved_app(item, *, bearer=""):
    """``(app, omitted)`` from one ``admin.apps.approved.list`` entry: the app, its scopes by token
    type and who approved it when. ``omitted`` names what was not kept and why."""
    if not isinstance(item, dict) or not isinstance(item.get("app"), dict) or not isinstance(item.get("scopes"), list):
        raise TypeError("SLACK_INVALID_APP")
    source = item["app"]
    omitted = _unknown(item, ITEM_FIELDS, "") + _unknown(source, APP_FIELDS, "app/")
    if not isinstance(source.get("id"), str) or not APP_ID.fullmatch(source["id"]):
        raise ValueError("SLACK_INVALID_APP_ID")
    try:
        name = safe_text(source.get("name"), bearer=bearer)
    except ValueError:
        # A name that could not be kept (empty, too long, shaped like a credential) is not reflected.
        name = source["id"]
        omitted.append(("app/name", "INVALID_METADATA_VALUE"))
    app = {"id": source["id"], "name": name}
    if source.get("developer_type") in DEVELOPERS:
        app["developer_type"] = source["developer_type"]
    if isinstance(source.get("is_internal"), bool):
        app["is_internal"] = source["is_internal"]
    by_type = {"bot": [], "user": []}
    for scope in item["scopes"]:
        if not isinstance(scope, dict):
            omitted.append(("scopes", "INVALID_METADATA_VALUE"))
            continue
        # Other token types (an app-level token) are not a credential this inventory lists.
        if scope.get("token_type") in by_type:
            by_type[scope["token_type"]].append(scope.get("name"))
    app["scopes"] = {kind: _scope_names(names, omitted, "scopes") for kind, names in by_type.items()}
    if "date_updated" in item:
        try:
            app["approved_at"] = iso(item["date_updated"])
        except ValueError:
            omitted.append(("date_updated", "INVALID_METADATA_TIME"))
    resolver = item.get("last_resolved_by")
    if isinstance(resolver, dict) and isinstance(resolver.get("actor_id"), str) and ACTOR_ID.fullmatch(resolver["actor_id"]):
        kind = resolver.get("actor_type")
        app["approved_by"] = {"id": resolver["actor_id"], "type": kind if kind in ("user", "app", "system") else "unknown"}
    elif resolver is not None:
        omitted.append(("last_resolved_by", "INVALID_METADATA_VALUE"))
    return app, omitted


def audit_event(entry, scope, *, bearer=""):
    """``(app_id, event)`` for an audit log entry about an app in ``scope``; None for anything else."""
    if not isinstance(entry, dict):
        raise TypeError("SLACK_INVALID_AUDIT_ENTRY")
    entity = entry.get("entity")
    if (entry.get("action") not in AUDIT_ACTIONS or not isinstance(entity, dict) or entity.get("type") != "app"
            or not isinstance(entity.get("app"), dict)):
        return None
    app = entity["app"]
    if not isinstance(app.get("id"), str) or not APP_ID.fullmatch(app["id"]):
        raise ValueError("SLACK_INVALID_APP_ID")
    location = (entry.get("context") or {}).get("location") if isinstance(entry.get("context"), dict) else None
    if (scope.kind == "workspace" and isinstance(location, dict) and location.get("type") == "workspace"
            and location.get("id") != scope.id):
        return None  # another workspace of the organization
    where = location.get("id") if isinstance(location, dict) else None
    event = {"action": entry["action"], "at": seconds(entry.get("date_create")), "name": None, "actor": None,
             "bot": None, "user": None,
             "where": where if isinstance(where, str) and PLACE.fullmatch(where) and where != "org" else "org"}
    try:
        event["name"] = safe_text(app.get("name"), bearer=bearer)
    except ValueError:
        pass
    actor = entry.get("actor")
    user = actor.get("user") if isinstance(actor, dict) and actor.get("type") == "user" else None
    if (isinstance(user, dict) and isinstance(user.get("id"), str) and ACTOR_ID.fullmatch(user["id"])
            and user["id"] not in ("USLACKUSER", "USLACKSECURITY")):
        event["actor"] = {"id": user["id"]}
        try:
            event["actor"]["name"] = safe_text(user.get("name"), bearer=bearer, max_length=200)
        except ValueError:
            pass
    omitted = []
    if isinstance(app.get("bot_scopes"), list):
        event["bot"] = _scope_names(app["bot_scopes"], omitted, "bot_scopes")
    if isinstance(app.get("scopes"), list):
        event["user"] = _scope_names(app["scopes"], omitted, "scopes")
    return app["id"], event


def places(text):
    """``{place: signed seconds}`` from a summary's ``w``: positive for an install, negative for a removal."""
    out = {}
    for part in text.split(";") if text else ():
        place, _, value = part.partition("=")
        out[place] = int(value)
    return out


def _place_text(found):
    return ";".join(f"{place}={value}" for place, value in sorted(found.items()))


def merge(summary, event):
    """Fold one audit event into an app's summary (``{}`` for a new app); the order events arrive in does not matter.

    Keys: n/na (name and when it was seen), b/ba and u/ua (bot and user scopes, comma-joined), i/iu/in (latest install,
    installer id and name), w (each place's latest install or removal), s/sa (installed while any place is, else
    removed; when that last changed), l/la (latest event)."""
    at = event["at"]
    # Each fact comes from the newest event that carries it.
    if event["name"] and at >= summary.get("na", -1):
        summary["n"], summary["na"] = event["name"], at
    for key, found in (("b", event["bot"]), ("u", event["user"])):
        if found is not None and at >= summary.get(key + "a", -1):
            summary[key], summary[key + "a"] = ",".join(found), at
    if event["action"] in INSTALLS and at >= summary.get("i", -1):
        summary["i"] = at
        summary.pop("iu", None)
        summary.pop("in", None)
        if event["actor"]:
            summary["iu"] = event["actor"]["id"]
            if event["actor"].get("name"):
                summary["in"] = event["actor"]["name"]
    if event["action"] in INSTALLS + REMOVALS:
        found = places(summary.get("w", ""))
        signed = (at + 1) * (1 if event["action"] in INSTALLS else -1)  # +1 keeps the sign at second 0
        where = event["where"]
        if where not in found and len(found) >= MAX_PLACES:
            # Full: an older removal makes room; installed places are never dropped, so "installed" stays true.
            removed = [place for place, value in found.items() if value < 0]
            if removed:
                del found[min(removed, key=lambda place: -found[place])]
        if (where in found or len(found) < MAX_PLACES) and abs(signed) >= abs(found.get(where, 0)):
            found[where] = signed
        if found:
            summary["w"] = _place_text(found)
            summary["s"] = "installed" if any(value > 0 for value in found.values()) else "removed"
            summary["sa"] = max(abs(value) for value in found.values()) - 1
    if at >= summary.get("l", -1):
        summary["l"], summary["la"] = at, event["action"]
    return summary


def audit_app(app_id, summary):
    """An app the audit log shows installed, in the shape ``approved_app`` gives."""
    return {"id": app_id, "name": summary.get("n") or app_id,
            "scopes": {"bot": [name for name in summary.get("b", "").split(",") if name],
                       "user": [name for name in summary.get("u", "").split(",") if name]}}


def rows(spec, scope, source, app, audit, *, observed_at, omitted=()):
    """One observation per credential ``app`` holds in ``scope``, with what the audit log says of it."""
    audit = audit or {}
    state = audit.get("s")
    # A window can miss older installs elsewhere; only this scope's own removal proves absence.
    if state == "removed" and places(audit.get("w", "")).get(scope.id, 0) >= 0:
        state = None
    provider_state = "INSTALLED" if state == "installed" else "UNINSTALLED" if state == "removed" else "APPROVED"
    normalized = {"INSTALLED": "ACTIVE", "UNINSTALLED": "REVOKED", "APPROVED": "UNKNOWN"}[provider_state]
    bot, user = app["scopes"]["bot"], app["scopes"]["user"]
    hook = [WEBHOOK_SCOPE] if WEBHOOK_SCOPE in bot or WEBHOOK_SCOPE in user else []
    out = []
    for kind, names in (("bot", bot), ("user", user), ("hook", hook)):
        if not names:
            continue
        writer = FactWriter()
        for path, reason in omitted:
            writer.omit(path, reason)
        fields = {"app_id": app["id"], "name": app["name"], "token_type": KINDS[kind]}
        if kind != "hook":  # a webhook's reach is its channel, which is not given
            fields["scopes"] = list(names)
        for key in ("developer_type", "is_internal", "approved_at", "approved_by"):
            if key in app:
                fields[key] = app[key]
        # A bot token and a webhook are made when the app is installed; each user grants their own token.
        if kind != "user" and "i" in audit:
            fields["created_at"] = iso(audit["i"])
            if "iu" in audit:
                fields["added_by"] = {"id": audit["iu"], **({"name": audit["in"]} if "in" in audit else {})}
        if "l" in audit:
            fields["last_change_at"], fields["last_change"] = iso(audit["l"]), audit["la"]
        out.append(EntityObservation(
            scope=scope, purpose="issuer_inventory",
            identity=EntityIdentity(provider="slack", origin=spec.origin, tenant=spec.tenant,
                                    tenant_confirmed=spec.tenant_confirmed, kind="credential",
                                    object_id=f"{kind}:{scope.id}:{app['id']}"),
            provenance=provenance(scope, source, observed_at), facts=writer.facts(fields),
            omissions=writer.omissions, provider_state=provider_state, normalized_state=normalized,
            state_basis="PROVIDER_REPORTED" if state else "UNKNOWN"))
    return out


def report(scope, source, *, observed_at, status, reasons=(), pages=0, received=0, saved=0, invalid=0,
           duplicates=0, complete=False, window=None):
    return OperationReport(
        scope=scope, provenance=provenance(scope, source, observed_at), status=status,
        reasons=sorted({*LIMITATIONS, *reasons}), pages=pages, received_records=received, saved_records=saved,
        proves_completeness=complete, shape="array", native_schema_version="web-api",
        report_type="slack_admin_source_report", collection_mode="inventory",
        window_start=iso(window[0]) if window else None, window_end=iso(window[1]) if window else None,
        record_quality=RecordQuality(records=received, identified=saved, invalid_records=invalid, duplicates=duplicates),
        facts=[MetadataFact(name="coverage_basis", value=BASIS[source])],
    )


def record_values(record):
    return unpack_facts(record.get("facts", []))
