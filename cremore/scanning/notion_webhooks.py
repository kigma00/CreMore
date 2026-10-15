"""Operator-confirmed Notion subscriptions on existing settings and scan receipts.

An unsigned verification challenge can only become a short-lived sealed candidate.
It cannot enable a subscription or enqueue work. An administrator must verify it
in Notion and confirm a subsequent signed probe before activation.
"""

import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta

from cremore_notion_provider import webhooks as provider

from cremore.db.settings_store import locked_settings
from cremore.domain.models import FindingEvent
from cremore.scanning import triggers
from cremore.secretstore.sealed import seal_fields, unseal

KEY = "notion_webhooks"
LOCK = "notion_webhooks:lock"
Error = provider.WebhookError


def _rows(repo):
    return dict((repo.get_setting(KEY) or {}).get("value") or {})


def _save(repo, rows, actor):
    repo.put_setting(KEY, rows, actor)


def _audit(repo, identity, actor, action):
    repo.record_finding_event(FindingEvent(target_type="notion_webhook", target_id=uuid.UUID(identity),
        actor=actor, event_type=action))


def public(repo):
    return [{k: row.get(k) for k in ("id", "profile_id", "state", "expires_at", "probe", "last_received_at")}
            for row in _rows(repo).values()]


def _profile(repo, settings, identity):
    profile, plan, target, _base, _source = triggers.prepare_trigger_plan(repo, settings, identity, "EVENT")
    if profile.kind != "source" or target.provider != "notion":
        raise Error("NOTION_WEBHOOK_PROFILE_REQUIRED")
    return profile, plan


def create(repo, settings, profile_id, actor):
    profile, _plan = _profile(repo, settings, profile_id)
    # Fail before allocating a subscription when this API cannot protect the key.
    seal_fields(settings.control_sealing_keys, {"probe": "configuration-check"})
    repo.put_setting(LOCK, {"version": 1}, "system:notion-webhook")
    with locked_settings(repo, setting_key=LOCK) as bound:
        rows = _rows(bound)
        if len(rows) >= 100:
            raise Error("NOTION_WEBHOOK_SUBSCRIPTION_LIMIT")
        identity = str(uuid.uuid4())
        row = {"id": identity, "profile_id": str(profile.id), "state": "WAITING",
               "expires_at": (datetime.now(UTC) + timedelta(minutes=30)).isoformat()}
        rows[identity] = row
        _save(bound, rows, actor)
        _audit(bound, identity, actor, "NOTION_WEBHOOK_CREATED")
    return {**row, "path": f"/api/v1/hooks/notion/{identity}"}


def challenge(repo, settings, identity):
    row = _rows(repo).get(identity)
    if row is None or row["state"] != "PENDING" or datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
        raise Error("NOTION_WEBHOOK_VERIFICATION_UNAVAILABLE")
    return {"verification_token": unseal(settings.control_sealing_keys, row["secret_ref"])["token"]}


def confirm(repo, settings, identity, actor, *, probe_digest):
    with locked_settings(repo, setting_key=LOCK) as bound:
        rows = _rows(bound)
        row = rows.get(identity)
        if (row is None or row["state"] != "PENDING" or not row.get("probe")
                or datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC)
                or probe_digest != row["probe"]["digest"]):
            raise Error("NOTION_WEBHOOK_CONFIRMATION_STALE")
        _profile(bound, settings, row["profile_id"])
        row["state"] = "ACTIVE"
        row.pop("expires_at", None)
        _save(bound, rows, actor)
        _audit(bound, identity, actor, "NOTION_WEBHOOK_CONFIRMED")
    return {"state": "ACTIVE"}


def remove(repo, identity, actor):
    with locked_settings(repo, setting_key=LOCK) as bound:
        rows = _rows(bound)
        if identity in rows:
            del rows[identity]  # Drop authentication configuration, not detection/audit history.
            _save(bound, rows, actor)
            _audit(bound, identity, actor, "NOTION_WEBHOOK_DISABLED")


def receive(repo, settings, identity, raw, signature):
    now = datetime.now(UTC)
    # Do not initialize configuration from an unauthenticated caller.
    if identity not in _rows(repo):
        raise Error("NOTION_WEBHOOK_UNKNOWN")
    with locked_settings(repo, setting_key=LOCK) as bound:
        rows = _rows(bound)
        row = rows.get(identity)
        if row is None:
            raise Error("NOTION_WEBHOOK_UNKNOWN")
        if row["state"] != "ACTIVE" and datetime.fromisoformat(row["expires_at"]) <= now:
            raise Error("NOTION_WEBHOOK_SETUP_EXPIRED")
        data = provider.body(raw)
        if set(data) == {"verification_token"}:
            candidate = provider.token(data["verification_token"])
            if row["state"] == "WAITING":
                row.update(state="PENDING", secret_ref=seal_fields(settings.control_sealing_keys, {"token": candidate}))
                _save(bound, rows, "system:notion-webhook")
            elif row["state"] != "PENDING" or not hmac.compare_digest(candidate, unseal(settings.control_sealing_keys, row["secret_ref"])["token"]):
                raise Error("NOTION_WEBHOOK_CHALLENGE_REFUSED")
            return {"accepted": True, "state": "PENDING"}
        if row["state"] == "WAITING":
            raise Error("NOTION_WEBHOOK_VERIFICATION_REQUIRED")
        event = provider.event(raw, signature, unseal(settings.control_sealing_keys, row["secret_ref"])["token"], now=now)
        probe = {key: event[key] for key in ("workspace_id", "subscription_id", "integration_id")}
        digest = hashlib.sha256(":".join(probe.values()).encode()).hexdigest()
        if row["state"] == "PENDING":
            if row.get("probe") and row["probe"]["digest"] != digest:
                raise Error("NOTION_WEBHOOK_IDENTITY_MISMATCH")
            row["probe"] = {**probe, "digest": digest}
            _save(bound, rows, "system:notion-webhook")
            return {"accepted": True, "state": "PENDING"}
        if row["state"] != "ACTIVE" or digest != row["probe"]["digest"]:
            raise Error("NOTION_WEBHOOK_IDENTITY_MISMATCH")
        _profile_row, plan = _profile(bound, settings, row["profile_id"])
        count = 0
        if event["supported"]:
            for target in provider.targets(plan, event):
                _job, created = triggers.enqueue_event(bound, settings, row["profile_id"],
                    {**target, "event_id": event["id"] + ":" + target["resource_id"]}, origin="notion:" + identity, now=now)
                count += int(created)
        row["last_received_at"] = now.isoformat()
        _save(bound, rows, "system:notion-webhook")
        # The outer transaction commits all receipts/jobs before the route returns 2xx.
        return {"accepted": True, "enqueued": count}
