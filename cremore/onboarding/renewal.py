"""Credentials the worker renews itself (a Microsoft app certificate CreMore made, a GitLab token that rotates
itself): the worker's sweep.

A provider module answers ``renew_due(record, kept, now)`` -- ``"renew"``, another action of its own
(``"retire"`` an old certificate, ``"inspect"`` a token's expiry) or None -- and does it in
``renew(record, envelope, action, kept, context)``. A module whose provider revokes the old credential the moment
it issues the next (``RENEWAL_REVOKES_OLD``, GitLab) has the attempt marked before it starts: a rotation that was
interrupted, or whose outcome is uncertain, is never tried again with the old credential (GitLab would revoke the
whole token family) and waits for a person's new credential.
Renewing makes the next credential at the provider with the current one; this module seals it and, in one
transaction, keeps its public part (``target.generated``), re-points every owned record at it and carries the
approved scan scopes over to it (the same app with the same permissions: an approval bound to the credential
would otherwise wait for a person), through the connection's compare-and-set, so a credential an admin changed
meanwhile is never overwritten; then asks for a new permission check. The old credential is retired only once
every owned record is on the new one. What the module asks to keep for later (the old certificate to retire)
and how the last attempt went are kept in ``checks.renewal``; no secret is kept there or logged. Renewals,
failures and retirements are audited. One replica sweeps per slot, for connections that are running
(``ACTIVE``).
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
import uuid
from dataclasses import dataclass

from cremore.onboarding import catalog, children
from cremore.onboarding.store import ProviderConnectionConflict, ProviderConnectionStore, atomic

SWEEP_KEY = "onboarding:credential-renewal"
SWEEP_SECONDS = 3600
# An attempt marked RUNNING this long ago was interrupted (the worker stopped mid-way).
INTERRUPTED_AFTER = _dt.timedelta(hours=1)
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,80}")
logger = logging.getLogger(__name__)


@dataclass
class RenewalContext:
    """What a provider's ``renew`` may use: an HTTP client factory and the sweep's time."""

    http_client: object
    now: _dt.datetime


def _iso(value):
    return value.astimezone(_dt.UTC).isoformat()


def _code(exc) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and _CODE.fullmatch(code) else "CREDENTIAL_RENEWAL_FAILED"


def _audit(repo, record, action, note):
    from cremore.domain.models import FindingEvent

    repo.record_finding_event(FindingEvent(target_type="provider_connection", target_id=uuid.UUID(str(record["id"])),
                                           actor="worker", event_type=action, note=note))


def sweep(repo, settings, resolver, http_client_factory, *, now=None, execution_role=None) -> int:
    """Renew or retire what is due; returns how many connections were acted on."""
    now = now or _dt.datetime.now(_dt.UTC)
    from cremore.secretstore.isolation import binding_for_record

    role = execution_role or settings.worker_execution_role
    if settings.isolated_deployment and role not in ("collector", "remediator"):
        return 0
    if not settings.isolated_deployment and not repo.claim_slot(SWEEP_KEY, int(now.timestamp()) // SWEEP_SECONDS, "worker"):
        return 0
    groups = {}
    ring = settings.credential_sealing_keys if settings.isolated_deployment else None
    acted = 0
    for record in ProviderConnectionStore(repo).list():
        if settings.isolated_deployment:
            binding = binding_for_record(record)
            if binding["purpose"] != role or not ring.can_open(binding):
                continue
            group = ring.group_id(binding)
            if group not in groups:
                groups[group] = repo.claim_slot(SWEEP_KEY + ":" + group, int(now.timestamp()) // SWEEP_SECONDS, "worker")
            if not groups[group]:
                continue
        if record["status"] != "ACTIVE":
            continue
        try:
            module = catalog.module(record["provider"])
        except catalog.CatalogError:
            continue
        due = getattr(module, "renew_due", None)
        note = (record.get("checks") or {}).get("renewal") or {}
        if note.get("state") == "RUNNING":
            try:
                began = _dt.datetime.fromisoformat(str(note.get("at")))
            except ValueError:
                began = now - INTERRUPTED_AFTER
            if now - began >= INTERRUPTED_AFTER:
                _note(repo, record, now, state="FAILED", action=note.get("action"), code="RENEWAL_INTERRUPTED")
            continue
        if getattr(module, "RENEWAL_REVOKES_OLD", False) and _uncertain(note.get("code")):
            continue  # the stored credential may be revoked: only a person's new one goes on
        action = due(record, note.get("keep"), now) if callable(due) else None
        if not isinstance(action, str) or not action:
            continue
        acted += 1
        try:
            run(repo, settings, record, action, resolver, http_client_factory, now=now)
        except Exception as exc:  # noqa: BLE001 -- one connection's failure never stops the others' renewals
            logger.warning("credential %s of provider connection %s failed: %s", action, record["id"], type(exc).__name__)
            _note(repo, record, now, state="FAILED", action=action, code=_code(exc))
    return acted


def _uncertain(code) -> bool:
    return isinstance(code, str) and (code == "RENEWAL_INTERRUPTED" or code.endswith("_UNCERTAIN"))


def _note(repo, record, now, **note):
    """How the attempt went, kept on the connection without touching its credential or target; a failure is
    audited too."""
    store = ProviderConnectionStore(repo)
    for _attempt in range(3):
        current = store.get(record["id"])
        if current is None or current["secret_refs"] != record["secret_refs"]:
            return  # a new credential: this attempt is no longer its story
        checks = dict(current.get("checks") or {})
        checks["renewal"] = {**(checks.get("renewal") or {}), **note, "at": _iso(now)}
        try:
            store.update(current["id"], current["revision"], "worker", checks=checks)
            break
        except ProviderConnectionConflict:
            continue
    if note.get("state") == "FAILED":
        _audit(repo, record, "PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED", f"{note.get('action')} {note.get('code')}")


def _approvals_before(repo, record):
    """Each owned content source as it is now (a copy), for its authorization revision."""
    out = {}
    for link in ProviderConnectionStore(repo).children(record["id"]):
        source = repo.get_connection(uuid.UUID(link["child_id"])) if link["kind"] == "content" else None
        if source is not None:
            out[link["child_id"]] = source.model_copy(deep=True)
    return out


def _carry_approvals(repo, before):
    """Approved scan scopes of the owned content sources follow them to the renewed credential: the approval
    was bound to the old credential's reference (cremore.scanning.scope.auth_revision), which only a renewal of the
    same principal changed. The revision it moves to is the old one's with the new reference, which the source has
    again once its credential check (queued by the re-pointing) says who it is."""
    from cremore.scanning import scope

    for child_id, source in before.items():
        renewed = repo.get_connection(uuid.UUID(child_id))
        if renewed is None:
            continue
        old = scope.auth_revision("source", source)
        new = scope.auth_revision("source", source.model_copy(update={"secret_ref": renewed.secret_ref}))
        if new == old:
            continue
        for profile in repo.list_scope_profiles("source", renewed.id):
            if profile.auth_revision == old:
                repo.update_scope_profile(profile.id, auth_revision=new)


def run(repo, settings, record, action, resolver, http_client_factory, *, now=None):
    """One renewal (``renew``) or retirement (``retire``) of ``record``'s credential; returns the connection as
    it is afterwards, or None when nothing changed."""
    from cremore.onboarding.service import request_check
    from cremore.secretstore.isolation import binding_for_record
    from cremore.secretstore.sealed import seal_fields

    now = now or _dt.datetime.now(_dt.UTC)
    module = catalog.module(record["provider"])
    kept = ((record.get("checks") or {}).get("renewal") or {}).get("keep")
    store = ProviderConnectionStore(repo)
    if action == "retire":
        # The old credential goes only once every owned record is on the new one.
        links = store.children(record["id"])
        if not all(children.points_at_credential(repo, record, link) for link in links if link["secret_slots"]):
            children.repoint(repo, record, "worker")
            _note(repo, record, now, state="FAILED", action=action, code="RECORDS_NOT_ON_THE_NEW_CREDENTIAL")
            return None
    try:
        bound_resolver = resolver.bound(binding_for_record(record)) if settings.isolated_deployment else resolver
        envelope = bound_resolver.resolve(record["secret_refs"]["credential"])
        if not isinstance(envelope, dict):
            raise TypeError
    except Exception:  # noqa: BLE001 -- a resolver error can carry the value; only a code is kept
        _note(repo, record, now, state="FAILED", action=action, code="CREDENTIAL_UNAVAILABLE")
        return None
    if action == "renew" and getattr(module, "RENEWAL_REVOKES_OLD", False):
        # Marked before the provider is asked: if this stops half-way the old credential is never used again.
        _note(repo, record, now, state="RUNNING", action=action, code=None)
    try:
        result = module.renew(record, envelope, action, kept, RenewalContext(http_client_factory, now)) or {}
    except Exception as exc:  # noqa: BLE001 -- one connection's failure is its own note, as a code
        _note(repo, record, now, state="FAILED", action=action, code=_code(exc))
        logger.warning("credential %s of provider connection %s failed: %s", action, record["id"], _code(exc))
        return None
    finally:
        envelope.clear()
    if action != "renew":
        _note(repo, record, now, state="OK", action=action, code=None, keep=result.get("keep"))
        if action == "retire":
            retired = ((kept or {}).get("retire") or {}).get("thumbprint")
            _audit(repo, record, "PROVIDER_CONNECTION_CREDENTIAL_RETIRED", retired or action)
        return None
    made = result["credential"]
    try:
        sealed = seal_fields(settings.credential_sealing_keys, made,
                             binding=binding_for_record(record) if settings.isolated_deployment else None)
    finally:
        made.clear()
    for _attempt in range(3):
        current = store.get(record["id"])
        if current is None or current["secret_refs"] != record["secret_refs"]:
            # An admin replaced the credential meanwhile; theirs stays. What the provider just issued is not kept
            # anywhere now and expires on its own.
            logger.warning("provider connection %s changed credential during renewal; the renewed one is dropped",
                           record["id"])
            return None
        before = _approvals_before(repo, current)
        checks = dict(current.get("checks") or {})
        checks["renewal"] = {"state": "OK", "action": action, "code": None, "at": _iso(now), "renewed_at": _iso(now),
                             "keep": result.get("keep")}
        try:
            with atomic(repo) as bound:
                updated = ProviderConnectionStore(bound).update(
                    current["id"], current["revision"], "worker", secret_refs={**current["secret_refs"], "credential": sealed},
                    target={**current["target"], **({"generated": result["generated"]} if "generated" in result else {})},
                    checks=checks)
                children.repoint(bound, updated, "worker")  # one left behind is re-pointed before the retirement
                _carry_approvals(bound, before)
            break
        except ProviderConnectionConflict:
            continue
    else:
        return None
    _audit(repo, updated, "PROVIDER_CONNECTION_CREDENTIAL_RENEWED", updated["auth_method"])
    return request_check(repo, updated["id"], "worker")
