"""Step 3 of the wizard, run by the worker: does the credential hold what each purpose needs?

The provider module answers per permission (GRANTED, MISSING, NOT_REPORTED when the
provider does not say for this credential type, ERROR when the question itself failed)
with an optional ``subject`` (an account or an organization) and a stable ``detail`` code.
Only those answers are stored: no secret, no response body, no exception text.

A result is kept only if the connection is still what was checked (same method,
credential references, purposes and target); otherwise a newer check owns the answer.

The check also keeps keyed digests of what the credential is (``credential_marks``): a token, a GitHub App, the
worker's own Google identity. Equal marks say two connections hold one credential, which the console warns about
when one of them acts (cremore.onboarding.service.shared_credentials); a mark is never shown.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import logging
import re
from contextlib import nullcontext
from dataclasses import dataclass, field

from cremore.onboarding import catalog
from cremore.onboarding.service import check_digest
from cremore.onboarding.store import ProviderConnectionConflict, ProviderConnectionStore

_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,80}")
_SUBJECT = re.compile(r"[^\x00-\x1f\x7f]{1,256}")
MAX_ITEMS = 2000
_MARK_CONTEXT = b"cremore-credential-mark-v1"
BACKFILL_KEY = "onboarding:credential-marks"  # one worker replica a minute
BACKFILL_ACTOR = "system:onboarding"
RETRY = _dt.timedelta(days=1)

logger = logging.getLogger(__name__)


@dataclass
class CheckContext:
    """What a provider check may use; it never receives the repository's writers."""

    repo: object
    settings: object
    http_client: object
    aws_role_checker: object = None
    aws_sessions: object = None
    children: list = field(default_factory=list)
    # A fenced write (the job's lease) for state a provider keeps up to date while
    # checking, such as an AWS account's scanner validation.
    write: object = None
    # Shared by the purposes of one check: an answer every purpose needs is asked once.
    memo: dict = field(default_factory=dict)
    before_request: object = None


def _code(exc) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and _CODE.fullmatch(code) else type(exc).__name__.upper()[:80]


def clean(items, permissions) -> list[dict]:
    """The provider's answers, restricted to the permissions the purpose declares."""
    known = {permission["id"] for permission in permissions}
    out = []
    for item in list(items or [])[:MAX_ITEMS]:
        if not isinstance(item, dict) or item.get("permission") not in known:
            continue
        status = item.get("status")
        if status not in catalog.CHECK_STATUSES:
            continue
        row = {"permission": item["permission"], "status": status}
        detail = item.get("detail")
        if isinstance(detail, str) and _CODE.fullmatch(detail):
            row["detail"] = detail
        subject = item.get("subject")
        if isinstance(subject, str) and _SUBJECT.fullmatch(subject):
            row["subject"] = subject
        out.append(row)
    answered = {row["permission"] for row in out}
    out.extend({"permission": permission, "status": "NOT_REPORTED", "detail": "NOT_CHECKED"}
               for permission in sorted(known - answered))
    return out


def summary(items) -> str:
    statuses = {item["status"] for item in items}
    for status in ("MISSING", "ERROR", "NOT_REPORTED"):
        if status in statuses:
            return status
    return "PASSED"


def open_secrets(worker, record) -> dict:
    """The credential envelopes, resolved only in the worker and only for this check (or one approved action,
    cremore.remediation.provider_actions); the caller clears them."""
    resolver = getattr(worker, "metadata_secret_resolver", None)
    if resolver is not None and (getattr(getattr(worker, "settings", None), "isolated_deployment", False)
                                or any(str(ref).startswith("sealed:v3:")
                                       for ref in (record.get("secret_refs") or {}).values())):
        from cremore.secretstore.isolation import binding_for_record

        resolver = resolver.bound(binding_for_record(record))
    out = {}
    for role, ref in (record.get("secret_refs") or {}).items():
        if resolver is None:
            raise ValueError("SECRET_RESOLVER_UNAVAILABLE")
        try:
            data = resolver.resolve(ref)
        except Exception:  # noqa: BLE001 -- a resolver error can carry the value; only a code leaves
            raise _Unavailable("CREDENTIAL_UNAVAILABLE") from None
        if not isinstance(data, dict):
            raise _Unavailable("CREDENTIAL_UNAVAILABLE")
        out[role] = data
    return out


class _Unavailable(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def credential_marks(settings, record, secrets, module, context) -> list[str] | None:
    """Keyed digests of what acts: the provider's ``credential_identity(connection, secrets, context)`` when it
    has one (an App, an account), else every stored role's token. None when it could not be told this time (the
    last marks of the same credential stand)."""
    try:
        found = getattr(module, "credential_identity", None)
        names = found(record, secrets, context) if callable(found) else None
        if names is None:  # the stored roles only: a check may have kept a short-lived access token beside them
            names = ["token:" + value for role in record.get("secret_refs") or {} if isinstance(secrets.get(role), dict)
                     for value in (secrets[role].get("token"), secrets[role].get("access_token"))
                     if isinstance(value, str) and value]
        if not isinstance(names, (list, tuple)):
            return None
        key = hmac.new(settings.fingerprint_key_bytes, _MARK_CONTEXT, hashlib.sha256).digest()
        return sorted({hmac.new(key, name.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
                       for name in names if isinstance(name, str) and name})
    except Exception as exc:  # noqa: BLE001 -- an identity not read is no answer, never a failed check
        logger.info("credential identity not read: %s", type(exc).__name__)
        return None


def _may_act(provider) -> bool:
    """Only a provider that offers the remediation purpose can share a credential with an acting integration."""
    try:
        return "remediation" in catalog.descriptor(provider)["purposes"]
    except catalog.CatalogError:
        return False


def _unmarked(record, now: _dt.datetime) -> bool:
    checks = record.get("checks") or {}
    if not checks.get("results"):
        return False
    if "credential_marks" not in checks:
        return True  # checked before checks kept marks
    checked = checks.get("checked_at")
    try:
        # A check that could not tell (an outage) is asked again a day later, not every minute.
        return bool(checks.get("credential_marks_unknown")) and now - _dt.datetime.fromisoformat(checked) >= RETRY
    except (TypeError, ValueError):
        return False


def backfill_marks(repo, now: _dt.datetime, limit: int = 5) -> int:
    """Integrations whose check has not told what their credential is -- checked before checks kept credential marks,
    or a day after one that could not tell -- are checked once more, a few a minute, so one credential that collects
    and acts is told for them too. Returns how many were asked for."""
    from cremore.onboarding.service import request_check
    from cremore.onboarding.sessions import expire

    expire(repo, now)

    due = [record for record in ProviderConnectionStore(repo).list() if record["status"] != "DISABLED"
           and _may_act(record["provider"]) and _unmarked(record, now)]
    if not due or not repo.claim_slot(BACKFILL_KEY, int(now.timestamp()) // 60, BACKFILL_ACTOR):
        return 0
    for record in due[:limit]:
        try:
            request_check(repo, record["id"], BACKFILL_ACTOR)  # a check already queued or running is left alone
        except (ProviderConnectionConflict, ValueError):
            continue  # changed meanwhile: the next minute looks again
    return min(len(due), limit)


def run(worker, job, *, write_context=None) -> None:
    payload = job.payload or {}
    if payload.get("onboarding_session_id"):
        from cremore.onboarding.sessions import run as run_session

        return run_session(worker, job, write_context=write_context)
    store = ProviderConnectionStore(worker.repo)
    record = store.get(payload.get("provider_connection_id"))
    if record is not None and (record["status"] == "DISABLED" or check_digest(record) != payload.get("digest")):
        record = None  # never open a newer credential for an obsolete check
    results, error, marks = {}, None, None  # marks not told when the credential could not be opened
    if record is not None:
        module = catalog.module(record["provider"])
        context = CheckContext(repo=worker.repo, settings=worker.settings,
                               http_client=getattr(worker, "http_client_factory", None),
                               aws_role_checker=getattr(worker, "aws_role_checker", None),
                               aws_sessions=getattr(worker, "aws_sessions", None),
                               children=store.children(record["id"]),
                               write=write_context or (lambda: nullcontext(worker.repo)))
        try:
            secrets = open_secrets(worker, record)
        except ValueError as exc:
            secrets, error = None, _code(exc)
        results = evaluate(record, secrets, context, error=error)
        if secrets is not None:
            try:
                marks = credential_marks(worker.settings, record, secrets, module, context)
            finally:
                for envelope in secrets.values():
                    envelope.clear()
    with write_context() if write_context else nullcontext(worker.repo) as repo:
        if record is not None:
            _store_results(repo, record, payload.get("digest"), results, error, marks)
        repo.complete_job(job.id, objects=0, findings=0)


def evaluate(record, secrets, context, *, error=None):
    """The same read-only access check for drafts and permanent connections."""
    from cremore.onboarding.targets import records_of

    module = catalog.module(record["provider"])
    results = {}
    for purpose in record["purposes"]:
        combined = []
        for root in records_of(record, purpose):
            permissions = catalog.permissions_for(root["provider"], purpose, root["auth_method"], root["target"])
            if secrets is None:
                items = [{"permission": p["id"], "status": "ERROR", "detail": error} for p in permissions]
            else:
                try:
                    items = clean(module.check(root, purpose, secrets, context), permissions)
                except Exception as exc:  # noqa: BLE001 -- no provider exception text is retained
                    items = [{"permission": p["id"], "status": "ERROR", "detail": _code(exc)} for p in permissions]
            combined.extend({**item, **({"target_id": root["target_id"]} if root.get("target_id") else {})}
                            for item in items)
        results[purpose] = {"status": summary(combined), "items": combined}
    return results


def _store_results(repo, record, digest, results, error, marks=()):
    store = ProviderConnectionStore(repo)
    for _attempt in range(3):
        current = store.get(record["id"])
        if current is None or check_digest(current) != digest:
            return  # the connection changed since this check was asked for
        before = current["checks"] or {}
        stored, unknown = marks, False
        if marks is None:  # not told this time: what the last check of this very credential found stands
            kept = before.get("credential_marks") if before.get("digest") == digest else None
            unknown = not isinstance(kept, list)  # nothing to keep: asked again a day later (backfill_marks)
            stored = [] if unknown else kept
        checks = {**before, "results": results, "digest": digest, "stale": False,
                  "checked_at": _dt.datetime.now(_dt.UTC).isoformat(), "error": error,
                  "credential_marks": list(stored), "credential_marks_unknown": unknown}
        status = "CHECKED" if current["status"] in ("DRAFT", "CHECKING", "CHECKED") else current["status"]
        try:
            store.update(current["id"], current["revision"], "worker", checks=checks, status=status)
            return
        except ProviderConnectionConflict:
            continue  # renamed meanwhile: the digest still matches, so try again
