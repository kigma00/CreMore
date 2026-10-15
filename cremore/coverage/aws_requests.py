"""Bounded, actor-owned AWS dashboard reads executed by the collector.

Only these named read operations are accepted. Jobs contain identifiers and
approval revisions; results contain the existing public metadata projections.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

from cremore_aws_provider import aws_access, aws_org_settings, aws_sso_settings
from cremore_aws_provider.aws_sessions import account_of_arn
from cremore_aws_provider.investigation import investigation_switches as switches

from cremore.collectors.base import CollectorError
from cremore.db.task_store import TaskStore
from cremore.domain.models import ScanJob

JOB_KIND = "aws-api-read"
OPERATIONS = {"discoverable", "discover", "secret-metadata", "secrets-inventory"}
MAX_RESULT_BYTES = 1_000_000


def declared_session(repo, settings, account_id):
    """A DB-only approval declaration. It cannot create a client or hold credentials."""
    accounts = repo.list_aws_accounts()
    if account_id is None:
        own = next((a for a in accounts if a.access == aws_access.RUNTIME_IDENTITY), None)
        account_id = own.account_id if own else None
    account = next((a for a in accounts if a.account_id == account_id), None)
    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    if account is None or approved is None:
        raise CollectorError("AWS_ACCOUNT_APPROVAL_REQUIRED")
    if refusal := aws_access.use_refusal(account, aws_access.SCANNER, approved):
        raise CollectorError(refusal)
    return SimpleNamespace(account_id=account_id,
                           pin=aws_access.validation_key(account, aws_access.SCANNER, approved["revision"]))


class DeclaredSessions:
    def __init__(self, repo, settings):
        self.repo, self.settings = repo, settings

    def open(self, account_id, purpose):
        if purpose != aws_access.SCANNER:
            raise aws_access.AccessBlocked("ACTION_REQUIRES_ISOLATED_WORKER")
        try:
            return declared_session(self.repo, self.settings, account_id)
        except CollectorError as exc:
            raise aws_access.AccessBlocked(exc.code) from None


def _target(repo, settings, operation, params):
    if operation not in OPERATIONS or not isinstance(params, dict):
        raise CollectorError("AWS_REQUEST_OPERATION_INVALID")
    if operation in ("discover", "discoverable"):
        if set(params) != {"source"} or params["source"] not in ("sso", "org"):
            raise CollectorError("AWS_REQUEST_TARGET_INVALID")
        source = params["source"]
        if not getattr(settings, "sso_discovery_allowed" if source == "sso" else "org_discovery_allowed"):
            raise CollectorError("AWS_DISCOVERY_DISABLED")
        approved = aws_access.approval(repo, aws_access.SCANNER, settings)
        if operation == "discover" and approved is None:
            raise CollectorError("IDENTITY_NOT_APPROVED")
        org = aws_org_settings.config(settings, repo)
        if operation == "discover" and source == "org" and not org["external_id"]:
            raise CollectorError("EXTERNAL_ID_NOT_SET")
        return {"source": source, "approval": approved,
                "org": org,
                "sso": aws_sso_settings.permission_set(settings, repo)}
    if not switches.effective(settings, repo, switches.SECRETS_INVENTORY):
        raise CollectorError("SECRETS_INVENTORY_OFF")
    if operation == "secret-metadata":
        if set(params) != {"kind", "id"} or params["kind"] not in ("credential", "connection"):
            raise CollectorError("AWS_REQUEST_TARGET_INVALID")
        ident = uuid.UUID(params["id"])
        if params["kind"] == "credential":
            record = repo.get_credential(ident)
            arn = record.management_reference if record else None
            if arn not in settings.secret_manager_reference_list:
                raise CollectorError("SECRET_METADATA_REFERENCE_NOT_ALLOWED")
            revision = int(record.management_revision or 0)
        else:
            record = repo.get_connection(ident)
            arn = record.secret_ref if record and record.status != "DISABLED" else None
            revision = None
        if not arn or ":secretsmanager:" not in arn:
            raise CollectorError("SECRET_METADATA_REFERENCE_UNAVAILABLE")
        account_id = account_of_arn(arn)
        target = {**params, "arn": arn, "revision": revision}
    else:
        if set(params) != {"account_id", "compact"} or type(params["compact"]) is not bool:
            raise CollectorError("AWS_REQUEST_TARGET_INVALID")
        account_id = params["account_id"]
        target = {"compact": params["compact"]}
    session = declared_session(repo, settings, account_id)
    return {**target, "account_id": session.account_id, "access_pin": session.pin}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def enqueue(repo, settings, operation, actor, params):
    if not actor:
        raise CollectorError("AWS_REQUEST_ACTOR_REQUIRED")
    target = _target(repo, settings, operation, params)
    # The same request while pending reuses its job; neither payload nor result
    # can be read through the result endpoint by another console identity.
    key = _digest([operation, params, target])
    from cremore.onboarding.store import atomic
    with atomic(repo) as bound:
        active = [job for job in bound.list_jobs(500) if job.kind == JOB_KIND
                  and job.status in ("QUEUED", "RUNNING") and job.payload.get("actor") == actor]
        old = next((job for job in active if job.payload.get("request_digest") == key), None)
        if old:
            return old
        if len(active) >= 10:
            raise CollectorError("AWS_REQUEST_LIMIT")
        return bound.enqueue_job(ScanJob(kind=JOB_KIND, payload={"operation": operation, "actor": actor,
            "params": params, "target_digest": _digest(target), "request_digest": key}))


def result(repo, request_id, actor):
    job = repo.get_job(uuid.UUID(str(request_id)))
    if job is None or job.kind != JOB_KIND or job.payload.get("actor") != actor:
        raise CollectorError("AWS_REQUEST_NOT_FOUND")
    tasks = TaskStore(repo).list_for_run(job.id)
    values = [task["result"]["aws_response"] for task in tasks
              if task["status"] == "SUCCEEDED" and (task.get("result") or {}).get("aws_response") is not None]
    if values and job.status == "SUCCEEDED":
        return "SUCCEEDED", values[0]
    code = next((t.get("error") for t in tasks if t.get("error")), None)
    return job.status, {"error_code": code or "AWS_REQUEST_FAILED"} if job.status in ("FAILED", "CANCELLED") else None


class _Client:
    def __init__(self, client, check):
        self.client, self.check = client, check

    def __getattr__(self, name):
        method = getattr(self.client, name)
        if not callable(method):
            return method
        def call(*args, **kwargs):
            self.check()
            return method(*args, **kwargs)
        return call

    def get_paginator(self, operation):
        paginator = self.client.get_paginator(operation)
        check = self.check
        class Paginator:
            def paginate(self, **kwargs):
                pages = iter(paginator.paginate(**kwargs))
                while True:
                    check()
                    try:
                        yield next(pages)
                    except StopIteration:
                        return
        return Paginator()


def _fenced_repo(repo, context, check):
    """The existing discovery reconciler commits only short fenced DB writes."""
    if getattr(repo, "engine", None) is not None:
        from cremore.db.sql import SqlRepository
        class Engine:
            dialect = repo.engine.dialect
            _task_bound = True
            @contextmanager
            def begin(self):
                with context() as bound:
                    check(bound)
                    with bound.engine.begin() as conn:
                        yield conn
            connect = begin
        wrapped = SqlRepository(Engine())
        wrapped._scan_schema_ready, wrapped.audit_key = True, repo.audit_key
        return wrapped
    class Memory:
        def __getattr__(self, name):
            value = getattr(repo, name)
            if not callable(value):
                return value
            def call(*args, **kwargs):
                with context() as bound:
                    check(bound)
                    return getattr(bound, name)(*args, **kwargs)
            return call
    return Memory()


def discoverable_view(repo, settings, source, probed):
    from cremore_aws_provider import aws_sso
    listed = probed.get("accounts") or []
    known = {a.account_id: a for a in repo.list_aws_accounts()}
    chosen = aws_sso_settings.permission_set(settings, repo)
    wanted, counts, accounts = chosen["name"] or "", {}, []
    for entry in listed:
        for role in entry.get("roles") or []:
            if aws_sso.PERMISSION_SET.fullmatch(str(role)):
                counts[str(role)] = counts.get(str(role), 0) + 1
    for entry in listed[:500]:
        account_id = str(entry.get("account_id") or entry.get("id") or "")
        roles = [str(r) for r in entry.get("roles") or []]
        record = known.get(account_id)
        selectable = not record and (bool(wanted) and wanted in roles if source == "sso" else entry.get("state") == "ACTIVE")
        accounts.append({"account_id": account_id, "name": str(entry.get("name") or account_id), "roles": roles,
                         "state": entry.get("state"), "registered": record is not None,
                         "registered_access": record.access if record else None, "selectable": bool(selectable)})
    return {"source": source, "available": bool(probed.get("available")), "reason": probed.get("reason"),
            "permission_set": wanted or None, "permission_set_locked": chosen["locked"],
            "permission_set_source": chosen["source"], "available_permission_sets": [
                {"name": name, "accounts": count} for name, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
            ] if source == "sso" else [], "start_url": probed.get("start_url"), "region": probed.get("region"),
            "external_id_configured": probed.get("external_id_configured"), "total": len(listed),
            "truncated": len(listed) > 500, "accounts": accounts}


def run(worker, job, task, context):
    from cremore.worker.isolation import execution_role
    if execution_role(worker.settings) not in ("collector", "mixed"):
        raise CollectorError("WORKER_AUTHORITY_MISMATCH")
    repo, settings, payload = worker.repo, worker.settings, job.payload
    operation, params = payload.get("operation"), payload.get("params")
    started, requests = time.monotonic(), 0

    def check(bound=None):
        nonlocal requests
        if time.monotonic() - started > 300 or requests >= 1000:
            raise CollectorError("AWS_REQUEST_BUDGET_EXCEEDED")
        target = _target(bound or repo, settings, operation, params)
        if _digest(target) != payload.get("target_digest"):
            raise CollectorError("AWS_REQUEST_SCOPE_CHANGED")
        if bound is None:
            with context():
                pass
            requests += 1
            if operation in ("discover", "discoverable") and target.get("approval") and worker.aws_identity_probe:
                current = worker.aws_identity() or {}
                if current.get("state") != "READY" or current.get("match_key") != target["approval"].get("match_key"):
                    raise CollectorError("AWS_SCANNER_IDENTITY_CHANGED")
                if (current.get("renewal_health") or {}).get("state") == "ERROR":
                    raise CollectorError("AWS_ROLES_ANYWHERE_RENEWAL_FAILED")
        return target

    target = check()
    if operation in ("discoverable", "discover"):
        output = _discover(worker, operation, target, context, check, payload["actor"])
    else:
        session = worker.aws_sessions.open(target["account_id"], aws_access.SCANNER)
        if session.pin != target["access_pin"]:
            raise CollectorError("AWS_REQUEST_SCOPE_CHANGED")
        if operation == "secret-metadata":
            from cremore_aws_provider.investigation.secret_metadata import SecretMetadataService
            arn = target["arn"]
            client = _Client(session.client("secretsmanager", arn.split(":")[3]), check)
            metadata = SecretMetadataService(client).describe(arn)
            prefix = ({"credential_id": params["id"], "reference_revision": target["revision"],
                       "match_status": "POSSIBLE_MATCH", "match_basis": "ADMIN_CONFIGURED"}
                      if params["kind"] == "credential" else {"connection_id": params["id"]})
            output = {**prefix, "secret_value_returned": False,
                      "last_access_semantics": "SECRET_STORAGE_ACCESS_NOT_CREDENTIAL_USE",
                      "observed_at": dt.datetime.now(dt.UTC).isoformat(), "metadata": metadata, **session.evidence()}
        else:
            from cremore_aws_provider.investigation import SecretsManagerService
            inv = SecretsManagerService(_Client(session.client("secretsmanager", settings.aws_region), check),
                                        region=settings.aws_region).collect()
            rows = [{"arn": s.arn, "name": s.name, "rotation_enabled": s.rotation_enabled, "stale": s.stale}
                    if target["compact"] else {key: getattr(s, key) for key in (
                        "arn", "name", "rotation_enabled", "last_rotated_at", "last_accessed_at", "created_at",
                        "next_rotation_at", "managed_by", "stale")} | {"tag_keys": list(s.tag_keys)} for s in inv.secrets]
            output = {**(session.evidence() if target["compact"] else {
                "account_id": session.account_id, "collected_via": session.via, "error_code": inv.error_code}),
                "region": inv.region, "collection_status": inv.collection_status, "total": len(inv.secrets),
                "without_rotation": len(inv.without_rotation), "secrets": rows}
    if len(json.dumps(output).encode()) > MAX_RESULT_BYTES:
        raise CollectorError("AWS_REQUEST_RESULT_LIMIT")
    with context() as bound:
        check(bound)
        TaskStore(bound).finish(task["id"], task["token"], {"aws_response": output})


def _discover(worker, operation, target, context, check, actor):
    from cremore_aws_provider import aws_sso
    from cremore_aws_provider.aws_org_discovery import list_org_accounts, reconcile_org_accounts
    from cremore_aws_provider.aws_sso_discovery import reconcile_sso_accounts
    repo, settings, source = worker.repo, worker.settings, target["source"]
    if source == "sso":
        approved = target.get("approval") or {}
        reason = ("IDENTITY_NOT_APPROVED" if not approved else
                  "NOT_AN_IDENTITY_CENTER_IDENTITY" if approved.get("kind") != "IDENTITY_CENTER" else
                  "IDENTITY_CENTER_START_URL_REQUIRED" if not approved.get("sso_start_url") else None)
        if reason:
            if operation == "discoverable":
                return discoverable_view(repo, settings, source, {"available": False, "reason": reason})
            raise CollectorError(reason)
        if worker.sso_session_factory is None:
            raise CollectorError("AWS_DISCOVERY_NOT_CONFIGURED")
        client, token = worker.sso_session_factory()
    else:
        if worker.org_client_factory is None:
            raise CollectorError("AWS_DISCOVERY_NOT_CONFIGURED")
        client, token = worker.org_client_factory(), None
    client = _Client(client, check)
    if operation == "discoverable":
        accounts = aws_sso.list_assigned(client, token) if source == "sso" else list_org_accounts(client)
        approved = target.get("approval") or {}
        return discoverable_view(repo, settings, source, {"available": True, "accounts": accounts,
            "region": approved.get("sso_region") if source == "sso" else settings.aws_region,
            "start_url": approved.get("sso_start_url") if source == "sso" else None})
    fenced = _fenced_repo(repo, context, check)
    def queue(account):
        with context() as bound:
            check(bound)
            aws_access.queue_validation(bound, account, aws_access.SCANNER, target["approval"]["revision"])
    summary = (reconcile_sso_accounts(fenced, settings, client, token, target["sso"]["name"], queue_validation=queue)
               if source == "sso" else reconcile_org_accounts(fenced, settings, client, target["org"],
                   queue_validation=queue if target["org"]["auto_validate"] else None))
    from cremore.onboarding.adoption import adopt
    with context() as bound:
        check(bound)
        adopted = adopt(bound, settings, actor)
    return {"source": source, **{k: summary.get(k) for k in ("registered", "changed", "skipped", "error")},
            "adopted": len(adopted)}
