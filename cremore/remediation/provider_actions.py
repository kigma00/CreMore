"""Actions on a credential another provider issued, by the id that provider's own list gives (P1).

The same contract as the AWS key actions (cremore.remediation.action_plans): a plan binds one exact credential in
its hash, needs an independent approval and the owner's, and runs write-then-read-back; an outcome that could not
be confirmed is only ever rechecked. The credential that acts is a provider connection's own (one with the
``remediation`` purpose, cremore.onboarding), whose secrets only the worker opens: execution and recheck are
queued (``JOB_KIND``) and the worker runs them (``run``).

A provider module (``MODULES``) says what it can act on and does it:

* ``ADAPTER_VERSION``: recorded on each plan;
* ``DISABLE_BEFORE_REVOKE`` (optional): a credential is revoked only once it is disabled (GCP keys);
* ``SUBJECT_METHODS`` (optional): the sign-in methods whose check names the acting account; a connection with one
  of them is used only once its check did;
* ``REVOKES`` (optional): what a revoke takes away when it is not the credential itself (``REVOKES_WHAT``), bound in
  the plan and named so to whoever approves;
* ``reference(entity, record) -> dict | None``: what acting needs, from the stored inventory entity and its
  current record (never a secret), with a ``hint`` naming it by identifiers only and a ``key``: the credential's
  identity at the provider alone (never where an inventory listed it), which the reservation is keyed on; None when
  it cannot act on it;
* ``actions(reference) -> tuple``: the plan actions it supports for that credential;
* ``covers(connection, reference) -> bool``: whether a remediation connection reaches it;
* ``state(connection, secrets, reference, http_client) -> "ACTIVE" | "DISABLED" | "EXPIRED" | "REVOKED" | "ABSENT"``;
* ``apply(connection, secrets, reference, action, http_client) -> None``;
* ``whoami(connection, secrets, http_client) -> str`` (optional): the account the credential acts as, as the
  connection's remediation check reports it in ``subject``; "" when the provider does not say. A plan bound to an
  account runs only while the credential still acts as that account.

They raise an error of their own with a fixed ``code`` (never text from a response) and ``refused=True`` on a write
the provider refused outright (nothing changed); a provider module does not import this package, which loads AWS's.
"""

from __future__ import annotations

import json
import re
import uuid
from contextlib import nullcontext
from importlib import import_module

JOB_KIND = "provider-credential-action"
ACTIONS = ("DISABLE_PROVIDER_CREDENTIAL", "REVOKE_PROVIDER_CREDENTIAL")
STATES = ("ACTIVE", "DISABLED", "EXPIRED", "REVOKED", "ABSENT")
# What a read-back must show for the write to count as done (a revoked credential some providers keep, others drop).
WANTED = {"DISABLE_PROVIDER_CREDENTIAL": ("DISABLED",), "REVOKE_PROVIDER_CREDENTIAL": ("REVOKED", "ABSENT")}
MODULES = {"gcp": "cremore_gcp_provider.remediation", "gitlab": "cremore_gitlab_provider.remediation",
           "notion": "cremore_notion_provider.remediation", "github": "cremore_github_provider.remediation",
           "azure_devops": "cremore_azure_provider.devops_tokens.remediation"}
# ORGANIZATION_ACCESS: an organization's grant to the credential (a GitHub fine-grained token keeps working elsewhere).
REVOKES_WHAT = ("ORGANIZATION_ACCESS",)
_NAMESPACE = uuid.UUID("5a0f3c2e-7d51-4c1b-9f0e-2b6a8d4e1c73")
_CODE = re.compile(r"[A-Z0-9_]{1,64}")
_HINT = re.compile(r"[^\x00-\x1f\x7f]{1,160}")


class ProviderActionError(Exception):
    def __init__(self, code: str, *, refused: bool = False):
        super().__init__(code)
        self.code, self.refused = code, refused


def code_of(error) -> str:
    """An error's code as CreMore keeps it: a provider module's own text never."""
    code = getattr(error, "code", None)
    return code if isinstance(code, str) and _CODE.fullmatch(code) else "PROVIDER_ACTION_ERROR"


def module(provider):
    """The provider's action module, or None when CreMore cannot act on its credentials."""
    name = MODULES.get(provider)
    return import_module(name) if name else None


def target_of(repo, entity_id) -> dict:
    """What a plan on this inventoried credential binds: the provider, the entity and what acting needs, built here
    from the stored entity (a request names only the entity)."""
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.coverage.store import CoverageError

    try:
        detail = MetadataStore(repo).entity_detail(uuid.UUID(str(entity_id)), limit=1)
    except (CoverageError, ValueError):
        raise ProviderActionError("CREDENTIAL_NOT_FOUND") from None
    entity, record = detail["entity"], detail["current_record"]
    found = module(entity["provider"])
    if found is None or record is None or entity.get("object_kind") != "credential":
        raise ProviderActionError("CREDENTIAL_NOT_ELIGIBLE")
    reference = found.reference(entity, record)
    try:
        encoded = json.dumps(reference, sort_keys=True)
    except (TypeError, ValueError):
        encoded = ""
    if (not isinstance(reference, dict) or not reference or not encoded or len(encoded) > 2000
            or not isinstance(reference.get("key"), dict) or not reference["key"]):
        raise ProviderActionError("CREDENTIAL_NOT_ELIGIBLE")
    actions = [action for action in found.actions(reference) if action in ACTIONS]
    if not actions:
        raise ProviderActionError("CREDENTIAL_NOT_ELIGIBLE")
    revokes = getattr(found, "REVOKES", None)
    return {"provider": entity["provider"], "entity_id": str(entity["id"]), "object_id": entity["object_id"],
            "origin": entity["origin"], "tenant": entity["tenant"], "reference": reference,
            "hint": _shown(reference.get("hint")), "actions": actions,
            **({"revokes": revokes} if revokes in REVOKES_WHAT else {})}


def _shown(text) -> str:
    """Text an approver reads as it is: printable, without hidden or reordering characters."""
    from cremore.domain.text import unsafe_text

    return text if isinstance(text, str) and _HINT.fullmatch(text) and not unsafe_text(text) else ""


def target_key(target: dict) -> uuid.UUID:
    """The key a plan reserves: the credential's identity at its provider, so every inventory listing the same
    credential, from wherever it listed it, shares it."""
    return uuid.uuid5(_NAMESPACE, json.dumps([target["provider"], target["origin"], target["reference"]["key"]],
                                             sort_keys=True, separators=(",", ":")))


def checked_subject(record: dict, reference: dict | None = None) -> str:
    """Who the connection's last remediation check says acts (a GitLab token's user), or ""."""
    results = (((record.get("checks") or {}).get("results") or {}).get("remediation") or {}).get("items") or []
    if record.get("target", {}).get("version") == 2:
        found = module(record["provider"])
        root = _narrow(found, record, reference) if found and reference else None
        if root is None:
            return ""
        subjects = {item["subject"] for item in results if isinstance(item, dict) and item.get("subject")
                    and item.get("target_id") == root["target_id"] and item.get("status") == "GRANTED"}
        return next(iter(subjects)) if len(subjects) == 1 else ""
    return next((item["subject"] for item in results if isinstance(item, dict) and item.get("subject")), "")


def remediation_connection(repo, target: dict) -> dict:
    """The one running provider connection with the remediation purpose that reaches this credential."""
    from cremore.onboarding.store import ProviderConnectionStore

    found = module(target["provider"])
    if found is None:
        raise ProviderActionError("CREDENTIAL_NOT_ELIGIBLE")
    matching = [record for record in ProviderConnectionStore(repo).list() if _serves(found, record, target)]
    if not matching:
        raise ProviderActionError("REMEDIATION_NOT_SET_UP")
    if len(matching) > 1:
        raise ProviderActionError("REMEDIATION_CONNECTION_AMBIGUOUS")
    record = matching[0]
    if record["auth_method"] in getattr(found, "SUBJECT_METHODS", ()) and not checked_subject(record, target["reference"]):
        # Its sign-in names the account that acts, but its check has not said which: a plan binds it, so check again.
        raise ProviderActionError("REMEDIATION_CHECK_REQUIRED")
    return record


def _serves(found, record, target) -> bool:
    from cremore.onboarding.store import active_plans

    # A credential changed since its check (``stale``) acts only once checked again.
    return (record is not None and record["provider"] == target["provider"] and record["status"] == "ACTIVE"
            and "remediation" in active_plans(record) and not (record.get("checks") or {}).get("stale")
            and _narrow(found, record, target["reference"]) is not None)


def _narrow(found, record, reference):
    from cremore.onboarding.targets import records_of

    # Several selected scopes may overlap. They still have one credential owner;
    # use the exact covering target for provider-specific endpoint validation.
    return next((root for root in records_of(record, "remediation") if found.covers(root, reference)), None)


def bound_connection(repo, target: dict) -> dict:
    """The remediation connection the plan was approved to act through, if it still does, with the same sign-in
    method and, where its check names one, the same acting account."""
    from cremore.onboarding.store import ProviderConnectionStore

    found = module(target["provider"])
    try:
        record = ProviderConnectionStore(repo).get(target.get("connection_id"))
    except (TypeError, ValueError):
        record = None
    if found is None or not _serves(found, record, target):
        raise ProviderActionError("REMEDIATION_CONNECTION_UNAVAILABLE")
    if (record["auth_method"] != target.get("auth_method")
            or checked_subject(record, target["reference"]) != target.get("subject", "")):
        raise ProviderActionError("REMEDIATION_CONNECTION_CHANGED")
    return record


class Session:
    """The worker's hands on one credential: the remediation connection's opened secrets, dropped on close."""

    def __init__(self, found, record: dict, secrets: dict, reference: dict, http_client_factory):
        self.module, self.record, self.secrets, self.reference = found, record, secrets, reference
        self.http_client_factory = http_client_factory
        # A provider whose deletion is irreversible and that offers a disable (GCP) revokes only a disabled one.
        self.disable_first = bool(getattr(found, "DISABLE_BEFORE_REVOKE", False))

    def _call(self, name, *args):
        client = self.http_client_factory()
        try:
            return getattr(self.module, name)(self.record, self.secrets, self.reference, *args, client)
        finally:
            client.close()

    def state(self) -> str:
        observed = self._call("state")
        if observed not in STATES:
            raise ProviderActionError("PROVIDER_STATE_UNKNOWN")
        return observed

    def apply(self, action: str) -> None:
        self._call("apply", action)

    def whoami(self) -> str:
        found = getattr(self.module, "whoami", None)
        if found is None:
            return ""
        client = self.http_client_factory()
        try:
            subject = found(self.record, self.secrets, client)
        finally:
            client.close()
        return subject if isinstance(subject, str) else ""

    def close(self) -> None:
        for envelope in self.secrets.values():
            if isinstance(envelope, dict):
                envelope.clear()
        self.secrets = {}


def open_session(worker, target: dict) -> Session:
    """The bound remediation connection with its secrets opened, in the worker only."""
    from cremore.onboarding.check import open_secrets

    record = bound_connection(worker.repo, target)
    try:
        secrets = open_secrets(worker, record)
    except ValueError as exc:
        raise ProviderActionError(code_of(exc) if hasattr(exc, "code") else "CREDENTIAL_UNAVAILABLE") from None
    found = module(target["provider"])
    return Session(found, _narrow(found, record, target["reference"]), secrets, target["reference"], worker.http_client_factory)


def settle(repo, settings) -> int:
    """Plans whose run ended without settling them (the job failed before the plan's own handler ran, or its lease
    ran out): one still waiting fails, one whose write started is unknown. Once a minute in the worker; returns how
    many it settled."""
    from cremore.remediation.action_plans import ActionPlanService

    open_plans = [plan for plan in repo.list_action_plans() if (plan.target or getattr(settings, "isolated_deployment", False)) and plan.status in ("QUEUED", "EXECUTING")]
    if not open_plans:
        return 0
    runs = {}
    for job in repo.list_jobs(500):  # newest first: a plan's last execution run
        payload = job.payload or {}
        if job.kind == JOB_KIND and payload.get("mode") != "recheck":
            runs.setdefault(payload.get("plan_id"), job)
    service = ActionPlanService(repo, settings)
    settled = 0
    for plan in open_plans:
        job = runs.get(str(plan.id))
        if job is not None and job.status in ("SUCCEEDED", "FAILED", "CANCELLED"):
            service.interrupted(plan.id, "worker")
            settled += 1
    return settled


class _Guarded:
    """Check the current task lease immediately before each provider operation."""
    def __init__(self, wrapped, guard):
        self.wrapped, self.guard = wrapped, guard

    def __getattr__(self, name):
        value = getattr(self.wrapped, name)
        if not callable(value) or name == "close":
            return value
        def call(*args, **kwargs):
            self.guard()
            return value(*args, **kwargs)
        return call


def run(worker, job, *, write_context=None) -> None:
    """Run provider and AWS plans through the same leased action queue."""
    from cremore.remediation import authorization
    from cremore.remediation.action_plans import ActionPlanError, ActionPlanService
    from cremore.worker.isolation import execution_role

    role = execution_role(worker.settings)
    if role not in ("mixed", "remediator"):
        raise ProviderActionError("WORKER_AUTHORITY_MISMATCH")
    payload = job.payload or {}
    mode = payload.get("mode", "execute")
    context = write_context or (lambda: nullcontext(worker.repo))
    try:
        plan = worker.repo.get_action_plan(uuid.UUID(str(payload.get("plan_id"))))
    except ValueError:
        plan = None
    if plan is not None:
        service = ActionPlanService(worker.repo, worker.settings, write_context=write_context,
                                    signed_approval=payload.get("signed_approval"), authorization_mode=mode)
        actor = str(payload.get("actor") or "")

        def guard():
            authorization.verify(worker.settings, plan, payload.get("signed_approval"), mode, repo=worker.repo)
            with context():
                pass

        def provider_session():
            guard()
            return _Guarded(open_session(worker, plan.target), guard)

        try:
            guard()
            if mode == "recheck":
                claims = authorization.verify(worker.settings, plan, payload.get("signed_approval"), mode, repo=worker.repo)
                with context() as repo:
                    authorization.consume(repo, claims)
            if plan.target:
                method = service.recheck_queued if mode == "recheck" else service.run_queued
                method(plan, actor, payload.get("plan_hash"), provider_session)
            elif mode != "recheck" and plan.status == "EXECUTING":
                service.interrupted(plan.id, actor)  # crash after write start: never retry the write
            elif mode == "recheck" or plan.status == "QUEUED":
                if mode != "recheck":
                    service._execution_gate(plan, actor, payload.get("plan_hash"),
                                            emergency=mode == "emergency", status="QUEUED")
                guard()
                adapter, rotation = worker.action_clients(plan)
                if rotation is not None:
                    # Preserve the provider's own phase guard and fence each SDK call.
                    for name in ("iam", "secrets", "sts"):
                        setattr(rotation, name, _Guarded(getattr(rotation, name), guard))
                adapter = _Guarded(adapter, guard) if adapter is not None else None
                if mode == "recheck":
                    service.recheck(plan, actor, payload.get("plan_hash"), adapter=adapter, rotation_service=rotation)
                else:
                    service.execute(plan, actor, payload.get("plan_hash"), adapter=adapter,
                                    rotation_service=rotation, emergency=mode == "emergency", queued=True)
        except ActionPlanError as exc:
            if plan.status == "QUEUED":
                service._save(plan, actor, status="FAILED", safe_error_code=exc.code)
        except Exception:
            service.interrupted(plan.id, actor)
            raise
    with context() as repo:
        repo.complete_job(job.id, objects=0, findings=0)
