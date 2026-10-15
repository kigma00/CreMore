"""Approved actions on another provider's credential: the plan binds it, the worker acts and reads it back (P1)."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from types import SimpleNamespace

import httpx
import pytest
from cremore_gcp_provider.metadata import normalization
from cremore_gcp_provider.metadata.adapter import ORIGIN as GCP_ORIGIN

from cremore.config import Settings
from cremore.coverage.metadata_models import (
    MetadataBatch,
    MetadataConnectionSpec,
    MetadataFinish,
    MetadataScope,
    metadata_contract,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.onboarding.store import ProviderConnectionStore
from cremore.remediation import owner_approval, provider_actions
from cremore.remediation.action_plans import ActionPlanError, ActionPlanService

PROJECT = "acme-prod-1"
EMAIL = "deploy@acme-prod-1.iam.gserviceaccount.com"
KEY = "5c" * 20
OTHER_KEY = "7d" * 20
U = lambda n: f"00000000-0000-4000-8000-{n:012d}"
GITLAB_TOKEN = "glpat-" + "Synthetic0Remediation1"  # built from parts: never a real token


def review(**overrides) -> dict:
    now = dt.datetime.now(dt.UTC)
    base = {"mode": "PLANNED", "scope_evidence_id": U(1), "recovery_evidence_id": U(2), "scope_complete": True,
            "unknown_consumers": False, "business_impact": "LIMITED", "impact_accepted": True,
            "stop_criteria_reviewed": True, "replacement_reviewed": True,
            "window_start": (now - dt.timedelta(hours=1)).isoformat(),
            "window_end": (now + dt.timedelta(hours=4)).isoformat(),
            "consumers": [{"consumer_id": U(3), "owner_id": U(4), "evidence_id": U(5), "environment": "PRODUCTION",
                           "transition": "SUCCEEDED", "authentication_basis": "NEW_CREDENTIAL",
                           "workload_succeeded": True, "scheduled_cycle_checked": True,
                           "confirmed_at": (now - dt.timedelta(hours=2)).isoformat(),
                           "valid_until": (now + dt.timedelta(hours=6)).isoformat()}]}
    base.update(overrides)
    return base


def body(action="DISABLE_PROVIDER_CREDENTIAL", **overrides) -> dict:
    return {"action_type": action, "reason_code": "EXPOSURE_CONTAINMENT", "idempotency_key": str(uuid.uuid4()),
            "operational_review": review(**({"deletion_acknowledged": True}
                                            if action == "REVOKE_PROVIDER_CREDENTIAL" else {})), **overrides}


def settings(**kw) -> Settings:
    return Settings(**{"AUTH_MODE": "oidc", "API_TOKEN": "t", "ACTION_EXECUTION_ENABLED": "true", **kw})


def service(repo, **kw) -> ActionPlanService:
    repo.put_setting(owner_approval.KEY, {"required": False}, "test")  # the owner's gate has its own tests
    return ActionPlanService(repo, settings(**kw))


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
    elif request.param == "sqlite":
        engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'p1.db').as_posix()}")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()
    else:
        yield request.getfixturevalue("pg")[1]  # the disposable cremore_test database, when one is set


# --- synthetic inventories, collected the way the providers' own collectors report them ------------------------


def _collect(repo, spec, items):
    """A run as the worker's own collection saves it (it may list the subgroups and projects it discovered)."""
    store = MetadataStore(repo)
    owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items), trusted_discovery=True)
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status="COMPLETE"))
    return owner


def gcp_inventory(repo, keys=((KEY, "service_account_user_managed_key"),), *, name="GCP · acme-prod-1") -> dict:
    """{key id: entity id} of a project collection listing ``keys``."""
    spec = MetadataConnectionSpec.model_validate({
        "schema_version": 2, "provider": "gcp", "name": name, "origin": GCP_ORIGIN, "edition": "cloud",
        "scopes": [{"kind": "project", "id": PROJECT}], "capabilities": ["inventory"], "auth_type": "adc",
        "options": {"mode": "inventory"}})
    scope = MetadataScope(kind="project", id=PROJECT)
    items = [normalization.observation(spec, scope, {
        "object_type": "credential", "credential_type": kind, "source": "gcp_iam_service_account_keys",
        "project_id": PROJECT, "source_id": f"projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{key}",
        "service_account_email": EMAIL, "key_id": key, "disabled": False}) for key, kind in keys]
    owner = _collect(repo, spec, items)
    listed = MetadataStore(repo).inventory(connection_id=owner["id"], object_kind="credential", limit=50)["items"]
    return {row["object_id"].rsplit(":", 1)[-1]: row["id"] for row in listed}


def gitlab_inventory(repo) -> dict:
    """{family: entity id} of GitLab's synthetic group collection (group 10)."""
    from cremore_gitlab_provider.metadata.tests.test_adapter import run, spec_for

    spec = spec_for()
    items = [item for page in run(spec) for item in page.records]
    owner = _collect(repo, spec, items)
    out = {}
    for row in MetadataStore(repo).inventory(connection_id=owner["id"], object_kind="credential", limit=500)["items"]:
        try:
            out.setdefault(provider_actions.target_of(repo, row["id"])["reference"]["family"], row["id"])
        except provider_actions.ProviderActionError:
            continue
    return out


def checked_as(subject) -> dict:
    """A remediation check that named the acting account."""
    return {"results": {"remediation": {"items": [{"permission": "api", "status": "GRANTED", "subject": subject}]}}}


def remediation(repo, provider="gcp", target=None, **extra) -> dict:
    # A GitLab token's check names its user (the synthetic provider's token belongs to user 77).
    record = {"provider": provider, "edition": "cloud", "name": f"{provider} remediation",
              "target": target or {"scope": "project", "project": PROJECT},
              "auth_method": {"gcp": "adc", "notion": "organization_bot"}.get(provider, "token"),
              "secret_refs": {} if provider == "gcp" else {"credential": "sealed:v2:synthetic"},
              "purposes": ["remediation"], "status": "ACTIVE", "plans": {"remediation": {}},
              **({"checks": checked_as("user:77")} if provider == "gitlab" else {}), **extra}
    return ProviderConnectionStore(repo).create(record, "admin")


class Provider:
    """A synthetic provider API: GCP's key and GitLab's token endpoints, with what each call did. Account and
    identity reads (a GCP service account, Google's token info, a GitLab token's own user) are not recorded."""

    def __init__(self, state="ACTIVE", *, write_status=None, read_status=None, visible=True, unreachable=False,
                 acting="google:admin@acme.test", self_user=77, account_project=PROJECT):
        self.state, self.write_status, self.read_status, self.requests = state, write_status, read_status, []
        self.visible, self.unreachable = visible, unreachable  # GitLab: the token's group or project; the network
        self.acting, self.self_user, self.account_project = acting, self_user, account_project

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"email": self.acting.removeprefix("google:"), "email_verified": "true"})
        if path.endswith("/personal_access_tokens/self"):
            return httpx.Response(200, json={"id": 9, "user_id": self.self_user, "active": True})
        if "googleapis" in request.url.host and "/keys/" not in path and request.method == "GET":
            email = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"projectId": self.account_project, "email": email})
        self.requests.append((request.method, path, request.headers.get("authorization")
                              or request.headers.get("private-token")))
        if self.unreachable and request.method != "GET":
            raise httpx.ConnectError("synthetic: no route")
        parts = path.split("/")
        if len(parts) == 5 and parts[3] in ("groups", "projects"):  # /api/v4/{groups|projects}/{id}
            return httpx.Response(200 if self.visible else 404, json={"id": int(parts[4])} if self.visible else {})
        if request.method == "GET":
            if self.read_status:
                return httpx.Response(self.read_status, json={})
            if self.state == "ABSENT":
                return httpx.Response(404, json={})
            if "googleapis" in request.url.host:
                return httpx.Response(200, json={
                    "name": path.removeprefix("/v1/"), "keyType": "USER_MANAGED",
                    "disabled": self.state == "DISABLED"})
            token = request.url.path.rsplit("/", 1)[-1]
            if not token.isdigit():
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"id": int(token), "revoked": self.state == "REVOKED",
                                             "active": self.state == "ACTIVE"})
        if self.write_status:
            return httpx.Response(self.write_status, json={"error": {"message": "SYNTHETIC_PROVIDER_TEXT"}})
        if request.method == "POST" and request.url.path.endswith(":disable"):
            self.state = "DISABLED"
            return httpx.Response(200, json={})
        self.state = "ABSENT" if "googleapis" in request.url.host else "REVOKED"
        return httpx.Response(200 if "googleapis" in request.url.host else 204)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handle))


def worker(repo, provider: Provider, opened=None, envelope=None, **kw):
    def resolve(reference):
        opened_envelope = dict(envelope or {"token": GITLAB_TOKEN})
        (opened if opened is not None else []).append(opened_envelope)
        return opened_envelope

    return SimpleNamespace(repo=repo, settings=settings(**kw), http_client_factory=provider.client,
                           metadata_secret_resolver=SimpleNamespace(resolve=resolve))


def run_jobs(repo, provider, opened=None, envelope=None, **kw):
    """Every queued provider action job, as the worker (with the installation's settings ``kw``) runs it; the
    remediation connection's credential opens as ``envelope`` (a token by default)."""
    for job in [job for job in repo.list_jobs() if job.kind == provider_actions.JOB_KIND and job.status == "QUEUED"]:
        provider_actions.run(worker(repo, provider, opened, envelope, **kw), job)


@pytest.fixture
def gcp_token(monkeypatch):
    monkeypatch.setattr("cremore_gcp_provider.onboarding._token", lambda connection, secrets: "gcp-synthetic-access")


def approved(svc, entity_id, action="DISABLE_PROVIDER_CREDENTIAL"):
    plan = svc.create_for_target(entity_id, "alice", body(action))
    return svc.approve(plan, "bob", plan.plan_hash)


def audit(repo):
    return repo.list_events(500)


# --- the plan binds the credential its provider lists --------------------------------------------------------


def test_a_gcp_key_is_disabled_by_the_worker_through_the_connection_set_up_to_act(repo, gcp_token):
    entities = gcp_inventory(repo)
    connection = remediation(repo)
    svc = service(repo)
    plan = svc.create_for_target(entities[KEY], "alice", body())
    target = plan.target
    assert target["reference"] == {"project": PROJECT, "email": EMAIL, "key_id": KEY,
                                    "key": {"email": EMAIL, "key_id": KEY}, "hint": f"{KEY[:12]} · {EMAIL} · {PROJECT}"}
    assert target["connection_id"] == str(connection["id"]) and target["entity_id"] == str(entities[KEY])
    assert (target["auth_method"], target["subject"], target["connection_name"]) == ("adc", "", connection["name"])
    assert plan.credential_id == provider_actions.target_key(target) and plan.identifier_hint == target["hint"]
    assert plan.adapter_version == "GCP_SERVICE_ACCOUNT_KEY_V1" and plan.status == "PENDING_APPROVAL"
    plan = svc.approve(plan, "bob", plan.plan_hash)
    # The API never opens the credential: execution is queued with its audit row, for the worker.
    queued = svc.queue_execution(plan, "carol", plan.plan_hash)
    assert queued.status == "QUEUED"
    [job] = [job for job in repo.list_jobs() if job.kind == provider_actions.JOB_KIND]
    assert job.payload == {"plan_id": str(plan.id), "plan_hash": plan.plan_hash, "actor": "carol", "mode": "execute"}
    google = Provider()
    run_jobs(repo, google)
    done = repo.get_action_plan(plan.id)
    assert done.status == "VERIFIED" and done.provider_write_started_at is not None
    base = f"/v1/projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{KEY}"
    assert google.requests == [("GET", base, "Bearer gcp-synthetic-access"),
                               ("POST", base + ":disable", "Bearer gcp-synthetic-access"),
                               ("GET", base, "Bearer gcp-synthetic-access")]  # and the account read before each GET
    public = svc.public(done)
    assert public["target"]["kind"] == "provider_credential" and public["target"]["provider"] == "gcp"
    assert repo.get_job(job.id).status == "SUCCEEDED"


def test_only_a_user_managed_key_of_the_project_is_planned(repo):
    entities = gcp_inventory(repo, ((KEY, "service_account_system_managed_key"),))
    remediation(repo)
    with pytest.raises(ActionPlanError) as refused:
        service(repo).create_for_target(entities[KEY], "alice", body())
    assert refused.value.code == "CREDENTIAL_NOT_ELIGIBLE"
    with pytest.raises(ActionPlanError) as missing:
        service(repo).create_for_target(uuid.uuid4(), "alice", body())
    assert (missing.value.code, missing.value.http_status) == ("CREDENTIAL_NOT_FOUND", 404)


def test_a_plan_needs_exactly_one_running_remediation_connection_that_reaches_the_key(repo):
    entities = gcp_inventory(repo)
    svc = service(repo)
    remediation(repo, target={"scope": "project", "project": "other-project-9"})
    remediation(repo, status="DISABLED")
    with pytest.raises(ActionPlanError) as none:
        svc.create_for_target(entities[KEY], "alice", body())
    assert none.value.code == "REMEDIATION_NOT_SET_UP"
    refusals = [event for event in audit(repo) if event.event_type == "ACTION_PLAN_REFUSED"]
    assert refusals[-1].target_type == "coverage_entity" and refusals[-1].note == "REQUEST REMEDIATION_NOT_SET_UP"
    remediation(repo)
    remediation(repo)
    with pytest.raises(ActionPlanError) as two:
        svc.create_for_target(entities[KEY], "alice", body())
    assert two.value.code == "REMEDIATION_CONNECTION_AMBIGUOUS"


def test_one_unresolved_plan_reserves_the_key_however_many_inventories_list_it(repo):
    first = gcp_inventory(repo)[KEY]
    second = gcp_inventory(repo, name="GCP · acme-prod-1 again")[KEY]
    assert first != second
    remediation(repo)
    svc = service(repo)
    svc.create_for_target(first, "alice", body())
    with pytest.raises(ActionPlanError) as locked:
        svc.create_for_target(second, "alice", body())
    assert locked.value.code == "ACTION_PLAN_TARGET_LOCKED"
    assert svc.target_policy(provider_actions.target_of(repo, second))["block_reason"] == "ACTION_PLAN_TARGET_LOCKED"


def test_competing_requests_on_one_key_from_two_inventories_reserve_it_once(repo):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    entities = [gcp_inventory(repo)[KEY], gcp_inventory(repo, name="GCP · acme-prod-1 again")[KEY]]
    remediation(repo)
    svc = service(repo)
    start = Barrier(2)

    def plan(entity_id):
        start.wait()
        try:
            return svc.create_for_target(entity_id, "alice", body()).id
        except ActionPlanError as exc:
            return exc.code

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(plan, entities))
    assert [outcome for outcome in outcomes if isinstance(outcome, str)] == ["ACTION_PLAN_TARGET_LOCKED"]
    assert sum(isinstance(outcome, uuid.UUID) for outcome in outcomes) == 1


def test_revoking_is_a_planned_irreversible_change_of_a_disabled_key(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    unacknowledged = body("REVOKE_PROVIDER_CREDENTIAL", operational_review=review(deletion_acknowledged=False))
    plan = svc.create_for_target(entities[KEY], "alice", unacknowledged)
    assert "DELETE_PLANNED_ACKNOWLEDGEMENT_REQUIRED" in plan.readiness["reasons"]
    svc.cancel(plan, "alice")
    plan = approved(svc, entities[KEY], "REVOKE_PROVIDER_CREDENTIAL")
    with pytest.raises(ActionPlanError) as switched_off:
        svc.queue_execution(plan, "carol", plan.plan_hash)
    assert switched_off.value.code == "DELETION_DISABLED"
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    svc.queue_execution(plan, "carol", plan.plan_hash)
    google = Provider("ACTIVE")
    run_jobs(repo, google, ACTION_DELETION_ENABLED="true")
    # Like an AWS key: deleted only once disabled, and nothing is written to find that out.
    failed = repo.get_action_plan(plan.id)
    assert (failed.status, failed.safe_error_code) == ("FAILED", "CREDENTIAL_NOT_DISABLED")
    assert [method for method, _path, _auth in google.requests] == ["GET"]
    plan = approved(svc, entities[KEY], "REVOKE_PROVIDER_CREDENTIAL")
    svc.queue_execution(plan, "carol", plan.plan_hash)
    google = Provider("DISABLED")
    run_jobs(repo, google, ACTION_DELETION_ENABLED="true")
    assert repo.get_action_plan(plan.id).status == "VERIFIED"
    assert [method for method, _path, _auth in google.requests] == ["GET", "DELETE", "GET"]


@pytest.mark.parametrize(("write_status", "status", "code"), [
    (403, "FAILED", "GCP_PERMISSION_DENIED"),  # refused outright: nothing changed
    (503, "OUTCOME_UNKNOWN", "GCP_HTTP_503"),  # may have happened: only ever rechecked
])
def test_a_refused_write_fails_and_an_uncertain_one_is_only_rechecked(repo, gcp_token, write_status, status, code):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    google = Provider(write_status=write_status)
    run_jobs(repo, google)
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == (status, code)
    text = json.dumps(svc.public(after)) + json.dumps([e.note for e in audit(repo)])
    assert "SYNTHETIC_PROVIDER_TEXT" not in text
    if status == "OUTCOME_UNKNOWN":
        with pytest.raises(ActionPlanError):
            svc.queue_execution(after, "carol", after.plan_hash)  # never retried
        svc.queue_recheck(after, "carol", after.plan_hash)
        google.state = "DISABLED"  # it did happen after all
        run_jobs(repo, google)
        checked = repo.get_action_plan(plan.id)
        assert checked.status == "VERIFIED" and checked.recheck_only is True
        assert [method for method, _path, _auth in google.requests[-1:]] == ["GET"]


def test_the_worker_checks_everything_again_before_it_opens_the_credential(repo, gcp_token):
    entities = gcp_inventory(repo)
    connection = remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    store = ProviderConnectionStore(repo)
    store.update(connection["id"], connection["revision"], "admin", status="DISABLED")
    google = Provider()
    run_jobs(repo, google)
    failed = repo.get_action_plan(plan.id)
    assert (failed.status, failed.safe_error_code) == ("FAILED", "REMEDIATION_CONNECTION_UNAVAILABLE")
    assert google.requests == []
    # Execution switched off after queueing: refused in the worker, before any read.
    remediation(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    for job in [job for job in repo.list_jobs() if job.status == "QUEUED"]:
        provider_actions.run(SimpleNamespace(**{**vars(worker(repo, google)),
                                                "settings": settings(ACTION_EXECUTION_ENABLED="false")}), job)
    assert repo.get_action_plan(plan.id).safe_error_code == "EXECUTION_DISABLED" and google.requests == []


def test_a_plan_cancelled_while_queued_never_runs_and_an_interrupted_write_is_unknown(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    queued = svc.queue_execution(plan, "carol", plan.plan_hash)
    svc.cancel(queued, "carol")
    google = Provider()
    run_jobs(repo, google)
    assert repo.get_action_plan(plan.id).status == "CANCELLED" and google.requests == []
    # Nobody tried to run a cancelled plan: the worker's finding it cancelled is no refusal.
    assert not any(e.event_type == "ACTION_PLAN_REFUSED" and e.target_id == plan.id for e in audit(repo))
    # A worker that stopped between its write and the read-back leaves the outcome unknown to the next one.
    plan = approved(svc, entities[KEY])
    queued = svc.queue_execution(plan, "carol", plan.plan_hash)
    executing = repo.update_action_plan(plan.id, expected_status="QUEUED", status="EXECUTING",
                                        provider_write_started_at=dt.datetime.now(dt.UTC))
    svc.run_queued(executing, "carol", plan.plan_hash, lambda: pytest.fail("no credential is opened"))
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == ("OUTCOME_UNKNOWN", "EXECUTION_INTERRUPTED")


def test_an_aws_style_call_cannot_run_a_provider_plan_in_the_api(repo):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    for call in (lambda: svc.execute(plan, "carol", plan.plan_hash),
                 lambda: svc.recheck(plan, "carol", plan.plan_hash)):
        with pytest.raises(ActionPlanError) as refused:
            call()
        assert refused.value.code == "PROVIDER_PLAN_RUNS_IN_WORKER"


# --- GitLab ---------------------------------------------------------------------------------------------------


def test_a_gitlab_group_token_is_revoked_and_its_connection_token_is_dropped_after(repo):
    families = gitlab_inventory(repo)
    remediation(repo, "gitlab", {"scope": "group", "id": "10"})
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    target = provider_actions.target_of(repo, families["group_access_token"])
    assert target["actions"] == ["REVOKE_PROVIDER_CREDENTIAL"]
    group = target["reference"]["scope"]
    assert group["kind"] == "group" and target["reference"]["listed_in"] == {"kind": "group", "id": "10"}
    with pytest.raises(ActionPlanError) as no_disable:
        svc.create_for_target(families["group_access_token"], "alice", body())
    assert no_disable.value.code == "ACTION_NOT_SUPPORTED_FOR_CREDENTIAL"
    plan = approved(svc, families["group_access_token"], "REVOKE_PROVIDER_CREDENTIAL")
    svc.queue_execution(plan, "carol", plan.plan_hash)
    gitlab, opened = Provider(), []
    run_jobs(repo, gitlab, opened, ACTION_DELETION_ENABLED="true")
    assert repo.get_action_plan(plan.id).status == "VERIFIED"
    path = f"/api/v4/groups/{group['id']}/access_tokens/{target['reference']['token_id']}"
    assert gitlab.requests == [("GET", path, GITLAB_TOKEN), ("DELETE", path, GITLAB_TOKEN), ("GET", path, GITLAB_TOKEN)]
    assert opened == [{}]  # the connection's token is cleared once the job is done
    # Another user's personal access token is an administrator's to revoke: no group connection reaches it.
    with pytest.raises(ActionPlanError) as personal:
        svc.create_for_target(families["personal_access_token"], "alice", body("REVOKE_PROVIDER_CREDENTIAL"))
    assert personal.value.code == "REMEDIATION_NOT_SET_UP"


def test_gitlab_reaches_only_what_its_role_and_instance_allow():
    from cremore_gitlab_provider import remediation as gitlab

    group_token = {"family": "group_access_token", "token_id": 5, "instance": "https://gitlab.example.test",
                   "scope": {"kind": "group", "id": 20}, "listed_in": {"kind": "group", "id": "10"}}
    personal = {"family": "personal_access_token", "token_id": 6, "instance": "https://gitlab.example.test",
                "listed_in": {"kind": "organization", "id": "https://gitlab.example.test"}}
    on = lambda **target: {"target": {"host": "https://gitlab.example.test", **target}}
    assert gitlab.covers(on(scope="group", id="10"), group_token)  # its collection listed it
    assert gitlab.covers(on(scope="group", id="20"), group_token)
    assert not gitlab.covers(on(scope="project", id="20"), group_token)
    assert not gitlab.covers(on(scope="group", id="10"), personal)
    assert gitlab.covers(on(scope="instance"), personal)
    assert not gitlab.covers({"target": {"host": "https://other.example.test", "scope": "instance"}}, personal)
    # The states GitLab reports; an expired token is already unusable.
    for answer, state in (({"id": 5, "revoked": True, "active": False}, "REVOKED"),
                          ({"id": 5, "revoked": False, "active": False}, "EXPIRED"),
                          ({"id": 5, "revoked": False, "active": True}, "ACTIVE")):
        client = httpx.Client(transport=httpx.MockTransport(lambda request, a=answer: httpx.Response(200, json=a)))
        assert gitlab.state(on(scope="group", id="20"), {"credential": {"token": "x"}}, group_token, client) == state


# --- the owner's words, the audit trail and the database ------------------------------------------------------


def test_the_owner_is_asked_about_the_credential_in_its_providers_words(repo):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = ActionPlanService(repo, settings())
    plan = svc.create_for_target(entities[KEY], "alice", body())
    assert owner_approval.needed(repo, plan)  # its users notice it: the owner approves first
    subject, text = owner_approval.message(plan, "https://console.example.test/owner#t", dt.datetime.now(dt.UTC), "ko")
    assert subject == "[CreMore] 자격증명 조치 승인 요청" and "AWS" not in text
    assert f"대상 자격증명: Google Cloud · {plan.identifier_hint}" in text and "자격증명 비활성화" in text
    title, lines = owner_approval.ticket_message(plan, dt.datetime.now(dt.UTC), "en")
    assert title.startswith("[CreMore] Approval asked for a credential action")
    assert f"Credential: Google Cloud · {plan.identifier_hint}" in lines


def test_every_step_of_a_provider_plan_is_audited(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    run_jobs(repo, Provider())
    trail = sorted((e.event_type, e.from_status or "", e.to_status) for e in audit(repo) if e.target_id == plan.id)
    assert trail == sorted([("ACTION_PLAN_REQUESTED", "", "PENDING_APPROVAL"),
                            ("ACTION_PLAN_APPROVED", "PENDING_APPROVAL", "APPROVED"),
                            ("ACTION_PLAN_QUEUED", "APPROVED", "QUEUED"),
                            ("ACTION_PLAN_EXECUTION_STARTED", "QUEUED", "EXECUTING"),
                            ("ACTION_PLAN_VERIFIED", "EXECUTING", "VERIFIED")])
    assert repo.get_action_plan(plan.id).target["reference"]["key_id"] == KEY  # the column round-trips


# --- what the security review asked (2026-09-30) -------------------------------------------------------------


def test_one_gitlab_token_has_one_key_wherever_it_was_listed():
    base = {"family": "group_access_token", "token_id": 202, "instance": "https://gitlab.com",
            "scope": {"kind": "group", "id": 20}}
    key = {"namespace": "resource_access_token", "token_id": 202, "scope": {"kind": "group", "id": 20}}
    listed_by_parent = {**base, "listed_in": {"kind": "group", "id": "10"}, "key": key, "hint": "a"}
    listed_by_itself = {**base, "listed_in": {"kind": "group", "id": "20"}, "key": key, "hint": "b"}
    target = lambda reference: {"provider": "gitlab", "origin": "https://gitlab.com", "reference": reference}
    assert provider_actions.target_key(target(listed_by_parent)) == provider_actions.target_key(target(listed_by_itself))
    # A personal token keeps its one ID space whether GitLab lists it as a user's or a service account's.
    from cremore_gitlab_provider import remediation as gitlab

    entity = {"origin": "https://gitlab.com"}
    def record(family):
        from cremore.coverage.facts import FactWriter

        values = {"identity": {"instance": "https://gitlab.com", "namespace": "personal_access_token",
                               "native_id": 7, "scope": {}}, "credential_types": [family]}
        return {"body": {"scope": {"kind": "group", "id": "10"},
                         "facts": [fact.model_dump() for fact in FactWriter().facts(values)]}}
    keys = {json.dumps(gitlab.reference(entity, record(family))["key"], sort_keys=True)
            for family in ("personal_access_token", "group_service_account_pat")}
    assert len(keys) == 1


def test_a_gitlab_404_counts_as_gone_only_while_the_tokens_group_is_visible(repo):
    families = gitlab_inventory(repo)
    remediation(repo, "gitlab", {"scope": "group", "id": "10"})
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    plan = approved(svc, families["group_access_token"], "REVOKE_PROVIDER_CREDENTIAL")
    svc.queue_execution(plan, "carol", plan.plan_hash)
    gitlab = Provider(write_status=503)
    run_jobs(repo, gitlab, ACTION_DELETION_ENABLED="true")
    unknown = repo.get_action_plan(plan.id)
    assert unknown.status == "OUTCOME_UNKNOWN"
    # The group moved out of the token's sight: its 404 proves nothing, and the plan stays unknown.
    svc.queue_recheck(unknown, "carol", unknown.plan_hash)
    gitlab.state, gitlab.visible = "ABSENT", False
    run_jobs(repo, gitlab, ACTION_DELETION_ENABLED="true")
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == ("OUTCOME_UNKNOWN", "GITLAB_TARGET_NOT_VISIBLE")
    # Seen again, and gone: revoked.
    svc.queue_recheck(after, "carol", after.plan_hash)
    gitlab.visible = True
    run_jobs(repo, gitlab, ACTION_DELETION_ENABLED="true")
    assert repo.get_action_plan(plan.id).status == "VERIFIED"


def test_one_recheck_at_a_time_and_each_request_is_audited(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    run_jobs(repo, Provider(write_status=502))
    unknown = repo.get_action_plan(plan.id)
    svc.queue_recheck(unknown, "carol", unknown.plan_hash)
    with pytest.raises(ActionPlanError) as twice:
        svc.queue_recheck(unknown, "carol", unknown.plan_hash)
    assert twice.value.code == "RECHECK_ALREADY_QUEUED"
    assert [e.actor for e in audit(repo) if e.event_type == "ACTION_PLAN_RECHECK_REQUESTED"] == ["carol"]


def test_the_worker_acts_only_with_the_sign_in_and_account_the_plan_was_approved_with(repo, gcp_token):
    entities = gcp_inventory(repo)
    connection = remediation(repo)
    svc = service(repo)
    store = ProviderConnectionStore(repo)
    for change, code in (({"auth_method": "google_oauth"}, "REMEDIATION_CONNECTION_CHANGED"),
                         ({"checks": {"stale": True}}, "REMEDIATION_CONNECTION_UNAVAILABLE"),
                         ({"checks": {"results": {"remediation": {"items": [
                             {"permission": "iam.serviceAccountKeys.get", "status": "GRANTED", "subject": "other"}]}}}},
                          "REMEDIATION_CONNECTION_CHANGED")):
        plan = approved(svc, entities[KEY])
        svc.queue_execution(plan, "carol", plan.plan_hash)
        current = store.get(connection["id"])
        store.update(connection["id"], current["revision"], "admin", **change)
        google = Provider()
        run_jobs(repo, google)
        failed = repo.get_action_plan(plan.id)
        assert (failed.status, failed.safe_error_code, google.requests) == ("FAILED", code, [])
        current = store.get(connection["id"])
        store.update(connection["id"], current["revision"], "admin", auth_method="adc", checks={})


def test_a_write_that_never_reached_google_fails_instead_of_staying_unknown(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    run_jobs(repo, Provider(unreachable=True))
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == ("FAILED", "GCP_UNAVAILABLE")


def test_a_key_read_back_must_be_exactly_the_one_the_plan_names():
    from cremore_gcp_provider import remediation as gcp

    reference = {"project": PROJECT, "email": EMAIL, "key_id": KEY}
    elsewhere = f"projects/other-project-9/serviceAccounts/{EMAIL}/keys/{KEY}"
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(
        200, json={"name": elsewhere, "keyType": "USER_MANAGED", "disabled": False} if "/keys/" in request.url.path
        else {"projectId": PROJECT, "email": EMAIL})))
    with pytest.raises(gcp.ProviderActionError) as refused:
        gcp.state({"auth_method": "adc"}, {gcp._ACCESS: {"token": "t"}}, reference, client)
    assert refused.value.code == "GCP_KEY_UNREADABLE"


def test_a_run_that_breaks_off_leaves_no_plan_waiting(repo, gcp_token, monkeypatch):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)

    def broken(self, *args, **kwargs):
        raise RuntimeError("synthetic: the database went away")

    monkeypatch.setattr(ActionPlanService, "run_queued", broken)
    [job] = [job for job in repo.list_jobs() if job.kind == provider_actions.JOB_KIND]
    with pytest.raises(RuntimeError):
        provider_actions.run(worker(repo, Provider()), job)
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == ("FAILED", "WORKER_ERROR")


def test_a_hint_that_hides_or_reorders_text_is_not_shown():
    assert provider_actions._shown("5c5c5c5c · svc@p.iam.gserviceaccount.com") != ""
    for hidden in ("key\u202e1", "key\u200b1", "key\u2066x"):
        assert provider_actions._shown(hidden) == ""

# --- what the second review round left (2026-09-30) -----------------------------------------------------------


def test_a_plan_bound_to_an_account_runs_only_while_the_credential_still_acts_as_it(repo):
    families = gitlab_inventory(repo)
    checked = {"results": {"remediation": {"items": [{"permission": "api", "status": "GRANTED", "subject": "user:77"}]}}}
    remediation(repo, "gitlab", {"scope": "group", "id": "10"}, checks=checked)
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    plan = approved(svc, families["group_access_token"], "REVOKE_PROVIDER_CREDENTIAL")
    assert plan.target["subject"] == "user:77"
    svc.queue_execution(plan, "carol", plan.plan_hash)
    swapped = Provider(self_user=99)  # the stored token now belongs to someone else; its check was not run again
    run_jobs(repo, swapped, ACTION_DELETION_ENABLED="true")
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == ("FAILED", "REMEDIATION_CONNECTION_CHANGED")
    assert [method for method, _path, _auth in swapped.requests] == ["GET"]  # read, never written


def test_a_run_that_ended_without_settling_its_plan_is_settled_by_the_worker(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    waiting = approved(svc, entities[KEY])
    svc.queue_execution(waiting, "carol", waiting.plan_hash)
    [job] = [job for job in repo.list_jobs() if job.kind == provider_actions.JOB_KIND]
    assert provider_actions.settle(repo, svc.settings) == 0  # still queued: the worker has not had it yet
    repo.fail_job(job.id, "LEASE_RETRY_LIMIT")
    assert provider_actions.settle(repo, svc.settings) == 1
    after = repo.get_action_plan(waiting.id)
    assert (after.status, after.safe_error_code) == ("FAILED", "WORKER_ERROR")
    assert provider_actions.settle(repo, svc.settings) == 0


def test_a_key_of_an_account_outside_the_plans_project_is_never_touched(repo, gcp_token):
    entities = gcp_inventory(repo)
    remediation(repo)
    svc = service(repo)
    plan = approved(svc, entities[KEY])
    svc.queue_execution(plan, "carol", plan.plan_hash)
    google = Provider(account_project="other-project-9")
    run_jobs(repo, google)
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code, google.requests) == ("FAILED", "GCP_ACCOUNT_NOT_IN_PROJECT", [])


def test_gitlab_not_answering_is_not_read_as_a_group_out_of_sight():
    from cremore_gitlab_provider import remediation as gitlab

    reference = {"family": "group_access_token", "token_id": 5, "instance": "https://gitlab.com",
                 "scope": {"kind": "group", "id": 20}}
    answers = {"/api/v4/groups/20/access_tokens/5": 404, "/api/v4/groups/20": 503}
    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(answers[request.url.path], json={})))
    with pytest.raises(gitlab.ProviderActionError) as refused:
        gitlab.state({"target": {"scope": "group", "id": "20"}}, {"credential": {"token": "t"}}, reference, client)
    assert refused.value.code == "GITLAB_UNAVAILABLE"

def test_a_token_connection_whose_check_never_named_its_user_plans_nothing(repo):
    families = gitlab_inventory(repo)
    remediation(repo, "gitlab", {"scope": "group", "id": "10"}, checks={})
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    target = provider_actions.target_of(repo, families["group_access_token"])
    assert svc.target_policy(target)["block_reason"] == "REMEDIATION_CHECK_REQUIRED"
    with pytest.raises(ActionPlanError) as refused:
        svc.create_for_target(families["group_access_token"], "alice", body("REVOKE_PROVIDER_CREDENTIAL"))
    assert refused.value.code == "REMEDIATION_CHECK_REQUIRED"


# --- Notion (P1b) ---------------------------------------------------------------------------------------------

NOTION_WORKSPACE, NOTION_PAT, NOTION_CREATOR = U(101), U(102), U(103)


def notion_inventory(repo) -> uuid.UUID:
    """The entity id of the one personal access token a workspace's inventory lists."""
    from cremore_notion_provider.metadata import ORIGIN as NOTION_ORIGIN
    from cremore_notion_provider.metadata import normalization as notion

    spec = MetadataConnectionSpec.model_validate({
        "schema_version": 2, "provider": "notion", "name": "Notion · workspace tokens", "origin": NOTION_ORIGIN,
        "edition": "cloud", "scopes": [{"kind": "workspace", "id": NOTION_WORKSPACE}], "capabilities": ["inventory"],
        "auth_type": "bearer", "secret_refs": {"token": "vault://notion/admin"}, "options": {"mode": "inventory"}})
    row = {"id": NOTION_PAT, "creator": {"id": NOTION_CREATOR, "name": "Synthetic Member"},
           "created_at": 1788220800000, "status": "active", "name": "Synthetic PAT"}
    item = notion.observation(spec, MetadataScope(kind="workspace", id=NOTION_WORKSPACE), "personal_access_tokens",
                              row, observed_at=dt.datetime.now(dt.UTC).isoformat())
    owner = _collect(repo, spec, [item])
    [listed] = MetadataStore(repo).inventory(connection_id=owner["id"], object_kind="credential", limit=5)["items"]
    return listed["id"]


class Notion:
    """Notion's Admin API for one workspace: a member's tokens, a page at a time, and the revoke, with each call."""

    def __init__(self, status="active", *, write_status=None, pages=1):
        self.status, self.write_status, self.pages, self.requests = status, write_status, pages, []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path, request.url.params.get("creator_ids"),
                              request.headers.get("authorization"), request.headers.get("notion-version")))
        if request.method == "DELETE":
            if self.write_status:
                return httpx.Response(self.write_status, json={"message": "SYNTHETIC_PROVIDER_TEXT"})
            self.status = "revoked"
            return httpx.Response(200, json={})
        page = int(request.url.params.get("cursor", "page-0").removeprefix("page-"))
        if page + 1 < self.pages:  # the member's other tokens come first
            other = {"id": U(900 + page), "creator": {"id": NOTION_CREATOR}, "status": "active"}
            return httpx.Response(200, json={"results": [other], "has_more": True, "next_cursor": f"page-{page + 1}"})
        mine = [{"id": NOTION_PAT, "creator": {"id": NOTION_CREATOR}, "status": self.status}]
        return httpx.Response(200, json={"results": [] if self.status == "absent" else mine, "has_more": False,
                                         "next_cursor": None})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handle))


def test_a_notion_token_is_revoked_by_the_workspace_bot_and_read_back_among_its_makers_tokens(repo):
    entity = notion_inventory(repo)
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    remediation(repo, "notion", {"workspace": U(104)})  # another workspace's bot
    with pytest.raises(ActionPlanError) as elsewhere:
        svc.create_for_target(entity, "alice", body("REVOKE_PROVIDER_CREDENTIAL"))
    assert elsewhere.value.code == "REMEDIATION_NOT_SET_UP"
    remediation(repo, "notion", {"workspace": NOTION_WORKSPACE})
    target = provider_actions.target_of(repo, entity)
    assert target["actions"] == ["REVOKE_PROVIDER_CREDENTIAL"]  # Notion has no disable
    assert target["reference"] == {"workspace": NOTION_WORKSPACE, "pat_id": NOTION_PAT, "creator_id": NOTION_CREATOR,
                                   "key": {"workspace": NOTION_WORKSPACE, "pat_id": NOTION_PAT},
                                   "hint": f"personal_access_token {NOTION_PAT} (creator {NOTION_CREATOR})"}
    plan = approved(svc, entity, "REVOKE_PROVIDER_CREDENTIAL")
    assert plan.adapter_version == "NOTION_PAT_REVOKE_V1" and plan.target["auth_method"] == "organization_bot"
    svc.queue_execution(plan, "carol", plan.plan_hash)
    notion, opened = Notion(pages=2), []
    run_jobs(repo, notion, opened, ACTION_DELETION_ENABLED="true")
    assert repo.get_action_plan(plan.id).status == "VERIFIED"
    listed, sent = f"/admin/v1/spaces/{NOTION_WORKSPACE}/personal_access_tokens", ("Bearer " + GITLAB_TOKEN, "2026-06-01")
    read = [("GET", listed, NOTION_CREATOR, *sent)] * 2  # the maker's tokens, both pages
    assert notion.requests == read + [("DELETE", f"{listed}/{NOTION_PAT}", None, *sent)] + read
    assert opened == [{}]


def test_notion_calls_a_token_gone_only_after_its_makers_whole_list():
    from cremore_notion_provider import remediation as notion

    reference = {"workspace": NOTION_WORKSPACE, "pat_id": NOTION_PAT, "creator_id": NOTION_CREATOR}
    secrets = {"credential": {"token": "t"}}

    def answer(*pages, status=200):
        queue = list(pages)
        return httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status, json=queue.pop(0))))

    def mine(status, creator=NOTION_CREATOR):
        return {"id": NOTION_PAT, "creator": {"id": creator}, "status": status}

    more = {"results": [], "has_more": True, "next_cursor": "c1"}
    assert notion.state({}, secrets, reference, answer(more, {"results": [mine("expired")], "has_more": False})) == "EXPIRED"
    assert notion.state({}, secrets, reference, answer({"results": [], "has_more": False, "next_cursor": None})) == "ABSENT"
    # The same token however Notion spells its UUID: never missed into a false absence.
    spelled = {**mine("active"), "id": NOTION_PAT.upper().replace("-", "")}
    assert notion.state({}, secrets, reference, answer({"results": [spelled], "has_more": False})) == "ACTIVE"
    for client, code in ((answer({}, status=404), "NOTION_WORKSPACE_NOT_VISIBLE"),  # the workspace, not the token
                         (answer({"results": [], "has_more": False, "next_cursor": "c9"}), "NOTION_TOKEN_UNREADABLE"),
                         (answer(more, more), "NOTION_TOKEN_UNREADABLE"),  # the same page again
                         (answer({"results": [mine("active", U(999))], "has_more": False}), "NOTION_TOKEN_UNREADABLE"),
                         (answer({}, status=429), "NOTION_UNAVAILABLE")):
        with pytest.raises(notion.ProviderActionError) as refused:
            notion.state({}, secrets, reference, client)
        assert refused.value.code == code


def test_a_notion_revoke_it_refused_fails_and_any_other_answer_is_only_rechecked():
    from cremore_notion_provider import remediation as notion

    reference = {"workspace": NOTION_WORKSPACE, "pat_id": NOTION_PAT, "creator_id": NOTION_CREATOR}
    for status, code, refused in ((403, "NOTION_PERMISSION_DENIED", True), (404, "NOTION_HTTP_404", True),
                                  (429, "NOTION_HTTP_429", False), (503, "NOTION_HTTP_503", False)):
        client = httpx.Client(transport=httpx.MockTransport(
            lambda request, s=status: httpx.Response(s, json={"message": "SYNTHETIC_PROVIDER_TEXT"})))
        with pytest.raises(notion.ProviderActionError) as failed:
            notion.apply({}, {"credential": {"token": "t"}}, reference, "REVOKE_PROVIDER_CREDENTIAL", client)
        assert (failed.value.code, failed.value.refused) == (code, refused)


# --- GitHub (P1b) ---------------------------------------------------------------------------------------------

GITHUB_ORG = "CreMore-1"
INSTALLATION_TOKEN = "ghs_" + "SyntheticInstallation0"  # built from parts: never a real token


def github_inventory(repo) -> uuid.UUID:
    """The entity id of the fine-grained PAT grant GitHub's synthetic organization lists (grant 31 of token 41)."""
    from cremore_github_provider.metadata.tests.fake import org_responses
    from cremore_github_provider.metadata.tests.fake import spec as github_spec
    from cremore_github_provider.metadata.tests.test_adapter import drive

    connection = github_spec()
    owner = _collect(repo, connection, drive(connection, org_responses())[2])
    listed = MetadataStore(repo).inventory(connection_id=owner["id"], object_kind="credential", limit=500)["items"]
    return next(row["id"] for row in listed if row["object_id"] == f"fgpat:{GITHUB_ORG}:31")


def github_app() -> dict:
    """A GitHub App's stored envelope, with a key made for this run."""
    import base64

    from cremore.onboarding.onboarding_test import PEM

    return {"GITHUB_APP_ID": "123", "GITHUB_APP_INSTALLATION_ID": "456",
            "GITHUB_APP_PRIVATE_KEY_BASE64": base64.b64encode(PEM.encode()).decode()}


class GitHub:
    """GitHub for one organization: the App's installation, its fine-grained PAT grants and the revoke, with each
    call to the organization."""

    def __init__(self, *, write_status=204, installed_on=GITHUB_ORG):
        self.listed, self.write_status, self.installed_on, self.requests = True, write_status, installed_on, []
        self.minted = []  # what each installation token was asked for

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/456/access_tokens":
            self.minted.append(json.loads(request.content))
            return httpx.Response(201, json={"token": INSTALLATION_TOKEN, "expires_at": "2099-01-01T00:00:00Z",
                                             "permissions": {"organization_personal_access_tokens": "write"}})
        if request.url.path == "/app/installations/456":
            return httpx.Response(200, json={"id": 456, "account": {"login": self.installed_on}})
        self.requests.append((request.method, request.url.path, request.url.params.get("token_id[]"),
                              request.headers.get("authorization"), json.loads(request.content) if request.content else None))
        if request.method == "POST":
            if self.write_status != 204:
                return httpx.Response(self.write_status, json={"message": "SYNTHETIC_PROVIDER_TEXT"})
            self.listed = False
            return httpx.Response(204)
        rows = [{"id": 31, "token_id": 41, "token_expired": False, "owner": {"login": "octocat"}}] if self.listed else []
        return httpx.Response(200, json=rows)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handle))


def test_a_github_tokens_organization_access_is_revoked_by_the_app_and_named_so(repo):
    entity = github_inventory(repo)
    remediation(repo, "github", {"organization": GITHUB_ORG}, auth_method="github_app",
                checks=checked_as(GITHUB_ORG))
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    target = provider_actions.target_of(repo, entity)
    assert target["revokes"] == "ORGANIZATION_ACCESS" and target["actions"] == ["REVOKE_PROVIDER_CREDENTIAL"]
    assert target["reference"] == {"host": "https://github.com", "organization": GITHUB_ORG, "pat_id": 31,
                                   "token_id": 41, "owner": "octocat", "hint": f"fine-grained PAT 41 · {GITHUB_ORG} (octocat)",
                                   "key": {"host": "https://github.com", "organization": "cremore-1", "pat_id": 31}}
    assert svc.target_policy(target)["revokes"] == "ORGANIZATION_ACCESS"
    plan = approved(svc, entity, "REVOKE_PROVIDER_CREDENTIAL")
    assert plan.target["revokes"] == "ORGANIZATION_ACCESS" and plan.target["subject"] == GITHUB_ORG
    assert svc.public(plan)["target"]["revokes"] == "ORGANIZATION_ACCESS"
    # The owner is told what goes: the organization's access, not the token.
    _subject, text = owner_approval.message(plan, "https://console.example.test/owner#t", dt.datetime.now(dt.UTC), "ko")
    assert "조치: 조직 접근 회수" in text and "영구 폐기" not in text
    _title, lines = owner_approval.ticket_message(plan, dt.datetime.now(dt.UTC), "en")
    assert "Action: Revoke its organization access" in lines
    svc.queue_execution(plan, "carol", plan.plan_hash)
    github, opened = GitHub(), []
    run_jobs(repo, github, opened, github_app(), ACTION_DELETION_ENABLED="true")
    assert repo.get_action_plan(plan.id).status == "VERIFIED"
    grants, sent = f"/orgs/{GITHUB_ORG}/personal-access-tokens", "Bearer " + INSTALLATION_TOKEN
    assert github.requests == [("GET", grants, "41", sent, None),
                               ("POST", grants + "/31", None, sent, {"action": "revoke"}),
                               ("GET", grants, "41", sent, None)]
    # One installation token per run, for the grants' write permission alone.
    assert github.minted == [{"permissions": {"organization_personal_access_tokens": "write"}}]
    assert opened == [{}]  # the App's key and the run's installation token are dropped with the run


def test_a_github_plan_runs_only_while_the_app_is_installed_on_the_organization_it_was_approved_for(repo):
    entity = github_inventory(repo)
    remediation(repo, "github", {"organization": GITHUB_ORG}, auth_method="github_app",
                checks=checked_as(GITHUB_ORG))
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    plan = approved(svc, entity, "REVOKE_PROVIDER_CREDENTIAL")
    svc.queue_execution(plan, "carol", plan.plan_hash)
    github = GitHub(installed_on="Someone-Else")  # the stored App now points at another account's installation
    run_jobs(repo, github, None, github_app(), ACTION_DELETION_ENABLED="true")
    after = repo.get_action_plan(plan.id)
    assert (after.status, after.safe_error_code) == ("FAILED", "REMEDIATION_CONNECTION_CHANGED")
    assert [method for method, *_rest in github.requests] == ["GET"]  # read, never written


@pytest.mark.parametrize("installed_on", [GITHUB_ORG, "Another-Org"])
def test_github_multi_org_plan_binds_the_selected_roots_subject_and_installation(repo, installed_on):
    from cremore.onboarding.targets import target_id

    entity = github_inventory(repo)
    roots = [{"id": target_id({"organization": name}), "target": {"organization": name}}
             for name in ("First-Org", GITHUB_ORG)]
    checks = {"results": {"remediation": {"items": [
        {"permission": "installation", "status": "GRANTED", "subject": root["target"]["organization"],
         "target_id": root["id"]} for root in roots]}}}
    record = remediation(repo, "github", {"version": 2, "roots": roots}, auth_method="github_app", checks=checks)
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    plan = approved(svc, entity, "REVOKE_PROVIDER_CREDENTIAL")
    assert plan.target["subject"] == GITHUB_ORG and plan.target["connection_id"] == str(record["id"])
    assert provider_actions.checked_subject(record) == "", "a v2 owner has no unqualified acting subject"
    missing = {**record, "checks": {"results": {"remediation": {"items": checks["results"]["remediation"]["items"][:1]}}}}
    assert provider_actions.checked_subject(missing, plan.target["reference"]) == "", "another root's check cannot bind this plan"
    svc.queue_execution(plan, "carol", plan.plan_hash)

    class MultiGitHub(GitHub):
        def handle(self, request):
            if request.url.path == f"/orgs/{GITHUB_ORG}/installation":
                return httpx.Response(200, json={"id": 789, "app_id": 123, "target_type": "Organization",
                    "account": {"login": installed_on}, "permissions": {"organization_personal_access_tokens": "write"}})
            if request.url.path == "/app/installations/789/access_tokens":
                self.minted.append(json.loads(request.content))
                return httpx.Response(201, json={"token": INSTALLATION_TOKEN, "expires_at": "2099-01-01T00:00:00Z",
                    "permissions": {"organization_personal_access_tokens": "write"}})
            assert "/app/installations/456" not in request.url.path, "the first installation must not be reused"
            return super().handle(request)

    github = MultiGitHub()
    run_jobs(repo, github, None, github_app(), ACTION_DELETION_ENABLED="true")
    after = repo.get_action_plan(plan.id)
    if installed_on == GITHUB_ORG:
        assert after.status == "VERIFIED" and len(github.minted) == 1
        assert any(method == "POST" for method, *_ in github.requests)
    else:
        assert after.status == "FAILED" and after.provider_write_started_at is None
        assert after.safe_error_code == "GITHUB_APP_INSTALLATION_MISMATCH"
        assert not github.minted and not github.requests


def test_github_calls_a_grant_gone_only_from_the_list_filtered_by_its_token_and_maps_its_answers():
    from cremore_github_provider import remediation as github

    reference = {"host": "https://github.com", "organization": GITHUB_ORG, "pat_id": 31, "token_id": 41}
    connection = {"target": {"organization": GITHUB_ORG}}
    secrets = {"credential": {}, github._ACCESS: {"token": "t"}}  # this run's installation token, asked already
    asked = []

    def answer(*pages, status=200):
        queue = list(pages)

        def handle(request):
            asked.append(dict(request.url.params))
            return httpx.Response(status, json=queue.pop(0))
        return httpx.Client(transport=httpx.MockTransport(handle))

    def grant(**patch):
        return {"id": 31, "token_id": 41, "token_expired": False, **patch}

    # Listed is active even once its token expired: the grant may serve the token again.
    assert github.state(connection, secrets, reference, answer([grant(token_expired=True)])) == "ACTIVE"
    assert asked[-1] == {"token_id[]": "41", "per_page": "100"}
    assert github.state(connection, secrets, reference, answer([])) == "ABSENT"
    assert github.state(connection, secrets, reference, answer([grant(id=77)])) == "ABSENT"  # a later grant, not it
    others = [{"id": 100 + n, "token_id": 900 + n, "token_expired": False} for n in range(3)]
    for client, code in ((answer([], status=404), "GITHUB_ORGANIZATION_NOT_VISIBLE"),  # the organization, not the grant
                         (answer(others), "GITHUB_GRANT_UNREADABLE"),  # GitHub did not filter: proves nothing
                         (answer([grant(), *others]), "GITHUB_GRANT_UNREADABLE"),
                         (answer([grant(id="5000")]), "GITHUB_GRANT_UNREADABLE"),  # never a false absence
                         (answer({"id": 31}), "GITHUB_GRANT_UNREADABLE"),
                         (answer([], status=502), "GITHUB_UNAVAILABLE")):
        with pytest.raises(github.ProviderActionError) as refused:
            github.state(connection, secrets, reference, client)
        assert refused.value.code == code
    for status, code, refused_outright in ((403, "GITHUB_PERMISSION_DENIED", True), (404, "GITHUB_HTTP_404", True),
                                           (422, "GITHUB_HTTP_422", True), (500, "GITHUB_HTTP_500", False)):
        with pytest.raises(github.ProviderActionError) as failed:
            github.apply(connection, secrets, reference, "REVOKE_PROVIDER_CREDENTIAL", answer({}, status=status))
        assert (failed.value.code, failed.value.refused) == (code, refused_outright)
    assert github.covers({"target": {"organization": "cremore-1"}}, reference)
    assert not github.covers({"target": {"organization": "CreMore-2"}}, reference)
    assert not github.covers({"target": {"organization": GITHUB_ORG, "host": "github.example.com"}}, reference)


# --- Azure DevOps (P1b) ---------------------------------------------------------------------------------------

DEVOPS_ORG, DEVOPS_PAT = "acme", U(201)
DEVOPS_OWNER = "aad." + "U3ludGhldGljT3duZXI"  # a subject descriptor's shape, made up


def devops_inventory(repo) -> uuid.UUID:
    """The entity id of the one personal access token an organization's inventory lists under its owner."""
    from cremore_azure_provider.devops_tokens import ORIGIN as DEVOPS_ORIGIN
    from cremore_azure_provider.devops_tokens import normalization as devops

    spec = MetadataConnectionSpec.model_validate({
        "schema_version": 2, "provider": "azure_devops", "name": "Azure DevOps · acme · tokens", "origin": DEVOPS_ORIGIN,
        "edition": "cloud", "scopes": [{"kind": "organization", "id": DEVOPS_ORG}], "capabilities": ["inventory"],
        "auth_type": "token", "secret_refs": {"token": "vault://devops"}, "options": {"mode": "inventory"}})
    row = {"authorizationId": DEVOPS_PAT, "displayName": "deploy", "scope": "vso.code", "isValid": True,
           "isPublic": False, "validFrom": "2026-09-01T00:00:00Z", "validTo": "2099-09-01T00:00:00Z"}
    member = {"descriptor": DEVOPS_OWNER, "name": "alice@acme.test", "origin": "aad"}
    item = devops.observation(spec, MetadataScope(kind="organization", id=DEVOPS_ORG), row, member,
                              observed_at=dt.datetime.now(dt.UTC).isoformat())
    owner = _collect(repo, spec, [item])
    [listed] = MetadataStore(repo).inventory(connection_id=owner["id"], object_kind="credential", limit=5)["items"]
    return listed["id"]


class DevOps:
    """Azure DevOps Token Admin for one owner's tokens; a revocation it shows only when told to (``shown``)."""

    def __init__(self, *, shown=True, write_status=204):
        self.valid, self.shown, self.write_status, self.requests = True, shown, write_status, []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path, request.url.params.get("isPublic"),
                              request.headers.get("authorization"), json.loads(request.content) if request.content else None))
        if request.method == "POST":
            if self.write_status != 204:
                return httpx.Response(self.write_status, json={"message": "SYNTHETIC_PROVIDER_TEXT"})
            self.valid = not self.shown
            return httpx.Response(204)
        rows = [{"authorizationId": DEVOPS_PAT, "isValid": self.valid, "validTo": "2099-09-01T00:00:00Z"}]
        return httpx.Response(200, json={"value": rows, "continuationToken": None})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handle))


def test_an_azure_devops_token_is_revoked_and_a_revocation_shown_late_is_confirmed_by_a_recheck(repo):
    import base64

    entity = devops_inventory(repo)
    remediation(repo, "azure_devops", {"organization": DEVOPS_ORG, "project": "web"})
    svc = service(repo, ACTION_DELETION_ENABLED="true")
    target = provider_actions.target_of(repo, entity)
    assert target["reference"] == {"organization": DEVOPS_ORG, "authorization_id": DEVOPS_PAT,
                                   "owner_descriptor": DEVOPS_OWNER, "hint": f"PAT {DEVOPS_PAT} · acme",
                                   "key": {"organization": DEVOPS_ORG, "authorization_id": DEVOPS_PAT}}
    assert "revokes" not in target  # the token itself goes
    plan = approved(svc, entity, "REVOKE_PROVIDER_CREDENTIAL")
    svc.queue_execution(plan, "carol", plan.plan_hash)
    devops = DevOps(shown=False)  # Azure DevOps can take up to an hour to show a revocation
    run_jobs(repo, devops, ACTION_DELETION_ENABLED="true")
    unknown = repo.get_action_plan(plan.id)
    assert (unknown.status, unknown.safe_error_code) == ("OUTCOME_UNKNOWN", "STATE_ACTIVE")
    listed = f"/{DEVOPS_ORG}/_apis/tokenadmin/personalaccesstokens/{DEVOPS_OWNER}"
    basic = "Basic " + base64.b64encode((":" + GITLAB_TOKEN).encode()).decode()
    assert devops.requests == [("GET", listed, "false", basic, None),
                               ("POST", f"/{DEVOPS_ORG}/_apis/tokenadmin/revocations", "false", basic,
                                [{"authorizationId": DEVOPS_PAT}]),
                               ("GET", listed, "false", basic, None)]
    svc.queue_recheck(unknown, "carol", unknown.plan_hash)
    devops.valid = False  # shown now
    run_jobs(repo, devops, ACTION_DELETION_ENABLED="true")
    checked = repo.get_action_plan(plan.id)
    assert checked.status == "VERIFIED" and checked.recheck_only is True
    assert [method for method, *_rest in devops.requests[3:]] == ["GET"]  # a recheck only reads


def test_azure_devops_reads_a_token_back_among_its_owners_tokens_only():
    from cremore_azure_provider.devops_tokens import remediation as devops

    reference = {"organization": DEVOPS_ORG, "authorization_id": DEVOPS_PAT, "owner_descriptor": DEVOPS_OWNER}
    secrets = {"credential": {"token": "t"}}

    def answer(*pages, status=200):
        queue = list(pages)
        return httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status, json=queue.pop(0))))

    def page(*rows, following=None):
        return {"value": list(rows), "continuationToken": following}

    mine = {"authorizationId": DEVOPS_PAT.upper(), "isValid": True, "validTo": "2020-01-01T00:00:00Z"}
    assert devops.state({}, secrets, reference, answer(page(following="c1"), page(mine))) == "EXPIRED"
    assert devops.state({}, secrets, reference, answer(page({**mine, "isValid": False}))) == "REVOKED"
    assert devops.state({}, secrets, reference, answer(page())) == "ABSENT"
    for client, code in ((answer({}, status=404), "AZURE_DEVOPS_OWNER_NOT_VISIBLE"),  # the owner left: not proof
                         (answer({}, status=203), "AZURE_DEVOPS_PERMISSION_DENIED"),  # the sign-in page
                         (answer(page(following="c1"), page(following="c1")), "AZURE_DEVOPS_TOKEN_UNREADABLE"),
                         (answer(page({**mine, "isValid": "yes"})), "AZURE_DEVOPS_TOKEN_UNREADABLE")):
        with pytest.raises(devops.ProviderActionError) as refused:
            devops.state({}, secrets, reference, client)
        assert refused.value.code == code
    assert devops.covers({"edition": "cloud", "target": {"organization": "ACME"}}, reference)
    assert not devops.covers({"edition": "server", "target": {"organization": DEVOPS_ORG,
                                                               "base_url": "https://devops.example.test/tfs"}}, reference)


def test_every_provider_offering_approved_actions_has_its_action_module():
    from cremore.onboarding import catalog

    offering = {name for name, descriptor in catalog.providers().items() if "remediation" in descriptor["purposes"]}
    assert offering == set(provider_actions.MODULES)
