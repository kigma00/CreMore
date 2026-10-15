"""A GitHub connection's Enterprise collection reuses the App credential, never a PAT for its reads."""

import uuid

import pytest
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.tests.fake import (
    ENTERPRISE,
    ORG,
    OTHER_ORG,
    enterprise_responses,
    enterprise_spec,
)
from cremore_github_provider.metadata.tests.test_adapter import NOW, drive
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.metadata_coverage_test import TOKEN, Signed
from cremore.config import Settings
from cremore.coverage.errors import CoverageError
from cremore.coverage.metadata_job import resolve_slots
from cremore.coverage.metadata_models import (
    MetadataBatch,
    MetadataConnectionSpec,
    metadata_contract,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.repository import InMemoryRepository
from cremore.onboarding.fixtures_test import activate_with_access
from cremore.onboarding.onboarding_test import PEM


@pytest.fixture
def environment(request):
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///:memory:") if getattr(request, "param", "memory") == "sqlite" else None
    if engine is not None:
        create_all(engine)
    repo = SqlRepository(engine) if engine is not None else InMemoryRepository()
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32))
    try:
        with TestClient(app) as raw:
            yield repo, Signed(raw)
    finally:
        if engine is not None:
            engine.dispose()


SETTINGS = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)
AUDIT_PAT = "ghp_" + "b" * 36


def github(**target):
    return {"provider": "github", "edition": target.pop("edition", "enterprise_cloud"), "purposes": ["inventory"],
            "auth_method": "github_app",
            "target": {"organization": ORG, "enterprise": ENTERPRISE, **target},
            "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}


def wizard(repo, body, *, plan=None):
    """Steps 1, 2 and 4 of a GitHub connection (the check is onboarding_test's)."""
    from cremore.onboarding import service
    from cremore.onboarding.store import ProviderConnectionStore

    record = service.create(repo, SETTINGS, body, "admin")
    store = ProviderConnectionStore(repo)
    current = store.get(uuid.UUID(record["id"]))
    store.update(current["id"], current["revision"], "worker", status="CHECKED")
    view = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {"inventory": plan or {}}}, "admin")
    enterprise = next((row for row in view["created"] if row["name"].startswith("GitHub Enterprise")), view["created"][0])
    return store.get(current["id"]), MetadataStore(repo).get(uuid.UUID(enterprise["id"]))


def connect(client, repo, enterprise=ENTERPRISE):
    """A legacy mixed collection: its organization roster must remain readable.

    New split onboarding is tested above; its export-only child intentionally
    no longer collects the organization's installation roster.
    """
    from cremore.onboarding.fixtures_test import collection

    spec = enterprise_spec()
    spec.scopes[0].id = enterprise
    row, _token = collection(repo, spec.model_dump())
    return client.get(f"/api/v2/coverage/connections/{row['id']}")


def test_the_wizard_adds_an_enterprise_collection_on_the_app_credential(environment):
    repo, client = environment
    record, row = wizard(repo, github())
    ref = record["secret_refs"]["credential"]
    assert row["spec"]["options"]["mode"] == "enterprise"
    assert row["spec"]["scopes"] == [{"kind": "enterprise", "id": ENTERPRISE}]
    assert row["spec"]["edition"] == "enterprise_cloud" and row["spec"]["origin"] == "https://github.com"
    assert row["spec"]["secret_refs"] == {"app_id": ref, "private_key": ref}
    assert not [job for job in repo.list_jobs(50) if job.kind == "provider-metadata-inventory"]
    public = client.get(f"/api/v2/coverage/connections/{row['id']}").text
    assert "sealed:" not in client.get("/api/v2/coverage/connections").text and "collector_token" not in public
    queued = client.post(f"/api/v2/coverage/connections/{row['id']}/collect", json={})
    assert queued.status_code == 202
    job = repo.get_job(uuid.UUID(queued.json()["job_id"]))
    assert job.kind == "provider-metadata-inventory"
    assert "secret_ref" not in job.payload and "token" not in job.payload


def test_github_enterprise_audit_token_is_sealed_as_its_own_role_and_never_echoed(environment):
    from cremore.secretstore.resolver import SecretResolver

    repo, client = environment
    body = github()
    for bad in ("github_pat_" + "b" * 60, "gho_" + "b" * 36, "ghp_short"):
        from cremore.onboarding import service

        with pytest.raises(service.OnboardingError) as refused:
            service.create(repo, SETTINGS, {**body, "credential": {**body["credential"], "audit_token": bad}}, "admin")
        assert refused.value.code == "GITHUB_AUDIT_TOKEN_MUST_BE_A_CLASSIC_PAT"
    record, inventory = wizard(repo, {**body, "credential": {**body["credential"], "audit_token": AUDIT_PAT}},
                               plan={"enterprise_audit": True})
    from cremore.onboarding.store import ProviderConnectionStore

    store = MetadataStore(repo)
    row = next(store.get(uuid.UUID(child["child_id"])) for child in ProviderConnectionStore(repo).children(record["id"])
               if child["kind"] == "metadata" and store.get(uuid.UUID(child["child_id"]))["spec"]["options"]["github_inventory"] is False)
    assert "audit_token" not in inventory["spec"]["secret_refs"]
    audit_ref = record["secret_refs"]["audit_token"]
    assert audit_ref.startswith("sealed:") and AUDIT_PAT not in audit_ref
    spec = row["spec"]
    assert spec["secret_refs"]["audit_token"] == audit_ref
    assert "audit" in spec["capabilities"] and spec["options"]["include_audit_events"] is True
    assert SecretResolver(sealing_key=SETTINGS.sealing_keys).resolve(audit_ref)["token"] == AUDIT_PAT
    shown = client.get(f"/api/v2/coverage/connections/{row['id']}").json()["spec"]["secret_refs"]
    assert shown["audit_token"] == "sealed:v2" and audit_ref not in client.get("/api/v2/coverage/connections").text


def test_an_audit_token_needs_an_enterprise_to_be_read_for(environment):
    from cremore.onboarding import service

    repo, _client = environment
    body = github()
    body["target"].pop("enterprise")
    with pytest.raises(service.OnboardingError) as refused:
        service.create(repo, SETTINGS, {**body, "credential": {**body["credential"], "audit_token": AUDIT_PAT}}, "admin")
    assert refused.value.code == "GITHUB_AUDIT_TOKEN_NEEDS_AN_ENTERPRISE"


def test_a_personal_token_cannot_serve_the_credential_inventory(environment):
    from cremore.onboarding import service

    repo, _client = environment
    with pytest.raises(service.OnboardingError) as refused:
        service.create(repo, SETTINGS, {**github(), "auth_method": "token", "credential": {"token": AUDIT_PAT}}, "admin")
    assert refused.value.code == "AUTH_METHOD_NOT_FOR_PURPOSES"
    assert not MetadataStore(repo).list_connections()


@pytest.mark.parametrize("host,edition", [("ghes.example.com", "enterprise_server"), ("example.ghe.com", "dedicated")])
def test_the_host_decides_the_edition_and_is_never_the_enterprise_slug(environment, host, edition):
    repo, _client = environment
    _record, row = wizard(repo, github(edition=edition, host="https://" + host))
    spec = row["spec"]
    assert spec["origin"] == "https://" + host and spec["edition"] == edition
    assert spec["scopes"][0]["id"] == (ORG if edition == "enterprise_server" else ENTERPRISE)


def test_the_enterprise_slug_is_explicit_and_connecting_requires_authentication(environment):
    from cremore.onboarding import service

    repo, client = environment
    for slug in ("../org", "https://github.com/enterprises/example"):
        with pytest.raises(service.OnboardingError):
            service.create(repo, SETTINGS, github(enterprise=slug), "admin")
    assert client.inner.post("/api/v1/provider-connections", json=github()).status_code == 401


def test_app_roles_do_not_fall_back_to_a_generic_token():
    class Resolver:
        def __init__(self, data): self.data = data
        def resolve(self, ref): return self.data
    spec = enterprise_spec()
    with pytest.raises(CoverageError, match="METADATA_SECRET_UNAVAILABLE"):
        resolve_slots(spec, Resolver({"token": "synthetic-personal-token"}))
    assert resolve_slots(spec, Resolver({"GITHUB_APP_ID": "123", "GITHUB_APP_PRIVATE_KEY_BASE64": "synthetic-pem"})) == {
        "app_id": "123", "private_key": "synthetic-pem"}


def test_an_audit_pat_the_worker_cannot_resolve_fails_only_the_audit_reads_optional_secret(monkeypatch):
    from functools import partial

    from cremore_github_provider.metadata.tests.fake import SECRETS, FakeBroker, FakeTransport

    from cremore.coverage import METADATA_JOB_KIND
    from cremore.domain.models import ScanJob
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    spec = enterprise_spec(capabilities=["inventory", "audit"], options={"include_audit_events": True})
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()))
    from cremore_github_provider.metadata import export_http

    transport = FakeTransport(responses, enterprise=ENTERPRISE)
    monkeypatch.setattr(export_http, "download", lambda tx, _location: tx.download())
    monkeypatch.setattr(adapter, "collect_pages", partial(adapter.collect_pages, now=lambda: NOW, broker=FakeBroker(),
                                                              transport=transport))
    store = MetadataStore(repo)
    connection, _ = store.create(spec, "test")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
        "provider": "github", "coverage_connection_id": str(connection["id"]),
        "coverage_revision": connection["revision"]}))

    def resolve(ref):
        if ref == spec.secret_refs["audit_token"]:
            raise RuntimeError("synthetic: the sealing key changed")
        return {"app_id": SECRETS["app_id"], "private_key": SECRETS["private_key"]}

    worker = JobWorker(repo, metadata_secret_resolver=type("R", (), {"resolve": staticmethod(resolve)}))
    assert worker.process_next()
    assert repo.get_job(job.id).status == "RUNNING"  # Export is queued asynchronously.
    from datetime import UTC, datetime, timedelta

    from cremore.db import task_store

    later = datetime.now(UTC) + timedelta(minutes=1)
    monkeypatch.setattr(task_store, "_clock", lambda _conn: later)
    assert worker.process_next()
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED", done.error
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "PARTIAL"
    audit = next(record for record in store.iter_records(run["id"]) if record["record_type"] == "operation_report"
                 and record["provenance"]["operation"] == "github.audit")
    assert audit["reasons"] == ["GITHUB_ENTERPRISE_AUDIT_TOKEN_UNAVAILABLE"]


def test_discovered_organizations_are_paged_even_before_org_reads(environment):
    repo, client = environment
    body = connect(client, repo).json()
    store = MetadataStore(repo)
    cid = uuid.UUID(body["id"])
    spec = MetadataConnectionSpec.model_validate(store.get(cid)["spec"])
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    _t, _b, records, _state, _final = drive(spec, responses, enterprise=ENTERPRISE)
    discovered = [record for record in records if record["provenance"]["operation"] == "github.organizations"]
    run = store.start(cid, 1, str(uuid.uuid4()), metadata_contract(spec).model_dump())
    with pytest.raises(CoverageError, match="METADATA_OUTSIDE_APPROVED_SCOPE"):
        store.append(cid, run["id"], MetadataBatch.model_validate({"schema_version": 2, "index": 0, "items": discovered}))
    store.append(cid, run["id"], MetadataBatch.model_validate({"schema_version": 2, "index": 0, "items": discovered}),
                 trusted_discovery=True)
    path = f"/api/v2/coverage/connections/{cid}/github-organizations"
    response = client.get(path + "?limit=1").json()
    assert response["total"] == 2 and response["next_offset"] == 1
    assert response["items"][0]["org"] == ORG
    assert response["items"][0]["status"] == "NOT_COLLECTED"
    assert response["discovery"]["status"] == "COMPLETE"
    # Not read yet: the permission health is unknown, listed against the reads it would start with.
    health = response["items"][0]["health"]
    assert (health["status"], health["api_access_verified"]) == ("unknown", False)
    assert "org_sso" in {row["kind"] for row in health["sources"]}
    # The permission table is the provider descriptor's; the roster does not repeat it.
    assert "source_permissions" not in response
    assert response["app"] is None
    assert client.get(path + "?limit=1&offset=1").json()["items"][0]["org"] == OTHER_ORG
    store.change(cid, 1, "test", spec=spec.model_copy(update={"name": "Changed"}))
    assert client.get(path).json()["current_revision"] is False


def _finished(store, cid, spec, records, *, trusted=True):
    from cremore.coverage.metadata_models import MetadataFinish

    run = store.start(cid, 1, str(uuid.uuid4()), metadata_contract(spec).model_dump())
    store.append(cid, run["id"], MetadataBatch.model_validate({"schema_version": 2, "index": 0, "items": records}),
                 trusted_discovery=trusted)
    store.finish(cid, run["id"], MetadataFinish(batch_count=1, item_count=len(records), status="PARTIAL"))
    return run["id"]


@pytest.mark.parametrize("environment", ["memory", "sqlite"], indirect=True)
def test_export_snapshot_rows_do_not_accumulate_in_inventory_and_pages_pin_the_run(environment):
    from cremore_github_provider.metadata.exports import Projection
    from cremore_github_provider.metadata.normalization import provenance
    from cremore_github_provider.metadata.tests.test_exports import AS_OF, row

    from cremore.coverage.metadata_models import OperationReport

    repo, client = environment
    _owner, inventory = wizard(repo, github())
    store = MetadataStore(repo)
    spec = MetadataConnectionSpec.model_validate(inventory["spec"])

    def collect(export, kinds):
        projection = Projection(spec, export=export, generated_at=AS_OF)
        records = []
        for i, kind in enumerate(["classic_pat", *kinds], 1):
            records.extend(projection.project(i, row(credential_type=kind,
                credential_id="17" if kind == "classic_pat" else "",
                item_type="token_issuer_principal" if kind == "github_app_installation" else "credential")))
        records.append(OperationReport(scope=spec.scopes[0], purpose="issuer_inventory", status="COMPLETE",
            provenance=provenance("github.inventory"), pages=1, saved_records=len(records)))
        return _finished(store, inventory["id"], spec, [r.model_dump() for r in records])

    first = collect("first", ["github_app_installation", "federated_jti"])
    path = f"/api/v2/coverage/connections/{inventory['id']}/github-export-rows"
    observed = client.get(path, params={"limit": 1}).json()
    assert observed["total"] == 2 and observed["next_offset"] == 1
    assert observed["run"]["id"] == str(first) and observed["current_revision"]
    second = collect("second", ["federated_jti"])
    current = client.get(path).json()
    assert current["total"] == 1 and current["run"]["id"] == str(second)
    prior = client.get(path, params={"run_id": str(first), "offset": 1, "limit": 1}).json()
    assert prior["total"] == 2 and not prior["current_revision"]
    assert prior["items"][0]["metadata"]["credential_type"] == "federated_jti"
    assert client.get(path, params={"credential_type": "github_app_installation"}).json()["total"] == 0
    assert client.get(path, params={"credential_type": "unknown"}).status_code == 422
    summary = store.inventory(provider="github", purpose="issuer_inventory")
    assert summary["total"] == summary["total_all"] == 1
    assert summary["counts"] == {"credential": 1}
    # Immutable rows and historical detail remain available, but are not unique credential entities.
    assert store.record_page(run_id=first, record_type="entity_observation")["total"] == 3
    assert "secret_refs" not in str(prior) and "spec_snapshot" not in str(prior)
    assert "inventory_id" not in str(prior) and "export:first" not in str(prior)
    _owner2, other = wizard(repo, github())
    assert client.get(f"/api/v2/coverage/connections/{other['id']}/github-export-rows",
                      params={"run_id": str(first)}).status_code == 404


def test_installation_check_route_needs_a_finished_collection_and_a_known_organization(environment):
    repo, client = environment
    cid = uuid.UUID(connect(client, repo).json()["id"])
    store = MetadataStore(repo)
    spec = MetadataConnectionSpec.model_validate(store.get(cid)["spec"])
    path = f"/api/v2/coverage/connections/{cid}/github-installation-check"
    refused = client.post(path, json={})
    assert refused.status_code == 409 and refused.json()["error"] == "GITHUB_INSTALLATION_CHECK_NEEDS_A_FINISHED_COLLECTION"
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    discovered = [record for record in drive(spec, responses, enterprise=ENTERPRISE)[2]
                  if record["provenance"]["operation"] == "github.organizations"]
    base = _finished(store, cid, spec, discovered)
    unknown = client.post(path, json={"org": "unknown-org"})
    assert unknown.status_code == 409 and unknown.json()["error"] == "GITHUB_ORGANIZATION_NOT_OBSERVED_BY_THE_COLLECTION"
    assert client.post(path, json={"org": "../x"}).status_code == 422
    queued = client.post(path, json={"org": ORG})
    assert queued.status_code == 202, queued.text
    job = repo.get_job(uuid.UUID(queued.json()["job_id"]))
    assert job.payload["retry_from_run"] == str(base) and job.payload["retry_operations"] == ["installation_check"]
    assert job.payload["retry_scope_id"] == ORG and job.payload["coverage_revision"] == 1
    # One active job per connection: a second request returns it instead of queueing another.
    assert client.post(path, json={}).json()["job_id"] == queued.json()["job_id"]


def test_installation_check_overlays_the_roster_route_after_the_collection(environment):
    from cremore_github_provider.metadata.tests.test_installation_check import check, installation

    repo, client = environment
    cid = uuid.UUID(connect(client, repo).json()["id"])
    store = MetadataStore(repo)
    spec = MetadataConnectionSpec.model_validate(store.get(cid)["spec"])
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    discovered = [record for record in drive(spec, responses, enterprise=ENTERPRISE)[2]
                  if record["provenance"]["operation"] == "github.organizations"]
    base = _finished(store, cid, spec, discovered)
    plan = adapter.plan_recollection(store.iter_records(base), operations=["installation_check"])
    rows = check(spec, {"/app/installations?per_page=100": [installation(ORG, 71)]}, plan)[2]
    checked = _finished(store, cid, spec, rows)
    roster = client.get(f"/api/v2/coverage/connections/{cid}/github-organizations").json()
    assert roster["run"]["id"] == str(base)
    assert [run["id"] for run in roster["installation_checks"]] == [str(checked)]
    health = {row["org"]: row["health"] for row in roster["items"]}
    assert health[OTHER_ORG]["status"] == "not_installed"
    assert health[ORG]["basis"] == "app_installations" and roster["app"]["slug"] == "cremore-metadata"


def test_audit_link_view_lists_the_latest_collections_links_and_unmatched_events_without_digests(environment):
    from cremore_github_provider.metadata.tests.test_audit_links import MANAGED, links

    repo, client = environment
    _result, records, _final = links()
    connection = enterprise_spec(capabilities=["inventory", "audit", "issuer_digest"],
                                 options={"include_audit_events": True, "include_provider_hashes": True,
                                          "sources": ["org_sso", "org_fgpat", "org_repositories"]})
    store = MetadataStore(repo)
    row, _token = store.create(connection, "test")
    path = f"/api/v2/coverage/connections/{row['id']}/github-audit-links"
    empty = client.get(path).json()
    assert (empty["total"], empty["run"]) == (0, None)
    _finished(store, row["id"], connection, records, trusted=True)
    view = client.get(path)
    assert view.status_code == 200, view.text
    body = view.json()
    assert body["counts"] == {"events": 8, "linked": 5, "unmatched": 3}
    assert body["relation_counts"] == {"target": 4, "associated": 1, "unmatched": 3}
    assert "fine_grained_pat" in body["credential_types"]
    keyed = next(item for item in records if item.get("event_id") == "e2")["value_match"]["fingerprint"]
    assert MANAGED not in view.text and keyed not in view.text
    unmatched = client.get(path + "?relation=unmatched").json()
    assert {item["event_id"]: item["reason"] for item in unmatched["items"]} == {
        "e4": "ambiguous_reference", "e7": "no_exact_reference", "e8": "no_observed_credential"}
    typed = client.get(path + "?credential_type=fine_grained_pat").json()
    assert [(item["event_id"], item["relation"]) for item in typed["items"]] == [("e1", "target")]
    paged = client.get(path + "?limit=2").json()
    assert paged["total"] == 8 and paged["next_offset"] == 2 and len(paged["items"]) == 2
    assert client.get(path + "?relation=everything").status_code == 422


def _collection_then_checks(repo, client, count):
    from cremore_github_provider.metadata.tests.test_installation_check import check, installation

    cid = uuid.UUID(connect(client, repo).json()["id"])
    store = MetadataStore(repo)
    spec = MetadataConnectionSpec.model_validate(store.get(cid)["spec"])
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    discovered = [record for record in drive(spec, responses, enterprise=ENTERPRISE)[2]
                  if record["provenance"]["operation"] == "github.organizations"]
    base = _finished(store, cid, spec, discovered)
    rows = check(spec, {f"/orgs/{ORG}/installation": installation(ORG, 71)},
                 {"installation_check": {"orgs": [ORG], "listing": False}})[2]
    checks = [_finished(store, cid, spec, rows) for _ in range(count)]
    return cid, base, checks


def test_the_roster_finds_the_collection_behind_checks(environment):
    repo, client = environment
    # More checks than one page of runs (50): the collection is behind all of them.
    cid, base, _checks = _collection_then_checks(repo, client, 55)
    roster = client.get(f"/api/v2/coverage/connections/{cid}/github-organizations").json()
    assert roster["run"]["id"] == str(base) and len(roster["installation_checks"]) == 55
    assert [row["org"] for row in roster["items"]] == [ORG, OTHER_ORG]
    queued = client.post(f"/api/v2/coverage/connections/{cid}/github-installation-check", json={"org": ORG})
    assert queued.status_code == 202, queued.text
    assert repo.get_job(uuid.UUID(queued.json()["job_id"])).payload["retry_from_run"] == str(base)


def test_installation_history_budget_refuses_an_incomplete_roster_and_keeps_run_pages(environment, monkeypatch):
    from cremore.api import metadata_coverage

    repo, client = environment
    cid, _base, _checks = _collection_then_checks(repo, client, 3)
    monkeypatch.setattr(metadata_coverage, "GITHUB_HISTORY_RUN_LIMIT", 3)
    for view in ("github-organizations", "github-audit-links"):
        response = client.get(f"/api/v2/coverage/connections/{cid}/{view}")
        assert response.status_code == 409
        assert response.json()["error"] == "GITHUB_INSTALLATION_HISTORY_LIMIT_USE_RUN_PAGES"
    history = client.get(f"/api/v2/coverage/connections/{cid}/runs?limit=2").json()
    assert history["total"] == 4 and len(history["items"]) == 2
    # An ordinary full collection remains available to establish a new base.
    assert client.post(f"/api/v2/coverage/connections/{cid}/collect", json={}).status_code == 202


def test_installation_overlay_has_shared_record_and_byte_budgets(environment, monkeypatch):
    from cremore.api import metadata_coverage

    repo, client = environment
    cid, _base, _checks = _collection_then_checks(repo, client, 2)
    monkeypatch.setattr(metadata_coverage, "GITHUB_CHECK_RECORD_LIMIT", 1)
    response = client.get(f"/api/v2/coverage/connections/{cid}/github-organizations")
    assert response.status_code == 409
    monkeypatch.setattr(metadata_coverage, "GITHUB_CHECK_RECORD_LIMIT", 10000)
    monkeypatch.setattr(metadata_coverage, "GITHUB_CHECK_BYTE_LIMIT", 1)
    assert client.get(f"/api/v2/coverage/connections/{cid}/github-organizations").status_code == 409


def test_the_generic_retry_refuses_a_check_run_as_retry_base(environment):
    repo, client = environment
    cid, _base, checks = _collection_then_checks(repo, client, 1)
    response = client.post(f"/api/v2/coverage/connections/{cid}/collect",
                           json={"retry_from_run": str(checks[0]), "operations": ["installation_check"]})
    assert response.status_code == 409 and response.json()["error"] == "GITHUB_INSTALLATION_CHECK_NEEDS_A_COLLECTION_BASE"


def _audit_link_run(repo):
    from cremore_github_provider.metadata.tests.test_audit_links import links

    _result, records, _final = links()
    connection = enterprise_spec(capabilities=["inventory", "audit", "issuer_digest"],
                                 options={"include_audit_events": True, "include_provider_hashes": True,
                                          "sources": ["org_sso", "org_fgpat", "org_repositories"]})
    store = MetadataStore(repo)
    row, _token = store.create(connection, "test")
    run_id = _finished(store, row["id"], connection, records, trusted=True)
    return f"/api/v2/coverage/connections/{row['id']}/github-audit-links", run_id


def test_audit_link_view_is_bounded_and_reuses_a_finished_run(environment, monkeypatch):
    repo, client = environment
    path, run_id = _audit_link_run(repo)
    reads = []
    original = MetadataStore.iter_records

    def counted(self, rid):
        reads.append(rid)
        return original(self, rid)

    monkeypatch.setattr(MetadataStore, "iter_records", counted)
    first = client.get(path).json()
    again = client.get(path + "?relation=unmatched&limit=2").json()
    assert first["total"] == 8 and again["total"] == 3 and len(again["items"]) == 2
    assert again["relation_counts"] == first["relation_counts"] == {"target": 4, "associated": 1, "unmatched": 3}
    # The finished run was read once; paging and filtering it again use the joined rows.
    assert reads == [run_id]


def test_audit_link_view_is_bounded_by_its_event_limit(environment, monkeypatch):
    from cremore_github_provider.metadata import audit_links

    repo, client = environment
    path, _run_id = _audit_link_run(repo)
    monkeypatch.setattr(audit_links, "AUDIT_LINK_LIMIT", 3)
    refused = client.get(path)
    assert refused.status_code == 409 and refused.json()["error"] == "GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES"


def _split_audit(environment):
    from cremore_github_provider.metadata.tests.test_audit_links import links

    from cremore.coverage.metadata_models import MetadataOptions
    from cremore.onboarding.store import ProviderConnectionStore

    repo, _client = environment
    owner, inventory = wizard(repo, github())
    store = MetadataStore(repo)
    spec = MetadataConnectionSpec.model_validate(inventory["spec"])
    audit_spec = spec.model_copy(update={"name": "Separate audit", "capabilities": ["inventory", "audit"],
        "options": MetadataOptions(mode="enterprise", github_inventory=False, enterprise_only=True,
                                   include_audit_events=True)})
    audit, _ = store.create(audit_spec, "test")
    ProviderConnectionStore(repo).link(owner["id"], "inventory", "metadata", audit["id"])
    _result, records, _final = links(provider_hashes=False)
    inventory_rows = [r for r in records if r.get("identity", {}).get("object_id") == "inventory:fine_grained_pat:id:41"]
    audit_rows = [r for r in records if r.get("event_id") == "e1"]
    for record in inventory_rows + audit_rows:
        for field in ("identity", "subject", "target"):
            if record.get(field):
                record[field]["tenant"] = spec.tenant
    _finished(store, inventory["id"], spec, inventory_rows)
    _finished(store, audit["id"], audit_spec, audit_rows)
    return store, owner, inventory, audit, inventory_rows


@pytest.mark.parametrize("environment", ["memory", "sqlite"], indirect=True)
def test_separate_audit_and_inventory_join_in_both_views_and_new_inventory_invalidates_cache(environment):
    store, _owner, inventory, audit, inventory_rows = _split_audit(environment)
    _repo, client = environment
    for row in (inventory, audit):
        body = client.get(f"/api/v2/coverage/connections/{row['id']}/github-audit-links").json()
        assert body["counts"] == {"events": 1, "linked": 1, "unmatched": 0}
        assert len(body["sources"]) == 2
        assert all(s["current_revision"] and s["run"]["status"] == "PARTIAL" for s in body["sources"])
    # Same audit run, a newly collected inventory with a different token ID.
    from copy import deepcopy
    changed = deepcopy(inventory_rows)
    changed[0]["identity"]["object_id"] = "inventory:fine_grained_pat:id:42"
    for fact in changed[0]["facts"]:
        if fact["name"] == "credential_id":
            fact["value"] = "42"
    _finished(store, inventory["id"], MetadataConnectionSpec.model_validate(inventory["spec"]), changed)
    body = client.get(f"/api/v2/coverage/connections/{audit['id']}/github-audit-links").json()
    assert body["counts"] == {"events": 1, "linked": 0, "unmatched": 1}


@pytest.mark.parametrize("change", ["disabled", "revision", "scope", "origin", "owner", "feature"])
@pytest.mark.parametrize("environment", ["memory", "sqlite"], indirect=True)
def test_audit_join_does_not_cross_changed_or_unapproved_sibling_boundaries(environment, change):
    from cremore.onboarding.store import ProviderConnectionStore

    store, owner, inventory, audit, _ = _split_audit(environment)
    repo, client = environment
    path = f"/api/v2/coverage/connections/{audit['id']}/github-audit-links"
    assert client.get(path).json()["counts"]["linked"] == 1
    parents = ProviderConnectionStore(repo)
    if change == "owner":
        other = parents.create({key: owner[key] for key in
            ("provider", "edition", "name", "auth_method", "target", "purposes", "secret_refs", "plans")}, "test")
        parents.relink(other["id"], "inventory", "metadata", inventory["id"])
    elif change == "feature":
        parents.update(owner["id"], owner["revision"], "test", disabled_purposes=["inventory"])
    elif change == "disabled":
        store.change(inventory["id"], 1, "test", enabled=False)
    else:
        spec = MetadataConnectionSpec.model_validate(inventory["spec"])
        if change == "scope":
            spec.scopes[0].id = "unapproved-enterprise"
        elif change == "origin":
            spec.origin, spec.edition = "https://another.ghe.com", "dedicated"
        else:
            spec.name = "Edited connection"
        store.change(inventory["id"], 1, "test", spec=spec)
    assert client.get(path).json()["counts"] == {"events": 1, "linked": 0, "unmatched": 1}


@pytest.mark.parametrize("environment", ["memory", "sqlite"], indirect=True)
def test_export_status_is_public_without_handles_and_manual_collection_respects_shared_wait(environment):
    from datetime import UTC, datetime

    from cremore.coverage.github_exports_test import confirmed, control

    repo, client = environment
    _owner, row = wizard(repo, github())
    spec = MetadataConnectionSpec.model_validate(row["spec"])
    now = datetime.now(UTC)
    owner = control(repo, spec, now=now)
    owner.reserve()
    owner.save({"stage": "submission_unknown", "error": "github_unavailable"})
    path = f"/api/v2/coverage/connections/{row['id']}"
    blocked = client.post(path + "/collect", json={})
    assert blocked.status_code == 409 and blocked.json()["error"] == "GITHUB_EXPORT_SUBMISSION_UNKNOWN"
    status = client.get(path).json()["enterprise_export"]
    assert status["creation_allowed"] is False and status["reuse_available"] is False
    assert status["request_blocked_reason"] == "GITHUB_EXPORT_SUBMISSION_UNKNOWN"
    owner.save(confirmed("reading", as_of=now.isoformat(), submitted_at=now.isoformat()))
    assert client.get(path).json()["enterprise_export"]["stage"] == "reading"
    owner.save(confirmed("complete", as_of=now.isoformat(), submitted_at=now.isoformat()))
    queued = client.post(path + "/collect", json={})
    assert queued.status_code == 202
    data = client.get("/api/v1/scan-runs/" + queued.json()["job_id"])
    assert data.status_code == 200, data.text
    shared = data.json()["enterprise_export"]
    assert shared["reuse_available"] is True and shared["as_of"] == now.isoformat()
    assert "export_id" not in shared and "job_id" not in shared and "url" not in shared
    # Same active job is returned, not duplicated.
    assert client.post(path + "/collect", json={}).json() == queued.json()
