"""The departed-owner check over synthetic IdP and provider collections (design 4.2 table)."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cremore_github_provider.identity import adapter as github_identity
from cremore_github_provider.metadata.tests import fake as github_fake
from cremore_github_provider.metadata.tests.test_adapter import drive as github_drive
from cremore_keycloak_provider.tests import test_identity as keycloak
from cremore_notion_provider.metadata.normalization import observation as notion_observation
from cremore_okta_provider.tests import test_identity as okta

from cremore.config import Settings
from cremore.coverage.metadata_job_test import (
    repo as repo,  # noqa: PLC0414 -- memory and sqlite repositories
)
from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataBatch,
    MetadataConnectionSpec,
    MetadataFinish,
    MetadataScope,
    metadata_contract,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable PostgreSQL
from cremore.identity import leavers
from cremore.identity.keys import Digester
from cremore.siem.outbox import SiemOutbox

KEY = b"k" * 32  # the okta test digester's key
SETTINGS = Settings(AUTH_MODE="local", API_TOKEN="t" * 40, FINGERPRINT_KEY=KEY.hex())
WORKSPACE = "11111111-2222-4333-8444-555555555555"
NOW = datetime.now(UTC)
DEPARTED_AT = NOW - timedelta(days=10)


def save(store, spec, items, *, owner=None, status="COMPLETE"):
    if owner is None:
        owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    records = [RECORD_ADAPTER.validate_python(item) if isinstance(item, dict) else item for item in items]
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=records), trusted_discovery=True)
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(records), status=status))
    return owner


def ms(moment):
    return int(moment.timestamp() * 1000)


def okta_people(*rows):
    page = okta.users_page(*rows)
    records, final = okta.run(okta.spec(options={"page_size": 200}), okta.Org({"": page}))
    assert final.status == "COMPLETE"
    return records


def notion_spec():
    return MetadataConnectionSpec.model_validate({
        "name": "notion", "provider": "notion", "origin": "https://api.notion.com",
        "scopes": [{"kind": "workspace", "id": WORKSPACE}], "capabilities": ["inventory"],
        "secret_refs": {"token": "vault://notion/bot"}})


def notion_pat(token_id, email, *, status="active", last_used=None):
    row = {"id": token_id, "creator": {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, email)), "name": email.split("@")[0],
                                       "email": email},
           "created_at": ms(NOW - timedelta(days=100)), "status": status, "name": "token " + token_id[-4:]}
    if last_used is not None:
        row["last_used_at"] = ms(last_used)
    return notion_observation(notion_spec(), MetadataScope(kind="workspace", id=WORKSPACE), "personal_access_tokens",
                              row, observed_at=NOW.isoformat())


def seed(repo, *, dana_status="DEPROVISIONED"):
    store = MetadataStore(repo)
    people = okta_people(
        okta.row("00udana00001", dana_status, email="dana@acme.test", changed=DEPARTED_AT.isoformat()),
        okta.row("00ueve000001", "ACTIVE", email="eve@acme.test"))
    idp = save(store, okta.spec(options={"page_size": 200}), people)
    tokens = [notion_pat("aaaaaaaa-0000-4000-8000-000000000001", "dana@acme.test", last_used=NOW - timedelta(days=2)),
              notion_pat("aaaaaaaa-0000-4000-8000-000000000002", "dana@acme.test"),
              notion_pat("aaaaaaaa-0000-4000-8000-000000000003", "dana@acme.test", status="revoked"),
              notion_pat("aaaaaaaa-0000-4000-8000-000000000004", "eve@acme.test")]
    notion = save(store, notion_spec(), tokens)
    return store, idp, notion


def evaluate(repo, now=NOW, **kwargs):
    return leavers.evaluate(repo, SETTINGS, now=now, fingerprint_key=KEY, report_rows=kwargs.pop("report_rows", []),
                            **kwargs)


def orphans_by_name(repo):
    return {row["body"]["credential"]["name"] if row["body"]["credential"] else "account": row
            for row in leavers.LeaverStore(repo).orphans().values()}


def events(repo):
    return [item["event"] for item in SiemOutbox(repo).claim("test", limit=500)
            if item["event"]["event_type"] == "identity.credential_orphaned"]


def test_the_verdict_table_for_a_departed_owners_tokens(repo):
    seed(repo)
    result = evaluate(repo)
    assert (result["people"], result["departed"], result["orphans"]) == (2, 1, 3)
    found = orphans_by_name(repo)
    verdicts = sorted(row["verdict"] for row in found.values())
    assert verdicts == ["ACTIVE", "REVOKED_OR_EXPIRED", "USED_AFTER_DEPARTURE"]
    person = next(iter(found.values()))["body"]["person"]
    assert person["departure_basis"] == "PROVIDER_REPORTED"
    assert person["departed_at"] == DEPARTED_AT.isoformat()
    assert next(iter(found.values()))["body"]["account"]["link_basis"] == "VERIFIED_EMAIL"
    # eve is active: her token is nobody's orphan.
    assert all(row["body"]["person"]["idp_user_id"] == "00udana00001" for row in found.values())


def test_events_are_edge_triggered_and_carry_no_personal_data(repo):
    seed(repo)
    evaluate(repo)
    first = events(repo)
    assert sorted(event["orphan"]["verdict"] for event in first) == ["ACTIVE", "USED_AFTER_DEPARTURE"]
    assert all(event["orphan"]["previous_verdict"] is None for event in first)
    text = json.dumps(first)
    for value in ("dana@acme.test", "00udana00001", "dana"):
        assert value not in text
    evaluate(repo, now=NOW + timedelta(minutes=5))
    assert events(repo) == []  # nothing changed


def test_a_revoked_token_publishes_the_change_and_tickets_open_once(repo):
    store, _idp, notion = seed(repo)
    evaluate(repo)
    tickets = {t.orphan_ref: t for t in repo.list_tickets()}
    assert sorted(t.priority for t in tickets.values()) == ["CRITICAL", "HIGH"]
    assert all(t.template_id == "DEPARTED_OWNER" for t in tickets.values())
    events(repo)
    save(store, notion_spec(), [
        notion_pat("aaaaaaaa-0000-4000-8000-000000000001", "dana@acme.test", last_used=NOW - timedelta(days=2)),
        notion_pat("aaaaaaaa-0000-4000-8000-000000000002", "dana@acme.test", status="revoked"),
        notion_pat("aaaaaaaa-0000-4000-8000-000000000003", "dana@acme.test", status="revoked"),
        notion_pat("aaaaaaaa-0000-4000-8000-000000000004", "eve@acme.test")], owner=notion)
    evaluate(repo, now=NOW + timedelta(minutes=10))
    changed = events(repo)
    assert [(e["orphan"]["previous_verdict"], e["orphan"]["verdict"]) for e in changed] == [("ACTIVE", "REVOKED_OR_EXPIRED")]
    assert len(repo.list_tickets()) == 2


def test_a_user_missing_from_a_complete_listing_departs_when_first_seen_missing(repo):
    store, idp, _notion = seed(repo, dana_status="ACTIVE")
    evaluate(repo)
    assert leavers.LeaverStore(repo).orphans() == {}
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00ueve000001", "ACTIVE")), owner=idp)
    evaluate(repo, now=NOW + timedelta(minutes=5))
    people = {row["idp_user_id"]: row for row in leavers.LeaverStore(repo).people().values()}
    assert people["00udana00001"]["state"] == "DEPARTED"
    assert people["00udana00001"]["departure_basis"] == "FIRST_OBSERVED_MISSING"
    # The first run that missed the user dates it: never before it was last seen active.
    found = orphans_by_name(repo)
    assert sorted(row["verdict"] for row in found.values()) == ["ACTIVE", "ACTIVE", "REVOKED_OR_EXPIRED"]


def test_a_user_missing_after_more_failed_runs_than_one_read_of_the_history_still_departs(repo, monkeypatch):
    store, idp, _notion = seed(repo, dana_status="ACTIVE")
    evaluate(repo)
    for _ in range(3):  # stands in for a week of partial five-minute runs: more than one read of the run history
        save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00ueve000001", "ACTIVE")), owner=idp,
             status="PARTIAL")
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00ueve000001", "ACTIVE")), owner=idp)
    runs = MetadataStore.connection_runs
    monkeypatch.setattr(MetadataStore, "connection_runs",
                        lambda self, cid, *, offset=0, limit=50: runs(self, cid, offset=offset, limit=min(limit, 2)))
    evaluate(repo, now=NOW + timedelta(minutes=5))
    people = {row["idp_user_id"]: row for row in leavers.LeaverStore(repo).people().values()}
    assert (people["00udana00001"]["state"], people["00udana00001"]["departure_basis"]) == (
        "DEPARTED", "FIRST_OBSERVED_MISSING")


def okta_apps(pages=None):
    """A run of the Okta app list: the org's apps, or what a refused listing records."""
    records, final = okta.run(okta.spec(**okta.APPS_SPEC), okta.apps_org(pages))
    return records, final.status


def test_a_people_collection_switched_to_its_app_list_departs_nobody(repo):
    """An admin may point an existing people collection at the IdP's app list: its runs then list no people, and
    nobody it listed before is read as gone."""
    store, idp, _notion = seed(repo, dana_status="ACTIVE")
    evaluate(repo)
    before = {row["idp_user_id"]: row["state"] for row in leavers.LeaverStore(repo).people().values()}
    owner, _token = store.change(idp["id"], idp["revision"], "synthetic", spec=okta.spec(**okta.APPS_SPEC))
    records, status = okta_apps()
    assert status == "COMPLETE"
    save(store, okta.spec(**okta.APPS_SPEC), records, owner=owner)
    evaluate(repo, now=NOW + timedelta(minutes=5))
    after = {row["idp_user_id"]: row["state"] for row in leavers.LeaverStore(repo).people().values()}
    assert before == after == {"00udana00001": "ACTIVE", "00ueve000001": "ACTIVE"}
    assert leavers.LeaverStore(repo).orphans() == {} and repo.list_tickets() == []


def test_an_app_list_beside_the_people_listing_changes_no_verdict_complete_or_failed(repo):
    store, _idp, _notion = seed(repo)
    evaluate(repo)
    verdicts = sorted(row["verdict"] for row in orphans_by_name(repo).values())
    apps_spec, apps = okta.spec(name="okta apps", **okta.APPS_SPEC), None
    denied = {(okta.ACTIVE, ""): httpx.Response(403), (okta.INACTIVE, ""): httpx.Response(403)}
    for pages, expected in ((None, "COMPLETE"), (denied, "FAILED")):
        records, status = okta_apps(pages)
        assert status == expected
        apps = save(store, apps_spec, records, owner=apps, status=status)
        result = evaluate(repo, now=NOW + timedelta(minutes=5))
        assert (result["people"], result["departed"]) == (2, 1)
        assert sorted(row["verdict"] for row in orphans_by_name(repo).values()) == verdicts


def test_a_partial_listing_never_departs_anyone(repo):
    store, idp, _notion = seed(repo, dana_status="ACTIVE")
    evaluate(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00ueve000001", "ACTIVE")), owner=idp,
         status="PARTIAL")
    evaluate(repo, now=NOW + timedelta(minutes=5))
    people = {row["idp_user_id"]: row for row in leavers.LeaverStore(repo).people().values()}
    assert people["00udana00001"]["state"] == "ACTIVE"


def test_two_people_of_one_idp_with_the_same_email_are_only_candidates(repo):
    store = MetadataStore(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(
        okta.row("00udana00001", "DEPROVISIONED", email="shared@acme.test", changed=DEPARTED_AT.isoformat()),
        okta.row("00udana00002", "DEPROVISIONED", email="shared@acme.test", login="other@acme.test",
                 changed=DEPARTED_AT.isoformat())))
    save(store, notion_spec(), [notion_pat("aaaaaaaa-0000-4000-8000-000000000009", "shared@acme.test")])
    result = evaluate(repo)
    assert (result["orphans"], result["candidates"]) == (0, 2)


def test_github_accounts_link_through_saml_identities_and_report_unlisted_tokens(repo):
    store = MetadataStore(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(
        okta.row("00udana00001", "SUSPENDED", email="dana@acme.test", changed=DEPARTED_AT.isoformat())))
    _t, _b, committed, _s, _final = github_drive(github_fake.spec(), github_fake.org_responses())
    save(store, github_fake.spec(), committed)
    directory = github_identity_spec()
    records = []
    for page in github_identity.collect_pages(
            directory, secrets={"token": "ghp_" + "a" * 36}, checkpoint={}, check=lambda: None,
            identity_digest=Digester(KEY), client=httpx.Client(transport=httpx.MockTransport(saml_directory)),
            sleep=lambda _s: None):
        records.extend(page.records)
    save(store, directory, records)
    evaluate(repo)
    found = list(leavers.LeaverStore(repo).orphans().values())
    kinds = sorted((row["body"]["credential"] or {}).get("type", "ACCOUNT") for row in found)
    # Both SSO authorizations are the person's: the classic PAT (a `credential` entity) and the SSH key (`public_key`).
    assert "ACCOUNT" in kinds and "GITHUB_FINE_GRAINED_PAT" in kinds and kinds.count("GITHUB_SSO_AUTHORIZED_CREDENTIAL") == 2
    account_row = next(row for row in found if row["body"]["credential"] is None)
    assert account_row["verdict"] == "UNKNOWN"
    assert account_row["body"]["reasons"] == ["PROVIDER_DOES_NOT_LIST_EVERY_CREDENTIAL"]
    assert all(row["body"]["account"]["link_basis"] == "SAML_NAME_ID" for row in found)


def github_identity_spec():
    return MetadataConnectionSpec.model_validate({
        "name": "gh saml", "provider": "github_identity", "origin": "https://github.com",
        "edition": "enterprise_cloud", "scopes": [{"kind": "organization", "id": github_fake.ORG}],
        "capabilities": ["identity_status"], "auth_type": "bearer", "secret_refs": {"token": "vault://gh/owner"}})


def saml_directory(request):
    return httpx.Response(200, json={"data": {"organization": {"samlIdentityProvider": {"externalIdentities": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [{"samlIdentity": {"nameId": "dana@acme.test", "username": None, "emails": []},
                   "scimIdentity": None, "user": {"login": "octocat"}}]}}}}})


AWS_ROW = {"origin": "ISSUANCE", "credential_type": "AWS_ACCESS_KEY", "identifier": "AKIAABCDEFGHIJKLMNOP",
           "state": "NO_VAULT_MATCH", "exposed": False,
           "issued": {"provider": "aws_iam", "evidence": "ISSUED", "credential_type": "AWS_ACCESS_KEY",
                      "identifier": "AKIAABCDEFGHIJKLMNOP", "account_id": "123456789012",
                      "principal_arn": "arn:aws:iam::123456789012:user/dana@acme.test", "state": "Active",
                      "last_used_at": (NOW - timedelta(days=1)).isoformat(), "current_evidence": True}}


def test_an_iam_user_is_a_candidate_until_an_administrator_confirms_it(repo):
    seed(repo)
    result = evaluate(repo, report_rows=[AWS_ROW])
    assert result["candidates"] == 1
    assert not [row for row in leavers.LeaverStore(repo).orphans().values() if row["provider"] == "aws"]
    last = repo.get_setting(leavers.RESULT_KEY)["value"]
    candidate = last["candidate_links"][0]
    assert candidate["basis"] == "PROVIDER_LOGIN" and candidate["account_provider"] == "aws"
    leavers.LeaverStore(repo).save(links=[{"account_ref": candidate["account_ref"],
                                           "person_ref": uuid.UUID(candidate["person_ref"]), "decision": "CONFIRMED",
                                           "basis": "OPERATOR_CONFIRMED", "actor_ref": "admin",
                                           "decided_at": NOW}])
    evaluate(repo, now=NOW + timedelta(minutes=5), report_rows=[AWS_ROW])
    aws = [row for row in leavers.LeaverStore(repo).orphans().values() if row["provider"] == "aws"]
    assert [row["verdict"] for row in aws] == ["USED_AFTER_DEPARTURE"]
    assert aws[0]["body"]["account"]["link_basis"] == "OPERATOR_CONFIRMED"
    assert aws[0]["body"]["credential"]["action"]["key_id"] == "AKIAABCDEFGHIJKLMNOP"


def test_a_rejected_candidate_stays_rejected(repo):
    seed(repo)
    evaluate(repo, report_rows=[AWS_ROW])
    candidate = repo.get_setting(leavers.RESULT_KEY)["value"]["candidate_links"][0]
    leavers.LeaverStore(repo).save(links=[{"account_ref": candidate["account_ref"],
                                           "person_ref": uuid.UUID(candidate["person_ref"]), "decision": "REJECTED",
                                           "basis": "OPERATOR_REJECTED", "actor_ref": "admin", "decided_at": NOW}])
    result = evaluate(repo, now=NOW + timedelta(minutes=5), report_rows=[AWS_ROW])
    assert result["candidates"] == 0


def revoke_all(store, notion):
    save(store, notion_spec(), [
        notion_pat("aaaaaaaa-0000-4000-8000-000000000001", "dana@acme.test", status="revoked",
                   last_used=NOW - timedelta(days=2)),
        notion_pat("aaaaaaaa-0000-4000-8000-000000000002", "dana@acme.test", status="revoked"),
        notion_pat("aaaaaaaa-0000-4000-8000-000000000003", "dana@acme.test", status="revoked"),
        notion_pat("aaaaaaaa-0000-4000-8000-000000000004", "eve@acme.test")], owner=notion)


def test_retention_keeps_a_person_whose_credential_is_still_on(repo):
    seed(repo)
    later = DEPARTED_AT + timedelta(days=SETTINGS.leaver_retention_days + 1)
    result = evaluate(repo, now=later)
    assert result["purged_people"] == 0
    # A year on, the token used after departure is still on: an open problem keeps its data.
    assert "USED_AFTER_DEPARTURE" in {row["verdict"] for row in leavers.LeaverStore(repo).orphans().values()}


def test_retention_turns_a_departed_person_into_a_tombstone(repo):
    store, _idp, notion = seed(repo)
    evaluate(repo)
    revoke_all(store, notion)
    later = DEPARTED_AT + timedelta(days=SETTINGS.leaver_retention_days + 1)
    result = evaluate(repo, now=later)
    assert result["purged_people"] == 1
    state = leavers.LeaverStore(repo)
    dana = next(row for row in state.people().values() if row["state"] == "PURGED")
    assert (dana["idp_user_id"], dana["keys"], dana["departed_at"]) == (None, [], None)
    assert state.orphans() == {}
    assert not [key for key in state.links() if key[1] == dana["person_ref"]]
    # Still listed by the IdP, the tombstone is never brought back.
    evaluate(repo, now=later + timedelta(minutes=5))
    assert state.people()[dana["person_ref"]]["state"] == "PURGED"


def test_identity_collection_history_older_than_its_window_is_deleted(repo):
    store, idp, _notion = seed(repo)
    for _ in range(2):
        save(store, okta.spec(options={"page_size": 200}), okta_people(
            okta.row("00udana00001", "DEPROVISIONED", email="dana@acme.test", changed=DEPARTED_AT.isoformat())),
             owner=idp)
    result = evaluate(repo, now=NOW + timedelta(days=leavers.IDENTITY_RUN_HISTORY_DAYS + 1))
    assert result["pruned_runs"] == 2  # the latest complete run stays
    assert store.connection_runs(idp["id"])["total"] == 1


def test_an_iam_inventory_run_reaches_the_check_through_the_coverage_comparison(repo):
    """End to end: a schema 1 IAM inventory run, the real coverage comparison, then the check."""
    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
    from cremore.coverage.store import CoverageStore
    from cremore.detection.engine import Engine, EngineConfig
    from cremore.scanning.orchestrator import Orchestrator

    seed(repo)
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    store = CoverageStore(repo)
    connection, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id="123456789012"), "admin")
    run = store.start(connection["id"], connection["revision"], str(uuid.uuid4()),
                      Contract(engine_digest=engine.detection_digest).model_dump())
    key = Observation(reference="arn:aws:iam::123456789012:user/dana@acme.test", account_id="123456789012",
                      evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier="AKIAABCDEFGHIJKLMNOP",
                      state="Active", principal_arn="arn:aws:iam::123456789012:user/dana@acme.test",
                      last_used_at=(NOW - timedelta(days=1)).isoformat())
    store.append(connection["id"], run["id"], Batch(index=0, items=[key]))
    store.finish(connection["id"], run["id"], Finish(batch_count=1, item_count=1, status="COMPLETE"))
    orchestrator = Orchestrator(repo, engine=engine, config=engine.config)
    result = leavers.evaluate(repo, SETTINGS, orchestrator, now=NOW, fingerprint_key=KEY)
    assert result["candidates"] == 1
    candidate = repo.get_setting(leavers.RESULT_KEY)["value"]["candidate_links"][0]
    assert candidate["account_ref"] == "aws|aws|123456789012:dana@acme.test"


def test_the_check_and_its_retention_on_postgresql(pg):
    """Upserts, JSON, UUID keys, ticket migration and run pruning on the production database."""
    _engine, database = pg
    store, idp, _notion = seed(database)
    first = evaluate(database)
    assert (first["orphans"], first["tickets"]) == (3, 2)
    assert all(ticket.orphan_ref and ticket.finding_id is None for ticket in database.list_tickets())
    again = evaluate(database, now=NOW + timedelta(minutes=5))
    assert (again["events"], again["tickets"]) == (0, 0)
    for _ in range(2):
        save(store, okta.spec(options={"page_size": 200}), okta_people(
            okta.row("00udana00001", "DEPROVISIONED", email="dana@acme.test", changed=DEPARTED_AT.isoformat()),
            okta.row("00ueve000001", "ACTIVE", email="eve@acme.test")), owner=idp)
    revoke_all(store, _notion)
    later = evaluate(database, now=DEPARTED_AT + timedelta(days=SETTINGS.leaver_retention_days + 1))
    assert later["purged_people"] == 1 and later["pruned_runs"] == 2
    assert leavers.LeaverStore(database).orphans() == {}


def test_the_worker_collects_an_idp_with_the_installation_identity_key(repo, monkeypatch):
    """The metadata job hands identity collectors a digester made from FINGERPRINT_KEY, never the key."""
    from functools import partial

    from cremore_azure_provider.entra_id import adapter as entra_adapter
    from cremore_azure_provider.entra_id import entra_id_test, identity

    from cremore.coverage import METADATA_JOB_KIND
    from cremore.detection.engine import Engine, EngineConfig
    from cremore.domain.models import ScanJob
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.worker import JobWorker

    monkeypatch.setattr(identity, "token_for_spec", lambda _spec: (lambda: "graph-token"))
    monkeypatch.setattr(entra_adapter, "collect_pages", partial(
        entra_adapter.collect_pages, client=httpx.Client(transport=httpx.MockTransport(entra_id_test.graph))))
    store = MetadataStore(repo)
    connection, _ = store.create(entra_id_test.spec(), "test")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
        "provider": "entra_id", "coverage_connection_id": str(connection["id"]),
        "coverage_revision": connection["revision"]}))
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    assert JobWorker(repo, orchestrator=Orchestrator(repo, engine=engine, config=engine.config)).process_next()
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED", done.error
    rows = store.inventory(provider="entra_id", purpose="identity_status", limit=10)["items"]
    assert {row["summary"]["normalized_state"] for row in rows} == {"ACTIVE", "DISABLED", "DELETED"}
    assert all(row["summary"]["identity_key_id"] == Digester(KEY).key_id for row in rows)
    result = evaluate(repo)
    assert result["people"] == 3 and result["departed"] == 2


def test_a_collection_pointed_at_another_directory_leaves_the_first_ones_people_as_they_were(repo, monkeypatch):
    store = MetadataStore(repo)
    owner = save(store, okta.spec(options={"page_size": 200}),
                 okta_people(okta.row("00ueve000001", "ACTIVE", email="eve@acme.test")))
    evaluate(repo)
    monkeypatch.setattr(okta, "ORIGIN", "https://other.okta.com")
    other = okta.spec(origin=okta.ORIGIN, tenant="other.okta.com",
                      scopes=[{"kind": "organization", "id": "other.okta.com"}], options={"page_size": 200})
    owner, _token = store.change(owner["id"], owner["revision"], "synthetic", spec=other)
    records, final = okta.run(other, okta.Org({"": okta.users_page(okta.row("00ufay000001", "ACTIVE",
                                                                            email="fay@other.test"))}))
    assert final.status == "COMPLETE"
    save(store, other, records, owner=owner)
    evaluate(repo)
    people = leavers.LeaverStore(repo).people().values()
    assert sorted((row["tenant"], row["state"]) for row in people) == [
        ("acme.okta.com", "ACTIVE"), ("other.okta.com", "ACTIVE")]  # eve is not called departed


def test_two_collections_of_one_tenant_do_not_call_each_others_people_departed(repo):
    """Both list eve ACTIVE; the one processed last ran first, so the shared row's newest observation is the other's."""
    store = MetadataStore(repo)
    specs = {name: okta.spec(name=name, options={"page_size": 200}) for name in ("Okta A", "Okta B")}
    owners = {name: store.create(spec, "synthetic")[0] for name, spec in specs.items()}
    order = [row["id"] for row in store.list_connections()]
    names = sorted(owners, key=lambda name: order.index(owners[name]["id"]), reverse=True)  # processed last first
    for name in names:
        save(store, specs[name], okta_people(okta.row("00ueve000001", "ACTIVE", email="eve@acme.test")),
             owner=owners[name])
    save(store, notion_spec(), [notion_pat("aaaaaaaa-0000-4000-8000-000000000004", "eve@acme.test")])
    evaluate(repo)
    states = [row["state"] for row in leavers.LeaverStore(repo).people().values()]
    assert states == ["ACTIVE"]  # neither collection's complete listing lost eve
    assert not [row for row in leavers.LeaverStore(repo).orphans().values() if row["verdict"] == "ACTIVE"]


KC_DANA = "dddddddd-0000-4000-8000-000000000001"


def keycloak_people(*users, events=()):
    """(spec, records) of a Keycloak realm's users, and its admin events when given, through the Keycloak collector."""
    def realm(request):
        if request.url.path.endswith("/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "kc-token", "token_type": "Bearer", "expires_in": 300})
        if request.url.path.endswith("/users/count"):
            return httpx.Response(200, json=len(users))
        query = parse_qs(urlsplit(str(request.url)).query)
        rows, first = list(users if request.url.path.endswith("/users") else events), int(query["first"][0])
        return httpx.Response(200, json=rows[first:first + int(query["max"][0])])

    spec = keycloak.spec(audit=bool(events))
    records, final = keycloak.run(spec, realm)
    assert final.status == "COMPLETE"
    return spec, records


def github_directory(store, *nodes):
    """An organization's SAML/SCIM identities (GraphQL externalIdentities nodes) through github_identity."""
    def graphql(_request):
        return httpx.Response(200, json={"data": {"organization": {"samlIdentityProvider": {"externalIdentities": {
            "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": list(nodes)}}}}})

    pages = github_identity.collect_pages(
        github_identity_spec(), secrets={"token": "ghp_" + "a" * 36}, checkpoint={}, check=lambda: None,
        identity_digest=Digester(KEY), client=httpx.Client(transport=httpx.MockTransport(graphql)),
        sleep=lambda _s: None)
    save(store, github_identity_spec(), [record for page in pages for record in page.records])


def test_a_github_identity_naming_people_of_two_idps_links_neither(repo):
    """Okta provisions the organization: its SCIM user name "dana" is Okta's dana, still active. Keycloak's departed
    "dana" names the same value; which IdP's dana it is only the organization's IdP could say, and the directory does
    not say which IdP that is. Both stay candidates, and no verdict is drawn for the active person's account."""
    store = MetadataStore(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00udana00001", "ACTIVE", login="dana")))
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False}))
    github_directory(store, {"samlIdentity": None, "scimIdentity": {"username": "dana", "emails": []},
                             "user": {"login": "octocat"}})
    result = evaluate(repo)
    assert (result["orphans"], result["linked_accounts"]) == (0, 0)
    assert leavers.LeaverStore(repo).orphans() == {} and leavers.LeaverStore(repo).links() == {}
    candidate = repo.get_setting(leavers.RESULT_KEY)["value"]["candidate_links"]  # the departed one, to decide
    people = leavers.LeaverStore(repo).people()
    assert [(people[uuid.UUID(c["person_ref"])]["provider"], c["basis"]) for c in candidate] == [
        ("keycloak", "SCIM_EXTERNAL_ID")]


def test_a_github_identitys_email_links_only_to_an_idp_email(repo):
    """A realm user name shaped like an email is no email the realm verified: the SCIM email is only a candidate."""
    store = MetadataStore(repo)
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana@acme.test", "enabled": False}))
    github_directory(store, {"samlIdentity": None, "user": {"login": "octocat"},
                             "scimIdentity": {"username": None, "emails": [{"value": "dana@acme.test"}]}})
    result = evaluate(repo)
    assert (result["orphans"], result["candidates"]) == (0, 1)


def test_a_gitlab_extern_uid_naming_people_of_two_idps_links_neither():
    """GitLab keeps the uid its external login (SAML, LDAP, OIDC) gave a user, and no record names that IdP: like a
    GitHub directory identity, it links on its own only while it reaches one human. An email GitLab itself confirmed is
    no IdP-sent value: the person it names stays linked."""
    def person(provider, *keys):
        return {"provider": provider, "origin": provider, "tenant": provider, "state": "ACTIVE",
                "keys": [{"kind": kind, "digest": digest} for kind, digest in keys]}

    def link(keys, people):
        account = leavers.Account(ref="gitlab|https://gitlab.com|user:7", provider="gitlab", label="dana",
                                  lists_every=False, keys=keys)
        exact, candidates, _new, contested = leavers.link_accounts({account.ref: account}, people, {}, NOW)
        return (exact.get(account.ref), sorted((found, basis) for _account, found, basis in candidates),
                contested.get(account.ref))

    okta_dana, kc_dana = sorted([uuid.uuid4(), uuid.uuid4()])
    two = {okta_dana: person("okta", ("LOGIN", "dana"), ("EMAIL", "dana@okta.test")),
           kc_dana: person("keycloak", ("LOGIN", "dana"), ("EMAIL", "dana@kc.test"))}
    assert link({("EXTERNAL_UID", "dana")}, two) == (
        None, [(okta_dana, "EXTERNAL_UID"), (kc_dana, "EXTERNAL_UID")], {okta_dana, kc_dana})
    one = {okta_dana: person("okta", ("LOGIN", "dana"), ("EMAIL", "dana@acme.test")),
           kc_dana: person("keycloak", ("LOGIN", "dana"), ("EMAIL", "dana@acme.test"))}
    assert link({("EXTERNAL_UID", "dana")}, one)[0] == {okta_dana: "EXTERNAL_UID", kc_dana: "EXTERNAL_UID"}
    # The uid "dana" names both IdPs' dana; the email GitLab confirmed names Okta's alone, who stays linked by it.
    named = {okta_dana: person("okta", ("LOGIN", "dana"), ("EMAIL", "dana@acme.test")),
             kc_dana: person("keycloak", ("LOGIN", "dana"), ("EMAIL", "dana@kc.test"))}
    assert link({("EXTERNAL_UID", "dana"), ("VERIFIED_EMAIL", "dana@acme.test")}, named) == (
        {okta_dana: "VERIFIED_EMAIL"}, [(kc_dana, "EXTERNAL_UID")], {okta_dana, kc_dana})


def test_listings_are_read_past_one_page_and_one_past_its_budget_decides_nothing(repo, monkeypatch):
    """Rows past one store read were dropped. Every listing is paged now; one longer than MAX_PAGES reads leaves
    people, links, verdicts and tickets as the last complete evaluation left them: a cut list shows nobody leaving."""
    store, _idp, notion = seed(repo)
    monkeypatch.setattr(leavers, "MAX_ROWS", 1)  # two people and four tokens: several reads each
    result = evaluate(repo)
    assert (result["people"], result["departed"], result["orphans"], result["tickets"]) == (2, 1, 3, 2)
    assert result["status"] == "COMPLETE"
    events(repo)
    state = leavers.LeaverStore(repo)
    before = state.people(), state.orphans(), state.links(), repo.get_setting(leavers.RESULT_KEY)["value"]
    save(store, notion_spec(), [notion_pat(f"aaaaaaaa-0000-4000-8000-{100 + n:012d}", "eve@acme.test")
                                for n in range(leavers.MAX_PAGES)], owner=notion)
    result = evaluate(repo, now=NOW + timedelta(minutes=5))
    assert (result["status"], result["reasons"]) == ("PARTIAL", ["ISSUED_CREDENTIALS_LIMIT_REACHED"])
    # The people listing was read whole, so it is saved again; nothing about them changed.
    assert {ref: row["state"] for ref, row in state.people().items()} == {ref: row["state"] for ref, row in before[0].items()}
    assert (state.orphans(), state.links()) == before[1:3]
    assert repo.get_setting(leavers.RESULT_KEY)["value"] == {**before[3], "status": "PARTIAL",
                                                            "reasons": ["ISSUED_CREDENTIALS_LIMIT_REACHED"]}
    assert events(repo) == [] and len(repo.list_tickets()) == 2


def test_a_listing_that_changed_between_reads_is_incomplete(monkeypatch):
    monkeypatch.setattr(leavers, "MAX_ROWS", 1)
    for pages in ([{"items": [{"id": 1}], "total": 2}, {"items": [{"id": 1}], "total": 2}],  # a row moved ahead
                  [{"items": [{"id": 1}], "total": 2}, {"items": [{"id": 2}], "total": 3}]):  # a row was added
        with pytest.raises(leavers.IncompleteListing, match="^X_CHANGED_WHILE_READ$"):
            leavers._every("X", lambda offset, limit, pages=pages: pages[offset])


def kc_event(event_id, at, enabled):
    """A Keycloak admin event turning KC_DANA on or off."""
    return {"id": event_id, "time": ms(at), "operationType": "UPDATE", "resourceType": "USER",
            "resourcePath": "users/" + KC_DANA, "representation": json.dumps({"enabled": enabled})}


def dana(repo):
    return next(iter(leavers.LeaverStore(repo).people().values()))


def test_status_events_are_read_from_the_latest_complete_run_only(repo, monkeypatch):
    """Every Keycloak run stores the realm's admin events of its whole look-back window again; only the latest
    complete run's copy is read, so the history read does not grow with the runs kept."""
    store = MetadataStore(repo)
    owner = None
    for _ in range(3):
        owner = save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False},
                                             events=[kc_event("e1", DEPARTED_AT, False)]), owner=owner)
    monkeypatch.setattr(leavers, "MAX_ROWS", 1)
    monkeypatch.setattr(leavers, "MAX_PAGES", 1)  # one stored copy fits; the three runs' copies would not
    result = evaluate(repo)
    assert (result["status"], result["reasons"], result["departed"]) == ("COMPLETE", [], 1)
    assert dana(repo)["departure_basis"] == "ADMIN_EVENT"
    assert abs(leavers._time(dana(repo)["departed_at"]) - DEPARTED_AT) < timedelta(seconds=1)


def test_status_events_past_the_budget_date_no_departure(repo, monkeypatch):
    """A history cut at the budget could miss a later enable and date a departure too early, so past it the first
    collection that saw the user disabled dates it."""
    store = MetadataStore(repo)
    history = [kc_event(f"e{n}", DEPARTED_AT + timedelta(hours=n), n % 2 == 1) for n in range(5)]  # off, on, off, on, off
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False}, events=history))
    monkeypatch.setattr(leavers, "MAX_ROWS", 1)
    monkeypatch.setattr(leavers, "MAX_PAGES", 2)  # three disables
    result = evaluate(repo)
    assert (result["status"], result["reasons"], result["departed"]) == ("COMPLETE", ["IDP_EVENTS_LIMIT_REACHED"], 1)
    assert dana(repo)["departure_basis"] == "FIRST_OBSERVED_DISABLED"
    monkeypatch.setattr(leavers, "MAX_PAGES", 3)
    assert evaluate(repo, now=NOW + timedelta(minutes=5))["reasons"] == []
    # The disable after the last enable, the earlier ones having ended.
    assert dana(repo)["departure_basis"] == "ADMIN_EVENT"
    assert abs(leavers._time(dana(repo)["departed_at"]) - (DEPARTED_AT + timedelta(hours=4))) < timedelta(seconds=1)


def test_an_enable_after_a_stored_departure_ends_it(repo):
    """Re-enabled and disabled again between two checks: the new departure dates it, not the stored one, so use while
    the person was back is never called use after departure."""
    store = MetadataStore(repo)
    owner = save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False},
                                         events=[kc_event("e1", DEPARTED_AT, False)]))
    evaluate(repo)
    back, again = DEPARTED_AT + timedelta(days=2), DEPARTED_AT + timedelta(days=3)
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False}, events=[
        kc_event("e1", DEPARTED_AT, False), kc_event("e2", back, True), kc_event("e3", again, False)]), owner=owner)
    evaluate(repo, now=NOW + timedelta(minutes=5))
    assert dana(repo)["departure_basis"] == "ADMIN_EVENT"
    assert abs(leavers._time(dana(repo)["departed_at"]) - again) < timedelta(seconds=1)


def test_a_user_missing_from_a_listing_departs_no_earlier_than_the_run_that_missed_them(repo):
    store, idp, _notion = seed(repo, dana_status="ACTIVE")
    evaluate(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00ueve000001", "ACTIVE")), owner=idp)
    evaluate(repo, now=NOW + timedelta(minutes=5))
    finished = leavers._time(store.connection_runs(idp["id"], limit=1)["items"][0]["finished_at"])
    gone = next(row for row in leavers.LeaverStore(repo).people().values() if row["idp_user_id"] == "00udana00001")
    assert (gone["departure_basis"], leavers._time(gone["departed_at"])) == ("FIRST_OBSERVED_MISSING", finished)


def test_one_person_in_two_idps_sharing_an_email_links_exactly(repo):
    """People often sit in two IdPs (an SSO directory and another one) under one work email: one human, so the GitHub
    identity links to both."""
    store = MetadataStore(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(
        okta.row("00udana00001", "DEPROVISIONED", login="dana", email="dana@acme.test", changed=DEPARTED_AT.isoformat())))
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "email": "dana@acme.test", "emailVerified": True,
                                  "enabled": False}))
    github_directory(store, {"samlIdentity": None, "user": {"login": "octocat"},
                             "scimIdentity": {"username": "dana", "emails": [{"value": "dana@acme.test"}]}})
    result = evaluate(repo)
    assert (result["linked_accounts"], result["candidates"]) == (1, 0)
    assert len(leavers.LeaverStore(repo).links()) == 2


def test_rejecting_the_other_idps_person_links_the_one_left(repo):
    store = MetadataStore(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00udana00001", "ACTIVE", login="dana")))
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False}))
    github_directory(store, {"samlIdentity": None, "scimIdentity": {"username": "dana", "emails": []},
                             "user": {"login": "octocat"}})
    evaluate(repo)
    people = leavers.LeaverStore(repo).people()
    by_idp = {row["provider"]: ref for ref, row in people.items()}
    account = "github|https://github.com|octocat"
    leavers.LeaverStore(repo).save(links=[{"account_ref": account, "person_ref": by_idp["keycloak"], "decision": "REJECTED",
                                           "basis": "OPERATOR_REJECTED", "actor_ref": "admin", "decided_at": NOW}])
    evaluate(repo, now=NOW + timedelta(minutes=5))
    assert leavers.LeaverStore(repo).links()[(account, by_idp["okta"])]["decision"] == "MATCHED"


def test_a_kept_link_says_the_idps_disagree_once_its_identity_reaches_an_active_person(repo):
    """A link made while one IdP was connected is kept; once the directory identity also reaches an active person of
    another IdP, who may be the one it belongs to, the verdicts say the IdPs disagree."""
    store = MetadataStore(repo)
    realm = save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": True}))
    github_directory(store, {"samlIdentity": None, "scimIdentity": {"username": "dana", "emails": []},
                             "user": {"login": "octocat"}})
    evaluate(repo)
    assert len(leavers.LeaverStore(repo).links()) == 1  # one IdP: the SCIM user name links
    save(store, okta.spec(options={"page_size": 200}), okta_people(
        okta.row("00udana00001", "ACTIVE", login="dana", email="dana@okta.test")))
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False}), owner=realm)
    evaluate(repo, now=NOW + timedelta(minutes=5))
    rows = list(leavers.LeaverStore(repo).orphans().values())
    assert rows and all(row["body"]["person"]["idp_disagreement"] for row in rows)


def test_a_cut_listing_still_saves_a_complete_people_listing_and_retention_waits(repo, monkeypatch):
    """A listing cut for weeks would let collection history expire before a departure was ever saved: a people
    listing read whole is saved anyway and history pruning goes on. Retention waits: only a complete evaluation knows
    whether the person left a credential on (dana's tokens are)."""
    store, idp, _notion = seed(repo, dana_status="ACTIVE")
    evaluate(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00ueve000001", "ACTIVE", email="eve@acme.test")),
         owner=idp)
    monkeypatch.setattr(leavers, "MAX_ROWS", 1)
    monkeypatch.setattr(leavers, "MAX_PAGES", 3)  # the two people fit, the four tokens do not
    result = evaluate(repo, now=NOW + timedelta(minutes=5))
    assert (result["status"], result["reasons"]) == ("PARTIAL", ["ISSUED_CREDENTIALS_LIMIT_REACHED"])
    people = {row["idp_user_id"]: row for row in leavers.LeaverStore(repo).people().values()}
    assert people["00udana00001"]["state"] == "DEPARTED" and leavers.LeaverStore(repo).orphans() == {}
    later = NOW + timedelta(days=SETTINGS.leaver_retention_days + 1)
    result = evaluate(repo, now=later)
    assert (result["status"], result["pruned_runs"]) == ("PARTIAL", 1)
    assert {row["state"] for row in leavers.LeaverStore(repo).people().values()} == {"DEPARTED", "ACTIVE"}
    # The listing fixed, a complete evaluation judges dana's tokens (a year-old observation is no longer current, so
    # nothing is left on to keep her for) and retention applies then.
    monkeypatch.setattr(leavers, "MAX_PAGES", 10)
    result = evaluate(repo, now=later + timedelta(minutes=5))
    assert (result["status"], result["purged_people"]) == ("COMPLETE", 1)


def test_a_cut_people_listing_keeps_its_people_and_saves_the_other_idps(repo, monkeypatch):
    store, _idp, _notion = seed(repo)  # Okta: two people
    save(store, *keycloak_people({"id": KC_DANA, "username": "kc-dana", "enabled": False}))
    monkeypatch.setattr(leavers, "MAX_ROWS", 1)
    monkeypatch.setattr(leavers, "MAX_PAGES", 1)
    result = evaluate(repo)
    assert (result["status"], result["reasons"]) == ("PARTIAL", ["IDP_PEOPLE_LIMIT_REACHED"])
    assert [row["provider"] for row in leavers.LeaverStore(repo).people().values()] == ["keycloak"]


def test_events_of_a_partial_latest_run_date_no_departure(repo):
    """Back between two complete runs and gone again in a partial one: the complete run's old event would date the
    departure before the person came back, and the partial run's events may be cut, so neither dates it."""
    store = MetadataStore(repo)
    owner = save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False},
                                         events=[kc_event("e1", DEPARTED_AT, False)]))
    evaluate(repo)
    back, again = DEPARTED_AT + timedelta(days=2), DEPARTED_AT + timedelta(days=3)
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": True},
                                 events=[kc_event("e1", DEPARTED_AT, False), kc_event("e2", back, True)]),
         owner=owner, status="PARTIAL")
    evaluate(repo, now=NOW + timedelta(minutes=5))
    assert dana(repo)["state"] == "ACTIVE"
    save(store, *keycloak_people({"id": KC_DANA, "username": "dana", "enabled": False}, events=[
        kc_event("e1", DEPARTED_AT, False), kc_event("e2", back, True), kc_event("e3", again, False)]),
        owner=owner, status="PARTIAL")
    result = evaluate(repo, now=NOW + timedelta(minutes=10))
    assert "IDP_EVENTS_NOT_CURRENT" in result["reasons"]
    assert dana(repo)["departure_basis"] == "FIRST_OBSERVED_DISABLED"
    assert leavers._time(dana(repo)["departed_at"]) > again


def test_a_cut_coverage_comparison_is_a_cut_listing(repo, monkeypatch):
    """The schema 1 IAM inventory reaches the check through the coverage comparison, whose row budget the vault
    snapshots share: a cut IAM snapshot may have cut a departed person's key, a cut vault snapshot leaves it whole."""
    from cremore.coverage import correlation
    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
    from cremore.coverage.store import CoverageStore
    from cremore.detection.engine import Engine, EngineConfig
    from cremore.scanning.orchestrator import Orchestrator

    seed(repo)
    engine, coverage = Engine(EngineConfig(fingerprint_key=KEY)), CoverageStore(repo)

    def collected(spec, items):
        connection, _ = coverage.create(spec, "admin")
        run = coverage.start(connection["id"], connection["revision"], str(uuid.uuid4()),
                             Contract(engine_digest=engine.detection_digest).model_dump())
        coverage.append(connection["id"], run["id"], Batch(index=0, items=items))
        coverage.finish(connection["id"], run["id"], Finish(batch_count=1, item_count=len(items), status="COMPLETE"))

    issued = AWS_ROW["issued"]
    collected(ConnectionSpec(name="IAM", provider="aws_iam", account_id="123456789012"), [Observation(
        reference=issued["principal_arn"], principal_arn=issued["principal_arn"], account_id="123456789012",
        evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier=issued["identifier"], state="Active",
        last_used_at=issued["last_used_at"])])
    arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db-Ab12Cd"
    collected(ConnectionSpec(name="SM", provider="aws_secrets_manager", account_id="123456789012", regions=["us-east-1"]),
              [Observation(reference=arn + str(n), account_id="123456789012", region="us-east-1", version="v1",
                           evidence="VALUE", credential_type="GITHUB_TOKEN", fingerprint=str(n) * 64) for n in (1, 2, 3)])
    orchestrator = Orchestrator(repo, engine=engine, config=engine.config)
    # Two rows: the IAM key fits and the vault's values do not. None: the key does not either.
    for limit, expected in ((2, ("COMPLETE", [], 1)), (0, ("PARTIAL", ["COVERAGE_REPORT_LIMIT_REACHED"], None))):
        monkeypatch.setattr(correlation, "REPORT_LIMIT", limit)
        result = leavers.evaluate(repo, SETTINGS, orchestrator, now=NOW, fingerprint_key=KEY)
        assert (result["status"], result["reasons"], result.get("candidates")) == expected, limit

    def outran(*_args, origin, **_kwargs):
        assert origin == "ISSUANCE"  # only issued rows are asked for
        return {"items": [AWS_ROW], "total": 2, "connections": []}

    monkeypatch.setattr(correlation, "report", outran)
    result = leavers.evaluate(repo, SETTINGS, orchestrator, now=NOW, fingerprint_key=KEY)
    assert (result["status"], result["reasons"]) == ("PARTIAL", ["COVERAGE_REPORT_LIMIT_REACHED"])


def test_a_collection_reading_no_status_events_gives_no_event_reason(repo):
    store = MetadataStore(repo)
    save(store, okta.spec(options={"page_size": 200}), okta_people(okta.row("00udana00001", "ACTIVE")), status="PARTIAL")
    assert evaluate(repo)["reasons"] == []


def test_a_listing_past_the_budget_stops_at_its_first_read(monkeypatch):
    monkeypatch.setattr(leavers, "MAX_ROWS", 2)
    reads = []

    def read(offset, limit):
        reads.append(offset)
        return {"items": [{"id": offset}, {"id": offset + 1}], "total": 100}

    with pytest.raises(leavers.IncompleteListing, match="^X_LIMIT_REACHED$"):
        leavers._every("X", read)
    assert reads == [0]
