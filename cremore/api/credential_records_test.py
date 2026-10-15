"""The credential list joins exposed findings with issued inventories; analysts annotate findings."""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app, credential_records
from cremore.config import Settings
from cremore.coverage.aws_evidence_correlation_test import (
    ACCOUNT,
    IAM_ID,
    expose,
    material,
    save,
    vault,
)
from cremore.coverage.metadata_linkage_test import KEY, TOKEN, save_vault
from cremore.coverage.metadata_linkage_test import issuer as github_inventory
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import ConnectionSpec, Observation
from cremore.db.annotation_store import AnnotationConflict, AnnotationStore
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import ResourceRef
from cremore.detection.engine import Engine, EngineConfig
from cremore.scanning.orchestrator import Orchestrator

API_TOKEN = "records-api-" + "z" * 32
OTHER_KEY_ID = "AKIA" + "Q1W2E3R4T5Y6U7I8"


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    elif request.param == "sqlite":
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()
    else:
        yield request.getfixturevalue("pg")[1]


def stack(repo, key=KEY):
    engine = Engine(EngineConfig(fingerprint_key=key))
    return engine, Orchestrator(repo, engine=engine, config=engine.config)


def build(repo, orchestrator):
    result = credential_records.build(repo, Settings(), orchestrator)
    assert result["total"] == len(result["items"])
    return result


@pytest.mark.parametrize("reappears_at", ["original.env", "new.env"])
def test_rescans_keep_one_credential_and_separate_confirmed_removal_from_partial_reads(repo, reappears_at):
    from cremore.collectors.base import CollectedObject
    from cremore.collectors.bytes_source import BytesCollector
    from cremore.scanning.service import ScanService

    _engine, orch = stack(repo)
    connection = uuid.uuid4()
    resource = ResourceRef(source_type="gitlab", resource="synthetic/app", location="original.env",
                           metadata={"source_instance": "https://gitlab.example.test"})

    def scan(data, where=resource, *, complete=True):
        return ScanService(orch).run(BytesCollector([CollectedObject(where, data, complete=complete)]),
            source_connection_id=connection, verify=False, reconcile_objects=True)

    scan(TOKEN)
    finding = repo.list_findings()[0]
    repo.assign_finding(finding.id, "Synthetic responder")
    before = build(repo, orch)
    [row] = before["items"]
    assert before["total"] == 1 and row["exposure_state"] == "ACTIVE"
    assert row["response"] == {"state": "ASSIGNED", "version": 0, "current": None, "reviewed_at": None, "reviewed_by": None}
    assert (row["active_location_count"], row["removed_location_count"], row["exposure_count"]) == (1, 0, 1)
    event_count = len(repo.list_finding_events(finding.id))
    scan(TOKEN)
    repeated = build(repo, orch)
    assert repeated["total"] == 1 and repeated["items"][0]["id"] == row["id"]
    assert len(repo.exposures_for_credential(finding.credential_id)) == 1
    assert len(repo.list_finding_events(finding.id)) == event_count
    scan(b"partially read clean content", complete=False)
    [partial] = build(repo, orch)["items"]
    assert partial["exposure_state"] == "ACTIVE" and not partial["all_locations_removed"]
    assert partial["active_location_count"] == 1
    assert len(repo.list_finding_events(finding.id)) == event_count
    scan(b"completely read clean content")
    [removed] = build(repo, orch)["items"]
    assert removed["exposure_state"] == "REMOVED" and removed["all_locations_removed"]
    assert removed["response"] == {"state": "REMOVED", "version": 0, "current": None, "reviewed_at": None, "reviewed_by": None}
    assert removed["workflow_status"] == "OPEN", "location removal does not prove credential revocation"
    assert (removed["active_location_count"], removed["removed_location_count"], removed["exposure_count"]) == (0, 1, 0)
    assert not removed["exposures"][0]["current"] and removed["owner"]["name"] == "Synthetic responder"
    retired_events = len(repo.list_finding_events(finding.id))
    scan(b"still clean")
    assert len(repo.list_finding_events(finding.id)) == retired_events
    new_place = ResourceRef(source_type=resource.source_type, resource=resource.resource,
                            location=reappears_at, metadata=resource.metadata)
    scan(TOKEN, new_place)
    returned = build(repo, orch)
    [again] = returned["items"]
    assert returned["total"] == 1 and again["id"] == row["id"] and again["finding_id"] == row["finding_id"]
    assert again["exposure_state"] == "ACTIVE" and not again["all_locations_removed"]
    assert again["active_location_count"] == 1 and again["removed_location_count"] == int(reappears_at != resource.location)
    assert again["owner"]["name"] == "Synthetic responder"
    assert again["response"] == {"state": "ASSIGNED", "version": 0, "current": None, "reviewed_at": None, "reviewed_by": None}
    assert again["exposures"][0]["current"] and again["exposures"][0]["location"] == reappears_at
    assert len(repo.list_finding_events(finding.id)) > retired_events


def test_notion_page_rename_reconciles_by_page_identity_only_after_complete_read(repo):
    from cremore.collectors.base import CollectedObject
    from cremore.collectors.bytes_source import BytesCollector
    from cremore.scanning.service import ScanService

    _engine, orch = stack(repo)
    connection = uuid.uuid4()
    page = "11111111111141118111111111111111"
    old = ResourceRef(source_type="notion", resource="Old title", location=f"https://notion.so/Old-title-{page}",
                      metadata={"page_id": page, "collector_epoch": 1})
    new = ResourceRef(source_type="notion", resource="New title", location=f"https://notion.so/New-title-{page}",
                      metadata={"page_id": page, "collector_epoch": 1})
    service = ScanService(orch)
    service.run(BytesCollector([CollectedObject(old, TOKEN)]), source_connection_id=connection, verify=False)
    service.run(BytesCollector([CollectedObject(new, b"clean", complete=False)]), source_connection_id=connection,
                verify=False, reconcile_objects=True)
    assert not repo.list_findings()[0].all_locations_removed
    service.run(BytesCollector([CollectedObject(new, b"clean")]), source_connection_id=connection,
                verify=False, reconcile_objects=True)
    [row] = build(repo, orch)["items"]
    assert row["exposure_state"] == "REMOVED" and row["removed_location_count"] == 1


def test_overlapping_connections_explain_pending_removal_without_counting_twice(repo):
    import datetime as dt
    from unittest.mock import patch

    _, orch = stack(repo)
    first, second = uuid.uuid4(), uuid.uuid4()
    resource = ResourceRef(source_type="github", resource="synthetic/repo", location="config.env")
    for connection in (first, second):
        orch.scan_resource(TOKEN, resource, source_connection_id=connection, verify=False)
    finding = repo.list_findings()[0]
    later = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=1)
    with patch("cremore.db.repository._now", return_value=later), patch("cremore.db.sql._now", return_value=later):
        orch.reconcile_resource(second, resource, [])
    [row] = build(repo, orch)["items"]
    assert row["exposure_state"] == "ACTIVE" and not row["all_locations_removed"]
    assert (row["exposure_count"], row["location_count"]) == (0, 1)
    assert (row["active_location_count"], row["removal_pending_location_count"], row["removed_location_count"]) == (0, 1, 0)
    assert len(row["exposures"]) == 1 and row["exposures"][0]["removal_pending"]
    assert not row["exposures"][0]["current"]
    client = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=API_TOKEN,
        FINGERPRINT_KEY=KEY.hex(), CREDENTIAL_VERIFICATION_MODE="disabled")))
    detail = client.get(f"/api/v1/findings/{finding.id}", headers={"Authorization": f"Bearer {API_TOKEN}"})
    assert detail.status_code == 200
    assert detail.json()["removal_pending_location_count"] == 1
    assert detail.json()["exposures"][0]["removal_pending"]
    orch.reconcile_resource(first, resource, [])
    [removed] = build(repo, orch)["items"]
    assert removed["exposure_state"] == "REMOVED"
    assert (removed["active_location_count"], removed["removal_pending_location_count"], removed["removed_location_count"]) == (0, 0, 1)
    assert not removed["exposures"][0]["removal_pending"]


def test_an_exposed_token_the_issuer_lists_is_one_row_with_both_sides(repo):
    engine, orch = stack(repo)
    orch.scan_resource(TOKEN, ResourceRef(source_type="gitlab", resource="team/app", location="test.env",
                       metadata={"source_instance": "https://gitlab.example.test"}), verify=False)
    provider_hash = github_inventory(MetadataStore(repo), engine)
    result = build(repo, orch)
    [row] = result["items"]
    finding = repo.list_findings()[0]
    assert row["finding_id"] == str(finding.id) and row["exposed"] is True and row["status"] == "pending"
    assert row["issued"]["provider"] == "github" and row["issued"]["object_id"] == "inventory:classic_pat:id:1"
    assert row["kind"] == "token" and row["exposures"][0]["resource_name"] == "team/app"
    public = json.dumps(result, default=str)
    private = repo.exposures_for_credential(finding.credential_id)[0].metadata["issuer_comparison"]["github_token_digest"]
    for secret in (TOKEN.decode(), provider_hash, private):
        assert secret not in public
    assert "issuer_comparison" not in public and "fingerprint" not in json.dumps(row["issued"])


def test_the_same_token_under_another_key_is_never_joined(repo):
    _engine, orch = stack(repo, key=b"z" * 32)
    orch.scan_resource(TOKEN, ResourceRef(source_type="inline", resource="synthetic", location="a.env"), verify=False)
    github_inventory(MetadataStore(repo), Engine(EngineConfig(fingerprint_key=KEY)))
    rows = build(repo, orch)["items"]
    assert sorted(row["exposed"] for row in rows) == [False, True]
    assert next(row for row in rows if row["exposed"])["issued"] is None


@pytest.mark.parametrize("key,linked", [(KEY, True), (b"z" * 32, False)])
def test_snapshot_digest_retains_exact_exposure_link_without_unique_inventory_rows(repo, key, linked):
    from cremore.coverage.metadata_correlation import finding_links

    engine, orch = stack(repo)
    orch.scan_resource(TOKEN, ResourceRef(source_type="inline", resource="test", location="key.env"), verify=False)
    store = MetadataStore(repo)
    github_inventory(store, engine, stable=False, key=key)
    [row] = build(repo, orch)["items"]
    assert bool(row["issued"]) is linked
    assert store.inventory(object_kind="credential")["total"] == 0
    finding = repo.list_findings()[0]
    evidence = finding_links(store, repo, finding.id)
    assert evidence["value_match_count"] == int(linked)
    if linked:
        assert row["issued"]["snapshot_observation"] is True
        assert evidence["items"][0]["verification"] == "NOT_PERFORMED"
    else:
        assert evidence["items"] == []


def test_an_expired_aws_api_key_reads_as_ended_and_its_expiry_as_not_collected():
    user = f"arn:aws:iam::{ACCOUNT}:user/robot"
    found = credential_records._aws_found({"credential_type": "AWS_SERVICE_CREDENTIAL", "identifier": "ACCA" + "3" * 16,
                                           "state": "Expired", "principal_arn": user})
    # Not "issued without an expiry": the ExpirationDate is not collected, and the key no longer works.
    assert (found["state"], found["expiry_known"]) == ("expired", False)
    key = credential_records._aws_found({"credential_type": "AWS_ACCESS_KEY", "identifier": IAM_ID, "state": "Active",
                                         "principal_arn": user})
    assert (key["state"], key["expiry_known"]) == ("active", True)


def test_unexposed_snapshot_never_creates_unique_credential_even_when_vault_matches(repo):
    engine, orch = stack(repo)
    github_inventory(MetadataStore(repo), engine, stable=False)
    save_vault(repo, engine, TOKEN)
    assert build(repo, orch)["items"] == []


def test_an_issued_token_nobody_exposed_is_its_own_row_with_the_vault_that_holds_it(repo):
    engine, orch = stack(repo)
    github_inventory(MetadataStore(repo), engine)
    save_vault(repo, engine, TOKEN)
    [row] = build(repo, orch)["items"]
    assert row["id"].startswith("issued:") and row["exposed"] is False and row["finding_id"] is None
    assert row["status"] is None and row["credential_type"] == "GITHUB_CLASSIC_PAT" and row["kind"] == "token"
    assert row["issued"]["type"] == "classic_pat"
    assert row["vault"]["state"] == "stored" and row["vault"]["where"][0]["provider"] == "aws_secrets_manager"
    assert row["verification"]["state"] in ("active", "unknown")


def test_iam_keys_join_the_exposed_key_by_id_and_the_rest_are_listed_with_their_vault_verdict(repo):
    engine, orch = stack(repo, key=b"synthetic-session-fingerprint-domain")
    expose(repo, engine, material(None, identifier=IAM_ID))
    vault(repo, engine, material(None, identifier=IAM_ID))
    issued = [Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/{name}", account_id=ACCOUNT, evidence="ISSUED",
                          credential_type="AWS_ACCESS_KEY", identifier=key, state="Active",
                          created_at="2025-06-10T01:00:00+00:00")
              for name, key in (("backup-job", IAM_ID), ("deploy-bot", OTHER_KEY_ID))]
    save(repo, engine, ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), issued)
    rows = {row["id"]: row for row in build(repo, orch)["items"]}
    [exposed] = [row for row in rows.values() if row["exposed"]]
    assert exposed["issued"]["provider"] == "aws_iam" and exposed["issued"]["object_id"] == IAM_ID
    assert exposed["issued"]["type"] == "access_key"
    assert exposed["expiry"] == "none" and exposed["created_at"] == "2025-06-10T01:00:00+00:00"
    assert exposed["vault"]["state"] == "stored"
    listed = rows["issued:aws:" + OTHER_KEY_ID]
    assert listed["exposed"] is False and listed["name"] == "deploy-bot" and listed["kind"] == "cloud"
    assert listed["issuer"] == {"name": "deploy-bot", "role": "IAM_USER", "basis": "aws_iam"}
    assert listed["vault"]["state"] == "none" and listed["verification"]["state"] == "active"
    assert listed["hint"] == OTHER_KEY_ID[:4] + "••••••••" + OTHER_KEY_ID[-4:]
    assert len(rows) == 2


def test_an_organization_rule_gives_its_matches_the_type_it_declares(repo):
    from cremore.domain.models import CustomRule

    rule = repo.create_rule(CustomRule(name="Deploy bot", pattern=r"(?P<secret>dpl_[A-Za-z0-9]{40})", keywords=["dpl_"],
                                       category="token"))
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=engine, config=engine.config, rule_provider=repo.list_rules)
    orch.refresh_rules()
    orch.scan_resource(b"DEPLOY=dpl_" + b"A1b2" * 10 + b"\n", ResourceRef(source_type="inline", resource="synthetic",
                       location="a.env"), verify=False)
    [row] = build(repo, orch)["items"]
    assert row["credential_type"].startswith("CUSTOM_RULE_") and (row["category"], row["kind"]) == ("token", "token")
    repo.update_rule(rule.id, category=None)
    [row] = build(repo, orch)["items"]
    assert (row["category"], row["kind"]) == ("other", "other")


def test_listed_public_keys_of_a_declared_type_are_rows_and_context_is_not(repo):
    from cremore_github_provider.metadata.tests.fake import inventory_row
    from cremore_github_provider.metadata.tests.test_adapter import drive
    from cremore_github_provider.metadata.tests.test_digest_evidence import connection, scripted

    from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract

    engine, orch = stack(repo)
    spec = connection()
    responses = scripted(credential_id="1")
    rows = responses[next(key for key in responses if key.endswith("/credentials/exports"))]
    rows.append(inventory_row("inv-ssh", credential_type="ssh_key", display_name="laptop key",
                              fingerprint="SHA256:" + "A" * 43, scopes=[]))
    rows.append(inventory_row("inv-person", item_type="token_issuer_principal", credential_type="github_app_installation"))
    import hashlib

    from cremore.coverage.models import Contract

    contract = Contract(engine_digest=engine.detection_digest)
    context = {"engine": engine, "key_id": hashlib.sha256(KEY).hexdigest(), "engine_digest": contract.engine_digest,
               "policy_digest": contract.policy_digest}
    _, _, items, _, final = drive(spec, responses, enterprise="cremore-enterprise", value_context=context)
    assert final.status == "COMPLETE"
    store = MetadataStore(repo)
    owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items), trusted_discovery=True)
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status="COMPLETE"))
    listed = {row["issued"]["type"]: row for row in build(repo, orch)["items"]}
    assert set(listed) == {"classic_pat", "ssh_key"}
    assert listed["ssh_key"]["credential_type"] == "GITHUB_SSH_KEY" and listed["ssh_key"]["name"] == "laptop key"
    assert listed["ssh_key"]["exposed"] is False


def test_annotations_are_revision_guarded_and_a_transition_ends_the_stage(repo):
    store = AnnotationStore(repo)
    finding_id = uuid.uuid4()
    first = store.change(finding_id, 0, "analyst", tags=["CI"])
    assert first["revision"] == 1 and store.get(finding_id)["tags"] == ["CI"]
    with pytest.raises(AnnotationConflict):
        store.change(finding_id, 0, "other", tags=["payments"])  # a concurrent first write
    with pytest.raises(AnnotationConflict):
        store.change(finding_id, 5, "other", stage="action")  # a stale read
    store.change(finding_id, 1, "analyst", stage="action")
    store.clear_stage(finding_id, "analyst")
    saved = store.get(finding_id)
    assert saved["stage"] is None and saved["tags"] == ["CI"] and saved["revision"] == 3
    store.clear_stage(finding_id, "analyst")  # nothing to end
    assert store.get(finding_id)["revision"] == 3
    assert set(store.many([finding_id, uuid.uuid4()])) == {finding_id}


@pytest.fixture
def api():
    repo = InMemoryRepository()
    settings = Settings(AUTH_MODE="local", API_TOKEN=API_TOKEN, FINGERPRINT_KEY=KEY.hex(),
                        CREDENTIAL_VERIFICATION_MODE="disabled")
    client = TestClient(create_app(repo=repo, settings=settings))
    client.headers["Authorization"] = f"Bearer {API_TOKEN}"
    scanned = client.post("/api/v1/scan", json={"text": f"token = {TOKEN.decode()}", "source_type": "inline"})
    assert scanned.status_code == 202
    return client, repo, scanned.json()["findings"][0]["id"]


def record(client, finding_id):
    rows = client.get("/api/v1/credential-records").json()["items"]
    return next(row for row in rows if row["finding_id"] == finding_id)


def test_tags_stage_steps_and_contacts_show_on_the_list_and_in_the_history(api):
    client, _repo, finding_id = api
    base = f"/api/v1/findings/{finding_id}"
    tagged = client.put(base + "/tags", json={"revision": 0, "tags": ["#CI", "payments", "CI"]})
    assert tagged.status_code == 200 and tagged.json()["tags"] == ["CI", "payments"]
    assert client.put(base + "/tags", json={"revision": 0, "tags": []}).status_code == 409
    assert client.put(base + "/stage", json={"revision": 1, "stage": "action"}).json()["detail"] == "FINDING_NOT_ACKNOWLEDGED"
    assert client.post(base + "/acknowledge").status_code == 200
    assert record(client, finding_id)["status"] == "review" and record(client, finding_id)["acknowledged_at"]
    assert client.put(base + "/stage", json={"revision": 1, "stage": "action"}).status_code == 200
    assert record(client, finding_id)["status"] == "action"
    step = client.put(base + "/remediation/revoke", json={"revision": 2, "status": "progress", "comment": "rotating"})
    assert step.status_code == 200 and step.json()["steps"]["revoke"]["status"] == "progress"
    kept = client.put(base + "/remediation/revoke", json={"revision": 3, "status": "done"})
    assert kept.json()["steps"]["revoke"]["comment"] == "rotating"
    assert client.put(base + "/remediation/other", json={"revision": 4, "status": "done"}).status_code == 404
    contact = client.post(base + "/contacts", json={"revision": 4, "channel": "mail", "template": "revoke",
                                                   "recipients": 2, "due_at": "2099-01-01"})
    assert contact.status_code == 422 and contact.json()["detail"] == "DUE_DATE_OUT_OF_RANGE"
    import datetime as dt

    due = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=3)).isoformat()
    contact = client.post(base + "/contacts", json={"revision": 4, "channel": "mail", "template": "revoke",
                                                   "recipients": 2, "due_at": due})
    assert contact.status_code == 201 and contact.json()["contact"]["due_at"] == due
    assert client.post(base + "/comments", json={"text": "owner confirmed the rollout"}).status_code == 201
    assert client.post(base + "/comments", json={"text": "steps:\n\t1. rotate\n\t2. remove"}).status_code == 201  # lines and tabs stay
    row = record(client, finding_id)
    assert row["tags"] == ["CI", "payments"] and row["steps"]["revoke"]["status"] == "done"
    assert row["contact"]["channel"] == "mail" and row["annotations_revision"] == 5
    events = [e["event_type"] for e in client.get(base + "/events").json()]
    assert {"TAGS_CHANGED", "STAGE_CHANGED", "REMEDIATION_STEP", "OWNER_CONTACTED", "COMMENT"} <= set(events)
    # Reopening ends the remediation stage; acknowledging again starts at review.
    assert client.post(base + "/reopen", json={"resolution": ""}).status_code == 200
    assert record(client, finding_id)["status"] == "pending"
    client.post(base + "/acknowledge")
    assert record(client, finding_id)["status"] == "review"


def test_free_text_with_a_credential_in_it_is_refused_and_never_stored(api):
    client, repo, finding_id = api
    base = f"/api/v1/findings/{finding_id}"
    secret = TOKEN.decode()
    assert client.post(base + "/comments", json={"text": f"use {secret}"}).json()["detail"] == "TEXT_CONTAINS_CREDENTIAL"
    assert client.put(base + "/tags", json={"revision": 0, "tags": [secret]}).status_code == 422
    assert client.put(base + "/remediation/cleanup", json={"revision": 0, "status": "open",
                                                           "comment": f"was {secret}"}).status_code == 422
    assert client.put(base + "/tags", json={"revision": 0, "tags": ["a\x07b"]}).json()["detail"] == "TAG_INVALID"
    assert client.post(base + "/comments", json={"text": "bad\x00text"}).json()["detail"] == "TEXT_CONTROL_CHARACTERS"
    # Nothing that reorders, breaks or hides text goes into the history: right-to-left override, line separator,
    # NEL, zero-width space, Hangul filler.
    for hidden in (0x202E, 0x2028, 0x85, 0x200B, 0x3164):
        refused = client.post(base + "/comments", json={"text": "owner " + chr(hidden) + " confirmed"})
        assert refused.json()["detail"] == "TEXT_CONTROL_CHARACTERS", hex(hidden)
    checked = client.post("/api/v1/text-check", json={"text": f"hello {secret}"}).json()
    assert checked == {"contains_credential": True, "credential_types": ["GITHUB_TOKEN"], "unsafe": False}
    assert client.post("/api/v1/text-check", json={"text": "hello"}).json()["contains_credential"] is False
    # The same draft check says whether a comment would be refused for hidden characters.
    assert client.post("/api/v1/text-check", json={"text": "basis" + chr(0x200E)}).json()["unsafe"] is True
    assert client.post("/api/v1/text-check", json={"text": "line one\n\tline two"}).json()["unsafe"] is False
    stored = json.dumps([e.model_dump(mode="json") for e in repo.list_finding_events(uuid.UUID(finding_id))])
    stored += json.dumps(client.get(base + "/annotations").json())
    assert secret not in stored and "COMMENT" not in stored
    missing = f"/api/v1/findings/{uuid.uuid4()}"
    assert client.post(missing + "/comments", json={"text": "x"}).status_code == 404
    assert client.put(missing + "/tags", json={"revision": 0, "tags": []}).status_code == 404


def test_a_viewer_reads_the_list_but_only_analysts_annotate(issuer):
    from cremore.api.conftest import GROUPS, oidc_settings

    repo = InMemoryRepository()
    stack(repo)[1].scan_resource(TOKEN, ResourceRef(source_type="inline", resource="synthetic", location="a.env"),
                                 verify=False)
    finding_id = repo.list_findings()[0].id
    client = TestClient(create_app(repo=repo, settings=oidc_settings(FINGERPRINT_KEY=KEY.hex(),
                                                                     CREDENTIAL_VERIFICATION_MODE="disabled"),
                                   oidc_http_client=issuer))
    viewer = {"Authorization": "Bearer " + issuer.mint("viewer-1", (GROUPS["viewer"],))}
    analyst = {"Authorization": "Bearer " + issuer.mint("analyst-1", (GROUPS["analyst"],))}
    assert client.get("/api/v1/credential-records", headers=viewer).json()["total"] == 1
    base = f"/api/v1/findings/{finding_id}"
    for method, path, body in (("put", "/tags", {"revision": 0, "tags": ["CI"]}),
                               ("post", "/comments", {"text": "noted"}),
                               ("put", "/remediation/revoke", {"revision": 0, "status": "done"})):
        assert client.request(method, base + path, headers=viewer, json=body).status_code == 403
    assert client.post("/api/v1/text-check", headers=viewer, json={"text": "x"}).status_code == 403
    assert client.put(base + "/tags", headers=analyst, json={"revision": 0, "tags": ["CI"]}).status_code == 200
    [event] = [e for e in repo.list_finding_events(finding_id) if e.event_type == "TAGS_CHANGED"]
    assert event.actor == "analyst-1" and event.note == "+#CI"


def test_iam_metadata_reasons_and_policy_summary_survive_storage_without_becoming_scopes(repo):
    from cremore.coverage.models import IAMPolicySummary
    from cremore.coverage.store import CoverageStore

    engine, orch = stack(repo)
    summary = IAMPolicySummary(status="COMPLETE", checked_at="2026-10-02T01:00:00Z",
                               policy_names=["ReadObjects"], allow_actions=["s3:GetObject"])
    item = Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/robot", account_id=ACCOUNT,
        principal_arn=f"arn:aws:iam::{ACCOUNT}:user/robot", evidence="ISSUED", credential_type="AWS_ACCESS_KEY",
        identifier=IAM_ID, state="Active", iam_policies=summary,
        iam_last_used={"status": "NO_INFORMATION", "checked_at": "2026-10-02T01:00:00Z"})
    connection = save(repo, engine, ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), [item])
    [row] = build(repo, orch)["items"]
    assert row["issued"]["iam_policies"] == summary.model_dump()
    assert row["issued"]["current"] is True
    assert row["issued"]["last_used_status"] == "NO_INFORMATION" and row["last_used"] is None
    assert row["verification"]["basis"] == "ISSUER_REPORTED" and row["scopes"] is None
    assert row["expiry"] == "none" and not repo.list_findings()
    CoverageStore(repo).change(connection["id"], connection["revision"], "admin", enabled=False)
    [historical] = build(repo, orch)["items"]
    assert historical["issued"]["current"] is False
    assert historical["issued"]["iam_policies"] == summary.model_dump()


def test_permission_lookup_joins_record_and_risk_only_for_the_exact_owner(repo):
    from cremore_aws_provider.investigation.potential_access import ACTION_CATALOG

    from cremore.api.finding_evidence import _risk

    engine, orch = stack(repo)
    finding = expose(repo, engine, IAM_ID.encode(), "AWS_ACCESS_KEY_ID")
    arn = f"arn:aws:iam::{ACCOUNT}:user/robot"
    potential = {"principal_arn": arn, "collection_status": "COMPLETE", "assessment_version": 2,
                 "evaluated_at": "2026-10-04T00:00:00Z",
                 "actions": [{"action": action, "decision": "ALLOWED"} for action, _ in ACTION_CATALOG]}
    snapshot = {"collected_account_id": ACCOUNT, "potential_access": potential}
    repo.update_credential(finding.credential_id, principal_arn=arn, usage_snapshot=snapshot)
    [row] = build(repo, orch)["items"]
    assert row["aws_permissions"]["potential_access"] == potential
    cred = repo.get_credential(finding.credential_id)
    [exposure] = repo.exposures_for_credential(cred.id)
    assert row["risk"] == _risk(exposure, cred)["effective_severity"].lower()
    assert row["scopes"] is None and row["verification"]["state"] == "unknown"
    repo.update_credential(cred.id, usage_snapshot={**snapshot, "collected_account_id": "999999999999"})
    assert build(repo, orch)["items"][0]["aws_permissions"] == {}
    # The addresses a saved lookup saw join the row on the same owner-account gate.
    def sources(row):
        return row["recent_sources"], row["recent_sources_total"], row["recent_sources_more"]

    events = [{"event_time": "2026-10-04T01:00:00+00:00", "source_address": "203.0.113.5", "source_address_kind": "IPV4"}]
    # The summary counted every event the lookup read, past the newest one kept, and more addresses past its cap.
    summary = {"events": 400, "sources_untracked": 12, "sources": {
        "203.0.113.5": {"kind": "IPV4", "count": 30, "last": "2026-10-04T01:00:00+00:00"},
        **{f"198.51.100.{n}": {"kind": "IPV4", "count": n, "last": f"2026-09-{n:02d}T00:00:00+00:00"} for n in range(1, 9)}}}
    for snapshot in ({"events": events}, {"events": events, "summary": summary}):
        repo.update_credential(cred.id, usage_snapshot={"collected_account_id": "999999999999", **snapshot})
        assert sources(build(repo, orch)["items"][0]) == ([], 0, False)
    repo.update_credential(cred.id, usage_snapshot={"collected_account_id": ACCOUNT, "events": events})
    assert sources(build(repo, orch)["items"][0]) == (
        [{"address": "203.0.113.5", "kind": "IPV4", "last_seen_at": "2026-10-04T01:00:00+00:00", "count": 1}], 1, False)
    repo.update_credential(cred.id, usage_snapshot={"collected_account_id": ACCOUNT, "events": events, "summary": summary})
    shown, total, lower_bound = sources(build(repo, orch)["items"][0])
    assert [(s["address"], s["count"]) for s in shown] == [("203.0.113.5", 30), *((f"198.51.100.{n}", n) for n in (8, 7, 6, 5))]
    assert (total, lower_bound) == (9, True)


@pytest.mark.parametrize("provider", ["github", "gitlab", "notion", "azure_devops", "gcp", "slack"])
def test_provider_reported_permissions_remain_available_after_inventory_merge(provider):
    # These are provider-reported fields, not a claim that every API exposes permissions.
    entity = {"id": uuid.uuid4(), "provider": provider, "origin": "https://example.test", "tenant": "test",
              "object_id": "pat:test", "observed_at": "2026-10-04T00:00:00Z", "summary": {"permissions": [
                  {"kind": "scope", "name": "read", "effect": "ALLOW"},
                  {"kind": "permission", "name": "contents", "actions": ["write"], "effect": "ALLOW"},
                  {"kind": "permission", "name": "administration", "actions": ["write"], "effect": "DENY"},
                  {"kind": "permission", "name": "unknown", "effect": "UNKNOWN"}]}}
    facts = credential_records._entity_facts(entity, {})
    record = {"created_at": None, "expires_at": None, "last_used": None, "name": None, "issuer": None,
              "scopes": None, "verification": {"state": "unknown"}}
    credential_records._merge(record, facts)
    assert [s["name"] for s in record["scopes"]] == ["read", "contents:write"]
    assert record["issued"]["provider"] == provider


def test_normalized_metadata_fields_are_values_and_creator_is_not_owner():
    from cremore.coverage.facts import FactWriter

    fields = {"label": "Automation", "createdAt": "2026-01-01T00:00:00Z", "expiresAt": "2027-01-01T00:00:00Z",
              "lastActiveAt": "2026-09-30T00:00:00Z", "scopes": ["read:org"],
              "createdBy.id": "admin-1", "createdBy.name": "Key creator"}
    tree = {"metadata": {"source": "admin-api-keys", "fields": [
        {"name": name, "metadata": {"state": "present", "value": value}} for name, value in fields.items()]}}
    entity = {"id": uuid.uuid4(), "provider": "atlassian", "origin": "https://api.atlassian.com", "tenant": "test",
              "object_id": "admin-key", "observed_at": "2026-10-04T00:00:00Z",
              "summary": {"facts": [f.model_dump() for f in FactWriter().facts(tree)]}}
    found = credential_records._entity_facts(entity, {"atlassian": "cremore_atlassian_provider.metadata.owners"})
    assert found["created"] == "2026-01-01T00:00:00+00:00"
    assert found["last_used"] == "2026-09-30T00:00:00+00:00"
    assert found["name"] == "Automation" and found["scopes"][0]["name"] == "read:org"
    assert found["source"]["creator_name"] == "Key creator" and found["issuer"] is None


def test_an_sso_authorization_takes_the_type_github_names_for_it():
    from cremore.coverage.facts import FactWriter

    # GET /orgs/{org}/credential-authorizations: credential_type is one of these four.
    for kind, expected in {"personal access token": "GITHUB_CLASSIC_PAT", "SSH key": "GITHUB_SSH_KEY",
                           "OAuth app token": "GITHUB_OAUTH_TOKEN", "GitHub app token": "GITHUB_APP_USER_TOKEN"}.items():
        entity = {"id": uuid.uuid4(), "provider": "github", "origin": "https://api.github.com", "tenant": "acme",
                  "object_id": "sso:1", "observed_at": "2026-10-08T00:00:00Z",
                  "summary": {"facts": [f.model_dump() for f in FactWriter().facts({"credential_type": kind})]}}
        assert credential_records._entity_facts(entity, {})["credential_type"] == expected, kind


def test_latest_scope_check_replaces_scopes_from_older_locations():
    from cremore.api.finding_evidence_test import exposure
    from cremore.domain.models import Credential, Finding

    cred = Credential(id=uuid.uuid4(), fingerprint="fp", provider="github", credential_type="GITHUB_TOKEN")
    old = exposure("notion", "old", "one", verification_state="verified", verification_scopes="repo,admin:org")
    new = exposure("notion", "new", "two", verification_state="verified", verification_scopes="read:org",
                   verification_checked_at="2026-10-04T00:00:00Z")
    old.id, new.id = uuid.uuid4(), uuid.uuid4()
    finding = Finding(id=uuid.uuid4(), credential_id=cred.id, primary_exposure_id=old.id, severity="LOW")
    record = credential_records._exposed(finding, cred, [old, new], None, {}, Settings())
    assert record["scopes"] == [{"name": "read:org", "write": False}]


def test_an_iam_permission_is_judged_by_its_verb_not_by_its_service_name():
    names = {"secretmanager.versions.access": False, "storage.objects.get": False,
             "cloudkms.cryptoKeyVersions.useToDecrypt": False, "resourcemanager.projects.getIamPolicy": False,
             "resourcemanager.projects.setIamPolicy": True, "iam.serviceAccountKeys.create": True,
             "iam.serviceAccounts.actAs": True, "iam.serviceAccounts.getAccessToken": True,
             "run.services.update": True, "compute.instances.create": True, "storage.objects.delete": True,
             # Other grammars keep their words: an Okta scope's verb is not an IAM verb.
             "okta.apps.manage": True, "chat:write": True, "read:org": False,
             # An Azure role is judged by its name, not by where it holds.
             "Reader · /providers/Microsoft.Management/managementGroups/t": False, "Contributor · /subscriptions/s": True,
             "Key Vault Secrets Officer · /subscriptions/s/resourceGroups/rg-admin": True,
             "Microsoft Graph: Directory.ReadWrite.All": True, "Microsoft Graph: User.Read.All": False,
             "Office 365 Management APIs: ActivityFeed.Read": False, "Contoso Admin Portal: Data.Read": False,
             "Reader and Data Access · /subscriptions/s/resourceGroups/rg": True}
    assert {name: credential_records._writes(name) for name in names} == names


def test_cloudtrail_creator_joins_account_and_target_key_without_changing_owner_or_last_use(repo):
    from datetime import UTC, datetime

    from cremore_aws_provider.usage_inventory import event_observations

    from cremore.coverage.store import CoverageStore

    engine, orch = stack(repo)
    now = datetime.now(UTC)
    iam = ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT)
    item = Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/owner", account_id=ACCOUNT,
        evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier=IAM_ID, state="Active")
    save(repo, engine, iam, [item])
    [row] = build(repo, orch)["items"]
    assert row["issued"]["creator_status"] == "NOT_CONNECTED"
    trail = ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT, regions=["us-east-1"])
    event = {"eventID": "create-key", "eventTime": now.isoformat(), "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey", "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/creator"},
        "responseElements": {"accessKey": {"accessKeyId": IAM_ID, "secretAccessKey": "do-not-store"}}}
    observations = event_observations(event, trail, event_id="create-key", region="us-east-1", source="EVENT_HISTORY", start=now, end=now)
    connection = save(repo, engine, trail, observations)
    [row] = build(repo, orch)["items"]
    assert row["issued"]["creator"]["arn"].endswith("/creator") and row["issuer"]["name"] == "owner"
    assert row["issued"]["creator"]["event_id"] == "create-key"
    assert row["last_used"] is None and row["verification"]["basis"] == "ISSUER_REPORTED"
    assert not repo.list_findings() and "do-not-store" not in json.dumps(row)
    CoverageStore(repo).change(connection["id"], 1, "admin", enabled=False)
    [row] = build(repo, orch)["items"]
    assert row["issued"]["creator"]["current"] is False
    # Conflicting positive evidence must not pick an arbitrary person.
    event["eventID"] = "different-creator"
    event["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/other"
    other = event_observations(event, trail, event_id="different-creator", region="us-east-1", source="EVENT_HISTORY", start=now, end=now)
    save(repo, engine, trail, other)
    [row] = build(repo, orch)["items"]
    assert row["issued"]["creator"] is None and row["issued"]["creator_status"] == "CONFLICT"


def test_only_a_value_match_reads_as_stored_in_a_vault():
    place = {"provider": "vault", "connection_name": "KV", "reference": "app/key"}
    for basis in ("IDENTIFIER_ONLY", "PUBLIC_CERTIFICATE_MATCH"):
        # A key ID or a public certificate names the credential in a vault; neither is its value there.
        named = credential_records._vault([{"state": basis, "locations": [place]}, {"state": "NO_VAULT_MATCH"}])
        assert (named["state"], named["basis"]) == ("unknown", basis)
        assert named["where"] == [{"provider": "vault", "connection": "KV", "reference": "app/key"}]
    matched = credential_records._vault([{"state": "MATCHED", "locations": [place]}, {"state": "IDENTIFIER_ONLY"}])
    assert (matched["state"], matched["basis"]) == ("stored", "MATCHED")
    assert credential_records._vault([{"state": "NO_VAULT_MATCH"}])["state"] == "none"


def entity(provider, object_id, facts):
    from cremore.coverage.facts import FactWriter

    return {"id": uuid.uuid4(), "provider": provider, "origin": "https://example.test", "tenant": "test",
            "object_id": object_id, "observed_at": "2026-10-04T00:00:00Z",
            "summary": {"facts": [f.model_dump() for f in FactWriter().facts(facts)]}}


def test_a_null_expiry_means_no_expiry_only_where_the_provider_field_says_so():
    # Atlassian's normalized null expiresAt is no evidence of no expiry.
    wrapped = {"metadata": {"source": "admin-api-keys", "fields": [
        {"name": "label", "metadata": {"state": "present", "value": "Automation"}},
        {"name": "expiresAt", "metadata": {"state": "null"}}]}}
    found = credential_records._entity_facts(entity("atlassian", "admin-key", wrapped), {})
    assert (found["expires"], found["expiry_known"]) == (None, False)
    assert credential_records._expiry(found["expires"], found["expiry_known"]) == "unknown"
    # A raw null the provider returned (a GitHub token with no expiry) still reads as none.
    raw = credential_records._entity_facts(entity("github", "fgpat:1", {"token_expires_at": None}), {})
    assert credential_records._expiry(raw["expires"], raw["expiry_known"]) == "none"


def test_an_organization_grant_or_sso_authorization_is_not_when_a_credential_was_created():
    for object_id, facts in (("fgpat:1", {"access_granted_at": "2026-01-02T00:00:00Z"}),
                             ("sso:1", {"credential_authorized_at": "2026-01-02T00:00:00Z"})):
        assert credential_records._entity_facts(entity("github", object_id, facts), {})["created"] is None
    created = credential_records._entity_facts(entity("github", "fgpat:2", {"token_created_at": "2022-05-01T00:00:00Z"}), {})
    assert created["created"] == "2022-05-01T00:00:00+00:00"


def test_names_are_preferred_over_ids_and_bitbucket_accounts_read_by_display_name():
    fields = {"serviceAccount.id": "opaque-sa", "serviceAccount.name": "Deploy robot",
              "createdBy.id": "opaque-admin", "createdBy.name": "Ada Admin"}
    wrapped = {"metadata": {"source": "service-oauth", "fields": [
        {"name": name, "metadata": {"state": "present", "value": value}} for name, value in fields.items()]}}
    found = credential_records._entity_facts(entity("atlassian", "client-1", wrapped), {})
    assert found["issuer"]["name"] == "Deploy robot" and found["source"]["creator_name"] == "Ada Admin"
    account = {"display_name": "Bea Builder", "uuid": "{0000}", "type": "user"}
    ssh = credential_records._entity_facts(entity("bitbucket", "ssh:1", {"owner": account}), {})
    deploy = credential_records._entity_facts(entity("bitbucket", "deploy:1", {"created_by": account}), {})
    assert ssh["issuer"]["name"] == "Bea Builder" and deploy["source"]["creator_name"] == "Bea Builder"


def test_the_later_last_use_wins_with_its_own_basis():
    found = credential_records._aws_found({"identifier": IAM_ID, "state": "Active", "current_evidence": True,
                                           "last_used_at": "2026-10-10T00:00:00+00:00"})
    record = {"created_at": None, "expires_at": None, "name": None, "issuer": None, "scopes": None,
              "verification": {"state": "unknown"},
              "last_used": {"at": "2026-06-01T00:00:00+00:00", "basis": "CREDENTIAL_USAGE"}}
    credential_records._merge(record, found)
    assert record["last_used"] == {"at": "2026-10-10T00:00:00+00:00", "basis": "ISSUER_REPORTED"}
    newer = {**record, "last_used": {"at": "2026-10-12T00:00:00+00:00", "basis": "CREDENTIAL_USAGE"}}
    credential_records._merge(newer, found)
    assert newer["last_used"] == {"at": "2026-10-12T00:00:00+00:00", "basis": "CREDENTIAL_USAGE"}


def test_an_issuer_state_no_longer_current_is_history_not_the_current_state(repo):
    from datetime import UTC, datetime, timedelta

    engine, orch = stack(repo)
    github_inventory(MetadataStore(repo), engine)
    [row] = build(repo, orch)["items"]
    assert row["issued"]["current"] is True and row["verification"]["state"] == "active"
    # The same entity, read after its issuer's collection went stale: its last state is history.
    later = credential_records.build(repo, Settings(), orch, now=datetime.now(UTC) + timedelta(days=30))
    [row] = later["items"]
    assert row["issued"]["current"] is False
    assert (row["verification"]["state"], row["verification"]["reason"]) == ("unknown", "ISSUER_OBSERVATION_NOT_CURRENT")
