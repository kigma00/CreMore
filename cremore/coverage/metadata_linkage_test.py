"""Passive issuer linkage through detection, provider normalization and storage."""

import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cremore_azure_provider.arm import arm_test as arm
from cremore_github_provider.metadata.tests.fake import ENTERPRISE, audit_row
from cremore_github_provider.metadata.tests.test_adapter import drive
from cremore_github_provider.metadata.tests.test_digest_evidence import (
    audit_connection,
    audited,
    connection,
    scripted,
)

from cremore.api.metadata_coverage import public_metadata
from cremore.coverage.metadata_correlation import finding_links, sas_candidates
from cremore.coverage.metadata_job_test import repo as repo  # noqa: PLC0414
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import Contract
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.detection import ResourceRef
from cremore.detection.engine import Engine, EngineConfig
from cremore.scanning.orchestrator import Orchestrator
from cremore.siem.events import finding_created

TOKEN = b"ghp_" b"aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
KEY = b"synthetic-offline-comparison-key!"


def issuer(store, engine, *, material=TOKEN, key=KEY, owner=None, empty=False, status="COMPLETE", reasons=(), stable=True):
    spec = connection()
    contract = Contract(engine_digest=engine.detection_digest)
    ctx = {"engine": Engine(EngineConfig(fingerprint_key=key)), "key_id": hashlib.sha256(key).hexdigest(),
           "engine_digest": contract.engine_digest, "policy_digest": contract.policy_digest}
    vendor_hash = base64.b64encode(hashlib.sha256(material).digest()).decode()
    responses = scripted(vendor_hash, credential_id="1" if stable else "")
    if empty:
        responses[f"/enterprises/{ENTERPRISE}/credentials/exports"] = []
    _, _, items, _, final = drive(spec, responses, enterprise=ENTERPRISE, value_context=ctx)
    assert final.status == "COMPLETE"
    if owner is None:
        owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    # These records came from the fake provider collector, as in the worker path.
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items), trusted_discovery=True)
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status=status, reasons=list(reasons)))
    return vendor_hash


@pytest.mark.parametrize("material,key,linked", [(TOKEN, KEY, True), (TOKEN.upper(), KEY, False), (TOKEN, b"z" * 32, False)])
def test_github_provider_digest_links_only_compatible_exact_bytes_and_never_uses_source_host(repo, material, key, linked):
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=engine, config=engine.config)
    orch.scan_resource(TOKEN, ResourceRef(source_type="gitlab", resource="team/app", location="test.env",
        metadata={"source_instance": "https://gitlab.example.test"}), verify=False)
    finding = repo.list_findings()[0]
    store = MetadataStore(repo)
    provider_hash = issuer(store, engine, material=material, key=key)
    result = finding_links(store, repo, finding.id)
    assert result["value_match_count"] == int(linked)
    assert result["evidence"] == ("LINKED" if linked else "CANDIDATE")
    assert result["items"][0]["verification"] == "NOT_PERFORMED"
    exposure = repo.exposures_for_credential(finding.credential_id)[0]
    assert exposure.metadata["verification_state"] == "not_attempted"
    private = exposure.metadata["issuer_comparison"]["github_token_digest"]
    outputs = json.dumps(result, default=str) + json.dumps(public_metadata(store.inventory()), default=str)
    outputs += json.dumps(finding_created(finding, repo.get_credential(finding.credential_id), exposure))
    for secret in (TOKEN.decode(), provider_hash, private):
        assert secret not in outputs
    repo.mark_exposure_removed(exposure.id)
    assert finding_links(store, repo, finding.id)["items"] == []
    # Completion must still resolve the old issuer after plaintext cleanup.
    retained = finding_links(store, repo, finding.id, include_removed=True)
    assert retained["value_match_count"] == int(linked)


def test_audit_activity_made_with_the_exposed_token_counts_each_entry_once_without_digests(repo):
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    Orchestrator(repo, engine=engine, config=engine.config).scan_resource(TOKEN, ResourceRef(
        source_type="gitlab", resource="team/app", location="test.env",
        metadata={"source_instance": "https://gitlab.example.test"}), verify=False)
    finding = repo.list_findings()[0]
    store = MetadataStore(repo)
    before = finding_links(store, repo, finding.id)
    assert "token_activity" not in before and "NO_TOKEN_ACTIVITY_COLLECTED" in before["reasons"]
    vendor_hash = base64.b64encode(hashlib.sha256(TOKEN).digest()).decode()
    other = base64.b64encode(hashlib.sha256(TOKEN + b"x").digest()).decode()
    rows = [audit_row("repo.create", _document_id="doc-1", created_at="2026-03-01T00:00:00Z",
                      hashed_token=vendor_hash, repo="acme/one"),
            audit_row("repo.update", _document_id="doc-2", created_at="2026-03-02T00:00:00Z",
                      hashed_token=vendor_hash, repo="acme/two"),
            audit_row("repo.create", _document_id="doc-3", hashed_token=other)]
    spec = audit_connection()
    contract = Contract(engine_digest=engine.detection_digest)
    owner, _ = store.create(spec, "synthetic")
    for key in (KEY, KEY, b"z" * 32):  # overlapping windows re-read entries; another key never matches
        ctx = {"engine": Engine(EngineConfig(fingerprint_key=key)), "key_id": hashlib.sha256(key).hexdigest(),
               "engine_digest": contract.engine_digest, "policy_digest": contract.policy_digest}
        _, _, items, _, final = drive(spec, audited(rows), enterprise=ENTERPRISE, value_context=ctx)
        assert final.status == "COMPLETE"
        run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items), trusted_discovery=True)
        store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status="COMPLETE"))
    result = finding_links(store, repo, finding.id)
    assert result["token_activity"] == {
        "events": 2, "first_seen_at": "2026-03-01T00:00:00+00:00", "last_seen_at": "2026-03-02T00:00:00+00:00",
        "actions": ["repo.create", "repo.update"], "repositories": ["acme/one", "acme/two"], "actors": ["octocat"]}
    assert "NO_TOKEN_ACTIVITY_COLLECTED" not in result["reasons"]
    private = repo.exposures_for_credential(finding.credential_id)[0].metadata["issuer_comparison"]["github_token_digest"]
    outputs = json.dumps(result, default=str) + json.dumps(store.provider_events(), default=str)
    outputs += json.dumps(public_metadata(store.run_detail(run["id"])), default=str)
    for secret in (TOKEN.decode(), vendor_hash, other, private):
        assert secret not in outputs


@pytest.mark.parametrize("invalid", [1, True, "event-as-a-scalar", {"unexpected": "shape"}])
def test_token_activity_scalar_facts_are_ignored_as_invalid_evidence(invalid):
    from types import SimpleNamespace

    from cremore.coverage.facts import FactWriter
    from cremore.coverage.metadata_correlation import GITHUB_SCHEME, _token_activity

    meta = {"issuer_comparison": {"github_token_digest": "digest", "key_id": "key"},
            "coverage_engine_digest": "engine", "coverage_policy_digest": "policy"}
    match = {"evidence": "PROVIDER_DIGEST", "scheme": GITHUB_SCHEME, "fingerprint": "digest",
             "key_id": "key", "engine_digest": "engine", "policy_digest": "policy", "material_kind": "credential"}
    facts = {"first_seen_at": "2026-03-01T00:00:00+00:00", "last_seen_at": "2026-03-02T00:00:00+00:00",
             "_document_id": ["event-1"], "action": ["repo.create"], "repo": ["acme/one"], "actor": ["octocat"]}
    for field in ("_document_id", "action", "repo", "actor"):
        writer = FactWriter()
        body = {"value_match": match,
                "facts": [fact.model_dump() for fact in writer.facts({**facts, field: invalid})]}
        store = SimpleNamespace(token_activity=lambda *_args, body=body, **_kwargs: [{"body": body}])
        reasons = set()
        assert _token_activity(store, [SimpleNamespace(metadata=meta)], reasons) is None
        assert "TOKEN_ACTIVITY_FACTS_INVALID" in reasons


def save_vault(repo, engine, material):
    from cremore.coverage.hasher import hash_value
    from cremore.coverage.models import Batch, ConnectionSpec, Finish
    from cremore.coverage.store import CoverageStore
    store = CoverageStore(repo)
    spec = ConnectionSpec(name="Vault", provider="aws_secrets_manager", account_id="123456789012", regions=["us-east-1"])
    owner, _ = store.create(spec, "synthetic")
    contract = Contract(engine_digest=engine.detection_digest)
    run = store.start(owner["id"], 1, str(uuid.uuid4()), contract.model_dump())
    items = hash_value(engine, material, {"reference": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-Ab12Cd",
        "account_id": "123456789012", "region": "us-east-1"}, max_bytes=4096)
    store.append(owner["id"], run["id"], Batch(index=0, items=items))
    return store.finish(owner["id"], run["id"], Finish(batch_count=1, item_count=len(items), status="COMPLETE"))


@pytest.mark.parametrize("stable", [True, False])
def test_issued_github_credential_can_match_vault_without_creating_an_exposure(repo, stable):
    from cremore.coverage.correlation import report
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    vendor_hash = issuer(MetadataStore(repo), engine, stable=stable)
    save_vault(repo, engine, TOKEN)
    result = report(repo, Contract(engine_digest=engine.detection_digest).model_dump(),
                    fingerprint_key_id=hashlib.sha256(KEY).hexdigest())
    [issued] = [row for row in result["items"] if row["origin"] == "ISSUANCE"]
    assert issued["state"] == "MATCHED" and issued["match_basis"] == "PROVIDER_DIGEST"
    assert issued["locations"][0]["provider"] == "aws_secrets_manager"
    assert issued["exposed"] is False and repo.list_findings() == []
    assert result["summary"]["exposed"] == result["summary"]["matched"] == 0
    assert result["summary"]["issued"] == result["summary"]["issued_in_vault"] == int(stable)
    assert bool(issued["issued"].get("snapshot_observation")) is not stable
    assert result["summary"]["issuance_only"] == int(stable)
    assert vendor_hash not in json.dumps(result, default=str)
    assert "provider_digest" not in json.dumps(result, default=str)


def test_bare_storage_key_in_vault_matches_exposed_labelled_key_without_retyping_unknown_values(repo):
    from cremore.coverage.correlation import report
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    raw = base64.b64encode(bytes(range(64)))
    orch = Orchestrator(repo, engine=engine, config=engine.config)
    orch.scan_resource(b"AccountKey=" + raw, ResourceRef(source_type="inline", resource="fixture"), verify=False)
    save_vault(repo, engine, raw)
    result = report(repo, Contract(engine_digest=engine.detection_digest).model_dump(),
                    fingerprint_key_id=hashlib.sha256(KEY).hexdigest())
    azure = next(row for row in result["items"] if row["credential_type"] == "AZURE_STORAGE_KEY")
    assert azure["state"] == "MATCHED"
    assert azure["locations"][0]["credential_type"] == "OPAQUE_VALUE"
    assert not any(row["origin"] == "VAULT" and row["credential_type"] == "OPAQUE_VALUE" for row in result["items"])


@pytest.mark.parametrize("condition,current", [
    ("fresh", True), ("partial_observation", True), ("omitted_later", False),
    ("failed_later", False), ("running_later", False), ("disabled", False),
    ("revision_changed", False), ("stale", False),
])
@pytest.mark.parametrize("stable", [True, False])
def test_saved_positive_issuer_link_preserves_equality_and_marks_collection_currentness(repo, condition, current, stable):
    from cremore.coverage.correlation import report

    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=engine, config=engine.config)
    orch.scan_resource(TOKEN, ResourceRef(source_type="gitlab", resource="synthetic"), verify=False)
    finding = repo.list_findings()[0]
    store = MetadataStore(repo)
    issuer(store, engine, stable=stable)
    [owner] = store.list_connections()
    save_vault(repo, engine, TOKEN)
    now = datetime.now(UTC)
    if condition == "partial_observation":
        issuer(store, engine, owner=owner, status="PARTIAL", reasons=["SOURCE_COLLECTION_INCOMPLETE"], stable=stable)
    elif condition in {"omitted_later", "failed_later"}:
        issuer(store, engine, owner=owner, empty=True, stable=stable,
               status="COMPLETE" if condition == "omitted_later" else "FAILED")
    elif condition == "running_later":
        store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(connection()).model_dump())
    elif condition == "disabled":
        store.change(owner["id"], 1, "synthetic", enabled=False)
    elif condition == "revision_changed":
        store.change(owner["id"], 1, "synthetic", rotate=True)
    elif condition == "stale":
        now += timedelta(hours=25)
    result = finding_links(store, repo, finding.id, now=now)
    assert result["evidence"] == "LINKED" and result["value_match_count"] == 1
    [item] = result["items"]
    assert item["evidence"] == "VALUE" and item["match_basis"] == "PROVIDER_DIGEST"
    assert item["verification"] == "NOT_PERFORMED"
    assert item["current_evidence"] is current
    assert ("ISSUER_OBSERVATION_NOT_CURRENT" in item["reasons"]) is not current
    coverage = report(repo, Contract(engine_digest=engine.detection_digest).model_dump(),
                      fingerprint_key_id=hashlib.sha256(KEY).hexdigest(), now=now)
    [issued] = [row for row in coverage["items"] if row["origin"] == "ISSUANCE"]
    assert issued["issued"]["current_evidence"] is current
    assert ("ISSUER_OBSERVATION_NOT_CURRENT" in issued["reasons"]) is not current
    if condition != "stale":
        assert issued["state"] == "MATCHED"  # Current Vault equality remains independent of issuer currentness.


def test_an_exposed_sas_links_to_its_storage_account_keys_by_name_only():
    from types import SimpleNamespace

    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import Credential, Exposure
    repo = InMemoryRepository()
    credential = repo.upsert_credential(Credential(fingerprint="f" * 64, credential_type="AZURE_SAS_TOKEN", provider="azure"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github", resource_name="acme/app",
        location="deploy.env", severity="HIGH", status="OPEN",
        metadata={"azure_sas": {"account": "myaccount", "kind": "service"}}))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    account = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/"

    def entity(name, slot):
        return {"id": f"{name}-{slot}", "provider": "azure_resource_manager", "origin": "https://management.azure.com",
                "tenant": "t", "tenant_confirmed": True, "object_kind": "credential",
                "object_id": account + name + "/keys/" + slot, "purpose": "issuer_inventory", "observed_at": None,
                "observation_run": None, "collections": [], "summary": {}}

    rows = [entity("myaccount", "key1"), entity("myaccount", "key2"), entity("otheraccount", "key1")]
    store = SimpleNamespace(inventory=lambda **kw: {"items": rows[kw["offset"]:], "total": len(rows)},
                            snapshot_matches=lambda *_a, **_kw: {"items": [], "truncated": False},
                            usage_counts=lambda ids: {}, list_connections=list,
                            inventory_details=lambda rows: rows)
    result = finding_links(store, repo, finding.id)
    linked = [item for item in result["items"] if item["evidence"] == "IDENTIFIER"]
    assert result["provider"] == "azure_resource_manager" and result["identifier_match_count"] == 2
    assert {item["object_id"].rsplit("/", 1)[-1] for item in linked} == {"key1", "key2"}
    assert all(item["match_basis"] == "STORAGE_ACCOUNT_NAME" and "otheraccount" not in item["object_id"] for item in linked)


def test_the_storage_key_that_signed_an_exposed_sas_is_linked_by_value(repo):
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    _, encoded, signed = arm.signed_sas(arm.VALUE, KEY)
    Orchestrator(repo, engine=engine, config=engine.config).scan_resource(
        ("https://acmeprod.blob.core.windows.net/?sv=2022-11-02&ss=b&srt=o&sp=r&se=2027-01-01T00:00:00Z&sig="
         + encoded).encode(), ResourceRef(source_type="gitlab", resource="team/app", location="deploy.env",
                                          metadata={"source_instance": "https://gitlab.example.test"}), verify=False)
    [finding] = [item for item in repo.list_findings()
                 if repo.get_credential(item.credential_id).credential_type == "AZURE_SAS_TOKEN"]
    assert repo.get_credential(finding.credential_id).fingerprint == signed
    spec, contract = arm.value_spec(), Contract(engine_digest=engine.detection_digest)
    ctx = {"engine": engine, "key_id": hashlib.sha256(KEY).hexdigest(), "engine_digest": contract.engine_digest,
           "policy_digest": contract.policy_digest, "sas_candidates": sas_candidates(repo, spec.options.azure_storage_accounts)}
    items = arm.records(arm.collect(spec, arm.Arm({arm.ACCOUNT + "/listKeys": arm.two_keys()}), value_context=ctx))
    store = MetadataStore(repo)
    owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items))
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status="COMPLETE"))
    result = finding_links(store, repo, finding.id)
    by_key = {item["object_id"].rsplit("/", 1)[1]: item for item in result["items"]}
    assert (by_key["key1"]["evidence"], by_key["key1"]["match_basis"]) == ("VALUE", "SAS_SIGNATURE")
    assert (by_key["key2"]["evidence"], by_key["key2"]["match_basis"]) == ("IDENTIFIER", "STORAGE_ACCOUNT_NAME")
    assert result["value_match_count"] == 1 and result["evidence"] == "LINKED"
    outputs = json.dumps(result, default=str) + json.dumps(public_metadata(store.inventory()), default=str)
    for private in (signed, encoded, arm.VALUE):
        assert private not in outputs


@pytest.mark.parametrize("provider,credential_type,facts,owner", [
    ("gitlab", "GITLAB_PERSONAL_ACCESS_TOKEN", lambda owner: [{"name": "observation", "children": [
        {"name": "metadata", "children": [{"name": "user_id", "value": owner}]}]}], {"verification_owner_id": "7"}),
    ("github", "GITHUB_TOKEN", lambda owner: [{"name": "login", "value": owner}],
     {"verification_owner_name": "Octo", "verification_host": "github.com"}),
    ("notion", "NOTION_TOKEN", lambda owner: [{"name": "creator", "children": [{"name": "id", "value": owner}]}],
     {"verification_owner_id": "0e8f6d7c-1111-2222-3333-444455556666"}),
])
def test_a_verified_owner_ranks_its_issued_tokens_first_without_claiming_a_match(provider, credential_type, facts, owner):
    from types import SimpleNamespace

    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import Credential, Exposure
    repo = InMemoryRepository()
    credential = repo.upsert_credential(Credential(fingerprint="f" * 64, credential_type=credential_type, provider=provider))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3", resource_name="bucket",
        location="app.env", severity="HIGH", status="OPEN", metadata={"verification_state": "verified", **owner}))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    mine = next(iter(owner.values()))
    origin = {"gitlab": "https://gitlab.com", "github": "https://github.com"}.get(provider, "https://api.notion.com")
    rows = [{"id": f"token-{index}", "provider": provider, "origin": origin, "tenant": "t",
             "tenant_confirmed": True, "object_kind": "credential", "object_id": f"token-{index}",
             "purpose": "issuer_inventory", "observed_at": None, "observation_run": None, "collections": [],
             "summary": {"facts": facts(value)}} for index, value in enumerate(["someone-else", mine.lower(), mine])]
    store = SimpleNamespace(inventory=lambda **kw: {"items": rows[kw["offset"]:], "total": len(rows)},
                            snapshot_matches=lambda *_a, **_kw: {"items": [], "truncated": False},
                            usage_counts=lambda ids: {}, list_connections=list,
                            inventory_details=lambda rows: rows)
    result = finding_links(store, repo, finding.id)
    assert result["owner_match_count"] == 2 and result["match_count"] == 0 and result["evidence"] == "CANDIDATE"
    assert [item["evidence"] for item in result["items"]] == ["OWNER", "OWNER", "CANDIDATE"]
    assert "OWNER_MATCH_IS_NOT_A_TOKEN_MATCH" in result["reasons"]


def test_a_gitlab_com_token_named_by_its_own_verification_links_exactly():
    from types import SimpleNamespace

    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import Credential, Exposure
    repo = InMemoryRepository()
    credential = repo.upsert_credential(Credential(fingerprint="f" * 64, credential_type="GITLAB_PERSONAL_ACCESS_TOKEN",
                                                   provider="gitlab"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3", resource_name="bucket",
        location="app.env", severity="HIGH", status="OPEN",
        metadata={"verification_state": "verified", "verification_token_id": "42", "verification_owner_id": "7"}))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")

    def token(instance, native_id, family="personal_access_token"):
        return {"id": f"{instance}-{native_id}", "provider": "gitlab", "origin": instance, "tenant": "", "tenant_confirmed": False,
                "object_kind": "credential", "object_id": f"{family}:{native_id}", "purpose": "issuer_inventory",
                "observed_at": None, "observation_run": None, "collections": [],
                "summary": {"facts": [{"name": "identity", "children": [
                    {"name": "instance", "value": instance}, {"name": "namespace", "value": family},
                    {"name": "native_id", "value": native_id}]}, {"name": "observation", "children": [
                    {"name": "metadata", "children": [{"name": "user_id", "value": 7}]}]}]}}

    # A project access token carries the namespace the GitLab collector really emits for it.
    from cremore_gitlab_provider.metadata.model import identity
    resource = identity("https://gitlab.com", "project_access_token", 42, {"kind": "project", "id": 5})["namespace"]
    rows = [token("https://gitlab.com", 41), token("https://gitlab.com", 42, resource),
            token("https://gitlab.example.test", 42)]
    store = SimpleNamespace(inventory=lambda **kw: {"items": rows[kw["offset"]:], "total": len(rows)},
                            usage_counts=lambda ids: {}, list_connections=list,
                            inventory_details=lambda rows: rows)
    result = finding_links(store, repo, finding.id)
    assert result["identifier_match_count"] == 1 and result["evidence"] == "LINKED"
    [linked] = [item for item in result["items"] if item["evidence"] == "IDENTIFIER"]
    assert linked["entity_id"] == "https://gitlab.com-42" and linked["match_basis"] == "PROVIDER_VERIFIED_TOKEN_ID"
    # Same GitLab.com owner ranks first; user 7 of another instance is someone else.
    assert [item["evidence"] for item in result["items"]][1:] == ["OWNER", "CANDIDATE"]


@pytest.mark.parametrize("verified_host", ["gitlab.example.test", "gitlab.other.test"])
def test_a_self_managed_token_links_only_to_the_instance_that_named_it(verified_host):
    from types import SimpleNamespace

    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import Credential, Exposure
    repo = InMemoryRepository()
    credential = repo.upsert_credential(Credential(fingerprint="f" * 64, credential_type="GITLAB_PERSONAL_ACCESS_TOKEN",
                                                   provider="gitlab"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="gitlab", resource_name="group/app",
        location="app.env", severity="HIGH", status="OPEN",
        metadata={"verification_state": "verified", "verification_token_id": "42", "verification_owner_id": "7",
                  "verification_host": verified_host, "source_instance": "https://gitlab.example.test"}))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")

    def token(instance, native_id):
        return {"id": f"{instance}-{native_id}", "provider": "gitlab", "origin": instance, "tenant": "", "tenant_confirmed": False,
                "object_kind": "credential", "object_id": f"personal_access_token:{native_id}", "purpose": "issuer_inventory",
                "observed_at": None, "observation_run": None, "collections": [],
                "summary": {"facts": [{"name": "identity", "children": [
                    {"name": "instance", "value": instance}, {"name": "namespace", "value": "personal_access_token"},
                    {"name": "native_id", "value": native_id}]}, {"name": "observation", "children": [
                    {"name": "metadata", "children": [{"name": "user_id", "value": 7}]}]}]}}

    rows = [token("https://gitlab.com", 42), token("https://gitlab.example.test", 41),
            token("https://gitlab.example.test", 42)]
    store = SimpleNamespace(inventory=lambda **kw: {"items": rows[kw["offset"]:], "total": len(rows)},
                            usage_counts=lambda ids: {}, list_connections=list,
                            inventory_details=lambda rows: rows)
    result = finding_links(store, repo, finding.id)
    if verified_host == "gitlab.example.test":
        # Token id 42 of the instance that verified it, not GitLab.com's token 42.
        [linked] = [item for item in result["items"] if item["evidence"] == "IDENTIFIER"]
        assert linked["entity_id"] == "https://gitlab.example.test-42"
        assert linked["match_basis"] == "PROVIDER_VERIFIED_TOKEN_ID"
        assert {item["entity_id"]: item["evidence"] for item in result["items"]} == {
            "https://gitlab.example.test-42": "IDENTIFIER", "https://gitlab.example.test-41": "OWNER",
            "https://gitlab.com-42": "CANDIDATE"}
    else:
        # A host that is not the instance the token was found in names nothing.
        assert result["identifier_match_count"] == 0


@pytest.mark.parametrize("backend", ["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def test_batched_sas_reads_equal_one_read_per_finding(backend, request):
    """Second review 2026-09-26: sas_candidates reads every candidate in three queries; the batch
    must return what get_finding, get_credential and exposures_for_credential return one by one."""
    from cremore.db.repository import InMemoryRepository
    from cremore.db.sql import SqlRepository, create_all, make_engine
    from cremore.domain.models import Credential, Exposure

    if backend == "memory":
        repo = InMemoryRepository()
    elif backend == "postgres":
        repo = request.getfixturevalue("pg")[1]
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    ids = []
    for index in range(4):
        credential = repo.upsert_credential(Credential(fingerprint=f"{index:064x}", credential_type="AZURE_SAS_TOKEN",
                                                       provider="azure"))
        for location in range(index % 3):
            exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="azure_blob",
                resource_name="acct/data", location=f"f{location}.env", severity="HIGH", status="OPEN",
                metadata={"azure_sas": {"account": "acct", "signed_resource": "b", "n": location}}))
        if index % 3:
            ids.append(repo.upsert_finding(credential.id, exposure.id, "HIGH").id)
    missing = uuid.uuid4()
    batch = repo.findings_with_exposures([ids[1], missing, ids[0], ids[1]])
    expected = [(repo.get_finding(i), repo.get_credential(repo.get_finding(i).credential_id),
                 repo.exposures_for_credential(repo.get_finding(i).credential_id)) for i in (ids[1], ids[0])]
    key = lambda exposures: sorted(str(exposure.id) for exposure in exposures)  # order is unspecified
    assert [(f.id, c.id, key(e)) for f, c, e in batch] == [(f.id, c.id, key(e)) for f, c, e in expected]
    assert repo.findings_with_exposures([]) == []
    limited = repo.findings_with_exposures(ids, exposure_limit=2)
    assert sum(len(exposures) for _, _, exposures in limited) == 2
    assert all(not exposures for _, _, exposures in repo.findings_with_exposures(ids, exposure_limit=0))


def test_sas_exposure_budget_is_applied_before_materialization_and_reports_incomplete(monkeypatch):
    from cremore.coverage import metadata_correlation
    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import Credential, Exposure

    repo = InMemoryRepository()
    credential = repo.upsert_credential(Credential(fingerprint="a" * 64, credential_type="AZURE_SAS_TOKEN", provider="azure"))
    for index in range(4):
        exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="azure_blob",
            resource_name="acct/data", location=f"f{index}", status="OPEN",
            metadata={"azure_sas": {"account": "acct", "kind": "service"}}))
    repo.upsert_finding(credential.id, exposure.id, "HIGH")
    original, limits = repo.findings_with_exposures, []

    def bounded(ids, *, exposure_limit=None):
        limits.append(exposure_limit)
        return original(ids, exposure_limit=exposure_limit)

    monkeypatch.setattr(repo, "findings_with_exposures", bounded)
    monkeypatch.setattr(metadata_correlation, "MAX_SAS_EXPOSURES", 2)
    status = {}
    assert len(sas_candidates(repo, ["acct"], status=status)) == 1
    assert limits == [3] and status == {"complete": False}
    monkeypatch.setattr(metadata_correlation, "MAX_SAS_EXPOSURES", 4)
    assert len(sas_candidates(repo, ["acct"], status=status)) == 1 and status == {"complete": True}
