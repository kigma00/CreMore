"""Onboarded read-only audit evidence reaches the shared credential projection."""

import json
import uuid
from copy import deepcopy

import pytest

from cremore.api.credential_records_test import build, stack
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore_gcp_provider.metadata.adapter import _derived, validate_record
from cremore_gcp_provider.metadata.relations import CREATE_API_KEY_METHOD, CREATE_KEY_METHOD

from .fake import API_KEY_NAME, EMAIL, KEY_ID, PROJECT, SECRET, inventory_responses, spec
from .test_adapter import LOGS, run
from .test_relations import KEY_NAME, collector, drain, entry


def creation():
    row = entry(resource=KEY_NAME.rsplit("/keys/", 1)[0], email="creator@example.test", key=None,
                method=CREATE_KEY_METHOD, service="iam.googleapis.com", insert="created-1")
    row["protoPayload"]["response"] = {"name": KEY_NAME, "privateKeyData": "never-persist-this-material"}
    return row


def test_creation_links_only_exact_listed_key_and_successful_in_scope_event():
    row = creation()
    edges, _ = drain(collector({LOGS: {"entries": [row]}}).key_creation())
    assert len(edges) == 1 and edges[0]["source_id"] == KEY_NAME
    assert edges[0]["target_id"] == "gcp_principal:user:creator@example.test"
    assert edges[0]["evidence_class"] == "credential_creation"
    assert "never-persist" not in json.dumps(edges)
    invalid = []
    for change in ({"status": {"code": 7}}, {"response": {"name": KEY_NAME.replace(KEY_ID, "unknown")}},
                   {"response": {}}, {"response": {"name": KEY_NAME.replace(PROJECT, "other-project")}}):
        altered = deepcopy(row)
        altered["protoPayload"].update(change)
        invalid.append(altered)
    assert drain(collector({LOGS: {"entries": invalid}}).key_creation())[0] == []


def test_numeric_account_alias_requires_current_unambiguous_listing():
    uid = "100000000000000000001"
    name = "//iam.googleapis.com/" + KEY_NAME.replace(EMAIL, uid)
    assert collector({}).key_id(name, EMAIL) is None
    allowed = collector({}, account_ids={EMAIL: uid})
    assert allowed.key_id(name, EMAIL) == KEY_NAME
    assert allowed.key_id(name, "other@example.test") is None
    assert allowed.key_id(name.replace(PROJECT, "other-project"), EMAIL) is None
    other = "other@synthetic-project.iam.gserviceaccount.com"
    ambiguous = collector({}, account_ids={EMAIL: uid, other: uid},
        principals={EMAIL: f"projects/{PROJECT}/serviceAccounts/{EMAIL}", other: f"projects/{PROJECT}/serviceAccounts/{other}"})
    assert ambiguous.key_id(name, EMAIL) is None


def test_api_key_creator_requires_the_exact_listed_resource_and_discards_key_string():
    row = entry(resource=API_KEY_NAME, email="creator@example.test", key=None,
                method=CREATE_API_KEY_METHOD, service="apikeys.googleapis.com")
    row["protoPayload"]["response"] = {"name": API_KEY_NAME, "keyString": "never-retain-key-string"}
    edges, _ = drain(collector({LOGS: {"entries": [row]}}, project_aliases={PROJECT, API_KEY_NAME.split("/")[1]}).key_creation())
    assert len(edges) == 1 and edges[0]["source_id"] == API_KEY_NAME
    assert edges[0]["relation"] == "api_key_created_by"
    assert "never-retain" not in json.dumps(edges)
    row["protoPayload"]["resourceName"] = "projects/other/locations/global/keys/unobserved"
    row["protoPayload"]["response"] = {"name": "operations/not-a-key"}
    assert drain(collector({LOGS: {"entries": [row]}}).key_creation())[0] == []


def test_regional_secret_access_and_policy_keep_the_region_even_with_duplicate_names():
    regional = SECRET.replace("/secrets/", "/locations/asia-northeast3/secrets/")
    url = f"https://secretmanager.asia-northeast3.rep.googleapis.com/v1/{regional}:getIamPolicy"
    policy = {"bindings": [{"role": "roles/secretmanager.secretAccessor", "members": [f"serviceAccount:{EMAIL}"]}]}
    subject = collector({LOGS: {"entries": [entry(resource=regional + "/versions/2")]}, url: policy},
                        secrets={"global": SECRET, "regional": regional})
    edges, _ = drain(subject.secret_access())
    assert edges and all(regional in edge["target_id"] for edge in edges)
    policies = subject.secret_policy(regional)
    assert policies and policies[0]["target_id"] == regional
    assert policies[0]["effective_access"] == "not_evaluated"


def test_service_account_role_is_a_candidate_not_effective_access_or_key_use():
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getIamPolicy"
    roles = collector({url: {"bindings": [{"role": "roles/owner", "members": [f"serviceAccount:{EMAIL}"],
                                          "condition": {"expression": "private-condition"}}]}}).service_account_roles()
    assert len(roles) == 2 and {r["source_id"] for r in roles} == {KEY_NAME, KEY_NAME.rsplit("/keys/", 1)[0]}
    assert all(r["effective_access"] == "not_evaluated" and r["condition_present"] for r in roles)
    assert all(r["evidence_class"] == "unconfirmed" and r["condition_evaluation"] == "not_evaluated" for r in roles)
    assert "private-condition" not in json.dumps(roles)


def test_policy_uncertainty_survives_normalization_and_native_export():
    from cremore_gcp_provider.metadata.normalization import record_values
    from cremore_gcp_provider.metadata.snapshot import native_snapshots

    from .test_adapter import with_evidence

    connection = spec(capabilities=["inventory", "vault_metadata", "relations"],
                      options={"locations": ["europe-west4"], "audit_lookback_days": 1})
    data = with_evidence()
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getIamPolicy"
    data[url] = {"bindings": [
        {"role": "roles/secretmanager.secretAccessor", "members": [f"serviceAccount:{EMAIL}"]},
        {"role": "roles/secretmanager.secretAccessor", "members": ["group:team@example.test"],
         "condition": {"expression": "private-condition-value"}},
    ]}
    transport, records, _ = run(connection, data)
    policies = [row for row in records if row["record_type"] == "relation"
                and record_values(row).get("evidence_source") == "iam_allow_policy"]
    assert len(policies) == 4 and all(row["confidence"] == "CANDIDATE" for row in policies)
    native = native_snapshots(records)["relations"]["relations"]
    native = [row for row in native if row["evidence_source"] == "iam_allow_policy"]
    assert len(native) == 4  # Both direct and group bindings reach each of the two listed secrets.
    for rows in ([record_values(row) for row in policies], native):
        for row in rows:
            assert row["inherited_policies"] == row["deny_policies"] == "not_evaluated"
            assert row["principal_access_boundaries"] == row["effective_access"] == "not_evaluated"
        group = next(row for row in rows if row["source_id"].startswith("iam_member:group:"))
        assert group["evidence_class"] == "unconfirmed"
        assert group["membership_resolution"] == group["condition_evaluation"] == "not_evaluated"
    assert "private-condition-value" not in json.dumps(records)
    assert not any("troubleshoot" in url or "groups" in url for _, url, _ in transport.calls)


@pytest.mark.parametrize("sql", [False, True])
@pytest.mark.parametrize("numeric_account", [False, True])
def test_inventory_only_audit_reaches_creator_and_last_use_without_secret_storage(sql, numeric_account):
    engine = make_engine("sqlite:///:memory:") if sql else None
    if engine:
        create_all(engine)
    repo = SqlRepository(engine) if engine else InMemoryRepository()
    try:
        connection = spec(capabilities=["inventory", "relations"], options={"sources": ["audit_logs"]})
        data = inventory_responses()
        # The shared fixture includes deliberately malformed inventory entries.
        for response in data.values():
            if "accounts" in response:
                response["accounts"] = [row for row in response["accounts"] if row.get("email") == EMAIL]
            if "keys" in response:
                response["keys"] = [row for row in response["keys"] if row.get("name", "").startswith("projects/")]
        used = entry(resource=f"projects/{PROJECT}/buckets/example", method="storage.objects.get",
                     service="storage.googleapis.com", insert="used-1")
        data[LOGS] = {"entries": [used, creation()]}
        if numeric_account:
            account_id = "100000000000000000001"
            for response in data.values():
                for account in response.get("accounts", []):
                    account["uniqueId"] = account_id
                for key in response.get("keys", []):
                    key["name"] = key["name"].replace(EMAIL, account_id)
            used["protoPayload"]["authenticationInfo"]["serviceAccountKeyName"] = (
                "//iam.googleapis.com/" + KEY_NAME.replace(EMAIL, account_id))
            data[LOGS]["entries"][1]["protoPayload"]["response"]["name"] = KEY_NAME.replace(EMAIL, account_id)
        transport, records, final = run(connection, data)
        assert final.status == "COMPLETE", final.reasons
        assert not any(url.startswith("https://secretmanager") for _, url, _ in transport.calls)
        assert not any("monitoring.googleapis.com" in url for _, url, _ in transport.calls)
        assert "never-persist" not in json.dumps(records)
        if numeric_account:
            assert _derived(records)["account_ids"][EMAIL] == account_id
        without_audit = connection.model_copy(update={"capabilities": ["inventory"],
            "options": connection.options.model_copy(update={"sources": []})})
        audit_records = MetadataBatch(index=0, items=[row for row in records
            if "cloud_logging" in row["provenance"]["operation"]]).items
        assert audit_records and all(not validate_record(without_audit, row) for row in audit_records)
        store = MetadataStore(repo)
        owner, _ = store.create(connection, "test")
        started = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(connection).model_dump())
        store.append(owner["id"], started["id"], MetadataBatch(index=0, items=records), trusted_discovery=True)
        store.finish(owner["id"], started["id"], MetadataFinish(batch_count=1, item_count=len(records), status="COMPLETE"))
        _, orch = stack(repo)
        row = next(r for r in build(repo, orch)["items"] if r["issued"]["object_id"].endswith(KEY_ID))
        assert row["issuer"]["name"] == EMAIL
        assert row["issued"]["creator_name"] == "gcp_principal:user:creator@example.test"
        assert row["last_used"] == {"at": "2026-09-21T11:00:00+00:00", "basis": "AUDIT_OBSERVED"}
    finally:
        if engine:
            engine.dispose()
