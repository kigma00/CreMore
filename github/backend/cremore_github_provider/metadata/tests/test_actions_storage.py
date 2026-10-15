"""Actions metadata uses read-only App scope and never publishes secret values."""

import json
from copy import deepcopy
from urllib.parse import quote

import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.actions import SECRET_SOURCES
from cremore_github_provider.metadata.descriptor import DESCRIPTOR
from cremore_github_provider.metadata.endpoints import EndpointError, validate_operation
from cremore_github_provider.metadata.normalization import record_values

from .fake import API, ORG, OTHER_ORG, REPO, FakeTransport, org_responses, repository, spec
from .test_adapter import drive

STAMP = "2026-09-25T00:00:00Z"
ENV = "Production / Seoul"


def secret(name="DEPLOY_TOKEN", **patch):
    return {"name": name, "created_at": STAMP, "updated_at": STAMP, **patch}


def connection(*sources, **patch):
    return spec(capabilities=["inventory", "vault_metadata"], options={"sources": list(sources)}, **patch)


def responses():
    return {
        f"/orgs/{ORG}/actions/secrets?per_page=100": {"total_count": 1, "secrets": [secret(visibility="private")]},
        "/installation/repositories?per_page=100": {"repositories": [repository()]},
        f"/repos/{ORG}/{REPO}/actions/secrets?per_page=100": {"total_count": 1, "secrets": [secret()]},
        f"/repos/{ORG}/{REPO}/environments?per_page=100": {"total_count": 1, "environments": [
            {"id": 700, "name": ENV, "created_at": STAMP, "updated_at": STAMP}]},
        f"/repos/{ORG}/{REPO}/environments/{quote(ENV, safe='')}/secrets?per_page=100": {
            "total_count": 1, "secrets": [secret()]},
    }


def test_explicit_sources_collect_all_three_storage_scopes_and_environment_names_are_encoded():
    spec = connection(*SECRET_SOURCES)
    transport, broker, records, _state, final = drive(spec, responses())
    assert final.status == "COMPLETE"
    assert len(transport.calls) == 5
    assert all(method == "GET" for method, _ in transport.calls)
    assert all(scope == "org" for scope, _ in broker.issued)
    rows = [row for row in records if row.get("identity", {}).get("kind") == "vault_item"]
    assert len(rows) == 3 and len({row["identity"]["object_id"] for row in rows}) == 3
    assert {record_values(row)["resource_type"] for row in rows} == {"organization", "repository", "environment"}
    assert all(row["purpose"] == "vault_metadata" and row["value_match"] is None for row in rows)
    assert all(adapter.validate_record(spec, RECORD_ADAPTER.validate_python(row)) for row in records)
    snapshot = adapter.native_snapshots(records)
    assert len(snapshot["organizations"][ORG]["records"]["actions_secrets"]) == 3


def test_defaults_keep_existing_authority_and_secret_sources_require_the_capability():
    _transport, _broker, records, _state, final = drive(spec(), org_responses())
    assert final.status == "COMPLETE"
    assert not any(row.get("identity", {}).get("kind") == "vault_item" for row in records)
    with pytest.raises(ValueError, match="VAULT_METADATA"):
        adapter.validate_spec(spec(options={"sources": ["org_actions_secrets"]}))
    assert set(SECRET_SOURCES) <= {item["value"] for item in DESCRIPTOR["source_options"]}


def test_selected_repository_links_are_derived_and_do_not_follow_provider_urls():
    scripted = responses()
    scripted[f"/orgs/{ORG}/actions/secrets?per_page=100"]["secrets"] = [secret(
        visibility="selected", selected_repositories_url="https://outside.example/steal",
        encrypted_value="should-never-persist", value="should-never-persist")]
    path = f"/orgs/{ORG}/actions/secrets/DEPLOY_TOKEN/repositories?per_page=100"
    scripted[path] = {"total_count": 1, "repositories": [repository()]}
    transport, _b, records, _s, final = drive(connection("org_actions_secrets"), scripted)
    assert final.status == "COMPLETE" and ("GET", path) in transport.calls
    assert "outside.example" not in json.dumps(records) and "should-never-persist" not in json.dumps(records)
    association = next(row for row in records if row.get("identity", {}).get("object_id", "").startswith(
        "actionsSecretRepository:"))
    assert record_values(association)["repository"]["full_name"] == f"{ORG}/{REPO}"
    assert len([row for row in records if row.get("identity", {}).get("kind") == "vault_item"]) == 1


def test_selected_repository_relations_are_access_grants_not_value_equality():
    scripted = responses()
    scripted[f"/orgs/{ORG}/actions/secrets?per_page=100"]["secrets"] = [secret(visibility="selected")]
    scripted[f"/orgs/{ORG}/actions/secrets/DEPLOY_TOKEN/repositories?per_page=100"] = {
        "total_count": 1, "repositories": [repository()]}
    spec = connection("org_actions_secrets")
    spec.capabilities.append("relations")
    _t, _b, records, _s, final = drive(spec, scripted)
    assert final.status == "COMPLETE"
    link = next(row for row in records if row["record_type"] == "relation")
    assert link["relation"] == "can_access" and link["match_basis"] == "PROVIDER_EXPLICIT"
    assert not any(row.get("relation") == "stored_in" for row in records)


def test_secret_pagination_resume_and_partial_failure_keep_prior_metadata():
    scripted = responses()
    path = f"/orgs/{ORG}/actions/secrets?per_page=100"
    second = path + "&page=2"
    scripted[path] = ({"total_count": 2, "secrets": [secret(visibility="all")]},
                      {"link": f'<{API}{second}>; rel="next"'})
    scripted[second] = {"total_count": 2, "secrets": [secret("NEXT_TOKEN", visibility="private")]}
    connection_spec = connection("org_actions_secrets")
    _t, _b, before, state, _f = drive(connection_spec, scripted, stop_after=2)
    transport, _b, complete, _s, final = drive(connection_spec, scripted, checkpoint=state, committed=before)
    assert transport.calls == [("GET", second)] and final.status == "COMPLETE"
    secrets = [row for row in complete if row.get("identity", {}).get("kind") == "vault_item"]
    assert len(secrets) == 2
    _t, _b, partial, _s, final = drive(connection_spec, scripted, checkpoint=state, committed=before,
                                     failures={second: "github_http_403"})
    assert final.status == "PARTIAL"
    assert len([row for row in partial if row.get("identity", {}).get("kind") == "vault_item"]) == 1
    assert any(row.get("status") == "FAILED" for row in partial)


@pytest.mark.parametrize("payload", [
    {"total_count": 4, "secrets": [secret(visibility="all")]},
    {"total_count": 1, "secrets": [secret(visibility="unknown")]},
    {"total_count": 1, "secrets": [secret(name="../outside", visibility="all")]},
    {"total_count": 1, "secrets": [secret(created_at="bad", visibility="all")]},
    {"total_count": True, "secrets": []}, {"secrets": []},
])
def test_incomplete_or_invalid_listings_never_become_complete(payload):
    scripted = {f"/orgs/{ORG}/actions/secrets?per_page=100": payload}
    _t, _b, records, _s, final = drive(connection("org_actions_secrets"), scripted)
    assert final.status == "PARTIAL"
    report = next(row for row in records if row["record_type"] == "operation_report"
                  and row["provenance"]["operation"] != "github.app")
    assert report["status"] in {"PARTIAL", "FAILED"} and not report["proves_completeness"]


def test_cross_origin_pagination_and_checkpoint_scope_tampering_send_no_off_scope_request():
    spec = connection("org_actions_secrets")
    path = f"/orgs/{ORG}/actions/secrets?per_page=100"
    payload = {"total_count": 2, "secrets": [secret(visibility="all")]}
    scripted = {path: (payload, {"link": f'<{API}{path}&page=2>; rel="next"'})}
    _t, _b, records, checkpoint, _f = drive(spec, scripted, stop_after=2)
    forged = deepcopy(checkpoint)
    current = next(item for item in forged["tasks"].values() if item["kind"] != "app")
    current["next_path"] = current["next_path"].replace(ORG, OTHER_ORG)
    transport, _b, _r, _s, final = drive(spec, {}, checkpoint=forged, committed=records)
    assert not transport.calls and final.status == "PARTIAL"
    scripted[path] = (payload, {"link": f'<https://outside.example{path}&page=2>; rel="next"'})
    _t, _b, records, _s, final = drive(spec, scripted)
    assert final.status == "PARTIAL" and "UNSAFE_PAGINATION_LINK" in final.reasons


@pytest.mark.parametrize("method,path", [
    ("POST", f"/orgs/{ORG}/actions/secrets/NAME"),
    ("GET", f"/orgs/{ORG}/actions/secrets/NAME"),
    ("PUT", f"/repos/{ORG}/{REPO}/actions/secrets/NAME"),
    ("GET", f"/repos/{ORG}/{REPO}/environments/../secrets"),
])
def test_actions_read_surface_does_not_allow_values_or_mutation(method, path):
    with pytest.raises(EndpointError):
        validate_operation(method, path)


def test_page_budget_bounds_cycles_and_cursor_changes():
    spec = connection("org_actions_secrets", max_pages=3)
    first = f"/orgs/{ORG}/actions/secrets?per_page=100"
    second = first + "&page=2"
    third = first + "&page=3"
    scripted = {
        first: ({"total_count": 3, "secrets": [secret(visibility="all")]}, {"link": f'<{API}{second}>; rel="next"'}),
        second: ({"total_count": 3, "secrets": [secret("SECOND", visibility="all")]}, {"link": f'<{API}{third}>; rel="next"'}),
    }
    transport = FakeTransport(scripted)
    _t, _b, _r, _s, final = drive(spec, scripted, transport=transport)
    assert len(transport.calls) == 2 and final.status == "PARTIAL"
    assert "PAGE_BUDGET_EXCEEDED" in final.reasons
