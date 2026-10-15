"""Current KV absence requires current KV scope, not version or lease metadata."""

import httpx
import pytest
from cremore_vault_provider.inventory_test import (
    collect,
    kv_handler,
    managed_handler,
    response,
    spec,
)

from cremore.coverage.correlation import is_vault_spec, report, scope_revision
from cremore.coverage.coverage_test import GH, contract, engine, save
from cremore.coverage.metadata_job_test import repo as repo  # noqa: PLC0414
from cremore.coverage.store import CoverageStore
from cremore.detection import ResourceRef
from cremore.scanning.orchestrator import Orchestrator


def exposure(repo):
    eng = engine()
    Orchestrator(repo, engine=eng, config=eng.config).scan_resource(
        GH.encode(), ResourceRef(source_type="inline", resource="synthetic"), verify=False)


def save_collection(store, config, handler):
    owner, _ = store.create(config, "test")
    result, _ = collect(config, handler)
    save(store, owner, result.items, status=result.status, reasons=result.reasons)
    return owner


def confirmed_report(repo):
    store = CoverageStore(repo)
    repo.put_setting("coverage_scope", {
        "confirmed": True, "revision": scope_revision(store.list_connections()),
    }, "test")
    result = report(repo, contract())
    row = next(item for item in result["items"] if item["origin"] == "EXPOSURE")
    return result, row


@pytest.mark.parametrize("provider", ["vault", "openbao"])
@pytest.mark.parametrize("empty", [False, True])
def test_fixed_kv_version_cannot_prove_current_value_absence(repo, provider, empty):
    exposure(repo)
    config = spec(provider=provider, version_selector="3")
    save_collection(CoverageStore(repo), config,
                    (lambda request: response({"keys": []})) if empty else kv_handler)
    result, row = confirmed_report(repo)
    assert row["state"] == "UNKNOWN"
    assert "CURRENT_VERSION_NOT_CONFIRMED" in row["reasons"]
    assert "CURRENT_VERSION_NOT_CONFIRMED" in result["scope_reasons"]
    assert not row["locations"]
    assert len(row["history"]) == int(not empty)
    if row["history"]:
        assert row["history"][0]["version"] == "3"
        assert row["history"][0]["current_evidence"] is False


@pytest.mark.parametrize("provider", ["vault", "openbao"])
def test_latest_kv_value_remains_current_match(repo, provider):
    exposure(repo)
    save_collection(CoverageStore(repo), spec(provider=provider), kv_handler)
    result, row = confirmed_report(repo)
    assert row["state"] == "MATCHED"
    assert row["locations"][0]["current_evidence"] is True
    assert result["scope_reasons"] == []


def lease_handler(denied):
    def handle(request):
        if denied and request.method == "POST":
            return httpx.Response(403, json={"errors": ["denied"]})
        return managed_handler(request)
    return handle


@pytest.mark.parametrize("provider", ["vault", "openbao"])
@pytest.mark.parametrize("denied", [False, True])
def test_lease_only_connection_is_not_value_coverage_but_management_remains(repo, provider, denied):
    exposure(repo)
    config = spec(provider=provider, mounts=[], lease_prefixes=["database/creds/app"])
    assert not is_vault_spec(config.model_dump())
    save_collection(CoverageStore(repo), config, lease_handler(denied))
    result, row = confirmed_report(repo)
    assert row["state"] == "UNKNOWN"
    assert "NO_VAULT_CONNECTED" in result["scope_reasons"]
    [managed] = [item for item in result["items"] if item["origin"] == "MANAGEMENT"]
    assert managed["state"] == ("UNKNOWN" if denied else "MANAGED")
    assert result["summary"]["managed"] == int(not denied)


def test_a_lease_id_is_shown_only_inside_the_admin_boundary(repo):
    exposure(repo)
    save_collection(CoverageStore(repo), spec(mounts=[], lease_prefixes=["database/creds/app"]), lease_handler(False))
    confirmed_report(repo)
    managed = [item for item in report(repo, contract())["items"] if item["origin"] == "MANAGEMENT"]
    hidden = [item for item in report(repo, contract(), management_references=False)["items"]
              if item["origin"] == "MANAGEMENT"]
    assert managed[0]["issued"]["reference"].startswith("database/creds/app")
    assert "reference" not in hidden[0]["issued"] and hidden[0]["state"] == managed[0]["state"]


@pytest.mark.parametrize("denied", [False, True])
def test_management_only_changes_do_not_affect_independent_current_kv_scope(repo, denied):
    exposure(repo)
    store = CoverageStore(repo)
    save_collection(store, spec(), lambda request: response({"keys": []}))
    before = scope_revision(store.list_connections())
    owner = save_collection(store, spec(mounts=[], lease_prefixes=["database/creds/app"]), lease_handler(denied))
    assert scope_revision(store.list_connections()) == before
    result, row = confirmed_report(repo)
    assert row["state"] == "NO_VAULT_MATCH"
    assert result["scope_reasons"] == []
    assert any(item["origin"] == "MANAGEMENT" for item in result["items"])
    store.change(owner["id"], owner["revision"], "test", enabled=False)
    assert scope_revision(store.list_connections()) == before


@pytest.mark.parametrize("provider", ["vault", "openbao"])
def test_token_accessor_and_lease_gaps_never_hold_back_a_complete_kv_absence(repo, provider):
    exposure(repo)
    store = CoverageStore(repo)

    def handler(request):
        if "/auth/token/" in request.url.path or "/sys/leases/" in request.url.path:
            # Listed, then every lookup refused: management gaps only.
            return managed_handler(request) if request.method == "LIST" else response({}, 403)
        return response({"keys": []})

    owner = save_collection(store, spec(provider=provider, include_token_accessors=True,
                                        lease_prefixes=["database/creds/app"]), handler)
    run = store.snapshots(owner["id"])[0]
    assert run["status"] == "COMPLETE" and run["completeness"] == "API_LISTING"
    assert {"BATCH_TOKEN_INVENTORY_UNSUPPORTED", "TOKEN_ACCESSOR_LOOKUP_FAILED", "LEASE_LOOKUP_FAILED"} <= set(run["reasons"])
    result, row = confirmed_report(repo)
    assert row["state"] == "NO_VAULT_MATCH" and row["absence_basis"] == "API_LISTING"
    assert result["scope_reasons"] == [] and result["absence_basis"] == "API_LISTING"
    managed = [item for item in result["items"] if item["origin"] == "MANAGEMENT"]
    assert len(managed) == 2 and all(item["state"] == "UNKNOWN" for item in managed)
    assert all("BATCH_TOKEN_INVENTORY_UNSUPPORTED" in item["reasons"] for item in managed)


def test_removing_kv_mounts_invalidates_existing_value_scope_declaration(repo):
    store = CoverageStore(repo)
    owner, _ = store.create(spec(lease_prefixes=["database/creds/app"]), "test")
    before = scope_revision(store.list_connections())
    store.change(owner["id"], owner["revision"], "test", spec=spec(mounts=[], lease_prefixes=["database/creds/app"]))
    assert scope_revision(store.list_connections()) != before


def test_disabled_vault_leaves_the_scope_only_after_the_admin_confirms_it_again(repo):
    exposure(repo)
    store = CoverageStore(repo)
    save_collection(store, spec(), lambda request: response({"keys": []}))
    retired = save_collection(store, spec(name="Retired"), kv_handler)
    _, row = confirmed_report(repo)
    assert row["state"] == "MATCHED"
    store.change(retired["id"], retired["revision"], "test", enabled=False)
    pending = report(repo, contract())
    assert "VAULT_SCOPE_NOT_CONFIRMED" in pending["scope_reasons"]
    assert next(item for item in pending["items"] if item["origin"] == "EXPOSURE")["state"] == "UNKNOWN"
    result, row = confirmed_report(repo)
    assert result["scope_reasons"] == [] and row["state"] == "NO_VAULT_MATCH"
    assert row["history"] and not row["locations"]  # the retired vault's match stays as history
