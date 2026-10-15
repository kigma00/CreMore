"""Public DER correspondence through provider collection and both stores."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cremore_azure_provider.entra.entra_test import Graph
from cremore_azure_provider.entra.entra_test import collect as collect_graph
from cremore_azure_provider.metadata.azure_key_vault_test import ORIGIN, Vault
from cremore_azure_provider.metadata.azure_key_vault_test import collect as collect_vault
from cremore_azure_provider.public_certificates import certificate_evidence
from cremore_azure_provider.public_certificates_test import (
    certificate as certificate_fixture,
)
from cremore_azure_provider.public_certificates_test import (
    graph_responses,
    graph_spec,
    keyvault_spec,
    vault_responses,
)

from cremore.coverage import certificate_coverage
from cremore.coverage.correlation import report, scope_revision
from cremore.coverage.coverage_test import repo as repo  # noqa: PLC0414
from cremore.coverage.issuer_coverage import issuance_rows
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import Contract
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414

CONTRACT = Contract(engine_digest="a" * 64).model_dump()


@pytest.fixture
def certificate():
    return certificate_fixture.__wrapped__()


def save(store, spec, pages, *, owner=None, status="COMPLETE"):
    if owner is None:
        owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    items = [item for page in pages for item in page.records]
    if items:
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items))
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=int(bool(items)), item_count=len(items), status=status))
    return owner


def pair(repo, certificate, *, vault_certificate=None, vault_config=None, graph_config=None):
    store = MetadataStore(repo)
    graph_config, vault_config = graph_config or graph_spec(), vault_config or keyvault_spec()
    graph_data = graph_responses(certificate[0])
    graph_data["/v1.0/applications"]["value"][0]["passwordCredentials"] = []
    issuer = save(store, graph_config, collect_graph(graph_config, Graph(graph_data)))
    vault = save(store, vault_config, collect_vault(vault_config, Vault(vault_responses((vault_certificate or certificate)[0]))))
    return store, issuer, vault


def certificate_rows(repo, **kwargs):
    result = report(repo, CONTRACT, **kwargs)
    return result, [row for row in result["items"] if row["credential_type"] == "AZURE_CERTIFICATE"]


def test_public_certificate_match_is_neither_a_secret_match_nor_an_exposure(repo, certificate):
    store, _, _ = pair(repo, certificate)
    result, rows = certificate_rows(repo)
    [row] = rows
    assert row["state"] == "PUBLIC_CERTIFICATE_MATCH"
    assert row["match_basis"] == "PUBLIC_CERTIFICATE_SHA256"
    assert row["issued"]["provider"] == "azure_entra" and row["issued"]["current_evidence"]
    assert len(row["locations"]) == 1 and row["locations"][0]["version"] == "a1"
    assert row["locations"][0]["provider"] == "azure_key_vault" and row["locations"][0]["current_evidence"]
    assert not row["exposed"] and not repo.list_findings()
    assert "PRIVATE_KEY_STORAGE_NOT_PROVEN" in row["reasons"]
    assert result["summary"]["matched"] == result["summary"]["exposed"] == result["summary"]["vault_only"] == 0
    assert result["summary"]["matched_percent"] is None
    assert result["summary"]["issuance_only"] == 1
    wire = json.dumps(result, default=str)
    assert certificate[0] not in wire and certificate[1] not in wire and "value_match" not in wire
    assert len(store.inventory(provider="azure_entra", object_kind="public_key")["items"]) == 1


def test_same_reported_thumbprint_with_different_der_cannot_match(repo, certificate):
    other = certificate_fixture.__wrapped__()
    pair(repo, certificate, vault_certificate=other)
    _, [row] = certificate_rows(repo)
    assert row["state"] == "UNKNOWN" and row["match_basis"] == "NONE"
    assert not row["locations"] and not row["history"]
    assert "NO_PUBLIC_CERTIFICATE_MATCH_OBSERVED" in row["reasons"]


def test_current_vault_certificate_does_not_promote_matching_old_version(repo, certificate):
    store = MetadataStore(repo)
    graph_data = graph_responses(certificate[0])
    graph_data["/v1.0/applications"]["value"][0]["passwordCredentials"] = []
    save(store, graph_spec(), collect_graph(graph_spec(), Graph(graph_data)))
    old = vault_responses(certificate[0])
    old["/certificates/signing"]["id"] = ORIGIN + "/certificates/signing/a2"
    old["/certificates/signing"]["cer"] = certificate_fixture.__wrapped__()[0]
    save(store, keyvault_spec(), collect_vault(keyvault_spec(), Vault(old)))
    _, [row] = certificate_rows(repo)
    assert row["state"] == "UNKNOWN" and row["match_basis"] == "PUBLIC_CERTIFICATE_SHA256"
    assert not row["locations"] and len(row["history"]) == 1
    assert row["history"][0]["version"] == "a1" and not row["history"][0]["current_evidence"]


@pytest.mark.parametrize("condition", ["disabled", "revision", "stale", "empty_later", "failed_later", "running_later"])
def test_noncurrent_vault_certificate_is_history_and_never_no_match(repo, certificate, condition):
    store, _, vault = pair(repo, certificate)
    now = datetime.now(UTC)
    if condition == "disabled":
        store.change(vault["id"], 1, "synthetic", enabled=False)
    elif condition == "revision":
        store.change(vault["id"], 1, "synthetic", rotate=True)
    elif condition == "stale":
        now += timedelta(hours=25)
    elif condition == "running_later":
        store.start(vault["id"], 1, str(uuid.uuid4()), metadata_contract(keyvault_spec()).model_dump())
    else:
        save(store, keyvault_spec(), [], owner=vault, status="FAILED" if condition == "failed_later" else "COMPLETE")
    _, [row] = certificate_rows(repo, now=now)
    assert row["state"] == "UNKNOWN" and not row["locations"] and len(row["history"]) == 1
    assert not row["history"][0]["current_evidence"]


def test_issuer_currentness_is_separate_from_retained_public_certificate_equality(repo, certificate):
    store, issuer, _ = pair(repo, certificate)
    store.change(issuer["id"], 1, "synthetic", enabled=False)
    _, [row] = certificate_rows(repo)
    assert row["state"] == "PUBLIC_CERTIFICATE_MATCH" and not row["issued"]["current_evidence"]
    assert "ISSUER_OBSERVATION_NOT_CURRENT" in row["reasons"]
    assert "AUTHENTICATION_NOT_CHECKED" in row["reasons"]


@pytest.mark.parametrize("side", ["issuer", "vault"])
def test_later_public_read_denied_retains_prior_evidence_as_history(repo, certificate, side):
    from cremore_azure_provider.entra.entra_test import APP
    from cremore_azure_provider.metadata.transport import ApiError

    store, issuer, vault = pair(repo, certificate)
    if side == "issuer":
        responses = graph_responses(certificate[0])
        responses[f"/v1.0/applications/{APP}"] = ApiError("permission_denied")
        save(store, graph_spec(), collect_graph(graph_spec(), Graph(responses)), owner=issuer, status="PARTIAL")
    else:
        responses = vault_responses(certificate[0])
        responses["/certificates/signing"] = responses["/certificates/signing/a1"] = ApiError("permission_denied")
        save(store, keyvault_spec(), collect_vault(keyvault_spec(), Vault(responses)), owner=vault, status="PARTIAL")
    _, [row] = certificate_rows(repo)
    assert row["match_basis"] == "PUBLIC_CERTIFICATE_SHA256"
    if side == "issuer":
        assert not row["issued"]["current_evidence"]
        assert "ISSUER_OBSERVATION_NOT_CURRENT" in row["reasons"]
    else:
        assert row["state"] == "UNKNOWN" and not row["locations"]
        assert len(row["history"]) == 1 and not row["history"][0]["current_evidence"]


def test_metadata_only_collections_do_not_change_value_scope_or_add_certificate_rows(repo, certificate):
    store = MetadataStore(repo)
    before = report(repo, CONTRACT)
    revision = scope_revision(store.list_connections())
    config = keyvault_spec(sources=["certificates", "certificate_versions"])
    save(store, config, collect_vault(config, Vault(vault_responses(certificate[0]))))
    config = graph_spec(sources=["applications"])
    data = graph_responses(certificate[0])
    data["/v1.0/applications"]["value"][0]["passwordCredentials"] = []
    save(store, config, collect_graph(config, Graph(data)))
    after = report(repo, CONTRACT)
    assert not after["items"]
    assert after["scope_reasons"] == before["scope_reasons"]
    assert after["summary"] == before["summary"]
    assert scope_revision(store.list_connections()) == revision
    assert issuance_rows(repo, CONTRACT, [], [], set(), key_id=None, now=datetime.now(UTC),
                         exposed_values=set(), exposed_digests=set(), exposed_identifiers=set(), limit=0) == ([], False)


@pytest.mark.parametrize("budget,expected_rows,truncated", [(0, 0, True), (1, 1, True), (2, 1, False), (3, 1, False)])
def test_certificate_projection_shares_record_budget_and_reports_truncation(repo, certificate, monkeypatch, budget, expected_rows, truncated):
    pair(repo, certificate)
    original = MetadataStore.inventory
    seen = []
    def bounded(self, **kwargs):
        result = original(self, **kwargs)
        seen.extend(result["items"])
        return result
    monkeypatch.setattr(MetadataStore, "inventory", bounded)
    rows, limited = issuance_rows(repo, CONTRACT, [], [], set(), key_id=None, now=datetime.now(UTC),
                                  exposed_values=set(), exposed_digests=set(), exposed_identifiers=set(), limit=budget)
    assert len(rows) == expected_rows and limited is truncated
    assert len(seen) <= budget
    assert all(row["state"] != "NO_VAULT_MATCH" for row in rows)


def test_partial_positive_reads_keep_public_evidence_without_proving_absence(repo, certificate):
    store, _, vault = pair(repo, certificate)
    pages = collect_vault(keyvault_spec(), Vault(vault_responses(certificate[0])))
    assert any(certificate_evidence(item) for page in pages for item in page.records)
    save(store, keyvault_spec(), pages, owner=vault, status="PARTIAL")
    _, [row] = certificate_rows(repo)
    assert row["state"] == "PUBLIC_CERTIFICATE_MATCH"
    assert row["locations"][0]["current_evidence"]


def test_query_and_match_link_limits_are_visible_not_absence(repo, certificate, monkeypatch):
    pair(repo, certificate)
    monkeypatch.setattr(certificate_coverage, "MAX_CERTIFICATE_QUERIES", 1)
    result, [row] = certificate_rows(repo)
    assert row["state"] == "UNKNOWN" and "REPORT_LIMIT_REACHED" in result["scope_reasons"]
    monkeypatch.setattr(certificate_coverage, "MAX_CERTIFICATE_QUERIES", 100)
    monkeypatch.setattr(certificate_coverage, "MAX_CERTIFICATE_LINKS", 0)
    result, [row] = certificate_rows(repo)
    assert row["state"] == "PUBLIC_CERTIFICATE_MATCH" and not row["locations"]
    assert "PUBLIC_CERTIFICATE_MATCHES_TRUNCATED" in row["reasons"]
    assert "REPORT_LIMIT_REACHED" in result["scope_reasons"]


@pytest.mark.parametrize("budget,expected", [(1, 1), (2, 2), (3, 2)])
def test_ordinary_issued_credentials_and_certificates_share_one_budget(repo, certificate, budget, expected):
    store = MetadataStore(repo)
    # Keep the synthetic application's ordinary password metadata as well.
    save(store, graph_spec(), collect_graph(graph_spec(), Graph(graph_responses(certificate[0]))))
    save(store, keyvault_spec(), collect_vault(keyvault_spec(), Vault(vault_responses(certificate[0]))))
    rows, truncated = issuance_rows(repo, CONTRACT, [], [], set(), key_id=None, now=datetime.now(UTC),
                                   exposed_values=set(), exposed_digests=set(), exposed_identifiers=set(), limit=budget)
    assert len(rows) == expected and truncated is (budget < 3)
    assert rows[0]["credential_type"] == "ISSUED_CREDENTIAL"
    assert all(row["state"] != "MATCHED" for row in rows)


def confirm_scope(repo):
    from cremore.coverage.store import CoverageStore
    repo.put_setting("coverage_scope", {"confirmed": True,
                     "revision": scope_revision(CoverageStore(repo).list_connections())}, "synthetic")


def test_confirmed_complete_vault_certificates_without_this_one_report_it_not_observed(repo, certificate):
    pair(repo, certificate, vault_certificate=certificate_fixture.__wrapped__())
    confirm_scope(repo)
    result, [row] = certificate_rows(repo)
    assert row["state"] == "PUBLIC_CERTIFICATE_NOT_OBSERVED" and not row["locations"] and not row["history"]
    assert {"PRIVATE_KEY_STORAGE_NOT_PROVEN", "NO_PUBLIC_CERTIFICATE_MATCH_OBSERVED"} <= set(row["reasons"])
    assert result["summary"]["issued_not_in_vault"] == 1


@pytest.mark.parametrize("condition", ["unconfirmed", "partial_vault", "stale_vault"])
def test_certificate_absence_needs_confirmed_complete_current_vault_reads(repo, certificate, condition):
    store, _, vault = pair(repo, certificate, vault_certificate=certificate_fixture.__wrapped__())
    now = datetime.now(UTC)
    if condition != "unconfirmed":
        confirm_scope(repo)
    if condition == "partial_vault":
        save(store, keyvault_spec(), [], owner=vault, status="PARTIAL")
    elif condition == "stale_vault":
        now += timedelta(hours=25)
    _, [row] = certificate_rows(repo, now=now)
    assert row["state"] == "UNKNOWN"
