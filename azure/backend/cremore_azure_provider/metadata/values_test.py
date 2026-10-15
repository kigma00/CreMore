"""An approved vault value becomes a keyed fingerprint, never stored bytes."""

import hashlib
from copy import deepcopy

import httpx
import pytest

from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import in_metadata_scope
from cremore.coverage.models import digest
from cremore.detection.engine import Engine, EngineConfig
from cremore_azure_provider.metadata import adapter, transport
from cremore_azure_provider.metadata.azure_key_vault_test import (
    ORIGIN,
    Vault,
    facts,
    records,
    secret,
    spec,
)

VALUE = "ghp_" "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture
def context():
    engine = Engine(EngineConfig(fingerprint_key=b"synthetic-vault-fingerprint-key-32bytes"))
    return {"engine": engine, "key_id": hashlib.sha256(engine.config.fingerprint_key).hexdigest(),
            "engine_digest": engine.detection_digest, "policy_digest": digest(["synthetic-policy"])}


def configured(*, versions=False, **changes):
    return spec(capabilities=["vault_metadata", "vault_value"],
                options={"include_values": True, "sources": ["secrets", "versions"] if versions else ["secrets"]},
                **changes)


class ValueVault(Vault):
    def get(self, path, params=None):
        return deepcopy(super().get(path, params))


def collect(connection, vault, holder, **kwargs):
    return list(adapter.collect_pages(connection, secrets={}, checkpoint=kwargs.pop("checkpoint", None),
                                      check=lambda: None, transport=vault, value_context=holder, **kwargs))


def test_value_matches_same_engine_fingerprint_without_storing_plaintext(context):
    def forbid_raw_storage(*args):
        raise AssertionError("Azure must not invoke the GCP raw-value capture hook")
    context["capture_value"] = forbid_raw_storage
    vault = ValueVault({"/secrets": {"value": [secret()]},
                        "/secrets/db-password": {**secret(version="a1"), "value": VALUE}})
    pages = collect(configured(), vault, context)
    assert pages[-1].status == "COMPLETE"
    matches = [r for r in records(pages) if getattr(r, "value_match", None)]
    assert len(matches) == 1 and matches[0].value_match.evidence == "VALUE"
    expected = hash_value(context["engine"], VALUE.encode(), {"reference": "synthetic"}, max_bytes=1024)[0]
    match = matches[0].value_match
    assert match.fingerprint == expected.fingerprint and match.version == "a1"
    assert match.reference == ORIGIN + "/secrets/db-password/a1" and match.version_state == "CURRENT"
    assert adapter.validate_machine_record(configured(), matches[0])
    assert in_metadata_scope(configured(), matches[0])
    assert VALUE not in "".join(page.model_dump_json() for page in pages)
    access = next(r for r in records(pages) if r.record_type == "operation_report"
                  and r.provenance.operation == "azure.key_vault.value_access")
    assert access.value_access == "COMPLETE" and access.value_contract.key_id == context["key_id"]


def test_default_metadata_collection_never_reads_values_even_with_context(context):
    vault = ValueVault({"/secrets": {"value": [secret()]}})
    pages = collect(spec(), vault, context)
    assert pages[-1].status == "COMPLETE"
    assert [path for path, _ in vault.calls] == ["/secrets"]
    assert all(not getattr(row, "value_match", None) for row in records(pages))


def test_versions_are_explicit_and_not_assumed_current(context):
    vault = ValueVault({"/secrets": {"value": [secret()]},
                        "/secrets/db-password/versions": {"value": [secret(version="a0")]},
                        "/secrets/db-password": {**secret(version="a1"), "value": VALUE},
                        "/secrets/db-password/a0": {**secret(version="a0"), "value": VALUE}})
    pages = collect(configured(versions=True), vault, context)
    matches = [r.value_match for r in records(pages) if getattr(r, "value_match", None)]
    assert {(r.version, r.version_state) for r in matches} == {("a1", "CURRENT"), ("a0", "UNKNOWN")}


@pytest.mark.parametrize("payload,reason", [
    (transport.ApiError("permission_denied"), "PERMISSION_DENIED"),
    ({"id": "https://other.vault.azure.net/secrets/db-password/a1", "value": VALUE}, "INVALID_IDENTIFIER"),
    ({"id": ORIGIN + "/secrets/db-password/a1"}, "INVALID_VALUE_RESPONSE"),
    ({"id": ORIGIN + "/secrets/db-password/a1", "value": "unknown plaintext"}, "UNRECOGNIZED_MATERIAL"),
])
def test_unread_or_unrecognized_values_block_absence_claims(context, payload, reason):
    pages = collect(configured(), ValueVault({"/secrets": {"value": [secret()]},
                                             "/secrets/db-password": payload}), context)
    assert pages[-1].status == "PARTIAL" and reason in pages[-1].reasons
    access = next(r for r in records(pages) if r.record_type == "operation_report"
                  and r.provenance.operation == "azure.key_vault.value_access")
    assert access.value_access == "PARTIAL"


def _access_entity(pages):
    return next(r for r in records(pages) if r.record_type == "entity_observation"
                and r.provenance.operation == "azure.key_vault.value_access")


def test_failed_value_read_keeps_the_listed_state_and_dates(context):
    pages = collect(configured(), ValueVault({"/secrets": {"value": [secret(exp=4102444800)]},
                                             "/secrets/db-password": transport.ApiError("permission_denied")}),
                    context)
    listed = next(r for r in records(pages) if r.record_type == "entity_observation"
                  and r.provenance.operation == "azure.key_vault.secrets")
    failed = _access_entity(pages)
    # The newest record becomes the entity summary; it must not erase what the listing said.
    assert failed.identity == listed.identity and failed.value_match.evidence == "UNRESOLVED"
    assert (failed.normalized_state, failed.provider_state) == ("ACTIVE", "enabled")
    assert facts(failed) == facts(listed) and facts(failed)["expires_at"]


def test_disabled_secret_is_not_requested_and_not_reported_as_a_permission_denial(context):
    vault = ValueVault({"/secrets": {"value": [secret(enabled=False)]},
                        "/secrets/db-password": transport.ApiError("permission_denied")})
    pages = collect(configured(), vault, context)
    assert [path for path, _ in vault.calls] == ["/secrets"]
    assert pages[-1].status == "PARTIAL" and "SECRET_DISABLED" in pages[-1].reasons
    assert "PERMISSION_DENIED" not in pages[-1].reasons
    failed = _access_entity(pages)
    assert failed.normalized_state == "DISABLED" and failed.value_match.reason == "SECRET_DISABLED"


def test_native_export_lists_only_live_secrets_once(context):
    connection = spec(capabilities=["vault_metadata", "vault_value"],
                      options={"include_values": True, "sources": ["secrets", "deleted_secrets"]})
    pages = collect(connection, ValueVault({
        "/secrets": {"value": [secret()]},
        "/deletedsecrets": {"value": [{**secret("retired"), "deletedDate": 1700000000}]},
        "/secrets/db-password": transport.ApiError("permission_denied")}), context)
    [snapshot] = adapter.native_snapshots([r.model_dump() for r in records(pages)])
    assert snapshot["secret_count"] == 1
    assert [(row["name"], row["created_at"] is not None) for row in snapshot["secrets"]] == [("db-password", True)]


def test_partial_listing_never_becomes_complete_value_coverage(context):
    pages = collect(configured(), ValueVault({"/secrets": {"value": [
        secret(), {"id": "https://other.vault.azure.net/secrets/foreign"}]},
        "/secrets/db-password": {**secret(version="a1"), "value": VALUE}}), context)
    assert pages[-1].status == "PARTIAL"
    access = next(r for r in records(pages) if r.record_type == "operation_report"
                  and r.provenance.operation == "azure.key_vault.value_access")
    assert access.value_access == "PARTIAL" and "METADATA_DISCOVERY_INCOMPLETE" in access.reasons


def test_value_phase_resume_uses_committed_metadata_and_never_rereads_completed_value(context):
    connection = configured()
    vault = ValueVault({"/secrets": {"value": [secret("first"), secret("second")]},
                        "/secrets/first": {**secret("first", version="a1"), "value": VALUE},
                        "/secrets/second": {**secret("second", version="b1"), "value": VALUE}})
    first = []
    for page in adapter.collect_pages(connection, secrets={}, checkpoint=None, check=lambda: None,
                                      transport=vault, value_context=context):
        first.append(page)
        if page.checkpoint.get("cursor", {}).get("index") == 1:
            break
    resumed = ValueVault({"/secrets/second": {**secret("second", version="b1"), "value": VALUE}})
    pages = collect(connection, resumed, context, checkpoint=first[-1].checkpoint,
                    read_records=lambda: [r.model_dump() for r in records(first)])
    assert pages[-1].status == "COMPLETE"
    assert [path for path, _ in resumed.calls] == ["/secrets/second"]


def test_missing_or_incompatible_value_context_is_refused_before_network(context):
    vault = ValueVault({})
    for holder in (None, {}, {**context, "key_id": "0" * 64}, {**context, "engine_digest": "0" * 64}):
        with pytest.raises(ValueError):
            collect(configured(), vault, holder)
    assert vault.calls == []


def test_value_transport_requires_explicit_opt_in_and_enforces_request_limit():
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={**secret(version="a1"), "value": VALUE})
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        wire = transport.Transport(client, lambda: "synthetic", origin=ORIGIN, options=spec().options,
                                   max_requests=1, api_version="2025-07-01", include_values=True)
        assert wire.get("/secrets/db-password")["value"] == VALUE
        with pytest.raises(transport.Budget):
            wire.get("/secrets/db-password/a1")
    assert len(requests) == 1 and requests[0].method == "GET"


def test_next_link_cannot_switch_to_another_approved_vault():
    with pytest.raises(transport.ApiError):
        transport.skip_token("https://other.vault.azure.net/secrets?$skiptoken=next",
                             origin=ORIGIN, path="/secrets")
    with pytest.raises(transport.ApiError):
        transport.skip_token(ORIGIN + ":invalid/secrets?$skiptoken=next", origin=ORIGIN, path="/secrets")


def test_page_size_respects_key_vault_maximum_of_25():
    vault = ValueVault({"/secrets": {"value": []}})
    collect(spec(), vault, None)
    assert vault.calls[0][1]["maxresults"] == 25


def test_value_rate_limit_resumes_same_unread_target(context):
    pages = collect(configured(), ValueVault({"/secrets": {"value": [secret()]},
        "/secrets/db-password": transport.ApiError("rate_limited", retry_after=10)}), context)
    assert pages[-1].status == "WAITING"
    resumed = ValueVault({"/secrets/db-password": {**secret(version="a1"), "value": VALUE}})
    again = collect(configured(), resumed, context, checkpoint=pages[-1].checkpoint,
                    read_records=lambda: [r.model_dump() for r in records(pages)])
    assert again[-1].status == "COMPLETE"
    assert [path for path, _ in resumed.calls] == ["/secrets/db-password"]


def test_metadata_response_version_cannot_be_assumed_current(context):
    pages = collect(configured(), ValueVault({"/secrets": {"value": [secret(version="a1")]}}), context)
    assert pages[-1].status == "PARTIAL"
    assert not any(getattr(r, "value_match", None) for r in records(pages))


def test_record_identity_must_match_its_resource(context):
    pages = collect(spec(), ValueVault({"/secrets": {"value": [secret()]}}), context)
    row = next(r for r in records(pages) if r.record_type == "entity_observation")
    row.provenance.resource_id = ORIGIN + "/secrets/different"
    assert adapter.validate_machine_record(spec(), row) is False


@pytest.mark.parametrize("change", [{"requests": -1}, {"phase": "foreign"},
                                    {"cursor": {"phase": "secrets", "seen": 3}}])
def test_invalid_checkpoints_are_rejected_before_network(change):
    pages = collect(spec(), ValueVault({"/secrets": {"value": []}}), None)
    checkpoint = {**pages[0].checkpoint, **change}
    vault = ValueVault({})
    with pytest.raises(ValueError, match="CHECKPOINT"):
        collect(spec(), vault, None, checkpoint=checkpoint, read_records=list)
    assert vault.calls == []
