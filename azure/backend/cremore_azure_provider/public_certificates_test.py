"""Synthetic public certificate collection, binding and evidence boundaries."""

import base64
import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cremore.coverage.providers.facts import unpack_facts
from cremore_azure_provider.entra import adapter as entra
from cremore_azure_provider.entra.entra_test import (
    APP,
    APP2,
    CLIENT,
    KEY,
    Graph,
    application,
    records,
)
from cremore_azure_provider.entra.entra_test import collect as entra_collect
from cremore_azure_provider.entra.entra_test import spec as entra_spec
from cremore_azure_provider.entra.transport import GraphTransport
from cremore_azure_provider.metadata import adapter as vault_adapter
from cremore_azure_provider.metadata.azure_key_vault_test import ORIGIN, Vault
from cremore_azure_provider.metadata.azure_key_vault_test import collect as vault_collect
from cremore_azure_provider.metadata.azure_key_vault_test import spec as vault_spec
from cremore_azure_provider.metadata.transport import ApiError, Transport
from cremore_azure_provider.public_certificates import (
    EVIDENCE_CLASS,
    certificate_evidence,
    certificate_sha256,
)


@pytest.fixture
def certificate():
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.invalid")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private_key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .sign(private_key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode(), hashlib.sha256(der).hexdigest()


def graph_spec(**changes):
    return entra_spec(capabilities=["inventory", "public_keys"],
                      options={"sources": ["applications", "service_principals", "public_certificates"], **changes})


def keyvault_spec(**changes):
    return vault_spec(capabilities=["vault_metadata", "public_keys"],
                      options={"sources": ["certificates", "certificate_versions", "public_certificates"], **changes})


def graph_responses(encoded, family="applications", parent=APP):
    row = application(parent)
    detail = {"id": parent, "appId": CLIENT, "keyCredentials": [
        {"keyId": KEY, "type": "AsymmetricX509Cert", "key": encoded}]}
    return {f"/v1.0/{family}": {"value": [row]}, f"/v1.0/{family}/{parent}": detail}


def vault_responses(encoded):
    base = ORIGIN + "/certificates/signing"
    return {"/certificates": {"value": [{"id": base}]},
            "/certificates/signing/versions": {"value": [{"id": base + "/a1"}]},
            "/certificates/signing": {"id": base + "/a1", "cer": encoded, "x5t": "custom-thumbprint",
                                       "sid": "https://unapproved.invalid/secrets/never-follow"},
            "/certificates/signing/a1": {"id": base + "/a1", "cer": encoded}}


@pytest.mark.parametrize("family,parent", [("applications", APP), ("servicePrincipals", APP2)])
def test_same_public_der_has_same_evidence_and_preserves_existing_metadata(certificate, family, parent):
    encoded, fingerprint = certificate
    graph = Graph(graph_responses(encoded, family, parent))
    graph_pages = entra_collect(graph_spec(), graph)
    vault = Vault(vault_responses(encoded))
    vault_pages = vault_collect(keyvault_spec(), vault)
    assert graph_pages[-1].status == vault_pages[-1].status == "COMPLETE"
    issued = [item for item in records(graph_pages) if certificate_evidence(item)]
    stored = [item for item in records(vault_pages) if certificate_evidence(item)]
    assert len(issued) == 1 and len(stored) == 2
    assert certificate_evidence(issued[0])["fingerprint"] == fingerprint
    assert certificate_evidence(issued[0])["evidence_class"] == EVIDENCE_CLASS
    assert all(certificate_evidence(item)["fingerprint"] == fingerprint for item in stored)
    assert all(certificate_evidence(item)["current_version"] for item in stored)
    facts = unpack_facts([f.model_dump() for f in issued[0].facts])
    assert facts["fingerprint"] == "616263" and facts["algorithm"] == "PROVIDER_CUSTOM_KEY_IDENTIFIER"
    assert all(item.value_match is None for item in [*issued, *stored])
    assert all(entra.validate_machine_record(graph_spec(), item) for item in issued)
    assert all(vault_adapter.validate_machine_record(keyvault_spec(), item) for item in stored)
    wire = "".join(page.model_dump_json() for page in [*graph_pages, *vault_pages])
    assert encoded not in wire and "unapproved.invalid" not in wire
    assert graph.calls[-1][1] == {"$select": "id,appId,keyCredentials"}
    assert not any("secrets" in path or "/keys/" in path for path, _ in vault.calls)


def test_default_listings_never_request_certificate_bundles(certificate):
    graph = Graph(graph_responses(certificate[0]))
    assert entra_collect(entra_spec(), graph)[-1].status == "COMPLETE"
    vault = Vault(vault_responses(certificate[0]))
    assert vault_collect(vault_spec(options={"sources": ["certificates"]}), vault)[-1].status == "COMPLETE"
    assert all(path != f"/v1.0/applications/{APP}" for path, _ in graph.calls)
    assert [path for path, _ in vault.calls] == ["/certificates"]


@pytest.mark.parametrize("bad", [None, "not-base64!", "", "YQ==", "A" * 90000],
                         ids=["missing", "bad-base64", "empty", "not-der", "oversized"])
def test_malformed_public_certificates_are_not_comparison_evidence(bad):
    with pytest.raises(ValueError, match="INVALID_PUBLIC_CERTIFICATE"):
        certificate_sha256(bad)


def test_concatenated_certificate_bytes_are_rejected(certificate):
    bad = base64.b64encode(base64.b64decode(certificate[0]) + b"trailing").decode()
    with pytest.raises(ValueError, match="INVALID_PUBLIC_CERTIFICATE"):
        certificate_sha256(bad)


@pytest.mark.parametrize("change", [{"id": APP2}, {"appId": APP2}, {"keyCredentials": []},
                                   {"keyCredentials": None}, {"@odata.nextLink": "https://other.invalid"}])
def test_graph_detail_cannot_bind_another_parent_or_missing_key(certificate, change):
    responses = graph_responses(certificate[0])
    responses[f"/v1.0/applications/{APP}"].update(change)
    pages = entra_collect(graph_spec(), Graph(responses))
    assert pages[-1].status == "PARTIAL"
    assert not any(certificate_evidence(item) for item in records(pages))


@pytest.mark.parametrize("returned", ["https://other.vault.azure.net/certificates/signing/a1",
                                      ORIGIN + "/certificates/other/a1", ORIGIN + "/certificates/signing"])
def test_keyvault_detail_must_be_a_version_of_the_requested_certificate(certificate, returned):
    responses = vault_responses(certificate[0])
    responses["/certificates/signing"]["id"] = returned
    responses["/certificates/signing/a1"]["id"] = returned
    pages = vault_collect(keyvault_spec(), Vault(responses))
    assert pages[-1].status == "PARTIAL"
    assert "INVALID_CERTIFICATE_IDENTIFIER" in pages[-1].reasons
    assert not any(certificate_evidence(item) for item in records(pages))


@pytest.mark.parametrize("provider", ["graph", "vault"])
def test_permission_failure_does_not_become_empty_complete_certificate_collection(certificate, provider):
    if provider == "graph":
        responses = graph_responses(certificate[0])
        responses[f"/v1.0/applications/{APP}"] = ApiError("permission_denied")
        pages = entra_collect(graph_spec(), Graph(responses))
    else:
        responses = vault_responses(certificate[0])
        responses["/certificates/signing"] = responses["/certificates/signing/a1"] = ApiError("permission_denied")
        pages = vault_collect(keyvault_spec(), Vault(responses))
    assert pages[-1].status == "PARTIAL"
    assert "PERMISSION_DENIED" in pages[-1].reasons
    assert not any(certificate_evidence(item) for item in records(pages))


def test_graph_resume_rebuilds_approved_targets_and_rechecks_tenant(certificate):
    responses = graph_responses(certificate[0])
    second = graph_responses(certificate[0], parent=APP2)
    responses["/v1.0/applications"]["value"].append(application(APP2))
    responses[f"/v1.0/applications/{APP2}"] = second[f"/v1.0/applications/{APP2}"]
    committed = []
    for page in entra.collect_pages(graph_spec(), secrets={}, checkpoint=None, check=lambda: None, transport=Graph(responses)):
        committed.append(page)
        if page.checkpoint.get("cursor", {}).get("index") == 1 and any(certificate_evidence(item) for item in page.records):
            break
    graph = Graph(responses)
    resumed = entra_collect(graph_spec(), graph, checkpoint=committed[-1].checkpoint,
                            read_records=lambda: [item.model_dump() for item in records(committed)])
    assert resumed[-1].status == "COMPLETE"
    assert [path for path, _ in graph.calls] == ["/v1.0/organization", f"/v1.0/applications/{APP2}"]


def test_keyvault_resume_keeps_current_version_evidence_without_repeating_read(certificate):
    responses = vault_responses(certificate[0])
    committed = []
    for page in vault_adapter.collect_pages(keyvault_spec(), secrets={}, checkpoint=None, check=lambda: None, transport=Vault(responses)):
        committed.append(page)
        if page.checkpoint["phase"] == "public_certificates" and page.checkpoint["cursor"].get("index") == 1:
            break
    vault = Vault(responses)
    resumed = vault_collect(keyvault_spec(), vault, checkpoint=committed[-1].checkpoint,
                            read_records=lambda: [item.model_dump() for item in records(committed)])
    assert resumed[-1].status == "COMPLETE"
    assert [path for path, _ in vault.calls] == ["/certificates/signing/a1"]
    assert all(certificate_evidence(item)["current_version"] for item in records(resumed) if certificate_evidence(item))


def test_reported_identifiers_and_other_operations_are_never_used_as_der_evidence(certificate):
    item = next(item for item in records(entra_collect(graph_spec(), Graph(graph_responses(certificate[0])))) if certificate_evidence(item))
    body = item.model_dump()
    for field, value in [("operation", "azure.entra.applications"), ("operation", "azure.key_vault.certificates")]:
        changed = deepcopy(body)
        changed["provenance"][field] = value
        assert certificate_evidence(changed) is None
    changed = deepcopy(body)
    changed["facts"].append(next(fact for fact in changed["facts"] if fact["name"] == "sha256_fingerprint"))
    assert certificate_evidence(changed) is None


@pytest.mark.parametrize("provider", ["graph", "vault"])
def test_public_certificate_source_requires_explicit_capability(provider):
    if provider == "graph":
        connection = entra_spec(options={"sources": ["applications", "public_certificates"]})
        validate = entra.validate_spec
    else:
        connection = vault_spec(options={"sources": ["certificates", "public_certificates"]})
        validate = vault_adapter.validate_spec
    with pytest.raises(ValueError, match="PUBLIC_CERTIFICATES_REQUIRE"):
        validate(connection)


def test_opt_in_transports_allow_only_public_certificate_read_surface():
    seen = []
    def wire(request):
        seen.append(request)
        return httpx.Response(200, json={})
    with httpx.Client(transport=httpx.MockTransport(wire)) as client:
        graph = GraphTransport(client, lambda: "synthetic", origin=graph_spec().origin,
                               options=graph_spec().options, max_requests=3, check=lambda: None)
        graph.get(f"/v1.0/applications/{APP}", {"$select": "id,appId,keyCredentials"})
        with pytest.raises(ValueError):
            graph.get(f"/v1.0/applications/{APP}", {"$select": "passwordCredentials"})
        vault = Transport(client, lambda: "synthetic", origin=ORIGIN, options=keyvault_spec().options,
                          max_requests=3, api_version="2025-07-01", include_public_certificates=True)
        vault.get("/certificates/signing/a1")
        for path in ("/secrets/signing/a1", "/keys/signing/a1", "/certificates/signing/pending/merge"):
            with pytest.raises(ValueError):
                vault.get(path)
    assert len(seen) == 2 and all(request.method == "GET" for request in seen)


@pytest.mark.parametrize("provider", ["graph", "vault"])
def test_certificate_page_and_target_limits_preserve_partial_status(certificate, provider):
    if provider == "graph":
        responses = graph_responses(certificate[0])
        responses["/v1.0/applications"]["value"].append(application(APP2))
        connection = graph_spec(max_targets=1)
        pages = entra_collect(connection, Graph(responses))
    else:
        connection = keyvault_spec(max_targets=1)
        pages = vault_collect(connection, Vault(vault_responses(certificate[0])))
    assert pages[-1].status == "PARTIAL" and "TARGET_LIMIT_REACHED" in pages[-1].reasons
    assert len([item for item in records(pages) if certificate_evidence(item)]) == 1


@pytest.mark.parametrize("provider", ["graph", "vault"])
def test_deferred_public_read_retries_same_target(certificate, provider):
    if provider == "graph":
        configured = graph_spec()
        responses = graph_responses(certificate[0])
        retry = deepcopy(responses)
        responses[f"/v1.0/applications/{APP}"] = ApiError("rate_limited", retry_after=1)
        first = entra_collect(configured, Graph(responses))
        resumed_wire = Graph(retry)
        collect = entra_collect
    else:
        configured = keyvault_spec()
        responses = vault_responses(certificate[0])
        retry = deepcopy(responses)
        responses["/certificates/signing"] = ApiError("rate_limited", retry_after=1)
        first = vault_collect(configured, Vault(responses))
        resumed_wire = Vault(retry)
        collect = vault_collect
    assert first[-1].status == "WAITING"
    resumed = collect(configured, resumed_wire, checkpoint=first[-1].checkpoint,
                      read_records=lambda: [item.model_dump() for item in records(first)])
    assert resumed[-1].status == "COMPLETE"
    assert any(certificate_evidence(item) for item in records(resumed))


def test_duplicate_graph_key_id_is_not_accepted_as_public_certificate_evidence(certificate):
    responses = graph_responses(certificate[0])
    detail = responses[f"/v1.0/applications/{APP}"]
    detail["keyCredentials"].append(deepcopy(detail["keyCredentials"][0]))
    pages = entra_collect(graph_spec(), Graph(responses))
    assert pages[-1].status == "PARTIAL" and "INVALID_CERTIFICATE_IDENTIFIERS" in pages[-1].reasons
    assert not any(certificate_evidence(item) for item in records(pages))


def test_old_certificate_version_is_not_promoted_by_a_different_current_certificate(certificate):
    responses = vault_responses(certificate[0])
    responses["/certificates/signing"]["id"] = ORIGIN + "/certificates/signing/a2"
    pages = vault_collect(keyvault_spec(), Vault(responses))
    old = [item for item in records(pages) if certificate_evidence(item)
           and item.provenance.resource_id.endswith("/a1")]
    assert len(old) == 1 and not certificate_evidence(old[0])["current_version"]
