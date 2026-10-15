"""Synthetic Graph contract proof; no tenant login or credential use."""

from copy import deepcopy
from types import ModuleType, SimpleNamespace

import httpx
import pytest

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.providers.facts import unpack_facts
from cremore_azure_provider.entra import adapter
from cremore_azure_provider.entra.transport import GraphTransport, cursor_from_link, token_for_spec
from cremore_azure_provider.metadata.transport import ApiError

TENANT = "10000000-0000-0000-0000-000000000001"
APP = "20000000-0000-0000-0000-000000000001"
APP2 = "20000000-0000-0000-0000-000000000002"
CLIENT = "30000000-0000-0000-0000-000000000001"
KEY = "40000000-0000-0000-0000-000000000001"
ORIGIN = "https://graph.microsoft.com"


def spec(**changes):
    return MetadataConnectionSpec.model_validate({
        "name": "Approved tenant", "provider": "azure_entra", "origin": ORIGIN,
        "tenant": TENANT, "tenant_confirmed": True,
        "scopes": [{"kind": "organization", "id": TENANT}],
        "capabilities": ["inventory"], "auth_type": "workload_identity", **changes})


def application(identifier=APP):
    return {"id": identifier, "appId": CLIENT, "displayName": "Billing",
            "passwordCredentials": [{"keyId": KEY, "displayName": "Automation",
                                     "startDateTime": "2026-01-01T00:00:00Z",
                                     "endDateTime": "2027-01-01T00:00:00Z",
                                     "secretText": "synthetic-secret-must-disappear", "hint": "abc"}],
            "keyCredentials": [{"keyId": KEY, "type": "AsymmetricX509Cert", "usage": "Verify",
                                "customKeyIdentifier": "YWJj", "key": "unexpected-key-material"}]}


class Graph:
    def __init__(self, responses=None):
        self.responses = {"/v1.0/organization": {"value": [{"id": TENANT}]}, **(responses or {})}
        self.calls = []
        self.requests = 0

    def get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        self.requests += 1
        result = self.responses.get(path, {"value": []})
        if isinstance(result, list):
            index = sum(1 for name, _ in self.calls if name == path) - 1
            result = result[min(index, len(result) - 1)]
        if isinstance(result, Exception):
            raise result
        return deepcopy(result)


def collect(connection=None, graph=None, **kwargs):
    return list(adapter.collect_pages(connection or spec(), secrets={}, checkpoint=kwargs.pop("checkpoint", None),
                                      check=kwargs.pop("check", lambda: None), transport=graph or Graph(), **kwargs))


def records(pages):
    return [record for page in pages for record in page.records]


def test_application_and_sp_credentials_are_metadata_not_values():
    sp = {**application(APP2), "accountEnabled": False, "servicePrincipalType": "ManagedIdentity"}
    pages = collect(graph=Graph({"/v1.0/applications": {"value": [application()]},
                                "/v1.0/servicePrincipals": {"value": [sp]}}))
    assert pages[-1].status == "COMPLETE"
    entities = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert len(entities) == 6
    assert all(adapter.validate_machine_record(spec(), row) for row in entities)
    serialized = "".join(page.model_dump_json() for page in pages)
    assert "synthetic-secret" not in serialized and "unexpected-key-material" not in serialized
    assert all(row.value_match is None for row in entities)
    credentials = [row for row in entities if row.identity.kind == "credential"]
    assert {row.normalized_state for row in credentials} == {"UNKNOWN", "DISABLED"}
    assert all(row.omissions for row in credentials)
    cert = next(row for row in entities if row.identity.kind == "public_key")
    facts = unpack_facts([f.model_dump() for f in cert.facts])
    assert facts["fingerprint"] == "616263" and facts["algorithm"] == "PROVIDER_CUSTOM_KEY_IDENTIFIER"


def test_a_credentials_start_is_its_validity_start_not_its_creation():
    from cremore.onboarding.catalog import INVENTORY_FIELDS
    from cremore_azure_provider.onboarding import AZURE_TYPES

    pages = collect(graph=Graph({"/v1.0/applications": {"value": [application()]}}))
    secret = next(row for row in records(pages) if getattr(row, "identity", None) and row.identity.kind == "credential")
    facts = unpack_facts([f.model_dump() for f in secret.facts])
    # Graph: startDateTime is when the credential becomes valid, set by the caller or the certificate.
    assert facts["not_before"] == "2026-01-01T00:00:00+00:00" and "created_at" not in facts
    assert {kind["id"]: kind["support"][INVENTORY_FIELDS.index("created")] for kind in AZURE_TYPES
            if kind["id"] in ("client_secret", "certificate")} == {"client_secret": "N", "certificate": "N"}


def test_multiple_pages_and_restart_preserve_tenant_check_and_cursor():
    graph = Graph({"/v1.0/applications": [
        {"value": [application()], "@odata.nextLink": ORIGIN + "/v1.0/applications?$skiptoken=next"},
        {"value": [application(APP2)]}]})
    first = next(adapter.collect_pages(spec(), secrets={}, checkpoint=None, check=lambda: None, transport=graph))
    assert first.checkpoint["requests"] == 2 and first.checkpoint["cursor"]["skiptoken"] == "next"
    resumed = Graph({"/v1.0/applications": {"value": [application(APP2)]}})
    pages = collect(graph=resumed, checkpoint=first.checkpoint,
                    read_records=lambda: [r.model_dump() for r in first.records])
    assert pages[-1].status == "COMPLETE"
    assert resumed.calls[0][0] == "/v1.0/organization"
    assert resumed.calls[1][1]["$skiptoken"] == "next"
    assert pages[-1].checkpoint["requests"] == 5


def test_federated_settings_are_trust_objects_and_are_paginated():
    row = {"id": KEY, "name": "github", "issuer": "https://token.actions.githubusercontent.com",
           "subject": "repo:example/approved:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]}
    path = f"/v1.0/applications/{APP}/federatedIdentityCredentials"
    configured = spec(capabilities=["inventory", "policy"],
                      options={"sources": ["applications", "service_principals", "federated_identity_credentials"]})
    pages = collect(configured, Graph({"/v1.0/applications": {"value": [application()]}, path: [
        {"value": [row], "@odata.nextLink": ORIGIN + path + "?$skiptoken=next"}, {"value": []}]}))
    assert pages[-1].status == "COMPLETE"
    trusts = [row for row in records(pages) if getattr(row, "identity", None) and row.identity.kind == "trust"]
    assert len(trusts) == 1 and trusts[0].normalized_state == "UNKNOWN"
    assert adapter.validate_record(configured, trusts[0])


@pytest.mark.parametrize("change", [
    {"tenant_confirmed": False}, {"tenant": "not-a-tenant"},
    {"origin": "https://graph.microsoft.com.attacker.test"},
    {"scopes": [{"kind": "organization", "id": APP}]},
    {"auth_type": "bearer"}, {"principal_pin": "unknown"},
    {"options": {"sources": ["federated_identity_credentials"]}},
    {"options": {"sources": ["applications", "federated_identity_credentials"]}},
])
def test_unapproved_connections_are_refused_before_any_call(change):
    graph = Graph()
    with pytest.raises(ValueError):
        collect(spec(**change), graph)
    assert graph.calls == []


def test_wrong_tenant_stops_before_inventory():
    graph = Graph({"/v1.0/organization": {"value": [{"id": APP}]}})
    pages = collect(graph=graph)
    assert pages[-1].status == "FAILED" and pages[-1].reasons == ["TENANT_MISMATCH"]
    assert len(graph.calls) == 1


@pytest.mark.parametrize("link", [
    "https://attacker.test/v1.0/applications?$skiptoken=next",
    ORIGIN + "/v1.0/servicePrincipals?$skiptoken=next",
    ORIGIN + "/v1.0/applications?$skiptoken=one&$skiptoken=two",
    ORIGIN + ":444/v1.0/applications?$skiptoken=next",
])
def test_pagination_requires_exact_origin_and_operation(link):
    with pytest.raises(ApiError):
        cursor_from_link(link, ORIGIN, "/v1.0/applications")


def test_denied_or_missing_credential_arrays_are_not_empty_success():
    row = application()
    del row["passwordCredentials"]
    pages = collect(graph=Graph({"/v1.0/applications": {"value": [row]},
                                "/v1.0/servicePrincipals": ApiError("permission_denied")}))
    assert pages[-1].status == "PARTIAL"
    assert set(pages[-1].reasons) == {"CREDENTIAL_COLLECTION_NOT_RETURNED", "PERMISSION_DENIED"}


def test_record_budget_does_not_advance_past_unsaved_page():
    pages = collect(spec(max_records=1), Graph({"/v1.0/applications": {"value": [application()]}}))
    assert pages[-1].status == "PARTIAL"
    assert pages[-1].checkpoint["phase"] == 0 and pages[-1].checkpoint["cursor"] == {}
    assert pages[-1].records == []


def test_report_budget_does_not_advance_past_unsaved_empty_phase():
    pages = collect(spec(max_records=1), Graph())
    assert pages[-1].status == "PARTIAL"
    assert pages[-1].checkpoint["phase"] == 1


def test_symmetric_application_key_is_not_mislabeled_public_certificate():
    row = application()
    row["keyCredentials"][0]["type"] = "Symmetric"
    pages = collect(graph=Graph({"/v1.0/applications": {"value": [row]}}))
    key = next(r for r in records(pages) if getattr(r, "identity", None)
               and ":keyCredentials:" in r.identity.object_id)
    assert key.identity.kind == "credential"
    assert adapter.validate_record(spec(), key)


def test_page_budget_preserves_partial_status():
    pages = collect(spec(max_pages=1), Graph({"/v1.0/applications": {
        "value": [application()], "@odata.nextLink": ORIGIN + "/v1.0/applications?$skiptoken=next"}}))
    assert pages[-1].status == "PARTIAL" and "PAGE_LIMIT_REACHED" in pages[-1].reasons


def test_deferral_preserves_cursor_and_charges_attempt():
    pages = collect(graph=Graph({"/v1.0/applications": ApiError("rate_limited", retry_after=12)}))
    assert pages[-1].status == "WAITING" and pages[-1].retry_after_seconds == 12
    assert pages[-1].checkpoint["phase"] == 0 and pages[-1].checkpoint["requests"] == 2


def test_cancellation_is_not_converted_to_a_provider_failure():
    def cancel():
        raise RuntimeError("synthetic cancellation")
    with pytest.raises(RuntimeError, match="cancellation"):
        collect(check=cancel)


def test_record_scope_and_values_cannot_be_forged():
    row = next(r for r in records(collect(graph=Graph({"/v1.0/applications": {"value": [application()]}})))
               if r.record_type == "entity_observation")
    row.identity.tenant = APP
    assert adapter.validate_machine_record(spec(), row) is False


def test_bad_checkpoint_counter_is_refused():
    state = adapter._initial(spec(), None)
    state["requests"] = -1
    with pytest.raises(ValueError, match="CHECKPOINT"):
        collect(checkpoint=state, read_records=list)


def test_real_transport_is_pinned_bounded_and_read_only():
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"value": [{"id": TENANT}]} if request.url.path.endswith("organization") else {"value": []})
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(adapter.collect_pages(spec(), secrets={}, checkpoint=None, check=lambda: None,
                                           client=client, token=lambda: "synthetic-collector-token"))
        wire = GraphTransport(client, lambda: "synthetic", origin=ORIGIN, options=spec().options,
                              max_requests=10, check=lambda: None)
        with pytest.raises(ValueError):
            wire.get("/v1.0/users")
    assert pages[-1].status == "COMPLETE"
    assert all(r.method == "GET" and r.url.host == "graph.microsoft.com" for r in requests)
    assert requests[1].url.params["$top"] == "25"


def test_ambient_auth_requests_configured_tenant_and_sovereign_authority(monkeypatch):
    import sys
    called = []
    class Credential:
        def __init__(self, **kwargs):
            called.append(kwargs)
        def get_token(self, scope, **kwargs):
            called.append((scope, kwargs))
            return SimpleNamespace(token="synthetic")
    module = ModuleType("azure.identity")
    module.DefaultAzureCredential = Credential
    monkeypatch.setitem(sys.modules, "azure.identity", module)
    assert token_for_spec(spec(origin="https://graph.microsoft.us"))() == "synthetic"
    assert called[0]["authority"] == "login.microsoftonline.us" and called[0]["exclude_cli_credential"] is True
    assert called[1] == ("https://graph.microsoft.us/.default", {"tenant_id": TENANT})
