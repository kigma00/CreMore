"""Entra ID user status through the shared identity collector, against a synthetic Graph."""

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec
from cremore.identity.keys import Digester
from cremore_azure_provider.entra_id import adapter, identity

TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
A, B, C = ("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
           "33333333-3333-4333-8333-333333333333")
DIGEST = Digester(b"k" * 32)


def spec(**overrides):
    body = {"name": "entra users", "provider": "entra_id", "origin": "https://graph.microsoft.com", "edition": "cloud",
            "tenant": TENANT, "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": TENANT}],
            "capabilities": ["identity_status"], "auth_type": "workload_identity", "options": {"page_size": 2}}
    body.update(overrides)
    return MetadataConnectionSpec.model_validate(body)


def graph(request):
    assert request.headers["Authorization"] == "Bearer graph-token"
    query = parse_qs(urlsplit(str(request.url)).query)
    if request.url.path == "/v1.0/organization":
        assert query == {"$select": ["id"]}
        return httpx.Response(200, json={"value": [{"id": TENANT}]})
    if request.url.path == "/v1.0/users":
        if "$skiptoken" not in query:
            assert query["$select"] == ["id,accountEnabled,userPrincipalName,mail,displayName,department,jobTitle"]
            return httpx.Response(200, json={"value": [
                {"id": A, "accountEnabled": True, "userPrincipalName": "a@acme.test", "mail": "a@acme.test",
                 "displayName": "Ada  Lovelace", "department": "Platform", "jobTitle": "Engineer"},
                {"id": B.upper(), "accountEnabled": False, "userPrincipalName": "b@acme.test", "mail": None,
                 "displayName": "Bob", "department": None, "jobTitle": None}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$top=2&$skiptoken=page2"})
        assert query["$skiptoken"] == ["page2"]
        return httpx.Response(200, json={"value": []})
    assert request.url.path == "/v1.0/directory/deletedItems/microsoft.graph.user"
    assert query["$select"] == ["id,deletedDateTime,userPrincipalName,mail,displayName,department,jobTitle"]
    return httpx.Response(200, json={"value": [
        {"id": C, "deletedDateTime": "2026-09-20T09:00:00Z",
         "userPrincipalName": C.replace("-", "") + "c@acme.test", "mail": "c@acme.test"}]})


def run(connection, handler=graph):
    committed, final = [], None
    for page in adapter.collect_pages(connection, secrets={}, checkpoint={}, check=lambda: None, identity_digest=DIGEST,
                                      client=httpx.Client(transport=httpx.MockTransport(handler)),
                                      sleep=lambda _s: None):
        committed.extend(item.model_dump() for item in page.records)
        final = page
    return committed, final


@pytest.fixture(autouse=True)
def fake_credential(monkeypatch):
    monkeypatch.setattr(identity, "token_for_spec", lambda _spec: (lambda: "graph-token"))


def test_enabled_disabled_and_deleted_users():
    records, final = run(spec())
    assert final.status == "COMPLETE"
    users = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert {k: v["normalized_state"] for k, v in users.items()} == {
        "user:" + A: "ACTIVE", "user:" + B: "DISABLED", "user:" + C: "DELETED"}
    deleted = users["user:" + C]
    assert deleted["effective_at"] == "2026-09-20T09:00:00+00:00"
    # The deleted user's UPN loses its object-id prefix before it is digested.
    assert {"kind": "LOGIN", "digest": DIGEST("c@acme.test")} in deleted["identity_keys"]
    for item in records:
        assert adapter.validate_record(spec(), RECORD_ADAPTER.validate_python(item))


def test_profiles_are_kept_only_when_the_collection_asks():
    records, _final = run(spec())
    assert not any(r["facts"] for r in records)  # digests only, as before
    kept = spec(options={"page_size": 2, "keep_profiles": True})
    records, final = run(kept)
    assert final.status == "COMPLETE"
    users = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    facts = {fact["name"]: fact["value"] for fact in users["user:" + A]["facts"]}
    assert facts == {"display_name": "Ada Lovelace", "email": "a@acme.test", "department": "Platform",
                     "title": "Engineer"}
    assert {fact["name"] for fact in users["user:" + B]["facts"]} == {"display_name"}
    for item in records:
        assert adapter.validate_record(kept, RECORD_ADAPTER.validate_python(item))
    # A record with a profile does not pass for a collection that keeps none.
    with_profile = RECORD_ADAPTER.validate_python(users["user:" + A])
    assert not adapter.validate_record(spec(), with_profile)


def test_a_next_link_elsewhere_is_refused():
    def handler(request):
        if request.url.path == "/v1.0/organization":
            return graph(request)
        if request.url.path == "/v1.0/users":
            return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://example.com/v1.0/users?$skiptoken=x"})
        return httpx.Response(200, json={"value": []})

    _records, final = run(spec(), handler)
    assert final.status == "PARTIAL" and "ENTRA_ID_INVALID_CURSOR" in final.reasons


def test_throttling_waits_with_the_retry_after():
    _records, final = run(spec(), lambda request: graph(request) if request.url.path == "/v1.0/organization"
                          else httpx.Response(429, headers={"retry-after": "12"}))
    assert final.status == "WAITING" and final.retry_after_seconds == 12


def jwt(claims):
    import base64
    import json

    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{body}.signature"


@pytest.mark.parametrize("tenant,status", [("ffffffff-0000-4000-8000-000000000000", "FAILED"), (TENANT.upper(), "COMPLETE")])
def test_a_token_from_another_directory_lists_nobody(monkeypatch, tenant, status):
    # A managed identity ignores the tenant it is asked for; the token's tid names the directory that answers.
    token = jwt({"tid": tenant})
    monkeypatch.setattr(identity, "token_for_spec", lambda _spec: (lambda: token))
    asked = []

    def handler(request):
        asked.append(request.url.path)
        assert request.headers["Authorization"] == "Bearer " + token
        return graph(httpx.Request(request.method, request.url, headers={"Authorization": "Bearer graph-token"}))

    records, final = run(spec(), handler)
    assert final.status == status
    if status == "FAILED":
        assert "ENTRA_ID_TENANT_MISMATCH" in final.reasons and asked == []
        assert not any(r["record_type"] == "entity_observation" for r in records)
    else:
        assert "/v1.0/organization" not in asked


@pytest.mark.parametrize("body,status_code,reason", [
    ({"value": [{"id": TENANT.upper()}]}, 200, None),
    ({"value": [{"id": "ffffffff-0000-4000-8000-000000000000"}]}, 200, "ENTRA_ID_TENANT_MISMATCH"),
    ({"value": []}, 200, "ENTRA_ID_TENANT_MISMATCH"),
    ({"value": [{"id": TENANT}, {"id": TENANT}]}, 200, "ENTRA_ID_TENANT_MISMATCH"),
    ({"value": [{"id": TENANT}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/organization"},
     200, "ENTRA_ID_TENANT_MISMATCH"),
    ({}, 403, "ENTRA_ID_TENANT_UNVERIFIED"),
    (None, 200, "ENTRA_ID_TENANT_UNVERIFIED"),
])
def test_opaque_token_confirms_organization_before_any_people(body, status_code, reason):
    asked = []

    def handler(request):
        asked.append(request.url.path)
        if request.url.path == "/v1.0/organization":
            assert dict(request.url.params) == {"$select": "id"}
            return httpx.Response(status_code, json=body) if body is not None else httpx.Response(200, text="invalid")
        return graph(request)

    records, final = run(spec(), handler)
    if reason:
        assert final.status == "FAILED" and reason in final.reasons
        assert asked == ["/v1.0/organization"] * len(identity.SOURCES)
        assert not any(r["record_type"] == "entity_observation" for r in records)
    else:
        assert final.status == "COMPLETE"
        assert len([r for r in records if r["record_type"] == "entity_observation"]) == 3
        assert asked[::2] == ["/v1.0/organization"] * 3
        assert final.checkpoint["requests"] == len(asked) == 6


def test_organization_confirmation_charges_the_people_request_budget():
    asked = []

    def handler(request):
        asked.append(request.url.path)
        return graph(request)

    records, final = run(spec(max_requests=1), handler)
    assert "REQUEST_BUDGET_EXCEEDED" in final.reasons
    assert asked == ["/v1.0/organization"] and final.checkpoint["requests"] == 1
    assert not any(r["record_type"] == "entity_observation" for r in records)


def test_organization_transport_failure_never_lists_people():
    asked = []

    def handler(request):
        asked.append(request.url.path)
        raise httpx.ConnectError("synthetic failure")

    records, final = run(spec(), handler)
    assert final.status == "FAILED" and "ENTRA_ID_TENANT_UNVERIFIED" in final.reasons
    assert asked == ["/v1.0/organization"] * len(identity.SOURCES)
    assert not any(r["record_type"] == "entity_observation" for r in records)


@pytest.mark.parametrize("overrides, code", [
    ({"tenant_confirmed": False}, "ENTRA_ID_CONFIRMED_TENANT_REQUIRED"),
    ({"origin": "https://graph.example.com"}, "ENTRA_ID_GRAPH_ORIGIN_REQUIRED"),
    ({"auth_type": "bearer", "secret_refs": {"token": "vault://x"}}, "ENTRA_ID_WORKLOAD_IDENTITY_REQUIRED"),
])
def test_the_spec_needs_a_confirmed_tenant_and_workload_identity(overrides, code):
    with pytest.raises(ValueError, match=code):
        adapter.validate_spec(spec(**overrides))
