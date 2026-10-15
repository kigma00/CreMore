"""KV history and management evidence with fake HTTP and synthetic non-AWS material."""

import json

import httpx
import pytest

from cremore.coverage.coverage_test import GH, engine
from cremore.coverage.models import ConnectionSpec
from cremore_vault_provider.coverage import collect_kv

AUTH = "synthetic-vault-inventory-auth"
TIME = "2026-09-25T00:00:00Z"


def spec(**changes):
    return ConnectionSpec.model_validate({"name": "Inventory", "provider": "vault",
        "endpoint": "https://vault.example.test", "namespaces": ["team"],
        "mounts": [{"name": "kv", "prefixes": ["app"]}], **changes})


def collect(config, handler):
    calls = []
    def handle(request):
        calls.append(request)
        assert request.headers["X-Vault-Namespace"] == "team"
        assert request.headers["X-Vault-Token"] == AUTH
        return handler(request)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = collect_kv(config, client, AUTH, engine())
    serialized = json.dumps([item.model_dump() for item in result.items])
    assert GH not in serialized and AUTH not in serialized
    return result, calls


def response(data, status=200):
    return httpx.Response(status, json={"data": data})


def kv_handler(request):
    if request.url.params.get("list"):
        return response({"keys": ["token"]})
    if "/metadata/" in request.url.path:
        return response({"current_version": 4, "versions": {
            "1": {"destroyed": True}, "2": {"deletion_time": "2020-01-01T00:00:00Z"},
            "3": {}, "4": {"deletion_time": "2099-01-01T00:00:00Z"}}})
    version = int(request.url.params.get("version", "4"))
    return response({"data": {"github": GH}, "metadata": {"version": version}})


@pytest.mark.parametrize("provider", ["vault", "openbao"])
def test_kv2_history_pins_each_available_version_and_marks_deleted_destroyed(provider):
    result, calls = collect(spec(provider=provider, include_previous_versions=True), kv_handler)
    assert result.status == "PARTIAL"
    assert {i.version: i.version_state for i in result.items} == {
        "4": "CURRENT", "3": "PREVIOUS", "2": "DELETED", "1": "DESTROYED"}
    assert {i.credential_type for i in result.items if i.evidence == "VALUE"} == {"GITHUB_TOKEN"}
    assert [r.url.params.get("version") for r in calls if "/data/" in r.url.path] == ["4", "3"]
    assert "VERSION_UNAVAILABLE" in result.reasons


def test_explicit_kv_version_is_requested_and_does_not_claim_it_is_current():
    result, calls = collect(spec(version_selector="3"), kv_handler)
    assert result.status == "COMPLETE" and result.items[0].version_state == "UNKNOWN"
    assert calls[-1].url.params["version"] == "3"


def test_kv_version_history_limit_is_visible():
    result, calls = collect(spec(include_previous_versions=True, max_versions_per_secret=1), kv_handler)
    assert len(result.items) == 1 and "KV_VERSION_LIMIT" in result.reasons
    assert len(calls) == 3


def test_kv1_history_option_is_not_silently_accepted():
    config = spec(mounts=[{"name": "kv", "kv_version": 1, "prefixes": ["app"]}], include_previous_versions=True)
    result, _ = collect(config, lambda r: response({"keys": ["token"]} if r.url.params else {"github": GH}))
    assert result.items[0].evidence == "VALUE"
    assert result.status == "PARTIAL" and "KV1_VERSION_HISTORY_UNSUPPORTED" in result.reasons


@pytest.mark.parametrize("bad", ["../escape", "child/other", "child//", "%2e%2e", "https://evil.test"])
def test_kv_bad_children_never_leave_list_scope(bad):
    result, calls = collect(spec(), lambda r: response({"keys": [bad]}))
    assert result.status == "FAILED" and len(calls) == 1


@pytest.mark.parametrize("status", [302, 403, 404])
def test_kv_metadata_history_denial_is_not_empty_success(status):
    def handler(r):
        return response({"keys": ["token"]}) if r.url.params else response({}, status)
    result, calls = collect(spec(include_previous_versions=True), handler)
    assert result.status == "PARTIAL" and result.items[0].evidence == "UNRESOLVED"
    assert "VAULT_HTTP_" + str(status) in result.reasons and len(calls) == 2


def managed_handler(request):
    if request.url.path.endswith("/auth/token/accessors"):
        assert request.method == "LIST"
        return response({"keys": ["accessor-1"]})
    if request.url.path.endswith("/auth/token/lookup-accessor"):
        assert request.method == "POST" and json.loads(request.content) == {"accessor": "accessor-1"}
        return response({"accessor": "accessor-1", "id": "NEVER_STORE_TOKEN_VALUE", "type": "service",
                         "issue_time": TIME, "ttl": 300, "renewable": True, "policies": ["app-read"],
                         "meta": {"password": "NEVER_STORE_TOKEN_VALUE"}})
    if request.method == "LIST":
        assert request.url.path == "/v1/sys/leases/lookup/database/creds/app"
        return response({"keys": ["lease-1"]})
    assert request.url.path == "/v1/sys/leases/lookup" and request.method == "POST"
    identifier = json.loads(request.content)["lease_id"]
    return response({"id": identifier, "issue_time": TIME, "ttl": 120, "renewable": True,
                     "password": "NEVER_STORE_TOKEN_VALUE"})


@pytest.mark.parametrize("provider", ["vault", "openbao"])
def test_accessor_and_lease_are_managed_evidence_not_kv_or_value(provider):
    config = spec(provider=provider, mounts=[], include_token_accessors=True, lease_prefixes=["database/creds/app"])
    result, calls = collect(config, managed_handler)
    assert len(calls) == 4 and len(result.items) == 2
    assert all(i.evidence == "MANAGED" and i.fingerprint is None and i.state == "UNKNOWN" for i in result.items)
    assert {i.vault_managed.kind for i in result.items} == {"SERVICE_TOKEN", "DYNAMIC_LEASE"}
    assert "BATCH_TOKEN_INVENTORY_UNSUPPORTED" in result.reasons
    assert "NEVER_STORE_TOKEN_VALUE" not in json.dumps([i.model_dump() for i in result.items])


@pytest.mark.parametrize("kind", ["accessor", "lease"])
def test_management_lookup_denial_keeps_listed_handle_without_inventing_metadata(kind):
    config = spec(mounts=[], include_token_accessors=kind == "accessor",
                  lease_prefixes=["database/creds/app"] if kind == "lease" else [])
    def handler(r):
        return managed_handler(r) if r.method == "LIST" else response({}, 403)
    result, _ = collect(config, handler)
    assert result.status == "PARTIAL" and len(result.items) == 1
    assert result.items[0].vault_managed.lookup_status == "FAILED"
    assert result.items[0].vault_managed.ttl_seconds is None
    assert result.items[0].reason == "VAULT_HTTP_403"
    assert ("TOKEN_ACCESSOR_LOOKUP_FAILED" if kind == "accessor" else "LEASE_LOOKUP_FAILED") in result.reasons
    assert "VAULT_HTTP_403" not in result.reasons


@pytest.mark.parametrize("kind", ["accessor", "lease"])
def test_management_list_denial_cannot_be_empty_complete(kind):
    config = spec(mounts=[], include_token_accessors=kind == "accessor",
                  lease_prefixes=["database/creds/app"] if kind == "lease" else [])
    result, calls = collect(config, lambda r: response({}, 403))
    assert not result.items and result.status == "FAILED" and len(calls) == 1
    assert ("TOKEN_ACCESSOR_LIST_FAILED" if kind == "accessor" else "LEASE_LIST_FAILED") in result.reasons
    assert "VAULT_HTTP_403" not in result.reasons


def test_lease_directories_stay_under_prefix_and_top_level_vault_response_is_supported():
    def handler(r):
        if r.method == "LIST":
            return response({"keys": ["nested/"] if r.url.path.endswith("/app") else ["lease-1"]})
        return httpx.Response(200, json={"id": "database/creds/app/nested/lease-1", "ttl": 12})
    result, calls = collect(spec(mounts=[], lease_prefixes=["database/creds/app"]), handler)
    assert result.status == "COMPLETE" and len(calls) == 3
    assert result.items[0].vault_managed.ttl_seconds == 12


def test_shared_request_budget_stops_kv_and_management_together():
    config = spec(include_previous_versions=True, include_token_accessors=True, max_requests=2)
    result, calls = collect(config, kv_handler)
    assert len(calls) == 2 and "REQUEST_LIMIT" in result.reasons


@pytest.mark.parametrize("provider", ["vault", "openbao"])
def test_renewed_token_and_lease_use_rfc3339_last_renewal(provider):
    def handler(request):
        original = managed_handler(request)
        payload = original.json()
        if request.method == "POST":
            payload["data"]["last_renewal"] = TIME
            if request.url.path.endswith("/lookup-accessor"):
                payload["data"]["last_renewal_time"] = 1790294400
        return httpx.Response(original.status_code, json=payload)

    result, _ = collect(spec(provider=provider, mounts=[], include_token_accessors=True,
                             lease_prefixes=["database/creds/app"]), handler)
    assert len(result.items) == 2
    assert all(item.vault_managed.lookup_status == "COMPLETE" for item in result.items)
    assert all(item.vault_managed.last_renewal_at == TIME for item in result.items)
    assert result.reasons == {"BATCH_TOKEN_INVENTORY_UNSUPPORTED"}


def test_a_namespace_suffixed_accessor_is_listed_and_looked_up():
    # Vault Enterprise suffixes a non-root namespace's accessors with `.<namespace ID>`.
    accessor = "accessor-1.ns123"

    def handler(request):
        if request.method == "LIST":
            return response({"keys": [accessor]})
        assert json.loads(request.content) == {"accessor": accessor}
        return response({"accessor": accessor, "type": "service", "ttl": 300})

    result, calls = collect(spec(mounts=[], include_token_accessors=True), handler)
    assert len(calls) == 2 and len(result.items) == 1
    assert result.items[0].vault_managed.lookup_status == "COMPLETE"
    assert result.reasons == {"BATCH_TOKEN_INVENTORY_UNSUPPORTED"}


@pytest.mark.parametrize("provider", ["vault", "openbao"])
@pytest.mark.parametrize("kind", ["kv1", "kv2", "lease", "accessor"])
def test_empty_list_404_is_zero_keys(provider, kind):
    config = spec(provider=provider,
                  mounts=[{"name": "kv", "kv_version": 1 if kind == "kv1" else 2, "prefixes": ["app"]}]
                  if kind.startswith("kv") else [],
                  include_token_accessors=kind == "accessor",
                  lease_prefixes=["database/creds/app"] if kind == "lease" else [])
    result, calls = collect(config, lambda r: httpx.Response(404, json={"errors": []}))
    assert not result.items and len(calls) == 1
    assert result.reasons == ({"BATCH_TOKEN_INVENTORY_UNSUPPORTED"} if kind == "accessor" else set())
    assert result.status == ("FAILED" if kind == "accessor" else "COMPLETE")


@pytest.mark.parametrize("kind", ["kv", "lease", "accessor"])
@pytest.mark.parametrize("payload", [
    {"errors": ['no handler for route "kv/metadata/app". route entry not found.']},
    {"errors": ["permission denied"]}, {"errors": None}, {}, [], {"data": {"keys": []}},
])
def test_list_404_without_explicit_empty_errors_remains_failure(kind, payload):
    config = spec(mounts=[{"name": "kv", "prefixes": ["app"]}] if kind == "kv" else [],
                  include_token_accessors=kind == "accessor",
                  lease_prefixes=["database/creds/app"] if kind == "lease" else [])
    result, calls = collect(config, lambda r: httpx.Response(404, json=payload))
    assert not result.items and len(calls) == 1 and result.status == "FAILED"
    assert {"kv": "VAULT_HTTP_404", "lease": "LEASE_LIST_FAILED",
            "accessor": "TOKEN_ACCESSOR_LIST_FAILED"}[kind] in result.reasons
    if kind != "kv":
        assert "VAULT_HTTP_404" not in result.reasons


@pytest.mark.parametrize("status", [403, 500])
def test_non404_empty_errors_is_not_empty_list(status):
    result, _ = collect(spec(), lambda r: httpx.Response(status, json={"errors": []}))
    assert result.status == "FAILED" and result.reasons == {"VAULT_HTTP_" + str(status)}


@pytest.mark.parametrize("provider", ["vault", "openbao"])
@pytest.mark.parametrize("state,metadata", [
    ("DELETED", {"deletion_time": "2020-01-01T00:00:00Z", "destroyed": False}),
    ("DESTROYED", {"deletion_time": "", "destroyed": True}),
])
@pytest.mark.parametrize("selector", ["latest", "3"])
def test_kv2_unavailable_read_404_keeps_version_state(provider, state, metadata, selector):
    def handler(request):
        if request.url.params.get("list"):
            return response({"keys": ["token"]})
        return response({"data": {"github": GH}, "metadata": {
            "version": 3, "custom_metadata": {"password": "NEVER_STORE_METADATA"}, **metadata}}, 404)

    result, calls = collect(spec(provider=provider, version_selector=selector), handler)
    assert len(calls) == 2 and len(result.items) == 1
    item = result.items[0]
    assert (item.evidence, item.version, item.version_state, item.reason) == (
        "UNRESOLVED", "3", state, "VERSION_UNAVAILABLE")
    assert result.status == "PARTIAL" and result.reasons == {"VERSION_UNAVAILABLE"}
    assert "NEVER_STORE_METADATA" not in item.model_dump_json()


@pytest.mark.parametrize("metadata", [
    {}, {"version": 3}, {"version": 3, "deletion_time": "2099-01-01T00:00:00Z"},
    {"version": 3, "deletion_time": "invalid"}, {"version": "3", "destroyed": True},
    {"version": 2, "destroyed": True},
])
def test_kv2_404_without_matching_unavailable_metadata_is_read_failure(metadata):
    def handler(request):
        if request.url.params.get("list"):
            return response({"keys": ["token"]})
        return response({"data": {"github": GH}, "metadata": metadata}, 404)

    result, _ = collect(spec(version_selector="3"), handler)
    assert result.status == "PARTIAL"
    assert result.items[0].evidence == "UNRESOLVED"
    assert result.items[0].version_state == "UNKNOWN"
    assert result.items[0].reason == "KV_VALUE_READ_FAILED"
    assert "VERSION_UNAVAILABLE" not in result.reasons


def test_kv1_404_metadata_cannot_be_mistaken_for_kv2_state():
    def handler(request):
        if request.url.params.get("list"):
            return response({"keys": ["token"]})
        return response({"metadata": {"version": 3, "destroyed": True}}, 404)

    result, _ = collect(spec(mounts=[{"name": "kv", "kv_version": 1, "prefixes": ["app"]}]), handler)
    assert result.items[0].version_state == "UNKNOWN"
    assert result.items[0].reason == "KV_VALUE_READ_FAILED"
    assert "VAULT_HTTP_404" in result.reasons


def test_unavailable_http_error_retains_only_version_state_metadata():
    from cremore.coverage.collection import Collection
    from cremore_vault_provider.inventory_http import InventoryHTTP, ReadError

    config = spec()
    metadata = {"version": 3, "destroyed": True, "deletion_time": ""}
    def handler(request):
        return response({"data": {"github": GH}, "metadata": {
            **metadata, "custom_metadata": {"password": "NEVER_STORE_METADATA"}}}, 404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        request = InventoryHTTP(config, client, AUTH, Collection(config))
        with pytest.raises(ReadError, match="^VAULT_HTTP_404$") as caught:
            request.data("team", "kv/data/app/token")
    assert caught.value.metadata == metadata
    assert GH not in repr(vars(caught.value))
    assert "NEVER_STORE_METADATA" not in repr(vars(caught.value))


def test_empty_errors_on_value_read_404_is_not_empty_success():
    def handler(request):
        if request.url.params.get("list"):
            return response({"keys": ["token"]})
        return httpx.Response(404, json={"errors": []})

    result, _ = collect(spec(), handler)
    assert result.status == "PARTIAL"
    assert result.items[0].reason == "KV_VALUE_READ_FAILED"
    assert "VAULT_HTTP_404" in result.reasons


def test_non_json_list_404_remains_http_failure():
    result, _ = collect(spec(), lambda r: httpx.Response(404, text="not found"))
    assert result.status == "FAILED" and result.reasons == {"VAULT_HTTP_404"}
