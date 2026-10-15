"""ARM inventory with synthetic management-plane responses only."""

import base64
from copy import deepcopy

import httpx
import pytest

from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import MetadataConnectionSpec, in_metadata_scope
from cremore_azure_provider.arm import ORIGIN, STORAGE_VERSION, adapter
from cremore_azure_provider.arm.transport import ArmTransport, page_query
from cremore_azure_provider.metadata.transport import ApiError, Budget
from cremore_azure_provider.metadata.values_test import (
    context as context,  # noqa: PLC0414 -- shared synthetic fingerprint fixture
)

TENANT = "10000000-0000-0000-0000-000000000001"
SUB = "20000000-0000-0000-0000-000000000001"
OTHER = "20000000-0000-0000-0000-000000000002"
ACCOUNT = f"/subscriptions/{SUB}/resourceGroups/Approved/providers/Microsoft.Storage/storageAccounts/acmeprod"
VAULT = f"/subscriptions/{SUB}/resourceGroups/Approved/providers/Microsoft.KeyVault/vaults/acme-prod"
STORAGE_PATH = f"/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts"
VAULT_PATH = f"/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults"
VALUE = base64.b64encode(bytes(range(64))).decode()


def spec(**changes):
    return MetadataConnectionSpec.model_validate({
        "name": "Approved subscriptions", "provider": "azure_resource_manager", "origin": ORIGIN,
        "tenant": TENANT, "tenant_confirmed": True, "auth_type": "workload_identity",
        "scopes": [{"kind": "subscription", "id": SUB}], "capabilities": ["inventory"], **changes})


def value_spec(**changes):
    return spec(capabilities=["inventory", "issuer_value"], options={"include_values": True,
        "sources": ["storage_keys"], "azure_storage_accounts": [ACCOUNT]}, **changes)


def subscription(identifier=SUB, tenant=TENANT):
    return {"id": "/subscriptions/" + identifier, "subscriptionId": identifier, "tenantId": tenant,
            "displayName": "Production", "state": "Enabled"}


def storage():
    return {"id": ACCOUNT, "name": "acmeprod", "type": "Microsoft.Storage/storageAccounts",
            "location": "koreacentral", "properties": {"allowSharedKeyAccess": True}}


def vault():
    return {"id": VAULT, "name": "acme-prod", "type": "Microsoft.KeyVault/vaults",
            "properties": {"tenantId": TENANT, "vaultUri": "https://acme-prod.vault.azure.net/"}}


def keys():
    return {"keys": [{"keyName": name, "value": VALUE, "permissions": "Full",
                      "creationTime": "2026-01-01T00:00:00Z"} for name in ("key1", "key2")]}


class Arm:
    def __init__(self, responses=None):
        self.responses = {"/subscriptions/" + SUB: subscription(), "/tenants": {"value": [{"tenantId": TENANT}]},
                          **(responses or {})}
        self.calls, self.requests = [], 0

    def _read(self, method, path, params):
        self.calls.append((method, path, params))
        self.requests += 1
        result = self.responses.get(path, {"value": []})
        if isinstance(result, list):
            index = sum(1 for _, requested, _ in self.calls if requested == path) - 1
            result = result[min(index, len(result) - 1)]
        if isinstance(result, Exception):
            raise result
        return deepcopy(result)

    def get(self, path, params=None):
        return self._read("GET", path, dict(params or {}))

    def list_keys(self, account):
        return self._read("POST", account + "/listKeys", {"api-version": STORAGE_VERSION})


def collect(connection=None, arm=None, **kwargs):
    return list(adapter.collect_pages(connection or spec(), secrets={}, checkpoint=kwargs.pop("checkpoint", None),
                                      check=kwargs.pop("check", lambda: None), transport=arm or Arm(), **kwargs))


def records(pages):
    return [row for page in pages for row in page.records]


def test_default_discovers_metadata_without_listkeys_or_data_plane_calls():
    arm = Arm({STORAGE_PATH: {"value": [storage()]}, VAULT_PATH: {"value": [vault()]}})
    pages = collect(arm=arm)
    assert pages[-1].status == "COMPLETE"
    entities = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert {row.identity.object_id for row in entities} == {ACCOUNT, VAULT}
    assert all(adapter.validate_machine_record(spec(), row) and in_metadata_scope(spec(), row) for row in entities)
    assert all(method == "GET" and "listKeys" not in path and "/secrets" not in path for method, path, _ in arm.calls)


def test_approved_storage_keys_match_existing_detector_fingerprints_without_raw_output(context):
    connection = value_spec()
    arm = Arm({ACCOUNT + "/listKeys": keys()})
    pages = collect(connection, arm, value_context=context)
    assert pages[-1].status == "COMPLETE"
    entities = [row for row in records(pages) if row.record_type == "entity_observation"]
    expected = next(row.fingerprint for row in hash_value(context["engine"], ("AccountKey=" + VALUE).encode(),
                    {"reference": "synthetic"}, max_bytes=1024) if row.credential_type == "AZURE_STORAGE_KEY")
    assert len(entities) == 2
    assert {row.value_match.fingerprint for row in entities} == {expected}
    assert {row.value_match.reference for row in entities} == {ACCOUNT + "/keys/key1", ACCOUNT + "/keys/key2"}
    assert all(adapter.validate_machine_record(connection, row) and in_metadata_scope(connection, row) for row in entities)
    assert VALUE not in "".join(page.model_dump_json() for page in pages)
    assert [method for method, _, _ in arm.calls] == ["GET", "POST"]


def signed_sas(key, fingerprint_key):
    """A synthetic account SAS for acmeprod signed with ``key``, and its URL-encoded fingerprint."""
    import hashlib
    import hmac

    from cremore.detection.fingerprint import fingerprint
    from cremore_azure_provider.sas import sas_facts, string_to_sign

    facts = sas_facts(b"sv=2022-11-02&ss=b&srt=o&sp=r&se=2027-01-01T00:00:00Z", account=b"acmeprod", service=b"blob")
    signature = base64.b64encode(hmac.new(base64.b64decode(key), string_to_sign(facts).encode(),
                                          hashlib.sha256).digest()).decode()
    encoded = signature.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    return facts, encoded, fingerprint(encoded.encode(), key=fingerprint_key)


OTHER_VALUE = base64.b64encode(bytes(range(1, 65))).decode()


def two_keys():
    return {"keys": [{"keyName": "key1", "value": VALUE, "permissions": "Full"},
                     {"keyName": "key2", "value": OTHER_VALUE, "permissions": "Full"}]}


def test_a_storage_key_records_only_the_discovered_sas_it_signed(context):
    import json

    from cremore.api.metadata_coverage import public_metadata

    facts, encoded, signed = signed_sas(VALUE, context["engine"].config.fingerprint_key)
    candidates = [{"fingerprint": signed, "sas": facts}, {"fingerprint": "e" * 64, "sas": {**facts, "account": "other"}}]
    connection = value_spec()
    pages = collect(connection, Arm({ACCOUNT + "/listKeys": two_keys()}),
                    value_context={**context, "sas_candidates": candidates})
    assert pages[-1].status == "COMPLETE"
    keys = {row.identity.object_id.rsplit("/", 1)[1]: row for row in records(pages)
            if row.record_type == "entity_observation"}
    assert keys["key1"].value_match.signed_fingerprints == [signed]
    assert keys["key2"].value_match.signed_fingerprints == []
    assert all(adapter.validate_machine_record(connection, row) and in_metadata_scope(connection, row)
               for row in keys.values())
    output = json.dumps(public_metadata([row.model_dump() for row in keys.values()]))
    for private in (signed, encoded, VALUE, OTHER_VALUE):
        assert private not in output


def test_a_capped_sas_candidate_read_keeps_the_key_inventory_partial(context):
    pages = collect(value_spec(), Arm({ACCOUNT + "/listKeys": two_keys()}),
                    value_context={**context, "sas_candidates": [], "sas_candidate_status": {"complete": False}})
    assert pages[-1].status == "PARTIAL"
    assert "SAS_CANDIDATE_LIMIT_REACHED" in pages[-1].reasons
    reports = [row for row in records(pages) if row.record_type == "operation_report"
               and "SAS_CANDIDATE_LIMIT_REACHED" in row.reasons]
    assert reports and all(row.status == "PARTIAL" for row in reports)


@pytest.mark.parametrize("change", [
    {"tenant_confirmed": False}, {"tenant": "other"}, {"auth_type": "bearer"},
    {"origin": "https://unapproved.example.com"},
    {"options": {"sources": ["storage_keys"]}},
    {"capabilities": ["inventory", "issuer_value"], "options": {"sources": ["storage_keys"], "include_values": True}},
    {"options": {"azure_storage_accounts": [ACCOUNT]}},
    {"capabilities": ["inventory", "issuer_value"], "options": {"sources": ["storage_keys"], "include_values": True,
         "azure_storage_accounts": [ACCOUNT.replace(SUB, OTHER)]}},
])
def test_unapproved_configuration_is_rejected_before_network(change):
    arm = Arm()
    with pytest.raises(ValueError):
        collect(spec(**change), arm)
    assert arm.calls == []


def test_subscription_tenant_mismatch_prevents_key_read(context):
    arm = Arm({"/subscriptions/" + SUB: subscription(tenant=OTHER), ACCOUNT + "/listKeys": keys()})
    pages = collect(value_spec(), arm, value_context=context)
    assert pages[-1].status == "FAILED"
    assert [path for _, path, _ in arm.calls] == ["/subscriptions/" + SUB]


def test_subscriptions_discovery_filters_other_tenants_and_creates_no_approvals():
    connection = spec(scopes=[{"kind": "organization", "id": TENANT}],
                       options={"mode": "discovery", "sources": ["subscriptions"]})
    arm = Arm({"/subscriptions": {"value": [subscription(), subscription(OTHER, OTHER)]}})
    pages = collect(connection, arm)
    assert pages[-1].status == "COMPLETE"
    entities = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert [row.identity.object_id for row in entities] == ["/subscriptions/" + SUB]
    assert [path for _, path, _ in arm.calls] == ["/tenants", "/subscriptions"]
    assert connection.options.azure_storage_accounts == []
    assert all(not row.proves_completeness for row in records(pages) if row.record_type == "operation_report")


def test_arm_pagination_resumes_and_rechecks_subscription_tenant():
    next_link = ORIGIN + STORAGE_PATH + "?api-version=2025-01-01&$skiptoken=next"
    connection = spec(options={"sources": ["storage_accounts"]})
    arm = Arm({STORAGE_PATH: {"value": [storage()], "nextLink": next_link}})
    first = next(adapter.collect_pages(connection, secrets={}, checkpoint=None, check=lambda: None, transport=arm))
    resumed = Arm({STORAGE_PATH: {"value": []}})
    pages = collect(connection, resumed, checkpoint=first.checkpoint)
    assert pages[-1].status == "COMPLETE"
    assert resumed.calls[0][1] == "/subscriptions/" + SUB
    assert resumed.calls[1][2]["$skiptoken"] == "next"


def test_official_vault_continuation_can_use_resources_path_inside_same_subscription():
    path = "/subscriptions/" + SUB + "/resources"
    link = ORIGIN + path + "?api-version=2024-11-01&$skiptoken=next"
    arm = Arm({VAULT_PATH: {"value": [vault()], "nextLink": link}, path: {"value": []}})
    pages = collect(spec(options={"sources": ["vaults"]}), arm)
    assert pages[-1].status == "COMPLETE" and arm.calls[-1][1] == path


@pytest.mark.parametrize("link", [
    "https://attacker.test" + STORAGE_PATH + "?api-version=2025-01-01&$skiptoken=x",
    ORIGIN + STORAGE_PATH.replace(SUB, OTHER) + "?api-version=2025-01-01&$skiptoken=x",
    ORIGIN + ACCOUNT + "/listKeys?api-version=2025-01-01&$skiptoken=x",
    ORIGIN + STORAGE_PATH + "?api-version=2025-01-01&$skiptoken=x&$skiptoken=y",
])
def test_unapproved_continuation_is_refused(link):
    with pytest.raises(ApiError):
        page_query(link, path=STORAGE_PATH, subscription=SUB)


@pytest.mark.parametrize("payload,reason", [
    ({"keys": [{"keyName": "future-key", "value": VALUE}]}, "UNSUPPORTED_OR_DUPLICATE_KEY_NAME"),
    ({"keys": [{"keyName": "key1", "value": "malformed"}]}, "INVALID_STORAGE_KEY_VALUE"),
    ({"keys": []}, "INVALID_KEY_LIST"),
    (ApiError("permission_denied"), "PERMISSION_DENIED"),
])
def test_missing_or_unsupported_key_inventory_is_partial(context, payload, reason):
    pages = collect(value_spec(), Arm({ACCOUNT + "/listKeys": payload}), value_context=context)
    assert pages[-1].status == "PARTIAL" and reason in pages[-1].reasons


def test_record_budget_rolls_back_key_task_index(context):
    pages = collect(value_spec(max_records=1), Arm({ACCOUNT + "/listKeys": keys()}), value_context=context)
    assert pages[-1].status == "PARTIAL" and pages[-1].checkpoint["index"] == 0
    assert not pages[-1].records


def test_rate_limit_keeps_same_key_task(context):
    pages = collect(value_spec(), Arm({ACCOUNT + "/listKeys": ApiError("rate_limited", retry_after=5)}), value_context=context)
    assert pages[-1].status == "WAITING" and pages[-1].checkpoint["index"] == 0
    assert pages[-1].checkpoint["requests"] == 2


def test_one_failed_metadata_source_does_not_become_an_empty_success():
    pages = collect(arm=Arm({VAULT_PATH: ApiError("permission_denied"), STORAGE_PATH: {"value": [storage()]}}))
    assert pages[-1].status == "PARTIAL"
    assert any(getattr(row, "identity", None) and row.identity.object_id == ACCOUNT for row in records(pages))


def test_forged_key_scope_is_rejected(context):
    connection = value_spec()
    row = next(row for row in records(collect(connection, Arm({ACCOUNT + "/listKeys": keys()}), value_context=context))
               if row.record_type == "entity_observation")
    row.value_match.reference = ACCOUNT.replace(SUB, OTHER) + "/keys/key1"
    assert not adapter.validate_record(connection, row) and not in_metadata_scope(connection, row)


def test_transport_allows_only_explicit_listkeys_post_and_charges_it():
    calls = []
    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=keys())
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        wire = ArmTransport(client, lambda: "synthetic", spec=value_spec(), max_requests=1, check=lambda: None)
        assert len(wire.list_keys(ACCOUNT)["keys"]) == 2
        with pytest.raises(Budget):
            wire.list_keys(ACCOUNT)
        with pytest.raises(ValueError):
            wire.list_keys(ACCOUNT.replace("acmeprod", "unapproved"))
        with pytest.raises(ValueError):
            wire.get(ACCOUNT + "/regenerateKey")
        metadata = ArmTransport(client, lambda: "synthetic", spec=spec(), max_requests=1, check=lambda: None)
        with pytest.raises(ValueError):
            metadata.list_keys(ACCOUNT)
    assert len(calls) == 1 and calls[0].method == "POST"
    assert calls[0].url.host == "management.azure.com"


def test_cancellation_propagates_before_any_collection():
    def cancel():
        raise RuntimeError("synthetic cancellation")
    arm = Arm()
    with pytest.raises(RuntimeError, match="cancellation"):
        collect(arm=arm, check=cancel)
    assert arm.calls == []


def test_additional_subscription_does_not_gain_key_access_without_explicit_account(context):
    connection = value_spec(scopes=[{"kind": "subscription", "id": SUB}, {"kind": "subscription", "id": OTHER}])
    arm = Arm({ACCOUNT + "/listKeys": keys(), "/subscriptions/" + OTHER: subscription(OTHER)})
    pages = collect(connection, arm, value_context=context)
    assert pages[-1].status == "COMPLETE"
    assert [path for method, path, _ in arm.calls if method == "POST"] == [ACCOUNT + "/listKeys"]
    report = next(row for row in records(pages) if row.record_type == "operation_report" and row.scope.id == OTHER)
    assert report.status == "NOT_REQUESTED" and report.value_access == "NOT_REQUESTED"


def test_forged_resume_path_fails_before_tenant_authentication():
    connection = spec()
    state = adapter._state(connection, None, adapter._tasks(connection))
    state["cursor"] = {"continuation": {"path": VAULT_PATH.replace(SUB, OTHER),
                                       "params": {"api-version": "2024-11-01", "$skiptoken": "next"}}}
    arm = Arm()
    with pytest.raises(ValueError, match="CHECKPOINT"):
        collect(connection, arm, checkpoint=state)
    assert arm.calls == []


def test_page_limit_and_cycle_never_report_complete_metadata():
    connection = spec(options={"sources": ["storage_accounts"]}, max_pages=1)
    link = ORIGIN + STORAGE_PATH + "?api-version=2025-01-01&$skiptoken=again"
    pages = collect(connection, Arm({STORAGE_PATH: {"value": [storage()], "nextLink": link}}))
    assert pages[-1].status == "PARTIAL" and "PAGE_LIMIT_REACHED" in pages[-1].reasons
    repeated = collect(spec(options={"sources": ["storage_accounts"]}),
                       Arm({STORAGE_PATH: {"value": [storage()], "nextLink": link}}))
    assert repeated[-1].status == "PARTIAL" and "PAGINATION_CYCLE" in repeated[-1].reasons


def test_discovered_unapproved_vault_uri_and_foreign_resources_are_partial():
    row = vault()
    row["properties"]["vaultUri"] = "https://unapproved.example.com/"
    pages = collect(spec(options={"sources": ["vaults"]}), Arm({VAULT_PATH: {"value": [row]}}))
    assert pages[-1].status == "PARTIAL"
    assert not any(record.record_type == "entity_observation" for record in records(pages))


def test_a_vault_and_account_in_a_unicode_resource_group_are_inventoried():
    # Resource group names allow Unicode letters and digits (Char.IsLetterOrDigit).
    account = ACCOUNT.replace("/Approved/", "/운영-그룹(1)/")
    identifier = VAULT.replace("/Approved/", "/운영-그룹(1)/")
    arm = Arm({STORAGE_PATH: {"value": [{**storage(), "id": account}]},
               VAULT_PATH: {"value": [{**vault(), "id": identifier}]}})
    pages = collect(arm=arm)
    assert pages[-1].status == "COMPLETE"
    assert {row.identity.object_id for row in records(pages) if row.record_type == "entity_observation"} == {
        account, identifier}


def test_a_vaults_creation_time_comes_from_system_data():
    from cremore.coverage.facts import unpack_facts

    row = {**vault(), "systemData": {"createdAt": "2020-01-01T12:00:00.0000000Z"}}
    pages = collect(spec(options={"sources": ["vaults"]}), Arm({VAULT_PATH: {"value": [row]}}))
    entity = next(record for record in records(pages) if record.record_type == "entity_observation")
    assert unpack_facts([f.model_dump() for f in entity.facts])["created_at"] == "2020-01-01T12:00:00+00:00"
