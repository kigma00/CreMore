"""Property-less ARM vault pages are hydrated through bounded, tenant-pinned reads."""

import httpx
import pytest

from cremore_azure_provider.arm import ORIGIN, VAULT_VERSION, adapter
from cremore_azure_provider.arm.arm_test import (
    OTHER,
    SUB,
    TENANT,
    VAULT,
    VAULT_PATH,
    records,
    spec,
    subscription,
    vault,
)
from cremore_azure_provider.arm.transport import ArmTransport

SECOND = VAULT.replace("acme-prod", "acme-second")
THIRD = VAULT.replace("acme-prod", "acme-third")
RESOURCES = f"/subscriptions/{SUB}/resources"


def details(identifier):
    name = identifier.rsplit("/", 1)[1]
    return {**vault(), "id": identifier, "name": name,
            "properties": {"tenantId": TENANT, "vaultUri": f"https://{name}.vault.azure.net/"}}


def collect_vaults(*, failure=None, max_requests=20, rows=None):
    calls = []
    connection = spec(options={"sources": ["vaults"], "requests_per_second": 100}, max_requests=max_requests)

    def handler(request):
        calls.append(request)
        assert request.method == "GET" and request.url.host == "management.azure.com"
        if request.url.path == "/subscriptions/" + SUB:
            return httpx.Response(200, json=subscription())
        if request.url.path == VAULT_PATH:
            return httpx.Response(200, json={"value": [vault()], "nextLink": ORIGIN + RESOURCES
                + "?api-version=2021-04-01&$skiptoken=next&$filter=resourceType%20eq%20%27Microsoft.KeyVault/vaults%27"})
        if request.url.path == RESOURCES:
            return httpx.Response(200, json={"value": rows if rows is not None else [
                {key: value for key, value in details(identifier).items() if key != "properties"}
                for identifier in (SECOND, THIRD)]})
        assert request.url.path in {SECOND, THIRD}
        assert request.url.params["api-version"] == VAULT_VERSION
        if request.url.path == SECOND and failure:
            return failure
        return httpx.Response(200, json=details(request.url.path))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pages = list(adapter.collect_pages(connection, secrets={}, checkpoint=None, check=lambda: None,
                                           client=client, token=lambda: "synthetic"))
    return pages, calls


def test_generic_resource_vault_pages_get_missing_details_and_charge_every_read():
    pages, calls = collect_vaults()
    assert pages[-1].status == "COMPLETE"
    assert {r.identity.object_id for r in records(pages) if r.record_type == "entity_observation"} == {
        VAULT, SECOND, THIRD}
    assert [r.url.path for r in calls] == ["/subscriptions/" + SUB, VAULT_PATH, RESOURCES, SECOND, THIRD]
    assert pages[-1].checkpoint["requests"] == len(calls) == 5
    report = next(r for r in records(pages) if r.record_type == "operation_report")
    assert report.status == "COMPLETE"


@pytest.mark.parametrize("failure,reason", [
    (httpx.Response(403), "PERMISSION_DENIED"),
    (httpx.Response(200, json={**details(SECOND), "properties": {
        "tenantId": OTHER, "vaultUri": "https://acme-second.vault.azure.net/"}}), "INVALID_OR_OUT_OF_SCOPE_RESOURCES"),
    (httpx.Response(200, json=details(SECOND.replace(SUB, OTHER))), "VAULT_RESOURCE_MISMATCH"),
    (httpx.Response(200, json=details(THIRD)), "VAULT_RESOURCE_MISMATCH"),
])
def test_failed_or_foreign_vault_detail_stays_partial_without_dropping_other_vaults(failure, reason):
    pages, calls = collect_vaults(failure=failure)
    assert pages[-1].status == "PARTIAL" and reason in pages[-1].reasons
    assert {r.identity.object_id for r in records(pages) if r.record_type == "entity_observation"} == {VAULT, THIRD}
    report = next(r for r in records(pages) if r.record_type == "operation_report")
    assert report.status == "PARTIAL" and reason in report.reasons
    assert pages[-1].checkpoint["requests"] == len(calls) == 5


def test_vault_detail_get_cannot_exceed_the_request_budget():
    pages, calls = collect_vaults(max_requests=3)
    assert pages[-1].status == "PARTIAL" and "REQUEST_BUDGET_EXCEEDED" in pages[-1].reasons
    assert pages[-1].checkpoint["requests"] == len(calls) == 3
    assert pages[-1].checkpoint["cursor"]["continuation"]["path"] == RESOURCES
    assert {r.identity.object_id for r in records(pages) if r.record_type == "entity_observation"} == {VAULT}


@pytest.mark.parametrize("row", [
    {"id": SECOND.replace(SUB, OTHER), "type": "Microsoft.KeyVault/vaults", "name": "acme-second"},
    {"id": SECOND + "/secrets", "type": "Microsoft.KeyVault/vaults", "name": "acme-second"},
    {"id": SECOND, "type": "Microsoft.Storage/storageAccounts", "name": "acme-second"},
    {**details(SECOND), "properties": {"tenantId": OTHER}},
])
def test_invalid_or_foreign_listed_vault_never_triggers_a_detail_read(row):
    pages, calls = collect_vaults(rows=[row])
    assert pages[-1].status == "PARTIAL" and "INVALID_OR_OUT_OF_SCOPE_RESOURCES" in pages[-1].reasons
    assert [r.url.path for r in calls] == ["/subscriptions/" + SUB, VAULT_PATH, RESOURCES]


def test_vault_detail_transport_rejects_unapproved_subscription_and_non_vault_paths():
    calls = []
    with httpx.Client(transport=httpx.MockTransport(lambda request: calls.append(request))) as client:
        wire = ArmTransport(client, lambda: "synthetic", spec=spec(), max_requests=5, check=lambda: None)
        for path in (SECOND.replace(SUB, OTHER), SECOND + "/secrets", SECOND + "/listKeys"):
            with pytest.raises(ValueError, match="UNAPPROVED_AZURE_ARM_PATH"):
                wire.get(path, {"api-version": VAULT_VERSION})
    assert calls == [] and wire.requests == 0
