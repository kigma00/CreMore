"""Azure DevOps PAT inventory through synthetic Graph and Token Admin responses only."""

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataConnectionSpec,
    in_metadata_scope,
)
from cremore_azure_provider.devops_tokens import adapter

SECRET = "synthetic-devops-admin-pat"
NOW = datetime(2026, 9, 26, tzinfo=UTC)
ALICE, BOB = "aad.QWxpY2UtdXNlci1kZXNjcmlwdG9y", "aad.Qm9iLXVzZXItZGVzY3JpcHRvcg"


def spec(**changes):
    return MetadataConnectionSpec.model_validate({
        "name": "Acme DevOps", "provider": "azure_devops", "origin": "https://vssps.dev.azure.com",
        "auth_type": "token", "secret_refs": {"token": "vault://devops/admin"},
        "scopes": [{"kind": "organization", "id": "acme"}], "capabilities": ["inventory"], **changes})


def token(authorization, *, valid=True, valid_to="2027-01-01T00:00:00", **extra):
    return {"authorizationId": authorization, "displayName": "deploy", "scope": "vso.code vso.build",
            "validFrom": "2026-01-01T00:00:00", "validTo": valid_to, "isValid": valid, "isPublic": False,
            "userId": "11111111-2222-4333-8444-555555555555", "clientId": "00000000-0000-0000-0000-000000000000",
            "token": None, "alternateToken": None, **extra}


class DevOps:
    def __init__(self, tokens, *, users_pages=None, statuses=None):
        self.tokens, self.statuses, self.calls = tokens, statuses or {}, []
        self.users_pages = users_pages or [([ALICE, BOB], "")]

    def __call__(self, request):
        self.calls.append(request)
        assert request.headers["authorization"] == "Basic " + base64.b64encode((":" + SECRET).encode()).decode()
        assert request.url.host == "vssps.dev.azure.com"
        path = request.url.raw_path.decode().split("?", 1)[0]
        if path == "/acme/_apis/graph/users":
            index = int(request.url.params.get("continuationToken", "0") or 0)
            users, following = self.users_pages[index]
            return httpx.Response(200, headers={"x-ms-continuationtoken": following} if following else {},
                                  json={"count": len(users), "value": [
                                      {"descriptor": d, "principalName": d[4:] + "@acme.test",
                                       "mailAddress": d[4:] + "@acme.test", "subjectKind": "user"} for d in users]})
        descriptor = path.rsplit("/", 1)[1]
        assert path == "/acme/_apis/tokenadmin/personalaccesstokens/" + descriptor
        assert request.url.params["isPublic"] == "false"
        if descriptor in self.statuses:
            return httpx.Response(self.statuses[descriptor])
        return httpx.Response(200, json={"value": self.tokens.get(descriptor, []), "continuationToken": None})


def collect(transport, connection=None, **kwargs):
    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        pages = list(adapter.collect_pages(connection or spec(), secrets={"token": SECRET}, checkpoint=None,
                                           check=lambda: None, client=client, now=NOW, **kwargs))
    return [record for page in pages for record in page.records], pages[-1]


def test_every_listed_user_token_is_kept_as_metadata_and_never_its_value():
    devops = DevOps({ALICE: [token("aaaaaaaa-0000-4000-8000-000000000001"),
                             token("aaaaaaaa-0000-4000-8000-000000000002", valid=False)],
                     BOB: [token("bbbbbbbb-0000-4000-8000-000000000003", valid_to="2026-02-01T00:00:00",
                                 token="synthetic-value-must-never-be-kept")]})
    records, final = collect(devops)
    tokens = {row.identity.object_id: row for row in records if row.record_type == "entity_observation"}
    assert set(tokens) == {"pat:acme:aaaaaaaa-0000-4000-8000-000000000001", "pat:acme:aaaaaaaa-0000-4000-8000-000000000002",
                           "pat:acme:bbbbbbbb-0000-4000-8000-000000000003"}
    states = {key.rsplit(":", 1)[1][-1]: row.normalized_state for key, row in tokens.items()}
    assert states == {"1": "ACTIVE", "2": "INACTIVE", "3": "EXPIRED"}
    first = tokens["pat:acme:aaaaaaaa-0000-4000-8000-000000000001"]
    values = adapter.record_values(first.model_dump())
    assert values["scopes"] == ["vso.code", "vso.build"] and values["owner"]["email"].endswith("@acme.test")
    assert values["expires_at"] == "2027-01-01T00:00:00+00:00" and "client_id" not in values
    assert final.status == "PARTIAL" and "AZURE_DEVOPS_TOKEN_VALUE_OMITTED" in final.reasons
    [report] = [row for row in records if row.record_type == "operation_report"]
    assert (report.received_records, report.saved_records, report.proves_completeness) == (3, 3, False)
    assert all(adapter.validate_record(spec(), row) and in_metadata_scope(spec(), row) for row in records)
    dumped = json.dumps([row.model_dump() for row in records])
    assert "synthetic-value-must-never-be-kept" not in dumped and SECRET not in dumped


def test_users_are_followed_by_continuation_token_and_a_departed_user_is_partial_not_empty():
    devops = DevOps({BOB: [token("bbbbbbbb-0000-4000-8000-000000000003")]},
                    users_pages=[([ALICE], "1"), ([BOB], "")], statuses={ALICE: 404})
    records, final = collect(devops)
    assert [row.identity.object_id for row in records if row.record_type == "entity_observation"] == [
        "pat:acme:bbbbbbbb-0000-4000-8000-000000000003"]
    assert final.status == "PARTIAL" and "AZURE_DEVOPS_HTTP_404" in final.reasons
    assert [call.url.params.get("continuationToken") for call in devops.calls
            if call.url.path.endswith("/graph/users")] == [None, "1"]


def test_a_rejected_token_fails_without_claiming_an_empty_inventory():
    devops = DevOps({}, statuses={ALICE: 401})
    devops.users_pages = [([ALICE], "")]
    records, final = collect(devops)
    [report] = records
    assert report.status == "PARTIAL" and final.status == "PARTIAL" and not report.proves_completeness


def test_a_complete_listing_proves_completeness_and_forged_records_are_rejected():
    records, final = collect(DevOps({ALICE: [token("aaaaaaaa-0000-4000-8000-000000000001")]}))
    assert final.status == "COMPLETE"
    [report] = [row for row in records if row.record_type == "operation_report"]
    assert report.proves_completeness
    row = next(row.model_dump() for row in records if row.record_type == "entity_observation")
    for forged in ({**row, "normalized_state": "REVOKED"},
                   {**row, "identity": {**row["identity"], "object_id": "pat:other:aaaaaaaa-0000-4000-8000-000000000001"}},
                   {**row, "facts": row["facts"] + [{"name": "name", "value": "extra"}]}):
        assert not adapter.validate_record(spec(), RECORD_ADAPTER.validate_python(forged))


@pytest.mark.parametrize("display_name", ["[]", '{"note":"metadata"}'])
def test_rejected_optional_metadata_is_isolated_to_its_token(display_name):
    devops = DevOps({ALICE: [token("aaaaaaaa-0000-4000-8000-000000000001", displayName=display_name)],
                     BOB: [token("bbbbbbbb-0000-4000-8000-000000000003")]})
    records, final = collect(devops)
    kept = [row for row in records if row.record_type == "entity_observation"]
    assert len(kept) == 1 and kept[0].identity.object_id.endswith("0003")
    assert final.status == "PARTIAL" and "AZURE_DEVOPS_INVALID_RECORD" in final.reasons
    report = next(row for row in records if row.record_type == "operation_report")
    assert not report.proves_completeness and report.received_records == 2 and report.saved_records == 1


@pytest.mark.parametrize("change", [
    {"origin": "https://example.test"}, {"auth_type": "bearer"}, {"secret_refs": {}},
    {"scopes": [{"kind": "project", "id": "acme"}]}, {"capabilities": ["inventory", "audit"]},
    {"scopes": [{"kind": "organization", "id": "-bad"}]},
])
def test_only_an_explicit_services_organization_with_a_token_reference_is_accepted(change):
    with pytest.raises(ValueError):
        adapter.validate_spec(spec(**change))
