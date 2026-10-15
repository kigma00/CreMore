"""Who owns each Azure DevOps PAT: an Entra user's originId is its Entra ID object id."""

import httpx

from cremore_azure_provider.devops_tokens import adapter, owners
from cremore_azure_provider.devops_tokens.devops_tokens_test import ALICE, BOB, collect, token

ENTRA_OBJECT = "0f0f0f0f-1111-4222-8333-444444444444"


def graph(request):
    path = request.url.raw_path.decode().split("?", 1)[0]
    if path == "/acme/_apis/graph/users":
        return httpx.Response(200, json={"count": 2, "value": [
            {"descriptor": ALICE, "principalName": "alice@acme.test", "mailAddress": "alice@acme.test",
             "subjectKind": "user", "origin": "aad", "originId": ENTRA_OBJECT.upper()},
            {"descriptor": BOB, "principalName": "bob@outlook.test", "mailAddress": "bob@outlook.test",
             "subjectKind": "user", "origin": "msa", "originId": "not-a-guid"}]})
    descriptor = path.rsplit("/", 1)[1]
    tokens = {ALICE: [token("aaaaaaaa-0000-4000-8000-000000000001")],
              BOB: [token("bbbbbbbb-0000-4000-8000-000000000002", valid=False)]}
    return httpx.Response(200, json={"value": tokens[descriptor], "continuationToken": None})


def test_an_entra_users_token_names_its_object_id_and_a_microsoft_account_only_its_email():
    records, final = collect(graph)
    assert final.status == "COMPLETE"
    rows = {record.identity.object_id: {"summary": record.model_dump()} for record in records
            if record.record_type == "entity_observation"}
    alice = owners.credential_owner(rows["pat:acme:aaaaaaaa-0000-4000-8000-000000000001"])
    assert ("IDP_OBJECT_ID", ENTRA_OBJECT) in alice["keys"] and ("VERIFIED_EMAIL", "alice@acme.test") in alice["keys"]
    assert (alice["state"], alice["credential_type"]) == ("ACTIVE", "AZURE_DEVOPS_PAT")
    bob = owners.credential_owner(rows["pat:acme:bbbbbbbb-0000-4000-8000-000000000002"])
    assert bob["keys"] == [("VERIFIED_EMAIL", "bob@outlook.test")] and bob["state"] == "REVOKED_OR_EXPIRED"
    assert all(adapter.validate_record(adapter_spec(), record) for record in records)


def test_the_pat_creator_is_not_declared_supported_since_none_is_collected():
    from cremore.api.credential_records import _FIELDS
    from cremore.coverage.facts import unpack_facts
    from cremore.onboarding.catalog import INVENTORY_FIELDS
    from cremore_azure_provider.onboarding import DEVOPS_TYPES

    records, _ = collect(graph)
    for record in records:
        if record.record_type != "entity_observation":
            continue
        row = {"summary": record.model_dump()}
        assert not set(unpack_facts(row["summary"]["facts"])) & set(_FIELDS["creator"])
        assert owners.credential_owner(row).get("relation") != "created_by"
    # The console shows "Supported -- the provider API returns this value" for a Y.
    assert DEVOPS_TYPES[0]["support"][INVENTORY_FIELDS.index("creator")] != "Y"


def adapter_spec():
    from cremore_azure_provider.devops_tokens.devops_tokens_test import spec

    return spec()
