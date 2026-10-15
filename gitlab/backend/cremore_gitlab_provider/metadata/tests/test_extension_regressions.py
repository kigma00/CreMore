"""Synthetic regressions for extension pagination and shared credential facts."""

from copy import deepcopy
from urllib.parse import urlencode

import pytest

from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.onboarding import catalog
from cremore_gitlab_provider import remediation
from cremore_gitlab_provider.metadata import adapter, extensions, normalization, owners
from cremore_gitlab_provider.metadata.http import CollectionError, Response
from cremore_gitlab_provider.metadata.model import identity

from .test_extensions import PUBLIC_KEY, VALUE, Fixture, collect, extras, spec


@pytest.fixture(autouse=True)
def fixed_time(monkeypatch):
    monkeypatch.setattr(extensions, "now", lambda: "2026-10-01T00:00:00+00:00")
    monkeypatch.setattr(normalization, "now", lambda: "2026-10-01T00:00:00+00:00")


def user_task(connection, url):
    return {"spec": {"handler": "instance_ssh_keys", "path": "/users",
                     "context": {"scope": connection.scopes[0].model_dump()},
                     "params": {"pagination": "keyset", "order_by": "id", "sort": "asc"}},
            "next_url": url}


def test_users_cursor_next_link_collects_all_keys():
    connection = spec(["instance_ssh_keys"], instance=True)
    cursor = "eyJpZCI6IjIifQ=="
    # Grape `params` = request query + every `default: false` Users param (CE, custom attributes, EE).
    echoed = ("active", "admins", "auditors", "blocked", "exclude_active", "exclude_external", "exclude_humans",
              "exclude_internal", "external", "humans", "skip_ldap", "with_custom_attributes",
              "without_project_bots", "without_projects")
    query = {"pagination": "keyset", "order_by": "id", "sort": "asc", "cursor": cursor, "page": "1",
             "per_page": "100", **dict.fromkeys(echoed, "false")}
    url = connection.origin + "/api/v4/users?" + urlencode(query)
    client = Fixture(connection, {
        "/users": Response([{"id": 2}], {"link": f'<{url}>; rel="next"'}),
        ("/users", cursor): [{"id": 3}],
        "/users/2/keys": [{"id": 12, "key": PUBLIC_KEY}],
        "/users/3/keys": [{"id": 13, "key": PUBLIC_KEY}],
    })
    pages = collect(connection, client)
    assert pages[-1].status == "COMPLETE", pages[-1].reasons
    assert {r.identity.object_id for r in extras(pages)} == {"ssh_key:12", "ssh_key:13"}
    assert [path for path, _ in client.calls] == ["/user", "/users", "/users/2/keys", "/users", "/users/3/keys"]
    assert ("/users", {key: [value] for key, value in query.items()}) in client.calls


@pytest.mark.parametrize("change", [
    "active=true", "admins=true", "exclude_internal=true", "user_id=2", "search=alice",
    "active=false&active=true", "active=", "cursor=one&cursor=two", "unknown=",
    "sort=desc", "order_by=name", "pagination=offset",
])
def test_users_cursor_rejects_changed_query(change):
    connection = spec(["instance_ssh_keys"], instance=True)
    query = "pagination=keyset&order_by=id&sort=asc&cursor=opaque&" + change
    with pytest.raises(CollectionError) as caught:
        extensions.Extensions(connection).check_task(user_task(connection, connection.origin + "/api/v4/users?" + query))
    assert caught.value.code == "PAGINATION_SCOPE_CHANGED"


@pytest.mark.parametrize("url", [
    "https://elsewhere.example/api/v4/users", "http://gitlab.example.com/api/v4/users",
    "https://gitlab.example.com/api/v4/users/2/keys", "https://user@gitlab.example.com/api/v4/users",
    "https://gitlab.example.com/api/v4/users#fragment",
])
def test_users_cursor_keeps_origin_path_boundary(url):
    connection = spec(["instance_ssh_keys"], instance=True)
    with pytest.raises(CollectionError) as caught:
        extensions.Extensions(connection).check_task(user_task(connection, url))
    assert caught.value.code == "PAGINATION_SCOPE_CHANGED"


@pytest.mark.parametrize("source,family,instance,scope_index", [
    ("instance_pat", "personal_access_token", True, 0),
    ("instance_deploy_tokens", "deploy_token", True, 0),
    ("user_ssh_keys", "ssh_key", True, 0),
    ("instance_deploy_keys", "deploy_key", True, 0),
    ("enterprise_ssh_keys", "ssh_key", False, 0),
    ("project_deploy_keys", "deploy_key", False, 1),
])
def test_extension_facts_reach_real_consumers(source, family, instance, scope_index):
    selected = "instance_ssh_keys" if source == "user_ssh_keys" else source
    connection = spec([selected], instance=instance)
    row = extensions.observation(connection, connection.scopes[scope_index], source,
                                 {"id": 8, "user_id": 2, "active": True, "name": "Synthetic",
                                  "token": VALUE, "key": PUBLIC_KEY})
    body = row.model_dump()
    facts = unpack_facts(body["facts"])
    declared = catalog.inventory_type("gitlab", {"provider": "gitlab", "object_kind": row.identity.kind, "facts": facts})
    assert declared is not None and declared["id"] == family
    assert facts["identity"] == identity(connection.origin, family, 8, {})
    assert facts["metadata"]["user_id"] == 2
    assert adapter.validate_machine_record(connection, row)
    owner = owners.credential_owner({"summary": {"facts": body["facts"]}})
    reference = remediation.reference({"origin": connection.origin}, {"body": body})
    if source == "instance_pat":
        assert owner["account"] == "user:2" and owner["keys"] == []
        assert owner["state"] == "ACTIVE" and owner["name"] == "Synthetic"
        assert reference["key"] == {"namespace": "personal_access_token", "token_id": 8}
        assert reference["user_id"] == 2
    else:
        assert owner is None and reference is None
    assert VALUE not in row.model_dump_json() and PUBLIC_KEY not in row.model_dump_json()
    for field, replacement in (("family", "project_access_token"), ("identity", identity(connection.origin, family, 99, {}))):
        forged = row.model_copy(deep=True)
        forged.facts = FactWriter().facts({**facts, field: replacement})
        assert not adapter.validate_machine_record(connection, forged)


def test_extension_metadata_comparison_and_key_absence_use_nested_facts():
    connection = spec(["instance_ssh_keys"], instance=True)
    row = extensions.observation(connection, connection.scopes[0], "user_ssh_keys", {"id": 8, "user_id": 2})
    before = row.model_dump()
    changed = extensions.observation(connection, connection.scopes[0], "user_ssh_keys", {"id": 8, "user_id": 2, "title": "new"})
    assert extensions.compare_metadata([before], [changed.model_dump()])[0]["fields"] == ["display_name"]
    report = {"provenance": {"operation": "gitlab.native.source"},
              "facts": [f.model_dump() for f in FactWriter().facts({
                  "status": "complete", "spec": {"handler": "user_ssh_keys", "path": "/users/2/keys"}})]}
    assert extensions.compare_metadata([before], [report])[0]["change"] == "not_observed"
    assert extensions.compare_metadata([before], [])[0]["change"] == "observation_unknown"
    legacy = deepcopy(before)
    legacy["facts"] = [f.model_dump() for f in FactWriter().facts(unpack_facts(before["facts"])["metadata"])]
    assert extensions.compare_metadata([legacy], [before]) == []
    assert extensions.compare_metadata([legacy], [report])[0]["change"] == "not_observed"


@pytest.mark.parametrize("source", ["instance_deploy_tokens", "group_deploy_token", "project_deploy_token"])
def test_live_deploy_token_state_is_provider_reported(source):
    connection = spec(["instance_deploy_tokens"], instance=True)
    metadata = {"id": 8, "revoked": False, "expired": False}
    if source == "instance_deploy_tokens":
        row = extensions.observation(connection, connection.scopes[0], source, metadata)
    else:
        scope = {"kind": source.split("_")[0], "id": 10}
        row = normalization.record(connection, connection.scopes[0], "inventory", {
            "identity": identity(connection.origin, source, 8, scope), "metadata": metadata})
    assert (row.provider_state, row.normalized_state, row.state_basis) == ("active", "ACTIVE", "PROVIDER_REPORTED")


@pytest.mark.parametrize("metadata,expected", [
    ({}, "UNKNOWN"), ({"revoked": False}, "UNKNOWN"), ({"expired": False}, "UNKNOWN"),
    ({"revoked": 0, "expired": False}, "UNKNOWN"),
    ({"revoked": False, "expired": False, "active": None}, "UNKNOWN"),
    ({"revoked": False, "expired": False, "active": False}, "INACTIVE"),
    ({"active": True}, "ACTIVE"), ({"revoked": True, "expired": False}, "REVOKED"),
    ({"revoked": False, "expired": True}, "EXPIRED"),
])
def test_state_preserves_missing_flags_and_pat_precedence(metadata, expected):
    assert normalization._state(metadata)[1] == expected


def test_instance_deploy_key_keeps_readonly_and_write_project_references():
    connection = spec(["instance_deploy_keys"], instance=True)
    row = extensions.observation(connection, connection.scopes[0], "instance_deploy_keys", {
        "id": 8, "projects_with_readonly_access": [{"id": 11, "name": "discard"}, {"id": True}, None],
        "projects_with_write_access": [{"id": 7}], "key": PUBLIC_KEY})
    metadata = unpack_facts(row.model_dump()["facts"])["metadata"]
    assert metadata["projects"] == [{"id": 11, "access": "read"}, {"id": 7, "access": "write"}]
    assert adapter.validate_machine_record(connection, row)
