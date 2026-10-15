"""Synthetic administrator/SSH/CI-variable inventory contract proofs."""

import base64
import hashlib
import json
from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.models import digest
from cremore.detection.engine import Engine, EngineConfig
from cremore_gitlab_provider.metadata import adapter
from cremore_gitlab_provider.metadata.extensions import PREFIX
from cremore_gitlab_provider.metadata.http import Client, CollectionError, Response
from cremore_gitlab_provider.metadata.normalization import unpack_facts

VALUE = "ghp_" "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
KEY_BYTES = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(KEY_BYTES).decode() + " private-comment"


def spec(sources, *, instance=False, values=False, scopes=None, **changes):
    defaults = {"include_self_pat": False, "include_enterprise_pat": False,
                "include_resource_access_tokens": False, "include_service_accounts": False,
                "include_graphql": False, "enrich_users": False,
                "sources": sources, "include_values": values}
    defaults.update(changes.pop("options", {}))
    origin = "https://gitlab.example.com" if instance else "https://gitlab.com"
    return MetadataConnectionSpec.model_validate({
        "name": "Synthetic GitLab inventory", "provider": "gitlab", "origin": origin,
        "edition": "self_managed" if instance else "cloud",
        "scopes": scopes or [{"kind": "organization", "id": origin}] if instance else (
            scopes or [{"kind": "group", "id": "10"}, {"kind": "project", "id": "100"}]),
        "capabilities": ["inventory", "public_keys", "vault_metadata"] + (["vault_value"] if values else []),
        "secret_refs": {"token": "vault://synthetic/gitlab"}, "options": defaults, **changes,
    })


class Fixture(Client):
    def __init__(self, connection, routes=None, *, admin=True):
        super().__init__(adapter._config(connection), "SYNTHETIC_ADMIN", sleep=lambda _: None)
        self.calls = []
        self.routes = {"/user": {"id": 1, "is_admin": admin},
                       "/groups/10": {"id": 10, "parent_id": None},
                       "/projects/100": {"id": 100}, **(routes or {})}

    def request(self, url, query=None, variables=None):
        assert query is None
        self.requests += 1
        parsed = urlsplit(url)
        path = parsed.path.removeprefix("/api/v4")
        self.calls.append((path, parse_qs(parsed.query)))
        params = parse_qs(parsed.query)
        data = self.routes.get((path, params.get("cursor", params.get("page", ["1"]))[0]),
                               self.routes.get(path, []))
        if isinstance(data, Exception):
            raise data
        if isinstance(data, Response):
            return deepcopy(data)
        return Response(deepcopy(data), {})


@pytest.fixture
def context():
    engine = Engine(EngineConfig(fingerprint_key=b"synthetic-value-fingerprint-key-32bytes"))
    return {"engine": engine, "key_id": hashlib.sha256(engine.config.fingerprint_key).hexdigest(),
            "engine_digest": engine.detection_digest, "policy_digest": digest(["synthetic-policy"])}


def collect(connection, client, context=None, **changes):
    return list(adapter.collect_pages(connection, secrets={"token": "SYNTHETIC_ADMIN"},
                                      checkpoint=changes.pop("checkpoint", None), check=lambda: None,
                                      client=client, value_context=context, **changes))


def records(pages):
    return [item for page in pages for item in page.records]


def extras(pages):
    return [item for item in records(pages) if item.provenance.operation.startswith(PREFIX)]


def variable(key="TOKEN", environment="*", **values):
    return {"key": key, "environment_scope": environment, "value": VALUE,
            "variable_type": "env_var", "hidden": True, "masked": True,
            "protected": True, "raw": True, **values}


def test_admin_pat_deploy_and_public_key_inventory_has_explicit_scope():
    connection = spec(["instance_pat", "instance_deploy_tokens", "instance_ssh_keys", "instance_deploy_keys"], instance=True)
    client = Fixture(connection, {
        "/personal_access_tokens": [{"id": 8, "user_id": 2, "active": True, "scopes": ["read_api"], "token": VALUE}],
        "/deploy_tokens": [{"id": 9, "revoked": True}],
        "/users": [{"id": 2}, {"id": 3}],
        "/users/2/keys": [{"id": 12, "key": PUBLIC_KEY, "usage_type": "auth"}],
        "/users/3/keys": [], "/deploy_keys": [{"id": 13, "key": PUBLIC_KEY}],
    })
    pages = collect(connection, client)
    assert pages[-1].status == "COMPLETE", pages[-1].reasons
    entities = [r for r in extras(pages) if r.record_type == "entity_observation"]
    assert len(entities) == 4
    assert all(adapter.validate_machine_record(connection, r) for r in entities)
    assert ("/personal_access_tokens", {"per_page": ["100"], "page": ["1"]}) in client.calls
    assert ("/users", {"per_page": ["100"], "pagination": ["keyset"], "order_by": ["id"], "sort": ["asc"]}) in client.calls
    public = [r for r in entities if r.identity.kind == "public_key"]
    assert len(public) == 2
    assert all(unpack_facts([f.model_dump() for f in r.facts])["metadata"]["sha256_fingerprint"].startswith("SHA256:")
               for r in public)
    serialized = "".join(page.model_dump_json() for page in pages)
    assert VALUE not in serialized and PUBLIC_KEY not in serialized and "private-comment" not in serialized


@pytest.mark.parametrize("admin", [False, None, "true", 1])
def test_instance_requires_provider_reported_admin_role(admin):
    connection = spec(["instance_pat"], instance=True)
    client = Fixture(connection, admin=admin)
    pages = collect(connection, client)
    assert pages[-1].status == "FAILED" and pages[-1].reasons == ["GITLAB_ADMIN_REQUIRED"]
    assert [p for p, _ in client.calls] == ["/user"]


def test_enterprise_ssh_metadata_uses_only_confirmed_top_level_group():
    connection = spec(["enterprise_ssh_keys", "project_deploy_keys"])
    client = Fixture(connection, {"/groups/10/manage/ssh_keys": [{"id": 19, "user_id": 3, "usage_type": "auth"}],
                                  "/projects/100/deploy_keys": [{"id": 20, "can_push": False}]})
    pages = collect(connection, client)
    assert pages[-1].status == "COMPLETE"
    assert len(extras(pages)) == 2
    child = Fixture(connection, {"/groups/10": {"id": 10, "parent_id": 8}})
    partial = collect(connection, child)
    assert partial[-1].status == "PARTIAL"
    assert "GITLAB_TOP_LEVEL_GROUP_REQUIRED" in partial[-1].reasons
    assert not any("/manage/ssh_keys" in p for p, _ in child.calls)


def test_default_variables_discard_values_and_keep_safe_flags(context):
    connection = spec(["ci_variables"])
    pages = collect(connection, Fixture(connection, {"/groups/10/variables": [variable()]}), context)
    assert pages[-1].status == "COMPLETE", pages[-1].reasons
    entity = next(r for r in extras(pages) if r.record_type == "entity_observation")
    assert entity.value_match is None
    facts = unpack_facts([f.model_dump() for f in entity.facts])
    assert facts["hidden"] is True and facts["variable_raw"] is True and "raw" not in facts
    assert VALUE not in "".join(page.model_dump_json() for page in pages)


def test_opt_in_variables_match_without_secret_export_and_separate_environments(context):
    connection = spec(["ci_variables"], values=True)
    pages = collect(connection, Fixture(connection, {
        "/groups/10/variables": [variable(environment="production"), variable(environment="development")],
        "/projects/100/variables": [variable("FILE_SECRET", variable_type="file")],
    }), context)
    assert pages[-1].status == "COMPLETE", pages[-1].reasons
    matches = [r for r in extras(pages) if getattr(r, "value_match", None)]
    assert len(matches) == 3 and len({r.identity.object_id for r in matches}) == 3
    expected = hash_value(context["engine"], VALUE.encode(), {"reference": "synthetic"}, max_bytes=1024)[0]
    assert all(r.value_match.fingerprint == expected.fingerprint for r in matches)
    assert all(adapter.validate_machine_record(connection, r) for r in matches)
    export = adapter.export_records([r.model_dump() for r in records(pages)], spec=connection)
    assert "supplemental_metadata" in export and "value_match" not in json.dumps(export)
    assert VALUE not in json.dumps(export) and VALUE not in "".join(p.model_dump_json() for p in pages)


@pytest.mark.parametrize("value,reason", [(None, "VALUE_UNAVAILABLE"), ("unknown plaintext", "UNRECOGNIZED_MATERIAL"),
                                         ("", "EMPTY_VALUE")])
def test_missing_hidden_or_unrecognized_value_is_not_complete(context, value, reason):
    connection = spec(["ci_variables"], values=True)
    pages = collect(connection, Fixture(connection, {"/groups/10/variables": [variable(value=value)]}), context)
    assert pages[-1].status == "PARTIAL", pages[-1].reasons
    assert reason in pages[-1].reasons
    report = next(r for r in extras(pages) if r.record_type == "operation_report" and r.scope.id == "10")
    assert report.value_access == "PARTIAL" and not report.proves_completeness


def test_variables_scope_failure_never_claims_complete_values(context):
    connection = spec(["ci_variables"], values=True)
    pages = collect(connection, Fixture(connection, {
        "/groups/10/variables": CollectionError("PERMISSION_DENIED", "synthetic", status=403),
    }), context)
    assert pages[-1].status == "PARTIAL"
    report = next(r for r in extras(pages) if r.record_type == "operation_report" and r.scope.id == "10")
    assert report.value_access == "PARTIAL" and "VARIABLE_DISCOVERY_INCOMPLETE" in report.reasons


def test_variables_resume_uses_committed_page_and_never_replays_values(context):
    connection = spec(["ci_variables"], values=True, options={"page_size": 1})
    route = "/groups/10/variables"
    first_client = Fixture(connection, {route: Response([variable()], {"x-next-page": "2"})})
    first = []
    for page in adapter.collect_pages(connection, secrets={"token": "SYNTHETIC_ADMIN"}, checkpoint=None,
                                      check=lambda: None, client=first_client, value_context=context):
        first.append(page)
        if any(getattr(r, "value_match", None) for r in page.records):
            break
    client = Fixture(connection, {(route, "2"): []})
    rest = collect(connection, client, context, checkpoint=first[-1].checkpoint,
                   read_records=lambda: [r.model_dump() for r in records(first)])
    assert rest[-1].status == "COMPLETE", rest[-1].reasons
    assert (route, {"per_page": ["1"], "page": ["1"]}) not in client.calls
    assert (route, {"per_page": ["1"], "page": ["2"]}) in client.calls


def test_variable_value_reference_cannot_cross_scope(context):
    connection = spec(["ci_variables"], values=True)
    pages = collect(connection, Fixture(connection, {"/groups/10/variables": [variable()]}), context)
    entity = next(r for r in extras(pages) if getattr(r, "value_match", None))
    entity.value_match.reference = entity.value_match.reference.replace("groups/10/", "groups/11/")
    assert not adapter.validate_machine_record(connection, entity)


def test_source_options_need_explicit_host_scope_and_capabilities():
    with pytest.raises(ValueError, match="ADMIN_INSTANCE_SCOPE"):
        adapter.validate_spec(spec(["instance_pat"]))
    with pytest.raises(ValueError, match="PUBLIC_KEYS_CAPABILITY"):
        adapter.validate_spec(spec(["enterprise_ssh_keys"], capabilities=["inventory"]))
    with pytest.raises(ValueError, match="VARIABLE_VALUE_CAPABILITY"):
        adapter.validate_spec(spec(["instance_pat"], instance=True, values=True))


def test_admin_pagination_cannot_inject_filter_or_change_endpoint():
    connection = spec(["instance_pat"], instance=True)
    client = Fixture(connection, {"/personal_access_tokens": Response(
        [{"id": 1, "user_id": 1}],
        {"link": '<https://gitlab.example.com/api/v4/personal_access_tokens?page=2&user_id=1>; rel="next"'})})
    pages = collect(connection, client)
    assert pages[-1].status == "PARTIAL"
    assert not any(q.get("user_id") for _, q in client.calls)


def test_ci_collection_does_not_authorize_discovered_project_variables():
    connection = spec(["ci_variables"], scopes=[{"kind": "group", "id": "10"}])
    client = Fixture(connection, {"/groups/10/projects": [{"id": 100}],
                                  "/groups/10/variables": [variable()]})
    pages = collect(connection, client)
    assert pages[-1].status == "COMPLETE"
    assert any(p == "/projects/100" for p, _ in client.calls)
    assert not any(p == "/projects/100/variables" for p, _ in client.calls)


def test_failed_value_page_remains_partial_after_resume(context):
    connection = spec(["ci_variables"], values=True, options={"page_size": 1})
    route = "/groups/10/variables"
    client = Fixture(connection, {route: Response([variable(value=None)], {"x-next-page": "2"})})
    first = []
    for page in adapter.collect_pages(connection, secrets={"token": "SYNTHETIC_ADMIN"}, checkpoint=None,
                                      check=lambda: None, client=client, value_context=context):
        first.append(page)
        if any(getattr(r, "value_match", None) for r in page.records):
            break
    rest = collect(connection, Fixture(connection, {(route, "2"): []}), context,
                   checkpoint=first[-1].checkpoint,
                   read_records=lambda: [r.model_dump() for r in records(first)])
    assert rest[-1].status == "PARTIAL" and "VALUE_UNAVAILABLE" in rest[-1].reasons


def test_changed_fingerprint_key_cannot_resume_value_inventory(context):
    connection = spec(["ci_variables"], values=True)
    pages = collect(connection, Fixture(connection), context)
    changed_engine = Engine(EngineConfig(fingerprint_key=b"another-synthetic-fingerprint-key-32bytes"))
    changed = {**context, "engine": changed_engine, "engine_digest": changed_engine.detection_digest,
               "key_id": hashlib.sha256(changed_engine.config.fingerprint_key).hexdigest()}
    with pytest.raises(ValueError, match="VALUE_RESUME_CONTRACT_CHANGED"):
        collect(connection, Fixture(connection), changed, checkpoint=pages[-1].checkpoint,
                read_records=lambda: [r.model_dump() for r in records(pages)])


def test_record_limit_does_not_commit_partial_variable_page(context):
    connection = spec(["ci_variables"], values=True, max_records=5)
    pages = collect(connection, Fixture(connection, {"/groups/10/variables": [variable("ONE"), variable("TWO")]}), context)
    assert pages[-1].status == "PARTIAL" and "RECORD_LIMIT" in pages[-1].reasons
    assert not any(getattr(r, "value_match", None) for r in records(pages))


def test_user_budget_does_not_silently_truncate_instance_ssh_inventory():
    connection = spec(["instance_ssh_keys"], instance=True, max_records=3)
    pages = collect(connection, Fixture(connection, {"/users": [{"id": n} for n in range(2, 6)]}))
    assert pages[-1].status == "PARTIAL" and "GITLAB_TARGET_LIMIT" in pages[-1].reasons


def test_instance_user_discovery_interleaves_ssh_before_next_page():
    connection = spec(["instance_ssh_keys"], instance=True)
    url = connection.origin + "/api/v4/users?pagination=keyset&order_by=id&sort=asc&cursor=eyJpZCI6IjIifQ%3D%3D"
    client = Fixture(connection, {"/users": Response([{"id": 2}], {"link": f'<{url}>; rel="next"'}),
                                  "/users/2/keys": []})
    # Stop after the first user's key source commits; the next /users page
    # cannot have run before it despite the earlier queue insertion sequence.
    for page in adapter.collect_pages(connection, secrets={"token": "SYNTHETIC_ADMIN"}, checkpoint=None,
                                      check=lambda: None, client=client):
        if any(p == "/users/2/keys" for p, _ in client.calls):
            break
    assert [p for p, _ in client.calls] == ["/user", "/users", "/users/2/keys"]


@pytest.mark.parametrize("rows", [[variable(), variable()], [variable(environment=None)], [variable(key="bad-key")]])
def test_invalid_variable_page_rolls_back_all_observations(rows):
    connection = spec(["ci_variables"])
    pages = collect(connection, Fixture(connection, {"/groups/10/variables": rows}))
    assert pages[-1].status == "PARTIAL"
    assert not any(r.record_type == "entity_observation" for r in extras(pages))


def test_comparison_includes_supplemental_metadata_and_partial_absence(context):
    connection = spec(["ci_variables"], values=True)
    before = [r.model_dump() for r in records(collect(connection, Fixture(connection, {
        "/groups/10/variables": [variable()],
    }), context))]
    after = [r.model_dump() for r in records(collect(connection, Fixture(connection), context))]
    changes = adapter._compare_runs(before, after, spec=connection)
    assert len(changes) == 1 and changes[0]["change"] == "not_observed"
    partial = [r.model_dump() for r in records(collect(connection, Fixture(connection, {
        "/groups/10/variables": CollectionError("PERMISSION_DENIED", "synthetic", 403),
    }), context))]
    unknown = adapter._compare_runs(before, partial, spec=connection)
    assert len(unknown) == 1 and unknown[0]["change"] == "observation_unknown"
    assert "fingerprint" not in json.dumps(changes + unknown)


def test_self_pat_query_remains_filtered_when_admin_options_not_selected():
    connection = spec([], instance=True, scopes=[{"kind": "user", "id": "self"}],
                      options={"include_self_pat": True})
    client = Fixture(connection)
    pages = collect(connection, client)
    assert pages[-1].status == "COMPLETE"
    paths = [(p, q) for p, q in client.calls if p == "/personal_access_tokens"]
    assert len(paths) == 1 and paths[0][1]["user_id"] == ["1"]


def test_resume_never_requests_forged_variable_cursor(context):
    connection = spec(["ci_variables"], values=True)
    route = "/groups/10/variables"
    client = Fixture(connection, {route: Response([variable()], {"x-next-page": "2"})})
    first = []
    for page in adapter.collect_pages(connection, secrets={"token": "SYNTHETIC_ADMIN"}, checkpoint=None,
                                      check=lambda: None, client=client, value_context=context):
        first.append(page)
        if any(getattr(r, "value_match", None) for r in page.records):
            break
    saved = deepcopy(first[-1].checkpoint)
    for task in saved["tasks"].values():
        if task["spec"]["path"] == route:
            task["next_url"] = connection.origin + "/api/v4/projects/999/variables?page=2"
    resumed = Fixture(connection)
    pages = collect(connection, resumed, context, checkpoint=saved,
                    read_records=lambda: [r.model_dump() for r in records(first)])
    assert pages[-1].status == "PARTIAL" and "PAGINATION_SCOPE_CHANGED" in pages[-1].reasons
    assert not any("999" in path for path, _ in resumed.calls)
