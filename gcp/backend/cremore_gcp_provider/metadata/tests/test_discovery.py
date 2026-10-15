"""Synthetic hierarchy discovery never authorizes project credentials or secrets."""

from copy import deepcopy

import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER
from cremore.coverage.models import digest
from cremore_gcp_provider.metadata import adapter
from cremore_gcp_provider.metadata.discovery import BASE
from cremore_gcp_provider.metadata.normalization import record_values
from cremore_gcp_provider.metadata.transport import ApiError

from .fake import spec

ROOT = "organizations/123456"
FOLDER = "folders/234567"
NESTED = "folders/345678"


def discovery_spec(**overrides):
    options = {"mode": "discovery", **overrides.pop("options", {})}
    return spec(scopes=[{"kind": "organization", "id": "123456"}],
                capabilities=["inventory"], options=options, **overrides)


def folder(name=FOLDER, parent=ROOT, **extra):
    return {"name": name, "parent": parent, "state": "ACTIVE", "displayName": "Security", **extra}


def project(number="456789", parent=ROOT, **extra):
    return {"name": "projects/" + number, "parent": parent, "projectId": "test-project-" + number,
            "state": "ACTIVE", "displayName": "Project", **extra}


class HierarchyTransport:
    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []
        self.requests = 0

    def get(self, url, params):
        self.requests += 1
        assert url in {BASE + "projects", BASE + "folders"}
        self.calls.append((url, deepcopy(params)))
        key = (params["parent"], url.rsplit("/", 1)[1], params.get("pageToken", ""))
        value = self.responses.get(key, {})
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


def run(transport=None, connection=None, checkpoint=None, records=None, check=lambda: None):
    transport = transport or HierarchyTransport()
    results = []
    pages = list(adapter.collect_pages(
        connection or discovery_spec(), secrets={}, checkpoint=checkpoint or {}, check=check,
        transport=transport, read_records=(lambda: iter(records)) if records is not None else None,
    ))
    for page in pages:
        results.extend(item.model_dump() for item in page.records)
    return results, pages[-1], pages


def hierarchy():
    return {
        (ROOT, "projects", ""): {"projects": [project()]},
        (ROOT, "folders", ""): {"folders": [folder()]},
        (FOLDER, "projects", ""): {"projects": [project("567890", FOLDER)]},
        (FOLDER, "folders", ""): {"folders": [folder(NESTED, FOLDER)]},
        (NESTED, "projects", ""): {"projects": [project("678901", NESTED)]},
    }


def test_recursive_parent_lists_emit_only_context_resources_without_project_reads():
    transport = HierarchyTransport(hierarchy())
    records, final, _ = run(transport)
    assert final.status == "COMPLETE"
    entities = [row for row in records if row["record_type"] == "entity_observation"]
    assert len(entities) == 5
    assert {row["identity"]["kind"] for row in entities} == {"resource"}
    assert all(row["scope"] == {"kind": "organization", "id": "123456"} for row in entities)
    assert all(row["value_match"] is None and record_values(row)["selection"] == "context_only"
               for row in entities)
    assert {(params["parent"], url.rsplit("/", 1)[1]) for url, params in transport.calls} == {
        (parent, kind) for parent in (ROOT, FOLDER, NESTED) for kind in ("projects", "folders")}
    assert all(not row["proves_completeness"] for row in records if row["record_type"] == "operation_report")
    assert all(adapter.validate_record(discovery_spec(), RECORD_ADAPTER.validate_python(row)) for row in records)


def test_explicit_folder_root_has_the_same_bounded_traversal():
    connection = discovery_spec().model_copy(update={"scopes": [
        discovery_spec().scopes[0].model_copy(update={"kind": "folder", "id": "234567"})]})
    transport = HierarchyTransport({(FOLDER, "projects", ""): {"projects": [project(parent=FOLDER)]}})
    records, final, _ = run(transport, connection)
    assert final.status == "COMPLETE"
    assert all(params["parent"] == FOLDER for _, params in transport.calls)
    assert all(row["scope"] == {"kind": "folder", "id": "234567"} for row in records)


@pytest.mark.parametrize("changes", [
    {"capabilities": ["inventory", "vault_metadata"]},
    {"options": {"mode": "discovery", "include_values": True}},
    {"options": {"mode": "discovery", "locations": ["us-central1"]}},
    {"options": {"mode": "discovery", "sources": ["other"]}},
    {"options": {"mode": "discovery", "audit_lookback_days": 1}},
    {"scopes": [{"kind": "project", "id": "test-project"}]},
    {"scopes": [{"kind": "organization", "id": "../123"}]},
    {"scopes": [{"kind": "organization", "id": "123"}, {"kind": "folder", "id": "456"}]},
])
def test_discovery_contract_refuses_value_capabilities_options_and_ambiguous_roots(changes):
    body = {**discovery_spec().model_dump(), **changes}
    with pytest.raises(ValueError):
        adapter.validate_spec(type(discovery_spec()).model_validate(body))


def test_unknown_fields_and_secret_material_never_enter_discovery_records_or_export():
    sentinel = "DO_NOT_RETAIN_SECRET"
    transport = HierarchyTransport({(ROOT, "projects", ""): {"projects": [
        project(labels={"password": sentinel}, private_key=sentinel, access_token=sentinel)]}})
    records, final, _ = run(transport)
    assert final.status == "COMPLETE"
    assert sentinel not in repr(records) + repr(final.checkpoint)
    native = adapter.native_snapshots(records)
    assert len(native["discovery"]["resources"]) == 1
    assert native["discovery"]["project_inventory_authorized"] is False
    assert native["inventory"]["items"] == []
    assert native["inventory"]["coverage"] == {}
    assert adapter.compare_records(records, [])["events"] == []


@pytest.mark.parametrize("response, reason", [
    ({"folders": [folder(parent="organizations/999999")]}, "GCP_DISCOVERY_PARENT_MISMATCH"),
    ({"folders": [folder(name="https://evil.test/folders/234567")]}, "GCP_INVALID_DISCOVERY_RESOURCE"),
    ({"folders": [folder(name="folders/123456/../../keys")]}, "GCP_INVALID_DISCOVERY_RESOURCE"),
    ({"folders": "wrong"}, "INVALID_RESPONSE"),
    ({"folders": [folder(state="NEW_UNKNOWN_STATE")]}, "GCP_INVALID_DISCOVERY_METADATA"),
])
def test_bad_or_cross_parent_resources_do_not_expand_the_traversal(response, reason):
    transport = HierarchyTransport({(ROOT, "folders", ""): response})
    _, final, _ = run(transport)
    assert final.status == "PARTIAL"
    assert reason in final.reasons
    assert {params["parent"] for _, params in transport.calls} == {ROOT}


def test_duplicate_ancestor_cycle_is_partial_and_is_not_followed():
    data = hierarchy()
    data[(FOLDER, "folders", "")] = {"folders": [folder(FOLDER, FOLDER)]}
    transport = HierarchyTransport(data)
    _, final, _ = run(transport)
    assert "GCP_DUPLICATE_DISCOVERY_RESOURCE" in final.reasons
    assert len(transport.calls) == 4


def test_deleted_folders_are_context_and_are_not_recursed():
    transport = HierarchyTransport({(ROOT, "folders", ""): {
        "folders": [folder(state="DELETE_REQUESTED")]}})
    _, final, _ = run(transport, discovery_spec(options={"include_deleted": True}))
    assert final.status == "COMPLETE"
    assert all(params["showDeleted"] == "true" for _, params in transport.calls)
    assert len(transport.calls) == 2


def test_resume_after_a_committed_page_reads_only_the_next_page_and_restores_folders():
    data = hierarchy()
    data[(ROOT, "folders", "")] = {"folders": [folder()], "nextPageToken": "next"}
    data[(ROOT, "folders", "next")] = {"folders": []}
    transport = HierarchyTransport(data)
    generator = adapter.collect_pages(discovery_spec(), secrets={}, checkpoint={}, check=lambda: None,
                                      transport=transport)
    first = next(generator)
    second = next(generator)
    generator.close()
    committed = [item.model_dump() for page in (first, second) for item in page.records]
    next_transport = HierarchyTransport(data)
    resumed, final, _ = run(next_transport, checkpoint=second.checkpoint, records=committed)
    assert final.status == "COMPLETE"
    assert next_transport.calls[0][1] == {"parent": ROOT, "pageSize": 100,
                                        "showDeleted": "false", "pageToken": "next"}
    assert {params["parent"] for _, params in next_transport.calls} == {ROOT, FOLDER, NESTED}
    assert len({row["identity"]["object_id"] for row in [*committed, *resumed]
                if row["record_type"] == "entity_observation"}) == 5


def test_an_uncommitted_page_is_read_again_from_the_previous_cursor():
    transport = HierarchyTransport(hierarchy())
    generator = adapter.collect_pages(discovery_spec(), secrets={}, checkpoint={}, check=lambda: None,
                                      transport=transport)
    next(generator)
    generator.close()
    again = HierarchyTransport(hierarchy())
    run(again)
    assert again.calls[0] == transport.calls[0]


@pytest.mark.parametrize("mutate", [
    lambda state: state.update(emitted=999),
    lambda state: state.update(pages=999),
    lambda state: state.update(config_hash="0" * 64),
    lambda state: state["cursor"].update(parent="folders/999999"),
    lambda state: state["cursor"].update(kind="secrets"),
    lambda state: state["cursor"].update(page=0),
    lambda state: state["cursor"].update(seen=[]),
    lambda state: state.update(finished=True),
])
def test_checkpoint_cannot_invent_a_folder_cursor_or_skip_pending_work(mutate):
    transport = HierarchyTransport({(ROOT, "projects", ""): {"projects": [], "nextPageToken": "next"}})
    generator = adapter.collect_pages(discovery_spec(), secrets={}, checkpoint={}, check=lambda: None,
                                      transport=transport)
    first = next(generator)
    generator.close()
    state = deepcopy(first.checkpoint)
    mutate(state)
    second = HierarchyTransport()
    with pytest.raises(ValueError):
        run(second, checkpoint=state, records=[row.model_dump() for row in first.records])
    assert second.calls == []


def test_discovery_checkpoint_before_raw_storage_retirement_requires_a_new_run():
    connection = discovery_spec()
    records, final, _pages = run(connection=connection)
    legacy = connection.model_dump()
    legacy["options"]["store_values"] = False
    state = {**final.checkpoint, "config_hash": digest(legacy)}
    with pytest.raises(ValueError, match="GCP_CHECKPOINT_MISMATCH"):
        run(connection=connection, checkpoint=state, records=records)
    _records, restarted, _pages = run(connection=connection)
    assert restarted.status == "COMPLETE"


def test_resume_rejects_replay_with_a_folder_outside_the_recorded_parent_chain():
    records, final, _ = run(HierarchyTransport(hierarchy()))
    tampered = deepcopy(records)
    first_folder = next(row for row in tampered if row.get("identity", {}).get("object_id") == FOLDER)
    parent = next(fact for fact in first_folder["facts"] if fact["name"] == "parent_id")
    parent["value"] = "folders/999999"
    with pytest.raises(ValueError):
        run(checkpoint=final.checkpoint, records=tampered)


@pytest.mark.parametrize("limit, expected, calls", [
    ({"max_pages": 1}, "PAGE_BUDGET_EXCEEDED", 1),
    ({"max_requests": 1}, "REQUEST_BUDGET_EXCEEDED", 1),
    ({"max_records": 1}, "RECORD_BUDGET_EXCEEDED", 1),
    ({"options": {"max_targets": 1}}, "TARGET_BUDGET_EXCEEDED", 2),
])
def test_global_budgets_bound_requests_and_keep_discovery_partial(limit, expected, calls):
    transport = HierarchyTransport(hierarchy())
    _, final, _ = run(transport, discovery_spec(**limit))
    assert final.status == "PARTIAL"
    assert expected in final.reasons
    assert len(transport.calls) == calls


def test_permission_failure_preserves_other_results_but_never_means_empty_complete_inventory():
    data = hierarchy()
    data[(FOLDER, "projects", "")] = ApiError("permission_denied")
    records, final, _ = run(HierarchyTransport(data))
    assert final.status == "PARTIAL"
    failed = [row for row in records if row.get("status") == "PARTIAL"]
    assert len(failed) == 1 and failed[0]["proves_completeness"] is False
    assert "PERMISSION_DENIED" in final.reasons


def test_rate_limit_waits_at_the_last_committed_cursor_and_charges_retry_requests():
    transport = HierarchyTransport({(ROOT, "projects", ""): ApiError("rate_limited", retry_after=7)})
    records, final, _ = run(transport)
    assert records == [] and final.status == "WAITING"
    assert final.retry_after_seconds == 7 and final.checkpoint["requests"] == 1
    resumed = HierarchyTransport(hierarchy())
    _, completed, _ = run(resumed, checkpoint=final.checkpoint, records=records)
    assert completed.status == "COMPLETE"
    assert completed.checkpoint["requests"] == 7


def test_cancellation_between_pages_stops_before_the_next_request():
    count = 0

    def cancel():
        nonlocal count
        count += 1
        if count > 2:
            raise InterruptedError("cancelled")

    transport = HierarchyTransport(hierarchy())
    with pytest.raises(InterruptedError):
        run(transport, check=cancel)
    assert len(transport.calls) == 1


def test_machine_submission_cannot_turn_a_claimed_folder_tree_into_authorized_discovery():
    records, _, _ = run(HierarchyTransport(hierarchy()))
    assert all(not adapter.validate_machine_record(discovery_spec(), RECORD_ADAPTER.validate_python(row))
               for row in records)


def test_repeated_page_token_stops_with_partial_coverage():
    data = {(ROOT, "projects", ""): {"projects": [], "nextPageToken": "same"},
            (ROOT, "projects", "same"): {"projects": [], "nextPageToken": "same"}}
    transport = HierarchyTransport(data)
    _, final, _ = run(transport)
    assert "PAGE_TOKEN_CYCLE" in final.reasons
    assert len(transport.calls) == 3


@pytest.mark.parametrize("token", [123, "x" * 8193, "invalid\nvalue"],
                         ids=["wrong-type", "too-long", "control-character"])
def test_invalid_page_token_is_partial_and_never_replayed(token):
    transport = HierarchyTransport({(ROOT, "projects", ""): {"projects": [], "nextPageToken": token}})
    _, final, _ = run(transport)
    assert "INVALID_PAGE_TOKEN" in final.reasons
    assert len(transport.calls) == 2
    assert final.checkpoint["cursor"] == {}


def test_invalid_project_id_is_omitted_without_authorizing_a_project():
    transport = HierarchyTransport({(ROOT, "projects", ""): {"projects": [project(projectId="x" * 31)]}})
    records, final, _ = run(transport)
    assert "GCP_INVALID_DISCOVERY_PROJECT_ID" in final.reasons
    assert not any(row["record_type"] == "entity_observation" for row in records)


def test_discovery_records_do_not_prove_a_service_account_key_absent():
    records, _, _ = run(HierarchyTransport(hierarchy()))
    from .fake import EMAIL, KEY_ID

    result = adapter.link_service_account_key(records, {"type": "service_account", "client_email": EMAIL,
                                                        "private_key_id": KEY_ID})
    assert result["status"] == "unknown_in_partial_scope"


OAUTH_SECRETS = {"client_id": "synthetic.apps.googleusercontent.com", "client_secret": "synthetic-secret",
                 "refresh_token": "synthetic-refresh"}


def oauth_discovery_spec():
    return discovery_spec(auth_type="google_oauth", secret_refs={
        slot: "vault://synthetic/gcp-oauth" for slot in ("client_id", "client_secret", "refresh_token")})


def run_over_http(connection, secrets, handler):
    import httpx

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return list(adapter.collect_pages(connection, secrets=secrets, checkpoint={}, check=lambda: None,
                                          client=client))


def test_oauth_discovery_lists_with_the_authorizing_user_token_never_the_worker_adc(monkeypatch):
    """Discovery predates dashboard OAuth; an OAuth connection must not fall back to ADC."""
    import httpx

    from cremore_gcp_provider import oauth
    from cremore_gcp_provider.metadata import discovery

    minted, sent = [], []
    monkeypatch.setattr(oauth, "oauth_token", lambda fields: minted.append(dict(fields)) or (lambda: "user-token"))
    monkeypatch.setattr(discovery, "adc_token", lambda: pytest.fail("OAuth discovery used the worker ADC"))

    def handler(request):
        sent.append(request.headers["authorization"])
        return httpx.Response(200, json={})

    pages = run_over_http(oauth_discovery_spec(), OAUTH_SECRETS, handler)
    assert pages[-1].status == "COMPLETE"
    assert minted == [OAUTH_SECRETS] and sent and set(sent) == {"Bearer user-token"}


def test_adc_discovery_keeps_using_the_worker_identity(monkeypatch):
    import httpx

    from cremore_gcp_provider.metadata import discovery

    monkeypatch.setattr(discovery, "adc_token", lambda: lambda: "worker-token")
    sent = []

    def handler(request):
        sent.append(request.headers["authorization"])
        return httpx.Response(200, json={})

    pages = run_over_http(discovery_spec(), {}, handler)
    assert pages[-1].status == "COMPLETE" and set(sent) == {"Bearer worker-token"}


def test_a_broken_stored_oauth_authorization_fails_the_page_instead_of_raising(monkeypatch):
    from cremore_gcp_provider import oauth
    from cremore_gcp_provider.gcp_auth import GcpAuthError

    def expired(fields):
        raise GcpAuthError("GCP_OAUTH_REAUTH_REQUIRED")

    monkeypatch.setattr(oauth, "oauth_token", expired)
    pages = run_over_http(oauth_discovery_spec(), OAUTH_SECRETS, lambda request: pytest.fail("no request expected"))
    assert (pages[-1].status, pages[-1].reasons) == ("FAILED", ["GCP_OAUTH_REAUTH_REQUIRED"])



def _run_with_token_service(connection, answers, monkeypatch):
    """Collect with the real oauth_token bound to a MockTransport: the token endpoint replies
    from ``answers`` in turn and nothing leaves the process."""
    import httpx

    from cremore_gcp_provider import oauth

    calls = {"token": 0}

    def handler(request):
        if request.url.host == "oauth2.googleapis.com":
            calls["token"] += 1
            status, headers = answers[min(calls["token"], len(answers)) - 1]
            body = {"access_token": "user-token", "token_type": "Bearer", "expires_in": 60} if status == 200 else {}
            return httpx.Response(status, json=body, headers=headers)
        return httpx.Response(404, json={})

    real = oauth.oauth_token
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        monkeypatch.setattr(oauth, "oauth_token",
                            lambda fields: real(fields, client_factory=lambda: oauth._Borrowed(client)))
        pages = list(adapter.collect_pages(connection, secrets=OAUTH_SECRETS, checkpoint={}, check=lambda: None,
                                           client=client))
    return pages, calls


def _oauth_inventory_spec():
    return spec(auth_type="google_oauth", secret_refs={slot: "vault://synthetic/gcp-oauth" for slot in OAUTH_SECRETS})


@pytest.mark.parametrize("mode", ["inventory", "discovery"])
def test_a_throttled_oauth_refresh_waits_and_resumes_instead_of_ending_the_run(mode, monkeypatch):
    """Review 2026-09-26: Google's 429/503 on a token refresh used to end the run as FAILED."""
    connection = oauth_discovery_spec() if mode == "discovery" else _oauth_inventory_spec()
    pages, calls = _run_with_token_service(connection, [(429, {"Retry-After": "120"})], monkeypatch)
    assert (pages[-1].status, pages[-1].reasons, pages[-1].retry_after_seconds) == (
        "WAITING", ["GCP_OAUTH_RATE_LIMITED"], 120)
    assert pages[-1].checkpoint and calls["token"] == 1


def test_a_mid_run_refresh_outage_waits_without_retrying_the_token_service_per_request(monkeypatch):
    # expires_in=60 makes every request refresh: the first succeeds, the next is a 503.
    pages, calls = _run_with_token_service(_oauth_inventory_spec(), [(200, {}), (503, {})], monkeypatch)
    assert (pages[-1].status, pages[-1].reasons) == ("WAITING", ["GCP_OAUTH_TEMPORARILY_UNAVAILABLE"])
    assert calls["token"] == 2
