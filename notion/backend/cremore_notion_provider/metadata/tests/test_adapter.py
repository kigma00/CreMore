"""Synthetic Admin API contracts; all HTTP is handled by httpx.MockTransport."""

from datetime import UTC, datetime

import httpx
import pytest
from cremore_notion_provider.metadata import API_VERSION, ORIGIN
from cremore_notion_provider.metadata.adapter import (
    _compare_runs,
    collect_pages,
    native_snapshots,
    validate_machine_record,
    validate_record,
    validate_spec,
)
from cremore_notion_provider.metadata.descriptor import DESCRIPTOR
from cremore_notion_provider.metadata.normalization import epoch_milliseconds

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.providers.facts import unpack_facts

WORKSPACE = "00000000-0000-4000-8000-000000000001"
WORKSPACE_TWO = "00000000-0000-4000-8000-000000000002"
TOKEN_ID = "00000000-0000-4000-8000-000000000010"
USER_ID = "00000000-0000-4000-8000-000000000020"
BEARER = "adm_" + "synthetic-admin-fixture-only"
STAMP = datetime(2026, 9, 25, tzinfo=UTC)


def spec(**patch):
    values = {"name": "Synthetic Notion", "provider": "notion", "origin": ORIGIN,
              "scopes": [{"kind": "workspace", "id": WORKSPACE}], "capabilities": ["inventory"],
              "auth_type": "bearer", "secret_refs": {"token": "vault://notion/admin"},
              "options": {"requests_per_second": 100.0}}
    values.update(patch)
    return MetadataConnectionSpec.model_validate(values)


def pat(**patch):
    row = {"id": TOKEN_ID, "creator": {"id": USER_ID, "name": "Synthetic User"},
           "created_at": 1788220800000, "status": "active", "name": "Synthetic PAT"}
    row.update(patch)
    return row


def mcp(**patch):
    row = {"client": {"key": "synthetic-client", "type": "other", "name": "Synthetic Client"},
           "user": {"id": USER_ID}, "workspaces": [{"id": WORKSPACE}],
           "created_at": 1788220800000, "is_enterprise_managed": False,
           "last_active_at": 1788220801000}
    row.update(patch)
    return row


def payload(*rows, cursor=None):
    result = {"results": list(rows), "has_more": cursor is not None}
    if cursor is not None:
        result["next_cursor"] = cursor
    return result


def client_for(responses, requests):
    def handle(request):
        requests.append(request)
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, httpx.Response):
            return response
        return httpx.Response(200, json=response)

    return httpx.Client(transport=httpx.MockTransport(handle))


def run(responses, *, connection=None, checkpoint=None, prior=(), check=lambda: None):
    requests = []
    with client_for(list(responses), requests) as client:
        pages = list(collect_pages(connection or spec(), secrets={"token": BEARER},
                     checkpoint=checkpoint or {}, check=check, read_records=lambda: iter(prior),
                     client=client, now=STAMP, sleep=lambda seconds: None))
    return pages, requests


def records(pages):
    return [item for page in pages for item in page.records]


def entities(pages):
    return [item for item in records(pages) if item.record_type == "entity_observation"]


def encoded(pages):
    return "".join(page.model_dump_json() for page in pages)


def test_pat_contract_fields_origin_version_and_no_fabricated_authentication():
    pages, requests = run([payload(pat(
        status="revoked", expires_at=1788220800123, last_used_at=1788220800456,
        revoked_at=1788220800789, revoked_by={"type": "organization_bot", "id": USER_ID}))])
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url).split("?")[0] == ORIGIN + f"/admin/v1/spaces/{WORKSPACE}/personal_access_tokens"
    assert request.url.params == httpx.QueryParams({"page_size": 100})
    assert request.headers["Notion-Version"] == API_VERSION
    assert request.headers["Authorization"] == "Bearer " + BEARER
    assert request.method == "GET"
    item = entities(pages)[0]
    values = unpack_facts(item.model_dump()["facts"])
    assert values["expires_at"] == "2026-09-01T00:00:00.123+00:00"
    assert values["revoked_at"] == "2026-09-01T00:00:00.789+00:00"
    assert item.normalized_state == "REVOKED" and item.state_basis == "PROVIDER_REPORTED"
    assert item.value_match is None and item.permissions == []
    assert all(not page.principal_verified and page.principal_id is None for page in pages)
    reports = [row for row in records(pages) if row.record_type == "operation_report"]
    assert [(row.status, row.proves_completeness) for row in reports] == [("COMPLETE", True), ("NOT_REQUESTED", False)]
    assert all(validate_machine_record(spec(), row) for row in records(pages))
    assert pages[-1].status == "COMPLETE" and BEARER not in encoded(pages)


@pytest.mark.parametrize("patch", [
    {"origin": "https://example.com"}, {"edition": "self_managed"},
    {"scopes": [{"kind": "organization", "id": WORKSPACE}]},
    {"scopes": [{"kind": "workspace", "id": "../outside"}]},
    {"scopes": [{"kind": "workspace", "id": WORKSPACE.replace("-", "")}]},
    {"auth_type": "token"}, {"secret_refs": {}},
    {"secret_refs": {"token": "vault://notion/admin", "username": "vault://notion/user"}},
    {"capabilities": ["inventory", "audit"]}, {"principal_pin": "unverifiable"},
    {"options": {"page_size": 101}}, {"options": {"mode": "workspace"}},
    {"options": {"sources": ["all_tokens"]}}, {"options": {"include_deleted": True}},
    {"options": {"include_actions": True}}, {"options": {"locations": ["elsewhere"]}},
])
def test_reject_unsupported_specs_before_http(patch):
    with pytest.raises(ValueError):
        validate_spec(spec(**patch))


def test_pagination_all_statuses_multiple_workspaces_and_safe_resume():
    requests = []
    connection = spec(scopes=[{"kind": "workspace", "id": WORKSPACE}, {"kind": "workspace", "id": WORKSPACE_TWO}])
    with client_for([payload(pat(), cursor="cursor_2")], requests) as client:
        stream = collect_pages(connection, secrets={"token": BEARER}, checkpoint={}, check=lambda: None,
                               read_records=lambda: iter(()), client=client, now=STAMP)
        first = next(stream)
        stream.close()
    prior = [row.model_dump() for row in first.records]
    pages, resumed = run([payload(pat(id=USER_ID, status="expired")), payload(pat(status="revoked"))],
                         connection=connection, checkpoint=first.checkpoint, prior=prior)
    assert resumed[0].url.params["cursor"] == "cursor_2"
    assert "cursor" not in resumed[1].url.params
    assert f"/spaces/{WORKSPACE_TWO}/" in resumed[1].url.path
    assert [row.normalized_state for row in entities(pages)] == ["EXPIRED", "REVOKED"]
    assert pages[-1].status == "COMPLETE"
    assert pages[-1].checkpoint["requests"] == 3
    assert pages[-1].checkpoint["records"] == len(prior) + len(records(pages))


def test_mcp_source_is_filtered_and_composite_identity_distinguishes_auth_settings():
    connection = spec(options={"sources": ["mcp_client_connections"], "requests_per_second": 100.0})
    managed = mcp(is_enterprise_managed=True, idp_issuer="https://idp.example.test")
    pages, requests = run([payload(mcp(), managed)], connection=connection)
    assert requests[0].url.path == "/admin/v1/mcp_client_connections"
    assert requests[0].url.params["workspace_ids"] == WORKSPACE
    assert len({item.identity.object_id for item in entities(pages)}) == 2
    assert all(item.identity.kind == "installation" and item.normalized_state == "UNKNOWN" for item in entities(pages))
    assert all(validate_record(connection, row) for row in records(pages))
    assert pages[-1].status == "COMPLETE"


def test_mcp_response_cannot_relabel_other_workspaces():
    connection = spec(options={"sources": ["mcp_client_connections"]})
    pages, _ = run([payload(mcp(workspaces=[{"id": WORKSPACE_TWO}]))], connection=connection)
    assert not entities(pages) and pages[-1].status == "PARTIAL"
    assert "NOTION_INVALID_RECORD" in pages[-1].reasons


def mcp_reports(pages):
    return [row for row in records(pages) if row.record_type == "operation_report"
            and row.provenance.operation == "notion.mcp_client_connections"]


BOTH = {"sources": ["personal_access_tokens", "mcp_client_connections"], "requests_per_second": 100.0}


@pytest.mark.parametrize("pat_answer,verified", [(payload(), True), (httpx.Response(404, json={}), False)])
def test_empty_mcp_listing_proves_completeness_only_for_a_verified_workspace(pat_answer, verified):
    # MCP answers an unknown or foreign workspace ID with []; only a PAT page (404 otherwise) shows it exists.
    connection = spec(options=BOTH)
    pages, _ = run([pat_answer, payload()], connection=connection)
    assert [row.proves_completeness for row in mcp_reports(pages)] == [verified]
    assert ("NOTION_WORKSPACE_UNVERIFIED" in pages[-1].reasons) is not verified
    assert all(validate_record(connection, row) for row in records(pages))
    assert pages[-1].status == ("COMPLETE" if verified else "PARTIAL")


def test_workspace_verified_by_the_pat_list_survives_a_resume():
    connection = spec(options=BOTH)
    with client_for([payload()], []) as client:
        stream = collect_pages(connection, secrets={"token": BEARER}, checkpoint={}, check=lambda: None,
                               read_records=lambda: iter(()), client=client, now=STAMP)
        first = next(stream)
        stream.close()
    prior = [row.model_dump() for row in first.records]
    pages, requests = run([payload()], connection=connection, checkpoint=first.checkpoint, prior=prior)
    assert [request.url.path for request in requests] == ["/admin/v1/mcp_client_connections"]
    assert [row.proves_completeness for row in mcp_reports(pages)] == [True]
    assert pages[-1].status == "COMPLETE"


def test_projection_omits_unknown_fields_and_token_echoes_without_logging(caplog):
    row = pat(name="label " + BEARER, access_token="ntn_" + "synthetic-leaked-fixture",
              creator={"id": USER_ID, "email": BEARER,
                       "profile_photo_url": "https://example.test/photo?secret=private"})
    row[BEARER] = "ignored"
    pages, _ = run([payload(row)])
    assert BEARER not in encoded(pages) + caplog.text
    assert "synthetic-leaked-fixture" not in encoded(pages) + caplog.text
    assert "photo?secret" not in encoded(pages)
    assert entities(pages)[0].omissions and pages[-1].status == "PARTIAL"
    assert not next(row for row in records(pages) if row.record_type == "operation_report").proves_completeness


def test_intentionally_omitted_profile_image_does_not_hide_pat_inventory_completeness():
    pages, _ = run([payload(pat(creator={"id": USER_ID, "profile_photo_url": "https://example.test/photo"}))])
    assert pages[-1].status == "COMPLETE"
    assert entities(pages)[0].omissions[0].reason == "PROFILE_IMAGE_NOT_COLLECTED"
    assert "https://example.test/photo" not in encoded(pages)


@pytest.mark.parametrize("patch", [
    {"user": "wrong"}, {"workspaces": []}, {"workspaces": [{"id": "invalid"}]},
    {"is_enterprise_managed": "false"}, {"client": {"key": "", "name": "Client", "type": "other"}},
    {"idp_issuer": "https://idp.example.test", "is_enterprise_managed": False},
    {"idp_issuer": "https://idp.example.test?token=sensitive", "is_enterprise_managed": True},
    {"idp_issuer": "https://username:password@idp.example.test", "is_enterprise_managed": True},
])
def test_invalid_mcp_metadata_never_becomes_a_complete_inventory(patch):
    connection = spec(options={"sources": ["mcp_client_connections"]})
    pages, _ = run([payload(mcp(**patch))], connection=connection)
    assert not entities(pages) and pages[-1].status == "PARTIAL"


@pytest.mark.parametrize("value", [None, True, "1788220800000", float("inf"), float("nan"), -1, 253402300800000])
def test_epoch_milliseconds_is_strict(value):
    with pytest.raises(ValueError):
        epoch_milliseconds(value)


@pytest.mark.parametrize("patch", [
    {"id": "ntn_" + "synthetic-fixture"}, {"creator": {"id": "outside"}},
    {"status": "verified"}, {"created_at": True}, {"created_at": "2026-09-01"},
])
def test_invalid_provider_records_are_rejected_without_empty_success(patch):
    pages, _ = run([payload(pat(**patch))])
    assert not entities(pages) and pages[-1].status == "PARTIAL"
    assert "NOTION_INVALID_RECORD" in pages[-1].reasons


def test_bad_optional_date_is_omitted_and_collection_is_partial():
    pages, _ = run([payload(pat(last_used_at=False))])
    assert len(entities(pages)) == 1
    assert "last_used_at" not in unpack_facts(entities(pages)[0].model_dump()["facts"])
    assert pages[-1].status == "PARTIAL"


@pytest.mark.parametrize("change", [
    lambda x: x["identity"].update(object_id="pat:" + WORKSPACE_TWO + ":" + TOKEN_ID),
    lambda x: x["identity"].update(origin="https://example.com"),
    lambda x: x["scope"].update(id=WORKSPACE_TWO),
    lambda x: x["provenance"].update(resource_id="workspace:" + WORKSPACE_TWO + "/personal_access_tokens"),
    lambda x: x["provenance"].update(operation="notion.mcp_client_connections"),
    lambda x: x.update(normalized_state="EXPIRED"),
    lambda x: x["facts"].append({"name": "password_hint", "value": "unsafe"}),
])
def test_record_validation_rejects_tampered_identity_state_and_extra_fields(change):
    from cremore.coverage.metadata_models import RECORD_ADAPTER

    pages, _ = run([payload(pat())])
    raw = entities(pages)[0].model_dump()
    change(raw)
    try:
        item = RECORD_ADAPTER.validate_python(raw)
    except ValueError:
        return
    assert not validate_record(spec(), item)


@pytest.mark.parametrize("response,reason", [
    (httpx.Response(403, text="secret provider error"), "NOTION_HTTP_403"),
    (httpx.Response(401, text="secret provider error"), "NOTION_HTTP_401"),
    (httpx.Response(302, headers={"location": "https://example.com"}), "NOTION_HTTP_302"),
    (httpx.Response(200, text="not JSON"), "NOTION_INVALID_RESPONSE"),
    ({"results": [], "has_more": "false"}, "NOTION_INVALID_RESPONSE"),
    ({"results": [], "has_more": True}, "NOTION_INVALID_CURSOR"),
    (payload(cursor="https://example.com"), "NOTION_INVALID_CURSOR"),
    (payload(cursor=BEARER), "NOTION_INVALID_CURSOR"),
])
def test_http_and_pagination_failures_are_sanitized(response, reason):
    pages, requests = run([response])
    assert len(requests) == 1 and pages[-1].status == "FAILED"
    assert reason in pages[-1].reasons
    assert "secret provider error" not in encoded(pages)
    assert all(not item.proves_completeness for item in records(pages))


def test_response_byte_and_page_size_limits():
    pages, _ = run([payload(pat(name="a" * 2000))], connection=spec(options={"max_response_bytes": 1024}))
    assert pages[-1].reasons == ["NOTION_RESPONSE_LIMIT"]
    pages, _ = run([payload(pat(), pat(id=USER_ID))], connection=spec(options={"page_size": 1}))
    assert pages[-1].reasons == ["NOTION_PAGE_SIZE_EXCEEDED"]


@pytest.mark.parametrize("response,reason", [
    (httpx.Response(429, headers={"retry-after": "123"}), "NOTION_RATE_LIMITED"),
    (httpx.Response(503), "NOTION_UNAVAILABLE"),
    (httpx.ConnectError("private transport detail"), "NOTION_UNAVAILABLE"),
])
def test_transient_failure_waits_and_resume_charges_prior_request(response, reason):
    first, _ = run([response])
    waiting = first[-1]
    assert waiting.status == "WAITING" and waiting.reasons == [reason]
    assert waiting.checkpoint["requests"] == 1 and not waiting.records
    pages, requests = run([payload(pat())], checkpoint=waiting.checkpoint)
    assert len(requests) == 1 and pages[-1].status == "COMPLETE"
    assert pages[-1].checkpoint["requests"] == 2


def test_retry_limit_preserves_previous_page_and_does_not_claim_absence():
    connection = spec(options={"max_retries": 1, "requests_per_second": 100.0})
    first, _ = run([payload(pat(), cursor="page2"), httpx.Response(429)], connection=connection)
    prior = [row.model_dump() for row in records(first)]
    second, _ = run([httpx.Response(429)], connection=connection,
                    checkpoint=first[-1].checkpoint, prior=prior)
    assert second[-1].status == "PARTIAL" and "NOTION_RETRY_LIMIT" in second[-1].reasons
    assert "NOTION_RATE_LIMITED" in second[-1].reasons
    assert next(row for row in records(second) if row.record_type == "operation_report").status == "PARTIAL"


def test_failure_in_one_workspace_keeps_other_workspace_records():
    connection = spec(scopes=[{"kind": "workspace", "id": WORKSPACE}, {"kind": "workspace", "id": WORKSPACE_TWO}])
    pages, _ = run([httpx.Response(403), payload(pat())], connection=connection)
    assert entities(pages)[0].scope.id == WORKSPACE_TWO
    assert pages[-1].status == "PARTIAL" and "NOTION_HTTP_403" in pages[-1].reasons


def test_cycle_and_duplicates_are_partial_and_bounded():
    pages, requests = run([payload(pat(), cursor="cycle"), payload(pat(), cursor="cycle")])
    assert len(requests) == 2 and len(entities(pages)) == 1
    assert {"NOTION_CURSOR_CYCLE", "NOTION_DUPLICATE_RECORD"} <= set(pages[-1].reasons)
    assert pages[-1].status == "PARTIAL"


@pytest.mark.parametrize("patch,reason,expected_requests", [
    ({"max_pages": 1}, "PAGE_BUDGET_EXCEEDED", 1),
    ({"max_requests": 1}, "REQUEST_BUDGET_EXCEEDED", 1),
    ({"max_records": 1}, "RECORD_BUDGET_EXCEEDED", 2),
])
def test_budgets_keep_only_committed_cursor_and_records(patch, reason, expected_requests):
    pages, requests = run([payload(pat(), cursor="page2"), payload(pat(id=USER_ID))], connection=spec(**patch))
    assert len(requests) == expected_requests
    assert reason in pages[-1].reasons and pages[-1].status == "PARTIAL"
    assert pages[-1].checkpoint["records"] == len(records(pages))
    if "max_records" in patch:
        assert pages[-1].checkpoint["cursor"] == "page2"


@pytest.mark.parametrize("patch", [
    {"provider": "github"}, {"config_hash": "0" * 64}, {"task": 999}, {"requests": -1},
    {"task": True}, {"cursor": "https://example.com"}, {"cursor": BEARER},
    {"task": 1}, {"task": 2}, {"version": True},
    {"cursor": "uncommitted-cursor"}, {"reasons": [BEARER]}, {"seen": ["bad-hash"]},
    {"saved": 99}, {"extra": "ignored"},
])
def test_checkpoint_tampering_rejected_before_any_http(patch):
    first, _ = run([httpx.Response(429)])
    checkpoint = {**first[-1].checkpoint, **patch}
    with pytest.raises(ValueError):
        run([], checkpoint=checkpoint)


def test_replay_count_and_scope_are_checked():
    first, _ = run([payload(pat(), cursor="page2"), httpx.Response(429)])
    with pytest.raises(ValueError, match="REPLAY_COUNT"):
        run([], checkpoint=first[-1].checkpoint)
    prior = [row.model_dump() for row in records(first)]
    prior[0]["scope"]["id"] = WORKSPACE_TWO
    with pytest.raises(ValueError, match="REPLAY_RECORD"):
        run([], checkpoint=first[-1].checkpoint, prior=prior)


def test_cancellation_is_not_converted_to_provider_failure():
    count = 0

    def check():
        nonlocal count
        count += 1
        if count == 4:
            raise RuntimeError("synthetic cancellation")

    with pytest.raises(RuntimeError, match="synthetic cancellation"):
        run([payload(pat())], check=check)


def test_native_export_and_comparison_are_scoped_and_do_not_infer_revocation():
    first, _ = run([payload(pat())])
    before = [row.model_dump() for row in records(first)]
    exported = native_snapshots(before)
    assert exported[0]["api_version"] == API_VERSION
    assert exported[0]["records"][0]["id"] == TOKEN_ID
    assert exported[0]["credential_match"] == "UNAVAILABLE"
    current, _ = run([payload(pat(status="expired"))])
    changed = _compare_runs(before, [row.model_dump() for row in records(current)], spec=spec())
    assert changed["changed"] == [{"object_id": entities(first)[0].identity.object_id, "fields": ["status"]}]
    incomplete, _ = run([httpx.Response(403)])
    result = _compare_runs(before, [row.model_dump() for row in records(incomplete)], spec=spec())
    assert not result["no_longer_listed"] and len(result["absence_not_evaluated"]) == 1
    empty, _ = run([payload()])
    result = _compare_runs(before, [row.model_dump() for row in records(empty)], spec=spec())
    assert result["no_longer_listed"] == [entities(first)[0].identity.object_id]
    assert "LISTING_ABSENCE_IS_NOT_REVOCATION" in result["notes"]
    conflicting = [row.model_dump() for row in records(empty) + records(incomplete)]
    assert not _compare_runs(before, conflicting, spec=spec())["no_longer_listed"]
    assert not _compare_runs(before, [], spec=spec(), scope_id=WORKSPACE_TWO)["absence_not_evaluated"]


def test_descriptor_matches_implemented_spec_and_sources():
    validate_spec(spec())
    assert DESCRIPTOR["provider"] == "notion"
    assert DESCRIPTOR["defaults"]["options"]["sources"] == ["personal_access_tokens"]
    for choice in DESCRIPTOR["source_options"]:
        validate_spec(spec(options={"sources": [choice["value"]]}))
    assert DESCRIPTOR["capabilities"] == ["inventory"]
    assert DESCRIPTOR["compare"] and DESCRIPTOR["native_export"]
