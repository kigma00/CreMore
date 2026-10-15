"""Official DC list shapes through the shared typed adapter; all HTTP is fake."""

import json
import uuid
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec
from cremore.coverage.providers import collector_for
from cremore_atlassian_provider.metadata import adapter
from cremore_atlassian_provider.metadata import bitbucket_dc as dc
from cremore_atlassian_provider.metadata.http import NoRedirect

from .test_collector_http import SECRET, Response

TIME = "2026-09-25T00:00:00+00:00"


def spec(**changes):
    data = {"name": "DC test", "provider": "bitbucket", "edition": "data_center",
            "origin": "https://bitbucket.example.test", "scopes": [{"kind": "user", "id": "alice"}],
            "capabilities": ["inventory"], "secret_refs": {"token": "vault://test/token"},
            "options": {"api_path": "/bitbucket", "max_retries": 0}}
    data.update(changes)
    return MetadataConnectionSpec.model_validate(data)


def page(*ids, start=0, next_start=None, rows=None):
    rows = rows if rows is not None else [{"id": i, "name": "ci", "createdDate": TIME} for i in ids]
    data = {"values": rows, "start": start, "size": len(rows), "limit": 100, "isLastPage": next_start is None}
    if next_start is not None:
        data["nextPageStart"] = next_start
    return Response(json.dumps(data).encode())


def stream(config, opener, **kwargs):
    def factory(config, scope, secrets, limits, check):
        return dc.Client(config, scope, secrets, limits, check, opener=opener)
    return adapter.collect_pages(config, secrets={"token": SECRET}, checkpoint=kwargs.pop("checkpoint", {}),
                                 check=kwargs.pop("check", lambda: None), now=lambda: TIME,
                                 client_factory=factory, **kwargs)


def run(config, responses, **kwargs):
    opener = Mock()
    opener.open.side_effect = responses
    pages = list(stream(config, opener, **kwargs))
    records = [r for p in pages for r in p.records]
    assert all(adapter.validate_record(config, RECORD_ADAPTER.validate_python(r.model_dump())) for r in records)
    return pages, records, opener


def test_three_scopes_fixed_paths_metadata_only_and_no_state_claim():
    config = spec(scopes=[{"kind": "user", "id": "alice"}, {"kind": "project", "id": "ENG"},
                          {"kind": "repository", "id": "ENG/portal"}])
    pages, records, opener = run(config, [page("1"), page("2"), page("3")])
    assert pages[-1].status == "COMPLETE"
    assert [urlsplit(c.args[0].full_url).path for c in opener.open.call_args_list] == [
        "/bitbucket/rest/access-tokens/latest/users/alice",
        "/bitbucket/rest/access-tokens/latest/projects/ENG",
        "/bitbucket/rest/access-tokens/latest/projects/ENG/repos/portal"]
    assert all(c.args[0].method == "GET" for c in opener.open.call_args_list)
    entities = [r for r in records if r.record_type == "entity_observation"]
    assert len(entities) == 3
    assert all(r.normalized_state == "UNKNOWN" and r.value_match is None and not r.permissions for r in entities)
    reports = [r for r in records if r.record_type == "operation_report"]
    assert all(not r.proves_completeness and dc.LIMITATION in r.reasons for r in reports)
    assert all(adapter.current_record_status(config, r.model_dump(), reports) == "COMPLETE" for r in entities)
    collector_for("bitbucket").validate_spec(config)


def test_epoch_millisecond_created_date_is_a_created_time_not_invalid_metadata():
    # Atlassian's access-token REST reference shows "createdDate":1503289426223.
    pages, records, _ = run(spec(), [page(rows=[{"id": "1", "name": "ci", "createdDate": 1503289426223},
                                                {"id": "2", "name": "ci", "createdDate": True}])])
    facts = {r.identity.object_id.rsplit(":", 1)[1]: {f.name: f for f in r.facts}
             for r in records if r.record_type == "entity_observation"}
    assert facts["1"]["created_at"].value == "2017-08-21T04:23:46.223000+00:00"
    assert facts["2"]["created_at"].state == "INVALID"  # a boolean is not a time
    assert pages[-1].status == "PARTIAL"
    pages, _, _ = run(spec(), [page(rows=[{"id": "1", "name": "ci", "createdDate": 1503289426223}])])
    assert pages[-1].status == "COMPLETE"


def test_cursor_checkpoint_commits_before_next_request_and_resume_skips_first_page():
    config, opener = spec(), Mock()
    opener.open.side_effect = [page("1", next_start=37), page("2", start=37)]
    iterator = stream(config, opener)
    first = next(iterator)
    assert opener.open.call_count == 1
    assert first.checkpoint["start"] == 37
    iterator.close()
    rest = list(stream(config, opener, checkpoint=first.checkpoint, read_records=lambda: iter(first.records)))
    assert rest[-1].status == "COMPLETE"
    assert [parse_qs(urlsplit(c.args[0].full_url).query)["start"] for c in opener.open.call_args_list] == [["0"], ["37"]]
    report = rest[0].records[-1]
    assert (report.pages, report.saved_records) == (2, 2)
    assert len([r for p in rest for r in p.records if r.record_type == "entity_observation"]) == 1


@pytest.mark.parametrize("cursor", [0, -1, True, "37", "https://evil.test", 2147483648])
def test_invalid_cursor_preserves_page_but_stops_partial(cursor):
    pages, records, opener = run(spec(), [page("1", next_start=cursor)])
    assert pages[-1].status == "PARTIAL" and opener.open.call_count == 1
    assert "INVALID_PAGINATION" in records[-1].reasons


@pytest.mark.parametrize("code", [301, 302, 401, 403, 404, 429, 500])
def test_http_errors_never_become_empty_success(code):
    pages, records, opener = run(spec(), [Response(b"untrusted response body", status=code)])
    assert pages[-1].status == "FAILED" and opener.open.call_count == 1
    assert records[-1].status == "FAILED"
    assert "untrusted" not in records[-1].model_dump_json()
    assert NoRedirect().redirect_request(None, None, None, None, None, None) is None


@pytest.mark.parametrize("changes,reason", [({"max_pages": 1}, "PAGE_LIMIT"),
                                           ({"max_requests": 1}, "REQUEST_LIMIT"),
                                           ({"max_records": 1}, "RECORD_LIMIT")])
def test_global_budgets_and_failure_after_first_page_do_not_republish_rows(changes, reason):
    pages, records, opener = run(spec(**changes), [page("1", next_start=3)])
    assert pages[-1].status == "PARTIAL" and opener.open.call_count == 1
    assert len([r for r in records if r.record_type == "entity_observation"]) == 1
    assert reason in records[-1].reasons


def test_redaction_and_only_documented_fields():
    rows = [{"id": "1", "name": SECRET, "createdDate": TIME, "token": "RAW_VALUE",
             "permissions": ["ADMIN"], "expiryDate": TIME, "lastAuthenticated": TIME}]
    pages, records, _ = run(spec(), [page(rows=rows)])
    serialized = json.dumps([r.model_dump() for r in records])
    assert SECRET not in serialized and "RAW_VALUE" not in serialized
    assert "expiryDate" not in serialized and "lastAuthenticated" not in serialized
    assert pages[-1].status == "PARTIAL"
    assert records[0].facts[1].state == "INVALID"


def test_malformed_and_duplicate_rows_remain_partial():
    pages, records, _ = run(spec(), [page(rows=[{}, {"id": "../bad"}, {"id": "1"}, {"id": "1"}])])
    assert pages[-1].status == "PARTIAL"
    assert {"DUPLICATE_IDENTIFIERS", "INVALID_METADATA"} <= set(records[-1].reasons)


def test_response_byte_budget_is_honored():
    config = spec(options={"max_response_bytes": 1024, "max_retries": 0})
    pages, records, _ = run(config, [Response(b" " * 1025)])
    assert pages[-1].status == "FAILED" and "RESPONSE_TOO_LARGE" in records[-1].reasons


@pytest.mark.parametrize("kind,value", [("user", "../alice"), ("project", "ENG%2fprivate"),
                                       ("repository", "ENG/a/extra"), ("repository", "ENG/.."),
                                       ("workspace", "team"), ("user", "alice?x=y")])
def test_scope_path_escape_and_unsupported_scope_rejected(kind, value):
    with pytest.raises(ValueError):
        adapter.validate_spec(spec(scopes=[{"kind": kind, "id": value}]))


def test_cancellation_propagates_and_changed_scope_cannot_resume():
    config, opener = spec(), Mock()
    opener.open.return_value = page("1", next_start=9)
    iterator = stream(config, opener)
    first = next(iterator)
    iterator.close()
    changed = spec(options={"api_path": "/other", "max_retries": 0})
    with pytest.raises(ValueError, match="CHECKPOINT_MISMATCH"):
        list(stream(changed, opener, checkpoint=first.checkpoint, read_records=lambda: iter(first.records)))
    def cancel():
        raise RuntimeError("synthetic cancellation")
    with pytest.raises(RuntimeError, match="synthetic cancellation"):
        list(stream(config, opener, check=cancel))
    assert opener.open.call_count == 1


def test_record_cannot_claim_values_validity_or_other_scope():
    config = spec()
    _, records, _ = run(config, [page("1")])
    entity = records[0]
    assert not adapter.validate_record(config, entity.model_copy(update={"normalized_state": "ACTIVE"}))
    assert not adapter.validate_record(config, entity.model_copy(update={
        "identity": entity.identity.model_copy(update={"origin": "https://other.example.test"})}))


def test_cloud_rejects_dc_context_path():
    from .test_common_adapter import spec as cloud_spec
    with pytest.raises(ValueError, match="CONTEXT_PATH"):
        adapter.validate_spec(cloud_spec(options={"api_path": "/bitbucket"}))


def test_cloud_default_operation_contract_matches_actual_default_sources():
    from cremore_atlassian_provider.metadata.specs import DEFAULT_SOURCES

    from .test_common_adapter import spec as cloud_spec
    assert adapter.allowed_operations(cloud_spec()) == set(DEFAULT_SOURCES)
    assert "org-oauth-clients" in adapter.allowed_operations(cloud_spec(
        options={"sources": ["org-oauth-clients"]}))


@pytest.mark.parametrize("sql", [False, True])
def test_shared_storage_projects_dc_observations_without_claiming_verification(sql):
    from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.db.repository import InMemoryRepository
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///:memory:") if sql else None
    if engine is not None:
        create_all(engine)
    try:
        store = MetadataStore(SqlRepository(engine) if engine is not None else InMemoryRepository())
        config = spec()
        owner, _ = store.create(config, "synthetic")
        started = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(config).model_dump())
        pages, records, _ = run(config, [page("1")])
        store.append(owner["id"], started["id"], MetadataBatch(index=0, items=records))
        store.finish(owner["id"], started["id"], MetadataFinish(
            batch_count=1, item_count=len(records), status=pages[-1].status))
        [item] = store.inventory(connection_id=owner["id"])["items"]
        assert item["verification"] == "NOT_PERFORMED"
        assert item["summary"]["normalized_state"] == "UNKNOWN"
        failed = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(config).model_dump())
        store.abort(owner["id"], failed["id"], "HTTP_403")
        [preserved] = store.inventory(connection_id=owner["id"])["items"]
        assert preserved["id"] == item["id"]
        assert preserved["current_record_id"] == item["current_record_id"]
    finally:
        if engine is not None:
            engine.dispose()
