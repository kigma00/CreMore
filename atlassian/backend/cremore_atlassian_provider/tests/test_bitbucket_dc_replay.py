"""DC replay and selected recovery preserve source-local coverage and identity."""

from copy import deepcopy
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest

from cremore.coverage.collector_runtime import CollectionContext
from cremore.coverage.providers import collector_for
from cremore_atlassian_provider.metadata import adapter
from cremore_atlassian_provider.metadata import bitbucket_dc as dc
from cremore_atlassian_provider.metadata import bitbucket_dc_replay as replay
from cremore_atlassian_provider.metadata.descriptor import BITBUCKET

from .test_bitbucket_dc import TIME, page, run, spec, stream
from .test_collector_http import SECRET, Response

LATER = "2026-09-25T01:00:00+00:00"


def later(records):
    return [record.model_copy(update={"provenance": record.provenance.model_copy(update={"observed_at": LATER})})
            for record in records]


def events(result):
    return [event for source in result["sources"] for event in source["events"]]


def test_native_dc_snapshot_preserves_typed_metadata_and_never_claims_cloud_or_values():
    _, records, _ = run(spec(), [page("1")])
    [snapshot] = adapter.native_snapshots(record.model_dump() for record in records)
    assert snapshot["provider"] == "bitbucket" and snapshot["environment"] == "data_center"
    assert snapshot["contract_version"] == dc.CONTRACT
    assert snapshot["records"] == [record.model_dump() for record in records]
    assert snapshot["coverage"] == "complete" and snapshot["inventory_complete"] is False
    assert snapshot["scope"] == {"kind": "user", "id": "alice"}
    assert SECRET not in str(snapshot)
    assert BITBUCKET["edition_features"]["data_center"] == {
        "native_export": True, "compare": True, "recollect": True}


def test_compare_reuses_observation_events_and_returns_no_metadata_values():
    config = spec()
    _, before, _ = run(config, [page("same", "old", "changed")])
    _, after, _ = run(config, [page(rows=[
        {"id": "same", "name": "ci", "createdDate": TIME},
        {"id": "new", "name": "ci", "createdDate": TIME},
        {"id": "changed", "name": "new-label", "createdDate": TIME}])])
    result = collector_for("bitbucket").compare_records(before, later(after), spec=config)
    assert result == adapter.compare_records(before, later(after))
    assert result["counts"] == {"first_observed": 1, "metadata_changed": 1, "not_observed": 1,
                                "observation_unknown": 0, "metadata_unknown": 0,
                                "unchanged_observations": 1, "sources": 1, "limited_sources": 0}
    assert result["comparison_status"] == "complete" and not result["inventory_complete"]
    changed = next(item for item in events(result) if item["change_type"] == "metadata_changed")
    assert changed["changed_paths"] == ["/name/value"]
    assert "new-label" not in str(result)
    assert all(item["change_type"] not in {"deleted", "revoked"} for item in events(result))


@pytest.mark.parametrize("response", [Response(b"denied", status=403), page(next_start=0)])
def test_failed_or_partial_listing_never_claims_absence(response):
    _, before, _ = run(spec(), [page("old")])
    _, after, _ = run(spec(), [response])
    result = adapter.compare_records(before, later(after))
    assert result["comparison_status"] == "limited"
    assert [item["change_type"] for item in events(result)] == ["observation_unknown"]
    assert result["counts"]["not_observed"] == 0


def test_unfinished_source_and_invalid_fields_remain_unknown():
    _, before, _ = run(spec(), [page("old")])
    _, invalid, _ = run(spec(), [page(rows=[{"id": "old", "name": SECRET, "createdDate": TIME}])])
    result = adapter.compare_records(before, later(invalid[:-1]))
    assert result["comparison_status"] == "limited"
    assert events(result)[0]["change_type"] == "metadata_unknown"
    assert events(result)[0]["unknown_paths"] == ["/name"]
    with pytest.raises(ValueError, match="NO_RECOLLECTION_TARGETS"):
        replay.plan_recollection(invalid[:-1])
    assert replay.plan_recollection(invalid[:-1], include_unverified=True)["selected_count"] == 1


def test_duplicate_identity_and_record_count_mismatch_cannot_support_absence():
    _, before, _ = run(spec(), [page("old")])
    _, after, _ = run(spec(), [page("new", "new")])
    result = adapter.compare_records(before, later(after))
    assert {event["change_type"] for event in events(result)} == {"observation_unknown"}
    assert result["counts"]["not_observed"] == 0
    _, empty, _ = run(spec(), [page()])
    empty[-1] = empty[-1].model_copy(update={"saved_records": 1})
    result = adapter.compare_records(before, later(empty))
    assert events(result)[0]["change_type"] == "observation_unknown"


@pytest.mark.parametrize("change", [
    {"origin": "https://other.example.test"}, {"tenant": "another", "tenant_confirmed": True},
    {"options": {"api_path": "/other", "max_retries": 0}},
])
def test_cross_installation_tenant_or_context_comparison_is_rejected(change):
    _, before, _ = run(spec(), [page("1")])
    _, after, _ = run(spec(**change), [page("1")])
    with pytest.raises(ValueError):
        adapter.compare_records(before, later(after))
    with pytest.raises(ValueError):
        collector_for("bitbucket").compare_records(before, later(after), spec=spec())


def test_replay_rejects_bad_contract_scope_terminal_and_chronology():
    _, records, _ = run(spec(), [page("1")])
    with pytest.raises(ValueError):
        adapter.compare_records(later(records), records)
    with pytest.raises(ValueError):
        adapter.native_snapshots([*records, records[-1]])
    broken = [record.model_dump() for record in records]
    broken[0]["identity"]["object_id"] = "dc:/bitbucket:user:bob:1"
    with pytest.raises(ValueError):
        adapter.native_snapshots(broken)
    broken = [record.model_dump() for record in records]
    broken[0]["provenance"]["contract_version"] = "cloud-contract"
    with pytest.raises(ValueError):
        adapter.native_snapshots(broken)


def test_scope_id_selection_rejects_ambiguity_and_keeps_operation_boundaries():
    config = spec(scopes=[{"kind": "user", "id": "same"}, {"kind": "project", "id": "same"}])
    _, records, _ = run(config, [Response(b"no", status=403), Response(b"no", status=403)])
    with pytest.raises(ValueError):
        adapter.plan_recollection(records, scope_id="same")
    with pytest.raises(ValueError):
        adapter.compare_records(records, later(records), scope_id="same")
    plan = adapter.plan_recollection(records, operations=["dc-project-http-tokens"])
    assert [item["scope"]["kind"] for item in plan["tasks"]] == ["project"]


def test_selected_failure_recollection_reads_only_failed_scope_and_keeps_other_scope_unknown():
    config = spec(scopes=[{"kind": "user", "id": "alice"}, {"kind": "project", "id": "ENG"}])
    _, baseline, _ = run(config, [page("user-old"), page("project-old")])
    _, previous, _ = run(config, [Response(b"no", status=403), page("project-old")])
    runtime = collector_for("bitbucket")
    plan = runtime.plan_recollection(iter(previous), operations=["dc-user-http-tokens"])
    assert plan["selected_count"] == 1 and plan["page_policy"] == "restart_at_first_page"
    pages, records, opener = run(config, [page("user-new")], recollection_plan=plan)
    assert opener.open.call_count == 1
    assert urlsplit(opener.open.call_args.args[0].full_url).path.endswith("/users/alice")
    assert pages[-1].status == "PARTIAL"
    report = records[-1]
    assert report.scope.kind == "project" and report.status == "NOT_REQUESTED"
    assert dc.current_record_status(config, baseline[2].model_dump(), [report]) is None
    result = runtime.compare_records(baseline, later(records), spec=config)
    project = next(item for item in result["sources"] if item["context"]["scope"]["kind"] == "project")
    assert project["after"]["coverage"] == "not_requested"
    assert project["events"][0]["change_type"] == "observation_unknown"
    with pytest.raises(ValueError, match="NO_RECOLLECTION_TARGETS"):
        runtime.plan_recollection(iter(records))


def test_runtime_forwards_recollection_and_resumes_only_identical_plan(monkeypatch):
    config = spec()
    _, failed, _ = run(config, [Response(b"no", status=403)])
    plan = adapter.plan_recollection(failed)
    opener = Mock()
    opener.open.side_effect = [page("1", next_start=4), page("2", start=4)]
    real = dc.Client
    monkeypatch.setattr(dc, "Client", lambda *args, **kwargs: real(*args, opener=opener, **kwargs))
    runtime = collector_for("bitbucket")
    context = CollectionContext(secrets={"token": SECRET}, checkpoint={}, check=lambda: None,
                                read_records=lambda: iter(()), recollection_plan=plan)
    iterator = runtime.collect(config, context)
    first = next(iterator)
    iterator.close()
    assert first.checkpoint["recollection_hash"]
    changed = deepcopy(plan)
    changed["include_unverified"] = True
    with pytest.raises(ValueError, match="CHECKPOINT_MISMATCH"):
        list(stream(config, opener, checkpoint=first.checkpoint, read_records=lambda: iter(first.records),
                    recollection_plan=changed))
    with pytest.raises(ValueError, match="CHECKPOINT_MISMATCH"):
        list(stream(config, opener, checkpoint=first.checkpoint, read_records=lambda: iter(first.records)))
    rest = list(runtime.collect(config, CollectionContext(
        secrets={"token": SECRET}, checkpoint=first.checkpoint, check=lambda: None,
        read_records=lambda: iter(first.records), recollection_plan=plan)))
    assert rest[-1].status == "COMPLETE" and opener.open.call_count == 2
    assert "start=4" in opener.open.call_args.args[0].full_url
    assert adapter.native_snapshots([*first.records, *(record for p in rest for record in p.records)])[0]["coverage"] == "complete"


@pytest.mark.parametrize("mutation", ["scope", "endpoint", "operation", "duplicate", "completed", "extra"])
def test_untrusted_plan_cannot_change_scope_or_select_successful_operation(mutation):
    config = spec()
    _, failed, _ = run(config, [Response(b"no", status=403)])
    plan = adapter.plan_recollection(failed)
    if mutation == "scope":
        plan["tasks"][0]["scope"]["id"] = "bob"
    elif mutation == "endpoint":
        plan["tasks"][0]["resource_id"] = "https://other.example.test"
    elif mutation == "operation":
        plan["tasks"][0]["operation"] = "dc-project-http-tokens"
    elif mutation == "duplicate":
        plan["tasks"].append(deepcopy(plan["tasks"][0]))
        plan["selected_count"] += 1
    elif mutation == "completed":
        plan["tasks"][0]["previous_coverage"] = "complete"
    else:
        plan["unexpected"] = True
    opener = Mock()
    with pytest.raises(ValueError):
        list(stream(config, opener, recollection_plan=plan))
    opener.open.assert_not_called()


def test_no_eligible_plan_never_executes_and_recollection_cancellation_still_propagates():
    config = spec()
    _, complete, _ = run(config, [page("1")])
    opener = Mock()
    with pytest.raises(ValueError):
        list(stream(config, opener, recollection_plan=adapter.plan_recollection(complete)))
    _, failed, _ = run(config, [Response(b"no", status=403)])
    def cancel():
        raise RuntimeError("synthetic cancellation")
    with pytest.raises(RuntimeError, match="synthetic cancellation"):
        list(stream(config, opener, recollection_plan=adapter.plan_recollection(failed), check=cancel))
    opener.open.assert_not_called()


@pytest.mark.parametrize("changes,reason", [({"max_pages": 1}, "PAGE_LIMIT"),
                                           ({"max_requests": 1}, "REQUEST_LIMIT"),
                                           ({"max_records": 1}, "RECORD_LIMIT")])
def test_recollection_preserves_global_budgets(changes, reason):
    config = spec(**changes)
    _, failed, _ = run(config, [Response(b"no", status=403)])
    pages, records, opener = run(config, [page("1", next_start=3)],
                                 recollection_plan=adapter.plan_recollection(failed))
    assert opener.open.call_count == 1 and pages[-1].status == "PARTIAL"
    assert reason in records[-1].reasons


def test_partial_recollection_retains_previous_observations_of_unselected_scope():
    import uuid

    from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.db.repository import InMemoryRepository

    config = spec(scopes=[{"kind": "user", "id": "alice"}, {"kind": "project", "id": "ENG"}])
    store = MetadataStore(InMemoryRepository())
    owner, _ = store.create(config, "synthetic")

    def save(records, status):
        started = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(config).model_dump())
        store.append(owner["id"], started["id"], MetadataBatch(index=0, items=records))
        store.finish(owner["id"], started["id"], MetadataFinish(batch_count=1, item_count=len(records), status=status))
        return {item["summary"]["identity"]["object_id"]: item
                for item in store.inventory(connection_id=owner["id"])["items"]}

    _, baseline, _ = run(config, [page("1"), page("2")])
    before = save(baseline, "COMPLETE")
    _, failed, _ = run(config, [Response(b"no", status=403), page("2")])
    pages, recollected, _ = run(config, [page("1")], recollection_plan=adapter.plan_recollection(failed))
    after = save(later(recollected), pages[-1].status)
    user, project = "dc:/bitbucket:user:alice:1", "dc:/bitbucket:project:ENG:2"
    assert after[user]["current_record_id"] != before[user]["current_record_id"]
    assert after[project]["current_record_id"] == before[project]["current_record_id"]
    assert after[project]["summary"]["normalized_state"] == "UNKNOWN"
