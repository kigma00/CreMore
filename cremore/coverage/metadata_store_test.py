"""Paged inventory enrichment preserves evidence without per-row SQL reads."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cremore_azure_provider.metadata.azure_key_vault_test import (
    Vault,
    collect,
    records,
    secret,
    spec,
)
from sqlalchemy import event

from cremore.coverage import metadata_store
from cremore.coverage.metadata_models import (
    MetadataBatch,
    MetadataConnectionSpec,
    MetadataFinish,
    metadata_contract,
)
from cremore.coverage.metadata_store import MetadataStore, finish_projection, project_batch
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine


@pytest.fixture(params=["memory", "sqlite"])
def store(request):
    if request.param == "memory":
        yield MetadataStore(InMemoryRepository())
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        try:
            yield MetadataStore(SqlRepository(engine))
        finally:
            engine.dispose()


def collected(store, count, *, name="First", tenant="synthetic-tenant"):
    connection = spec(name=name, tenant=tenant, tenant_confirmed=True)
    owner, _ = store.create(connection, "test")
    run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(connection).model_dump())
    items = records(collect(connection, Vault({"/secrets": {
        "value": [secret(f"item-{i}") for i in range(count)]}})))
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items))
    store.finish(owner["id"], run["id"], MetadataFinish(
        batch_count=1, item_count=len(items), status="COMPLETE"))
    return owner, run


def test_recent_run_reports_uses_one_bounded_window_and_preserves_report_order(store):
    owner, run = collected(store, 2)
    before = store.record_page(run_id=run["id"], record_type="operation_report", limit=5)["items"]
    recent = store.start(owner["id"], 1, str(uuid.uuid4()), run["contract"])
    runs, reports = store.recent_run_reports(owner["id"], limit=1)
    assert [item["id"] for item in runs] == [recent["id"]] and reports[recent["id"]] == []
    runs, reports = store.recent_run_reports(owner["id"], limit=2)
    assert [item["id"] for item in runs] == [recent["id"], run["id"]]
    assert reports[run["id"]] == [row["body"] for row in before]


def test_tenant_filter_applies_before_inventory_pagination(store):
    collected(store, 1, tenant="selected-tenant")
    collected(store, 101, name="Other", tenant="other-tenant")
    page = store.inventory(tenant="selected-tenant", limit=1)
    assert page["total"] == 1
    assert page["items"][0]["tenant"] == "selected-tenant"
    assert store.inventory(tenant="unknown")["total"] == 0
    assert store.inventory(tenant="")["total"] == 0


def test_recent_run_report_queries_do_not_grow_with_the_history_window():
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    try:
        store = MetadataStore(SqlRepository(engine))
        owner, run = collected(store, 2)
        for _ in range(3):
            recent = store.start(owner["id"], 1, str(uuid.uuid4()), run["contract"])
            store.abort(owner["id"], recent["id"], "SYNTHETIC_FAILURE")
        statements = []
        event.listen(engine, "before_cursor_execute", lambda *args: statements.append(args[2]))
        counts = []
        for limit in (1, 4):
            statements.clear()
            store.recent_run_reports(owner["id"], limit=limit)
            counts.append(sum(query.lstrip().upper().startswith("SELECT") for query in statements))
            assert not any("count(" in query.lower() for query in statements)
        assert counts == [3, 3]
    finally:
        engine.dispose()


def test_inventory_and_detail_preserve_collection_and_observation_statuses(store, monkeypatch):
    from cremore.coverage import store as coverage_store

    base = datetime.now(UTC)

    class CollectionClock(datetime):
        tick = 0

        @classmethod
        def now(cls, tz=None):
            # Distinct collections must have distinct times for this assertion;
            # Windows can otherwise give both runs the same clock tick.
            cls.tick += 1
            return (base + timedelta(seconds=cls.tick)).astimezone(tz)

    monkeypatch.setattr(coverage_store, "datetime", CollectionClock)
    first, _ = collected(store, 2)
    second, observed = collected(store, 1, name="Second")
    collected(store, 1, name="Unrelated", tenant="separate-tenant")
    failed = store.start(second["id"], 1, str(uuid.uuid4()), observed["contract"])
    store.abort(second["id"], failed["id"], "SYNTHETIC_FAILURE")
    store.change(first["id"], 1, "test", enabled=False)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return (datetime.now(UTC) + timedelta(days=2)).astimezone(tz)

    monkeypatch.setattr(metadata_store, "datetime", Later)
    page = store.inventory(connection_id=first["id"], q="item-0")
    assert page["total_all"] == 3 and page["total"] == 1
    [item] = page["items"]
    assert item["observation_run"]["id"] == observed["id"]
    assert item["verification"] == "NOT_PERFORMED"
    collections = {row["connection_id"]: row for row in item["collections"]}
    assert set(collections) == {first["id"], second["id"]}
    assert collections[first["id"]]["reasons"] == [
        "CONNECTION_DISABLED", "CONNECTION_SCOPE_CHANGED", "STALE_COLLECTION"]
    assert collections[second["id"]]["status"] == "FAILED"
    assert collections[second["id"]]["latest_run_id"] == failed["id"]
    assert collections[second["id"]]["reasons"] == ["STALE_COLLECTION", "SYNTHETIC_FAILURE"]
    assert store.entity_detail(item["id"])["collections"] == item["collections"]
    assert store.inventory(connection_id=first["id"], offset=2)["items"] == []


def test_details_attached_after_a_lean_read_equal_the_full_read(store):
    """Second review 2026-09-26: finding_links ranks up to 10,000 rows read without per-row
    details and attaches them to the displayed page only; that must equal the full read."""
    collected(store, 3)
    second, observed = collected(store, 2, name="Second")
    failed = store.start(second["id"], 1, str(uuid.uuid4()), observed["contract"])
    store.abort(second["id"], failed["id"], "SYNTHETIC_FAILURE")
    full = store.inventory(limit=100)["items"]
    lean = store.inventory(limit=100, details=False)["items"]
    assert lean and not any({"observation_run", "verification", "collections"} & set(row) for row in lean)
    assert store.inventory_details(lean) == full
    assert store.inventory_details([]) == []


def test_inventory_database_reads_do_not_grow_with_the_page():
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    try:
        store = MetadataStore(SqlRepository(engine))
        collected(store, 40)
        statements = []
        event.listen(engine, "before_cursor_execute", lambda *args: statements.append(args[2]))
        counts = []
        for limit in (1, 40):
            statements.clear()
            assert len(store.inventory(limit=limit)["items"]) == limit
            counts.append(len(statements))
        assert 0 < counts[0] == counts[1], counts
    finally:
        engine.dispose()


def project_filter_records(store, provider, observations, event_type):
    """Exercise the persisted projection; provider transport is outside this test."""
    model = MetadataConnectionSpec(name=provider, provider=provider, origin=f"https://{provider}.example.com",
                                   scopes=[{"kind": "project", "id": "synthetic"}],
                                   capabilities=["inventory", "audit"])
    owner, _ = store.create(model, "test")
    run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(model).model_dump())
    base = {"scope": model.scopes[0].model_dump(),
            "provenance": {"operation": "synthetic.list", "observed_at": "2026-09-24T00:00:00Z"}}
    items = [{**base, "record_type": "entity_observation", "purpose": purpose,
              "identity": {"provider": provider, "origin": model.origin, "kind": kind,
                           "object_id": f"{provider}-{index}"}}
             for index, (kind, purpose) in enumerate(observations)]
    items.append({**base, "record_type": "provider_event", "purpose": "usage", "event_id": provider,
                  "event_type": event_type, "occurred_at": "2026-09-24T00:00:00Z",
                  "subject": {"provider": provider, "origin": model.origin,
                              "kind": "resource", "object_id": "unobserved-event-subject"}})
    with store.transaction() as conn:
        project_batch(store, conn, run, MetadataBatch(index=0, items=items))
        finish_projection(store, conn, {**run, "status": "COMPLETE"})
    return owner


def test_inventory_facets_cover_collected_data_outside_pages_and_filters(store):
    assert store.inventory()["facets"] == {"provider": [], "object_kind": [], "purpose": []}
    first = project_filter_records(store, "gcp", [("credential", "issuer_inventory")] * 53
                                   + [("vault_item", "vault_metadata")], "KEY_CREATED")
    project_filter_records(store, "gitlab", [("public_key", "issuer_inventory")], "KEY_REVOKED")
    store.create(spec(), "not-collected")
    facets = {"provider": ["gcp", "gitlab"], "object_kind": ["credential", "public_key", "vault_item"],
              "purpose": ["issuer_inventory", "vault_metadata"]}
    first_page, last_page = store.inventory(limit=50), store.inventory(offset=50, limit=50)
    assert first_page["total"] == last_page["total"] == 55
    assert len(first_page["items"]) == 50 and len(last_page["items"]) == 5
    assert {r["id"] for r in first_page["items"]}.isdisjoint(r["id"] for r in last_page["items"])
    for page in (first_page, last_page,
                 store.inventory(provider="gcp", object_kind="credential", purpose="issuer_inventory",
                                 connection_id=first["id"], q="gcp-0", limit=1),
                 store.inventory(q="no-such-object")):
        assert page["facets"] == facets
    narrowed = store.inventory(object_kind="public_key")
    assert narrowed["total"] == 1 and narrowed["counts"] == {"public_key": 1}


def test_event_facets_survive_pages_self_filters_and_empty_combinations(store):
    assert store.provider_events()["facets"] == {"provider": [], "event_type": []}
    first = project_filter_records(store, "gcp", [], "KEY_CREATED")
    project_filter_records(store, "gitlab", [], "KEY_REVOKED")
    facets = {"provider": ["gcp", "gitlab"], "event_type": ["KEY_CREATED", "KEY_REVOKED"]}
    for page in (store.provider_events(limit=1), store.provider_events(offset=1, limit=1),
                 store.provider_events(provider="gcp", connection_id=first["id"]),
                 store.provider_events(event_type="KEY_CREATED"),
                 store.provider_events(provider="gitlab", event_type="KEY_CREATED")):
        assert page["facets"] == facets
    narrowed = store.provider_events(event_type="KEY_CREATED")
    assert narrowed["total"] == 1 and narrowed["event_types"] == ["KEY_CREATED"]


def test_event_facets_are_bounded_independently_of_event_pagination(store, monkeypatch):
    monkeypatch.setattr(metadata_store, "EVENT_FACET_LIMIT", 2)
    for label in ("CREATED", "REVOKED", "UPDATED"):
        project_filter_records(store, "gcp", [], label)
    page = store.provider_events(limit=1)
    assert page["total"] == 3 and len(page["items"]) == 1
    assert page["facets"]["event_type"] == page["event_types"] == ["CREATED", "REVOKED"]
    assert page["facets_truncated"] and page["event_types_truncated"]
    selected = store.provider_events(event_type="UPDATED")
    assert selected["total"] == 1 and selected["event_types"] == ["UPDATED"]
    assert selected["facets_truncated"] and not selected["event_types_truncated"]


def test_an_event_every_run_rereads_is_listed_once_from_the_newest_run(store):
    # A look-back collector (GitHub audit) stores its whole window again in each run.
    model = MetadataConnectionSpec(name="gh", provider="github", origin="https://api.github.com",
                                   scopes=[{"kind": "organization", "id": "acme"}], capabilities=["audit"])
    owner, _ = store.create(model, "test")
    runs = []
    for index, event_ids in enumerate((["same"], ["same"], ["same", "new"])):
        run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(model).model_dump())
        base = {"scope": model.scopes[0].model_dump(), "record_type": "provider_event", "purpose": "usage",
                "provenance": {"operation": "audit.list", "observed_at": f"2026-09-2{index + 1}T00:00:00Z"}}
        items = [{**base, "event_id": event_id, "event_type": "token.use", "occurred_at": "2026-09-20T00:00:00Z"}
                 for event_id in event_ids]
        with store.transaction() as conn:  # the projection itself; provider submission rules are not under test
            project_batch(store, conn, run, MetadataBatch(index=0, items=items))
            finish_projection(store, conn, {**run, "status": "COMPLETE"})
            store._put(conn, "runs", {**store._get(conn, "runs", run["id"]), "status": "COMPLETE"})
        runs.append(run)
    page = store.provider_events()
    assert page["total"] == 2 and sorted(item["event_id"] for item in page["items"]) == ["new", "same"]
    assert {item["run_id"] for item in page["items"]} == {str(runs[-1]["id"])}
    assert store.provider_events(limit=1, offset=1)["total"] == 2
    # One run's own events are still all of that run's.
    assert store.provider_events(run_id=runs[0]["id"])["total"] == 1


def test_usage_counts_require_observed_use_not_ownership_policy_or_lifecycle_events(store):
    owner = project_filter_records(store, "gcp", [("credential", "issuer_inventory")], "KEY_CREATED")
    run = store.connection_runs(owner["id"])["items"][0]
    [observed] = store.record_page(run_id=run["id"], record_type="entity_observation")["items"]
    target = observed["body"]["identity"]
    subject = {**target, "kind": "principal", "object_id": "synthetic-user"}
    base = {"scope": observed["body"]["scope"], "provenance": observed["body"]["provenance"],
            "purpose": "usage", "subject": subject, "target": target}
    records = [{**base, "record_type": "relation", "relation": kind,
                "match_basis": "PROVIDER_ID", "confidence": confidence}
               for kind, confidence in (("owns", "EXACT"), ("can_access", "CANDIDATE"),
                                         ("used", "CANDIDATE"), ("used", "EXACT"))]
    records.append({**base, "record_type": "provider_event", "event_id": "lifecycle-1",
                    "event_type": "KEY_REVOKED", "occurred_at": "2026-09-24T00:00:00Z"})
    with store.transaction() as conn:
        project_batch(store, conn, store._get(conn, "runs", run["id"]), MetadataBatch(index=1, items=records))
    counts = store.usage_counts([observed["entity_id"]])
    assert counts == {observed["entity_id"]: 1}


def test_usage_time_ignores_lifecycle_ownership_running_and_failed_records(store):
    owner = project_filter_records(store, "gcp", [("credential", "issuer_inventory")], "KEY_CREATED")
    run = store.connection_runs(owner["id"])["items"][0]
    [observed] = store.record_page(run_id=run["id"], record_type="entity_observation")["items"]
    target = observed["body"]["identity"]
    principal = {**target, "kind": "principal", "object_id": "creator"}
    base = {"scope": observed["body"]["scope"], "provenance": observed["body"]["provenance"],
            "purpose": "usage", "subject": target, "target": principal, "record_type": "relation",
            "match_basis": "PROVIDER_ID", "confidence": "EXACT", "window_end": "2026-09-24T09:00:00Z"}
    items = [{**base, "relation": "created_by"}, {**base, "relation": "used", "confidence": "CANDIDATE"},
             {**base, "relation": "used", "window_end": "2026-09-24T08:00:00Z",
              "provenance": {**base["provenance"], "operation": "cloud_monitoring.api_request_count"}}]
    with store.transaction() as conn:
        project_batch(store, conn, store._get(conn, "runs", run["id"]), MetadataBatch(index=1, items=items))
    assert store.latest_usage([observed["entity_id"]]) == {}
    assert store.explicit_creators([observed["entity_id"]]) == {}

    with store.transaction() as conn:
        store._put(conn, "runs", {**store._get(conn, "runs", run["id"]), "status": "PARTIAL"})
    assert store.latest_usage([observed["entity_id"]]) == {
        observed["entity_id"]: {"at": "2026-09-24T08:00:00+00:00", "basis": "METRIC_INTERVAL"}}
    assert store.explicit_creators([observed["entity_id"]]) == {observed["entity_id"]: "creator"}
    with store.transaction() as conn:
        project_batch(store, conn, store._get(conn, "runs", run["id"]), MetadataBatch(index=2, items=[
            {**base, "relation": "created_by", "target": {**principal, "object_id": "different-creator"}}]))
    assert store.explicit_creators([observed["entity_id"]]) == {observed["entity_id"]: None}
    with store.transaction() as conn:
        store._put(conn, "runs", {**store._get(conn, "runs", run["id"]), "status": "FAILED"})
    assert store.latest_usage([observed["entity_id"]]) == {}
    assert store.explicit_creators([observed["entity_id"]]) == {}


def test_snapshot_matches_keep_latest_compatible_evidence_without_unique_counts(store):
    from cremore_github_provider.metadata.exports import Projection
    from cremore_github_provider.metadata.tests.test_digest_evidence import (
        VENDOR_HASH,
        connection,
        context,
    )
    from cremore_github_provider.metadata.tests.test_exports import AS_OF, row

    config = connection()
    owner, _ = store.create(config, "test")

    def save(name, status="COMPLETE", material=VENDOR_HASH, ctx=None):
        records = Projection(config, export=name, generated_at=AS_OF, value_context=ctx or context()).project(
            1, row(credential_id="", hashed_token=material))
        run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(config).model_dump())
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=records), trusted_discovery=True)
        store.finish(owner["id"], run["id"], MetadataFinish(
            batch_count=1, item_count=len(records), status=status))
        return run, records[0].value_match.fingerprint

    _, fingerprint = save("first")
    latest, _ = save("second")
    result = store.snapshot_matches([fingerprint])
    assert len(result["items"]) == 1 and result["items"][0]["latest_run_id"] == latest["id"]
    assert not result["truncated"]
    assert store.snapshot_matches([fingerprint], limit=1)["truncated"]
    save("failed", status="FAILED")
    assert store.snapshot_matches([fingerprint])["items"][0]["latest_run_id"] == latest["id"]
    assert store.inventory(object_kind="credential")["total"] == 0
    assert store.snapshot_matches(["0" * 64])["items"] == []
