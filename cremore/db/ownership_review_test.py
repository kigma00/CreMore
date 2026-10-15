"""Stale or competing bulk edits must never publish half a review decision."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import event

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, Exposure, OwnershipReview


@pytest.fixture(params=["memory", "sql"])
def repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'reviews.db').as_posix()}")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


def finding_ids(repo):
    ids = []
    for index in range(2):
        cred = repo.upsert_credential(Credential(fingerprint=f"synthetic-{index}", credential_type="TEST"))
        exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="inline",
                                               resource_name="synthetic", location=str(index)))
        ids.append(repo.upsert_finding(cred.id, exposure.id, "LOW").id)
    return ids


def reviews(ids, actor="first"):
    return [OwnershipReview(finding_id=fid, revision=1, status="IN_PROGRESS",
                            assigned_team=actor, updated_by=actor) for fid in ids]


def test_stale_last_item_rejects_the_whole_bulk_edit(repo):
    ids = finding_ids(repo)
    repo.save_ownership_review(reviews(ids[1:], "other")[0])
    prior = repo.get_ownership_review(ids[1]).model_copy(deep=True)
    assert repo.save_ownership_reviews(reviews(ids), audit_actor=None) is None
    assert repo.get_ownership_review(ids[0]) is None
    assert repo.get_ownership_review(ids[1]) == prior


def test_each_saved_review_is_audited_in_the_same_transaction(repo):
    ids = finding_ids(repo)
    before = len(repo.list_events(1000))
    assert repo.save_ownership_reviews(reviews(ids), audit_actor="alice") is not None
    rows = [event for event in repo.list_events(1000) if event.event_type == "OWNERSHIP_REVIEW_UPDATED"]
    assert sorted(str(event.finding_id) for event in rows) == sorted(str(fid) for fid in ids)
    assert {(event.actor, event.from_status, event.to_status, event.note) for event in rows} == {
        ("alice", None, "IN_PROGRESS", 'team="first" due=-')}
    # A stale bulk edit writes neither the reviews nor their audit rows.
    assert repo.save_ownership_reviews(reviews(ids, "late"), audit_actor="alice") is None
    assert len(repo.list_events(1000)) == before + 2


def test_competing_edits_cannot_both_advance_the_same_revision(repo):
    ids = finding_ids(repo)
    ready = Barrier(2)

    def save(actor, ordered):
        proposed = reviews(ordered, actor)
        ready.wait(timeout=10)
        return repo.save_ownership_reviews(proposed, audit_actor=actor)

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(save, "first", ids)
        second = workers.submit(save, "second", list(reversed(ids)))
        results = [first.result(timeout=20), second.result(timeout=20)]
    assert sum(result is not None for result in results) == 1
    winner = next(result for result in results if result is not None)[0].updated_by
    for fid in ids:
        saved = repo.get_ownership_review(fid)
        assert saved.revision == 1 and saved.updated_by == winner and saved.assigned_team == winner


def test_failed_second_write_rolls_back_the_whole_sql_review_batch(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'rollback.db').as_posix()}")
    create_all(engine)
    repo = SqlRepository(engine)
    ids = finding_ids(repo)
    writes = 0

    def fail_second(conn, cursor, statement, parameters, context, executemany):
        nonlocal writes
        if statement.startswith("INSERT INTO ownership_reviews"):
            writes += 1
            if writes == 2:
                raise RuntimeError("synthetic persistence failure")

    event.listen(engine, "before_cursor_execute", fail_second)
    try:
        with pytest.raises(RuntimeError, match="synthetic persistence failure"):
            repo.save_ownership_reviews(reviews(ids), audit_actor=None)
        assert writes == 2
        assert all(repo.get_ownership_review(fid) is None for fid in ids)
    finally:
        event.remove(engine, "before_cursor_execute", fail_second)
        engine.dispose()


def test_a_failed_audit_row_rolls_back_the_reviews_it_records(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'audit-rollback.db').as_posix()}")
    create_all(engine)
    repo = SqlRepository(engine)
    ids = finding_ids(repo)

    def fail_audit(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO finding_events"):
            raise RuntimeError("synthetic audit failure")

    event.listen(engine, "before_cursor_execute", fail_audit)
    try:
        with pytest.raises(RuntimeError, match="synthetic audit failure"):
            repo.save_ownership_reviews(reviews(ids), audit_actor="alice")
        # No review without its audit row.
        assert all(repo.get_ownership_review(fid) is None for fid in ids)
    finally:
        event.remove(engine, "before_cursor_execute", fail_audit)
        engine.dispose()
