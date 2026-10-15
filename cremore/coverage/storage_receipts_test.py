"""Storage assertions use real collection contracts and synthetic observations."""

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import inspect, update

from cremore.coverage.coverage_test import repo as repo  # noqa: PLC0414
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
from cremore.coverage.storage_receipts import (
    TABLE,
    ReceiptAnchor,
    StorageReceiptInput,
    StorageReceiptStore,
)
from cremore.coverage.store import CoverageError, CoverageStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414
from cremore.db.sql import SqlRepository, create_all, make_engine

ACCOUNT = "123456789012"
KEY_ID = "AKIA" + "A" * 16
ISSUER = f"arn:aws:iam::{ACCOUNT}:user/synthetic"
VAULT = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:synthetic-Ab12Cd"


def save(repo, spec, items, *, status="COMPLETE", finish=True):
    store = CoverageStore(repo)
    owner, _ = store.create(spec, "synthetic")
    v2 = spec.model_dump().get("schema_version") == 2
    contract = metadata_contract(spec) if v2 else Contract(engine_digest="d" * 64)
    run = store.start(owner["id"], 1, str(uuid.uuid4()), contract.model_dump())
    store.append(owner["id"], run["id"], (MetadataBatch if v2 else Batch)(index=0, items=items))
    if finish:
        run = store.finish(owner["id"], run["id"], (MetadataFinish if v2 else Finish)(
            batch_count=1, item_count=len(items), status=status))
    return owner, run


def issued(repo, *, v2=False, public_key=False, **changes):
    if public_key:
        from cremore_azure_provider.entra.entra_test import application, spec
        from cremore_azure_provider.entra.normalization import entity_records
        connection = spec()
        items, _ = entity_records(connection, "applications", application())
    elif v2:
        from cremore_notion_provider.metadata.normalization import observation
        from cremore_notion_provider.metadata.tests.test_adapter import pat, spec
        connection = spec()
        items = [observation(connection, connection.scopes[0], "personal_access_tokens", pat(),
                             observed_at=datetime.now(UTC).isoformat())]
    else:
        connection = ConnectionSpec(name="Issuer", provider="aws_iam", account_id=ACCOUNT)
        items = [Observation(reference=ISSUER, account_id=ACCOUNT, identifier=KEY_ID,
                             evidence="ISSUED", credential_type="AWS_ACCESS_KEY")]
    return save(repo, connection, items, **changes)


def vault(repo, *, v2=False, **changes):
    if v2:
        from cremore_azure_provider.metadata.azure_key_vault_test import (
            Vault,
            collect,
            records,
            secret,
            spec,
        )
        connection = spec()
        items = records(collect(connection, Vault({"/secrets": {"value": [secret()]}})))
    else:
        connection = ConnectionSpec(name="Vault", provider="aws_secrets_manager", account_id=ACCOUNT, regions=["us-east-1"])
        items = [Observation(reference=VAULT, account_id=ACCOUNT, region="us-east-1", version="version-1",
                             evidence="VALUE", fingerprint="a" * 64, credential_type="AWS_ACCESS_KEY")]
    return save(repo, connection, items, **changes)


def request(issuer_run, vault_run, **changes):
    return StorageReceiptInput.model_validate({
        "id": str(uuid.uuid4()), "source_system": "rotation-system", "source_record_id": "job/123",
        "stored_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        "issuer": {"run_id": str(issuer_run["id"]), "batch_index": 0, "item_index": 0},
        "vault": {"run_id": str(vault_run["id"]), "batch_index": 0, "item_index": 0}, **changes})


@pytest.mark.parametrize("issuer_v2,vault_v2", [(False, False), (False, True), (True, False), (True, True)])
def test_immutable_receipt_replay_revoke_and_no_secret_projection(repo, issuer_v2, vault_v2):
    owner, irun = issued(repo, v2=issuer_v2)
    _, vrun = vault(repo, v2=vault_v2)
    store, body = StorageReceiptStore(repo), request(irun, vrun)
    created = store.create(body, "admin")
    assert created["state"] == "STORAGE_RECORDED" and created["applicable"]
    assert created["submitted_by"] == "admin"
    assert created == store.create(body, "different-admin")
    assert created["issuer"]["anchor"] == body.issuer.model_dump(mode="json")
    assert created["vault"]["anchor"] == body.vault.model_dump(mode="json")
    assert created["issuer"]["schema_version"] == (2 if issuer_v2 else 1)
    assert store.list()["total"] == 1
    filters = {"issuer_entity_id": created["issuer"]["entity_id"]} if issuer_v2 else {
        "issuer_connection_id": owner["id"], "issuer_identifier": KEY_ID}
    assert store.list(**filters)["items"] == [created]
    assert store.list(issuer_entity_id=uuid.uuid4())["items"] == []
    assert store.list(issuer_connection_id=uuid.uuid4(), issuer_identifier=KEY_ID)["items"] == []
    assert store.list(issuer_identifier="other-key")["items"] == []
    assert store.list(offset=1)["items"] == []
    with pytest.raises(CoverageError, match="RECEIPT_REPLAY_CONFLICT"):
        store.create(body.model_copy(update={"source_record_id": "job/different"}), "admin")
    revoked = store.revoke(body.id, "reviewer")
    assert revoked["state"] == "REVOKED" and not revoked["applicable"]
    assert revoked["revoked_by"] == "reviewer" and revoked["revoked_at"]
    assert store.revoke(body.id, "other-reviewer") == revoked
    assert store.create(body, "admin") == revoked  # Replays never revive evidence.
    serialized = json.dumps(store.list())
    assert "fingerprint" not in serialized and "a" * 64 not in serialized
    assert "secret_refs" not in serialized and "raw" not in serialized and "MATCHED" not in serialized
    assert "current_evidence" not in serialized
    assert not repo.list_findings()
    assert len(CoverageStore(repo).list_connections()) == 2
    assert len(CoverageStore(repo).snapshots(owner["id"])) == 1


def test_candidates_are_paged_actual_observations_and_support_public_keys(repo):
    owner, irun = issued(repo, public_key=True)
    _, vrun = vault(repo, v2=True)
    store = StorageReceiptStore(repo)
    first = store.candidates(irun["id"], role="issuer", limit=1)
    second = store.candidates(irun["id"], role="issuer", offset=1, limit=1)
    assert first["total"] == second["total"] == 2  # Principal is not selectable.
    assert first["items"][0]["kind"] == "credential" and second["items"][0]["kind"] == "public_key"
    assert first["items"][0]["anchor"]["item_index"] == 1
    assert second["items"][0]["anchor"]["item_index"] == 2
    body = request(irun, vrun, issuer=second["items"][0]["anchor"])
    assert store.create(body, "admin")["issuer"]["kind"] == "public_key"
    assert store.candidates(irun["id"], role="vault")["items"] == []
    assert store.candidates(vrun["id"], role="vault")["total"] == 1
    assert store.candidates(vrun["id"], role="vault", offset=1)["items"] == []
    choices = store.connection_choices()["items"]
    assert len(choices) == 2 and all(set(row) == {"id", "name", "provider", "enabled", "revision"} for row in choices)
    page = store.run_page(owner["id"], limit=1)
    assert page["total"] == 1 and page["items"][0]["id"] == str(irun["id"])
    assert "contract" not in page["items"][0]
    assert store.run_page(owner["id"], offset=1)["items"] == []


@pytest.mark.parametrize("change,reason", [("disabled", "CONNECTION_DISABLED_OR_MISSING"), ("revision", "SCOPE_CHANGED")])
@pytest.mark.parametrize("role", ["issuer", "vault"])
def test_scope_changes_preserve_history_but_block_new_assertions(repo, change, reason, role):
    issuer_owner, irun = issued(repo)
    vault_owner, vrun = vault(repo)
    store, body = StorageReceiptStore(repo), request(irun, vrun)
    created = store.create(body, "admin")
    target = issuer_owner if role == "issuer" else vault_owner
    CoverageStore(repo).change(target["id"], 1, "admin", **({"enabled": False} if change == "disabled" else {"rotate": True}))
    row = store.list()["items"][0]
    assert not row["applicable"] and role.upper() + "_" + reason in row["reasons"]
    assert row["state"] == "STORAGE_RECORDED"
    assert row["issuer"] == created["issuer"] and row["vault"] == created["vault"]
    assert store.create(body, "admin") == row
    with pytest.raises(CoverageError, match="RECEIPT_" + reason):
        store.create(body.model_copy(update={"id": uuid.uuid4()}), "admin")


@pytest.mark.parametrize("role", ["issuer", "vault"])
@pytest.mark.parametrize("state", ["RUNNING", "FAILED", "PARTIAL"])
def test_completed_partial_observations_are_eligible_but_failed_or_open_runs_are_not(repo, role, state):
    kwargs = {"finish": state != "RUNNING", "status": state if state != "RUNNING" else "COMPLETE"}
    _, irun = issued(repo, **(kwargs if role == "issuer" else {}))
    _, vrun = vault(repo, **(kwargs if role == "vault" else {}))
    store, body = StorageReceiptStore(repo), request(irun, vrun)
    if state == "PARTIAL":
        assert store.create(body, "admin")["applicable"]
    else:
        with pytest.raises(CoverageError, match="COMPLETED_RUN_REQUIRED"):
            store.create(body, "admin")
        with pytest.raises(CoverageError, match="COMPLETED_RUN_REQUIRED"):
            store.candidates(getattr(body, role).run_id, role=role)


def test_unknown_or_wrong_role_anchors_cannot_become_receipts(repo):
    _, irun = issued(repo)
    _, vrun = vault(repo)
    store, body = StorageReceiptStore(repo), request(irun, vrun)
    for changes, error in [({"issuer": body.vault}, "ROLE_MISMATCH"),
                           ({"vault": body.issuer}, "ROLE_MISMATCH"),
                           ({"issuer": ReceiptAnchor(run_id=uuid.uuid4(), batch_index=0, item_index=0)}, "RUN_NOT_FOUND"),
                           ({"issuer": body.issuer.model_copy(update={"batch_index": 1})}, "OBSERVATION_NOT_FOUND"),
                           ({"issuer": body.issuer.model_copy(update={"item_index": 1})}, "OBSERVATION_NOT_FOUND")]:
        with pytest.raises(CoverageError, match=error):
            store.create(body.model_copy(update=changes), "admin")
    assert store.list()["total"] == 0


def test_dynamic_management_is_not_a_stored_vault_item(repo):
    _, irun = issued(repo)
    connection = ConnectionSpec(name="Lease manager", provider="vault", endpoint="https://vault.example.test",
                                lease_prefixes=["database/creds/app"])
    item = Observation(reference="database/creds/app/lease-1", mount="database", evidence="MANAGED",
        credential_type="VAULT_DYNAMIC_LEASE", version_state="UNKNOWN", vault_managed={"kind": "DYNAMIC_LEASE"})
    _, vrun = save(repo, connection, [item])
    store = StorageReceiptStore(repo)
    assert store.candidates(vrun["id"], role="vault")["total"] == 0
    with pytest.raises(CoverageError, match="ROLE_MISMATCH"):
        store.create(request(irun, vrun), "admin")


@pytest.mark.parametrize("v2", [False, True])
def test_persisted_issuer_identity_is_revalidated_against_actual_owner(repo, v2):
    _, irun = issued(repo, v2=v2)
    _, vrun = vault(repo)
    store, body = StorageReceiptStore(repo), request(irun, vrun)
    with store.transaction() as conn:
        batch = store._batch(conn, body.issuer)
        items = deepcopy(batch["items"])
        if v2:
            items[0]["identity"]["tenant"] = "foreign-tenant"
        else:
            items[0]["account_id"] = "000000000001"
        if conn is None:
            store.memory["batches"][(irun["id"], 0)]["items"] = items
        else:
            conn.execute(update(store.batches).where(store.batches.c.run_id == irun["id"]).values(items=items))
    with pytest.raises(CoverageError, match="OUTSIDE_SCOPE"):
        store.create(body, "admin")
    assert store.list()["total"] == 0


def test_receipt_creation_uses_sorted_connection_locks_and_rolls_back_on_failure(repo, monkeypatch):
    issuer_owner, irun = issued(repo)
    vault_owner, vrun = vault(repo)
    store, body = StorageReceiptStore(repo), request(irun, vrun)
    original_get, original_put, locks = store._get, store._put, []

    def locked(conn, name, key, lock=False):
        if name == "connections" and lock:
            locks.append(key)
        return original_get(conn, name, key, lock)

    def failing_put(conn, name, row, new=False):
        original_put(conn, name, row, new)
        if name == TABLE:
            raise RuntimeError("synthetic rollback")

    monkeypatch.setattr(store, "_get", locked)
    monkeypatch.setattr(store, "_put", failing_put)
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        store.create(body, "admin")
    assert locks == sorted([issuer_owner["id"], vault_owner["id"]], key=str)
    assert store.list()["total"] == 0


@pytest.mark.parametrize("field,value", [
    ("source_system", "contains spaces"), ("source_record_id", "ghp_" + "a" * 36),
    ("source_record_id", "id\nforged"), ("source_record_id", "https://example.test/?token=value"),
    ("stored_at", "2026-01-01T00:00:00"), ("stored_at", ""), ("stored_at", "2999-01-01T00:00:00Z"),
    ("secret_value", "synthetic-not-accepted"),
])
def test_submission_accepts_only_bounded_nonsecret_identifiers_and_past_zoned_time(field, value):
    with pytest.raises(ValidationError):
        request({"id": uuid.uuid4()}, {"id": uuid.uuid4()}, **{field: value})


def test_store_read_errors_are_safe_and_paging_is_bounded(repo):
    store = StorageReceiptStore(repo)
    for call in [lambda: store.list(issuer_identifier="ghp_" + "a" * 36),
                 lambda: store.list(limit=1000), lambda: store.list(offset=-1),
                 lambda: store.candidates(uuid.uuid4(), role="other"),
                 lambda: store.run_page(uuid.uuid4()), lambda: store.revoke(uuid.uuid4(), "admin")]:
        with pytest.raises(CoverageError):
            call()


def test_populated_database_adds_receipt_table_without_rewriting_collection_evidence(tmp_path):
    engine = make_engine("sqlite:///" + str(tmp_path / "upgrade.sqlite"))
    try:
        create_all(engine)
        repo = SqlRepository(engine)
        owner, irun = issued(repo)
        _, vrun = vault(repo)
        before = CoverageStore(repo).snapshots(owner["id"])
        from cremore.db.schema import metadata
        metadata.tables[TABLE].drop(engine)
        assert TABLE not in inspect(engine).get_table_names()
        create_all(engine)
        create_all(engine)
        assert TABLE in inspect(engine).get_table_names()
        assert len(inspect(engine).get_indexes(TABLE)) == 2
        assert CoverageStore(repo).snapshots(owner["id"]) == before
        assert StorageReceiptStore(repo).create(request(irun, vrun), "admin")["state"] == "STORAGE_RECORDED"
    finally:
        engine.dispose()


def test_concurrent_identical_submission_and_revoke_never_duplicate_or_revive(tmp_path):
    engine = make_engine("sqlite:///" + str(tmp_path / "concurrent.sqlite"))
    try:
        create_all(engine)
        repo = SqlRepository(engine)
        _, irun = issued(repo)
        _, vrun = vault(repo)
        body = request(irun, vrun)

        def submit(_):
            return StorageReceiptStore(SqlRepository(engine)).create(body, "admin")

        with ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(submit, range(8)))
        assert all(row == replies[0] for row in replies)
        store = StorageReceiptStore(repo)
        assert store.list()["total"] == 1
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda operation: operation(), [lambda: submit(None), lambda: store.revoke(body.id, "reviewer")]))
        assert submit(None)["state"] == "REVOKED"
        assert store.list()["total"] == 1
    finally:
        engine.dispose()
