"""Synthetic policy and opt-in PostgreSQL permission proofs on a disposable DB.

CREMORE_TEST_POSTGRES_URL must name localhost/127.0.0.1 cremore_test, PG16+.
The test administrator needs superuser rights to create disposable identities;
all runtime assertions use a distinct session authorization, never SET ROLE.
"""

import os
import uuid
from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from cremore.db import privileges as policy
from cremore.db.catalog_store import CatalogStore
from cremore.db.schema import metadata
from cremore.db.sql import SqlRepository
from cremore.db.startup import DatabaseSchemaError, initialize, startup
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.domain.models import Credential, Exposure, FindingEvent, ManagementAction, ScopeCatalog
from cremore.siem.outbox import SiemOutbox


@pytest.mark.parametrize("name", ["", "PUBLIC", "a.b", 'a"b', "role;drop", "x" * 64, "pg_database_owner", None])
def test_identifiers_fail_closed(name):
    with pytest.raises(policy.DatabasePrivilegeError, match="IDENTIFIER_INVALID"):
        policy.identifier(name)


def test_roles_are_distinct_and_not_builtin():
    with pytest.raises(policy.DatabasePrivilegeError, match="MUST_DIFFER"):
        replace(policy.Roles(), api="cremore_migration").validated()
    with pytest.raises(policy.DatabasePrivilegeError, match="ROLE_RESERVED"):
        replace(policy.Roles(), migration="postgres").validated()


def test_every_registered_table_has_a_reviewed_policy_and_no_destructive_audit_rights():
    assert set(metadata.tables) <= policy.TABLE_ACCESS.keys()
    for role in policy.RUNTIME_ROLES:
        for table in ("finding_events", "credentials", "findings", "exposures"):
            assert not {"DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"} & policy.table_grants(role, table)
        assert "UPDATE" not in policy.table_grants(role, "finding_events")
        for table in ("gcp_values", "migration_archive"):
            assert policy.table_grants(role, table) == set()
    assert policy.COLUMN_ACCESS[("collector", "finding_events", "UPDATE")] == {"chain_seq", "chain_mac"}
    assert policy.table_grants("collector", "action_plans") == {"SELECT"}
    assert policy.table_grants("remediator", "remediation_authorization_nonces") == {"SELECT", "INSERT"}


def test_alert_delivery_is_granted_to_the_process_that_sends_and_nothing_wider():
    """The control process sends the Slack alerts in a split deployment (cremore.worker.worker.ALERT_ROLES): it claims,
    settles and reports its delivery rows, paces messages and reads what a message names. The API's test message
    takes the same paced slot."""
    for table in ("siem_deliveries", "siem_destination_status", "scan_request_pacing"):
        assert policy.table_grants("control", table) == {"SELECT", "INSERT", "UPDATE"}
    for table in ("siem_events", "findings", "credentials", "exposures", "connections", "aws_accounts", "scan_jobs",
                  "installation_settings"):
        assert "SELECT" in policy.table_grants("control", table)
    assert policy.table_grants("api", "scan_request_pacing") == {"SELECT", "INSERT", "UPDATE"}
    # Nothing it does not need: no delivery-row deletes, no AWS account writes, no pacing for a remediator.
    assert policy.table_grants("control", "aws_accounts") == {"SELECT"}
    assert "DELETE" not in policy.table_grants("control", "siem_deliveries")
    assert policy.table_grants("remediator", "scan_request_pacing") == set()
    assert policy.table_grants("remediator", "siem_deliveries") == set()


def test_provisioning_cli_suppresses_driver_secrets(monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", "synthetic-sensitive-url")
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic-password-and-row")
    monkeypatch.setattr(policy, "create_engine", fail)
    assert policy.main(["prepare"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "DATABASE_PRIVILEGES_FAILED\n" and captured.err == ""


@pytest.fixture(scope="module")
def pg_roles():
    value = os.environ.get("CREMORE_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("Set CREMORE_TEST_POSTGRES_URL for isolated PostgreSQL role tests")
    url = make_url(value)
    if (url.get_backend_name() != "postgresql" or url.host not in {"127.0.0.1", "localhost"}
            or url.database != "cremore_test"):
        pytest.fail("Refusing a database other than disposable localhost cremore_test")
    admin = create_engine(url, hide_parameters=True)
    prefix = "cremore_test_" + uuid.uuid4().hex[:16]
    roles = policy.Roles(**{name: prefix + "_" + name for name in ("migration", *policy.RUNTIME_ROLES)})
    schema = prefix
    engines = {}
    prepared = False
    with admin.connect() as conn:
        assert int(conn.execute(text("SHOW server_version_num")).scalar_one()) >= 160000
        if not conn.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")).scalar_one():
            pytest.skip("Disposable role tests need a superuser test administrator")
        public_database = {right: conn.execute(text(
            "SELECT EXISTS(SELECT 1 FROM pg_database d, LATERAL aclexplode(coalesce(d.datacl, acldefault('d',d.datdba))) a "
            "WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type=:right)"), {"right": right}).scalar_one()
                           for right in ("CREATE", "TEMPORARY")}
        public_create = conn.execute(text(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace n, LATERAL aclexplode(coalesce(n.nspacl, acldefault('n',n.nspowner))) a "
            "WHERE n.nspname='public' AND a.grantee=0 AND a.privilege_type='CREATE')")).scalar_one()
    try:
        with admin.begin() as conn:
            policy.prepare_roles(conn, roles, schema)
            policy.prepare_roles(conn, roles, schema)
        prepared = True
        for name, role in roles.validated().items():
            engine = create_engine(url, hide_parameters=True)
            def authorize(dbapi, _record, role=role):
                with dbapi.cursor() as cursor:
                    cursor.execute(f"SET SESSION AUTHORIZATION {policy.identifier(role)}")
                    cursor.execute(f"SET search_path TO {policy.identifier(schema)}, pg_catalog")
                dbapi.commit()
            event.listen(engine, "connect", authorize)
            engines[name] = engine
        initialize(engines["migration"])
        initialize(engines["migration"])
        with admin.begin() as conn:
            policy.grant_runtime(conn, roles, schema)
            policy.grant_runtime(conn, roles, schema)
        yield SimpleNamespace(admin=admin, engines=engines, roles=roles, schema=schema)
    finally:
        for engine in engines.values():
            engine.dispose()
        if prepared:
            # Only our random schema and identities in the guarded test DB.
            assert schema.startswith("cremore_test_") and len(schema) == 29
            with admin.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA {policy.identifier(schema)} CASCADE")
                for role in roles.validated().values():
                    conn.exec_driver_sql(f"DROP OWNED BY {policy.identifier(role)}")
                    conn.exec_driver_sql(f"DROP ROLE {policy.identifier(role)}")
                for right, present in public_database.items():
                    if present:
                        conn.exec_driver_sql(f"GRANT {right} ON DATABASE cremore_test TO PUBLIC")
                if public_create:
                    conn.exec_driver_sql("GRANT CREATE ON SCHEMA public TO PUBLIC")
        admin.dispose()


@pytest.mark.parametrize("role", policy.RUNTIME_ROLES)
def test_postgres_runtime_boot_is_readonly_and_cannot_initialize(pg_roles, role):
    engine = pg_roles.engines[role]
    statements = []
    def record(_conn, _cursor, sql, *_):
        statements.append(sql)
    event.listen(engine, "before_cursor_execute", record)
    try:
        startup(SimpleNamespace(isolated_deployment=True), engine, runtime_role=role)
        assert all(sql.lstrip().upper().startswith(("SELECT", "SHOW")) for sql in statements)
        assert len(statements) < 60  # catalog checks are batched, not per table/column
    finally:
        event.remove(engine, "before_cursor_execute", record)
    with pytest.raises(policy.DatabasePrivilegeError, match="MIGRATION_OWNER_REQUIRED"):
        initialize(engine)


def _denied(engine, sql):
    with pytest.raises(DBAPIError) as denied, engine.begin() as conn:
        conn.exec_driver_sql(sql)
    assert getattr(denied.value.orig, "sqlstate", None) == "42501"


@pytest.mark.parametrize("role", policy.RUNTIME_ROLES)
def test_postgres_runtime_cannot_ddl_destroy_audit_or_read_retired_values(pg_roles, role):
    engine = pg_roles.engines[role]
    for sql in ("CREATE TABLE forbidden_table(id integer)", "CREATE TEMP TABLE forbidden_temp(id integer)",
                "ALTER TABLE finding_events ADD COLUMN forbidden integer", "DROP TABLE finding_events",
                "TRUNCATE finding_events", "DELETE FROM finding_events", "UPDATE finding_events SET note='changed'",
                "UPDATE finding_events SET entry_mac='changed'", "DELETE FROM findings", "DELETE FROM credentials",
                "SELECT * FROM gcp_values", "SELECT * FROM migration_archive"):
        _denied(engine, sql)


def test_postgres_real_collection_lease_audit_action_and_siem_operations(pg_roles):
    collector = SqlRepository(pg_roles.engines["collector"])
    api = SqlRepository(pg_roles.engines["api"])
    remediator = SqlRepository(pg_roles.engines["remediator"])
    control = SqlRepository(pg_roles.engines["control"])
    tasks = TaskStore(collector)
    run = uuid.uuid4()
    tasks.enqueue(run, "synthetic-root", {"mode": "BASELINE"})
    task = tasks.claim()
    assert task and tasks.heartbeat(task["id"], task["token"])
    with tasks.fenced(task["id"], task["token"]) as bound:
        credential = bound.upsert_credential(Credential(fingerprint="synthetic-grant-proof", credential_type="TOKEN"))
        exposure = bound.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
                                                 resource_name="synthetic", location="config"))
        finding = bound.upsert_finding(credential.id, exposure.id, "HIGH")
        TaskStore(bound).checkpoint(task["id"], task["token"], {"cursor": "committed"})
        TaskStore(bound).finish(task["id"], task["token"], {"objects": 1})
    with pytest.raises(LeaseLost):
        tasks.heartbeat(task["id"], task["token"])
    api.record_finding_event(FindingEvent(finding_id=finding.id, actor="synthetic", event_type="ACKNOWLEDGED"))
    assert collector.seal_audit(b"synthetic-audit-key")["sealed"] >= 1
    action = api.create_management_action(ManagementAction(finding_id=finding.id,
        action_type="ACKNOWLEDGE_OWNER", requested_by="synthetic"))
    assert remediator.update_management_action(action.id, expected_status="PENDING", status="CONFIRMED")
    control.put_setting("synthetic:ticket", {"state": "PENDING"}, "test-control")
    control.record_finding_event(FindingEvent(finding_id=finding.id, actor="control", event_type="ACKNOWLEDGED"))
    queue = SiemOutbox(SqlRepository(pg_roles.engines["siem"]))
    claimed = queue.claim("synthetic-destination")
    assert claimed
    for item in claimed:
        assert queue.acknowledge("synthetic-destination", item["event"]["event_id"], item["token"])
    queue.record_status("synthetic-destination", "SUCCESS")
    assert SiemOutbox(api).status()
    _denied(pg_roles.engines["collector"], "UPDATE action_plans SET status='APPROVED'")
    _denied(pg_roles.engines["siem"], "SELECT * FROM connections")
    _denied(pg_roles.engines["api"], "UPDATE finding_events SET chain_seq=1")


def test_postgres_control_delivers_alerts_and_the_api_sends_a_test_with_their_own_grants(pg_roles):
    import datetime as dt
    import json

    import httpx

    from cremore.alerts import delivery, setup
    from cremore.config import Settings
    from cremore.domain.models import AwsAccount

    settings = Settings(FINGERPRINT_KEY="ab" * 32)
    sent = []

    def answer(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, text="ok")

    def client():
        return httpx.Client(transport=httpx.MockTransport(answer))

    api, collector = SqlRepository(pg_roles.engines["api"]), SqlRepository(pg_roles.engines["collector"])
    control = SqlRepository(pg_roles.engines["control"])
    webhook = "https://hooks.slack.com/services/T0ABC1234/B0ABC5678/" + "k" * 24  # built at run time
    setup.save(api, settings, {"webhook_url": webhook, "enabled": True}, "synthetic-admin")
    account = api.create_aws_account(AwsAccount(account_id="210987654321", name="synthetic-alert-account"))
    credential = collector.upsert_credential(Credential(fingerprint="synthetic-alert-proof", credential_type="TOKEN"))
    exposure = collector.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3", severity="HIGH",
                                                  resource_name="synthetic-alert-bucket", location="keys/app.env",
                                                  aws_account_id=account.id))
    collector.upsert_finding(credential.id, exposure.id, "HIGH")
    # Every statement of a pass runs as the control login: delivery rows, status, pacing, what the message names.
    result = delivery.deliver_pending(control, settings, http_client_factory=client,
                                      now=dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2))
    assert result["error_code"] is None and result["delivered"] >= 1
    assert "synthetic-alert-bucket" in json.dumps(sent) and "synthetic-alert-account" in json.dumps(sent)
    assert delivery.status(api)["last_success_at"]
    assert delivery.send_test(api, settings, http_client_factory=client) == {"delivered": True, "error_code": None}
    for role in ("collector", "remediator"):
        _denied(pg_roles.engines[role], "UPDATE siem_destination_status SET consecutive_failures=0")
    _denied(pg_roles.engines["remediator"], "SELECT * FROM scan_request_pacing")
    _denied(pg_roles.engines["control"], "DELETE FROM siem_deliveries")


def test_postgres_control_runs_the_response_thread_job_and_ticket_listing_without_delete(pg_roles, monkeypatch):
    """The control login has no DELETE on installation_settings: the exposure-response thread job and the ticket
    sweep's listing of response requests run there anyway; the collector's response sweep drops what they retired and
    ends a link send past its deadline."""
    import datetime as dt

    from cremore.governance import response, response_routing, response_threads
    from cremore.governance.response_link_test import (
        NOW,
        TEAM,
        Directory,
        answer,
        contact_setup,
        finding,
        statement,
    )
    from cremore.governance.response_threads_test import (
        LINK,
        TEAM_CHANNEL,
        Workspace,
        approve,
        ask,
        run,
    )

    monkeypatch.setattr(response_routing, "resolve", Directory())
    ws = Workspace()
    api, collector = SqlRepository(pg_roles.engines["api"]), SqlRepository(pg_roles.engines["collector"])
    control = SqlRepository(pg_roles.engines["control"])
    _denied(pg_roles.engines["control"], "DELETE FROM installation_settings WHERE key = 'synthetic'")
    item = finding(collector)
    contact_setup(api)
    approve(api, ws, TEAM_CHANNEL)
    first = ask(api, ws, item)
    answer(api, LINK.search(ws.notices()[-1]["text"]).group(1), statement(
        result="INCOMPLETE", path="EXCEPTION", actions=[], explanation="The deploy job still reads it; next week."))
    ask(api, ws, item, version=response.summary(api, item.id)["version"], now=NOW + dt.timedelta(minutes=3))
    assert run(control, ws, 4) == 2 and run(control, ws, 5) == 0  # replied, then the replaced thread retired
    retired = response_threads.THREAD_PREFIX + str(item.id) + ":" + first["current"]["request_id"]
    assert control.get_setting(retired)["value"] == {"retired": True}
    # A link send past its deadline: the ticket sweep's listing in the control process leaves it alone.
    stuck = finding(collector)
    monkeypatch.setattr(response, "_finish_link", lambda *a, **kw: None)
    ask(api, ws, stuck)
    monkeypatch.undo()
    monkeypatch.setattr(response_routing, "resolve", Directory())
    late = NOW + dt.timedelta(seconds=response.SEND_SECONDS)
    assert response.pending(control, now=late) == []
    response.sweep(collector, TEAM, None, now=late)
    assert api.get_setting(retired) is None and response.public(api, stuck.id)["state"] == "NOT_SENT"


def test_postgres_api_onboarding_catalog_and_collection_contract(pg_roles):
    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
    from cremore.coverage.store import CoverageStore
    from cremore.scanning import scope

    api = SqlRepository(pg_roles.engines["api"])
    cid = uuid.uuid4()
    catalog = CatalogStore(api)
    item = scope.resource("aws", cid, "S3_BUCKET", "synthetic", "synthetic", "arn:aws:s3:::synthetic", "aws")
    catalog.refresh(ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="synthetic"), [item])
    assert catalog.selected("aws", cid, [item["id"]]).items == [item]
    # Exercise refresh deletion and header locks used by onboarding and the UI.
    catalog.refresh(ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="next"), [])
    assert catalog.header("aws", cid).snapshot_id == "next"
    owner, _ = CoverageStore(api).create(ConnectionSpec(name="Synthetic", provider="aws_secrets_manager",
        account_id="123456789012", regions=["us-east-1"]), "synthetic")
    collector = CoverageStore(SqlRepository(pg_roles.engines["collector"]))
    run = collector.start(owner["id"], owner["revision"], str(uuid.uuid4()), Contract(engine_digest="b" * 64).model_dump())
    collector.append(owner["id"], run["id"], Batch(index=0, items=[Observation(
        reference="arn:aws:secretsmanager:us-east-1:123456789012:secret:synthetic-Ab12Cd",
        account_id="123456789012", region="us-east-1", version="v1", evidence="VALUE",
        credential_type="TOKEN", fingerprint="a" * 64)]))
    finished = collector.finish(owner["id"], run["id"], Finish(batch_count=1, item_count=1, status="COMPLETE"))
    assert finished["status"] == "COMPLETE"


@pytest.mark.parametrize("role", ["api", "collector"])
def test_postgres_metadata_ingestion_updates_people_projection(pg_roles, role):
    from cremore_okta_provider.tests import test_identity as okta

    from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
    from cremore.coverage.metadata_store import MetadataStore

    spec = okta.spec(options={"page_size": 200, "keep_profiles": True})
    records, outcome = okta.run(spec, okta.Org({"": okta.users_page(okta.row("00usynthetic001", "ACTIVE"))}))
    assert outcome.status == "COMPLETE"
    store = MetadataStore(SqlRepository(pg_roles.engines[role]))
    owner, _ = store.create(spec, "synthetic")
    for _ in range(2):
        run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(spec).model_dump())
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=records), trusted_discovery=True)
        store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(records), status="COMPLETE"))
    assert store.inventory(connection_id=owner["id"], purpose="identity_status")["total"] == 1


@pytest.mark.parametrize("grant, reason", [
    ("GRANT UPDATE(note) ON {schema}.finding_events TO {api}", "COLUMN_PRIVILEGE_MISMATCH"),
    ("GRANT DELETE ON {schema}.credentials TO PUBLIC", "TABLE_PRIVILEGE_MISMATCH"),
    ("GRANT SELECT ON {schema}.connections TO {api} WITH GRANT OPTION", "TABLE_PRIVILEGE_MISMATCH"),
    ("REVOKE INSERT ON {schema}.finding_events FROM {api}", "TABLE_PRIVILEGE_MISMATCH"),
])
def test_postgres_drift_rejected_and_reprovisioning_removes_stale_column_grants(pg_roles, grant, reason):
    parameters = {"schema": policy.identifier(pg_roles.schema), "api": policy.identifier(pg_roles.roles.api)}
    try:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(grant.format(**parameters))
        with pytest.raises(policy.DatabasePrivilegeError, match=reason):
            startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["api"], runtime_role="api")
    finally:
        with pg_roles.admin.begin() as conn:
            policy.grant_runtime(conn, pg_roles.roles, pg_roles.schema)
    startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["api"], runtime_role="api")


def test_postgres_noinherit_membership_is_still_rejected(pg_roles):
    api, migration = policy.identifier(pg_roles.roles.api), policy.identifier(pg_roles.roles.migration)
    try:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(f"GRANT {migration} TO {api}")
        with pytest.raises(policy.DatabasePrivilegeError, match="MEMBERSHIP_FORBIDDEN"):
            startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["api"], runtime_role="api")
    finally:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(f"REVOKE {migration} FROM {api}")


@pytest.mark.parametrize("change, restore, reason", [
    ("ALTER ROLE {api} BYPASSRLS", "ALTER ROLE {api} NOBYPASSRLS", "ROLE_PRIVILEGED"),
    ("ALTER ROLE {api} CREATEROLE", "ALTER ROLE {api} NOCREATEROLE", "ROLE_PRIVILEGED"),
    ("GRANT TEMPORARY ON DATABASE cremore_test TO {api}", "REVOKE TEMPORARY ON DATABASE cremore_test FROM {api}", "DDL_PRIVILEGE_FORBIDDEN"),
    ("GRANT CREATE ON SCHEMA public TO {api}", "REVOKE CREATE ON SCHEMA public FROM {api}", "SCHEMA_PRIVILEGE_FORBIDDEN"),
    ("ALTER SCHEMA {schema} OWNER TO {api}", "ALTER SCHEMA {schema} OWNER TO {migration}", "SCHEMA_PRIVILEGE_FORBIDDEN"),
    ("CREATE FUNCTION {schema}.synthetic_definer() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
     "DROP FUNCTION {schema}.synthetic_definer()", "DEFINER_FUNCTION_FORBIDDEN"),
])
def test_postgres_escalating_capabilities_are_rejected(pg_roles, change, restore, reason):
    parameters = {"schema": policy.identifier(pg_roles.schema), "api": policy.identifier(pg_roles.roles.api),
                  "migration": policy.identifier(pg_roles.roles.migration)}
    try:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(change.format(**parameters))
        with pytest.raises(policy.DatabasePrivilegeError, match=reason):
            startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["api"], runtime_role="api")
    finally:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(restore.format(**parameters))
            # ALTER SCHEMA OWNER rewrites the former owner's ACL entry too.
            policy.prepare_roles(conn, pg_roles.roles, pg_roles.schema)


def test_postgres_boot_rejects_another_process_role(pg_roles):
    with pytest.raises(policy.DatabasePrivilegeError, match="PRIVILEGE_MISMATCH"):
        startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["collector"], runtime_role="api")


def test_postgres_signed_nonce_is_atomic_and_runtime_cannot_erase_it(pg_roles):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    nonce, plan_id = str(uuid.uuid4()), str(uuid.uuid4())
    barrier = Barrier(4)

    def consume(_):
        barrier.wait(timeout=10)
        return TaskStore(SqlRepository(pg_roles.engines["remediator"])).consume_authorization(nonce, plan_id)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(consume, range(4)))
    assert results.count(True) == 1 and results.count(False) == 3
    for role in policy.RUNTIME_ROLES:
        _denied(pg_roles.engines[role], "DELETE FROM remediation_authorization_nonces")
        _denied(pg_roles.engines[role], "UPDATE remediation_authorization_nonces SET nonce=nonce")


def test_postgres_missing_unique_constraint_is_incompatible(pg_roles):
    table = policy.identifier(pg_roles.schema) + ".connections"
    try:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(f"ALTER TABLE {table} DROP CONSTRAINT connections_provider_name_key")
        with pytest.raises(DatabaseSchemaError, match="UNIQUE_CONSTRAINT_MISSING"):
            startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["api"], runtime_role="api")
    finally:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(f"ALTER TABLE {table} ADD CONSTRAINT connections_provider_name_key UNIQUE (provider, name)")


def test_postgres_schema_drift_requires_migration(pg_roles):
    schema = policy.identifier(pg_roles.schema)
    try:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(f"DELETE FROM {schema}.schema_migrations WHERE version=10")
        with pytest.raises(DatabaseSchemaError, match="MIGRATIONS_INCOMPLETE"):
            startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines["api"], runtime_role="api")
    finally:
        initialize(pg_roles.engines["migration"])
