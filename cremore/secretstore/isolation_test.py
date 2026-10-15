"""Synthetic regressions for admission, scoped opening and offline migration."""

import base64
import copy
import hashlib
import json
import uuid
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, create_engine, select

from cremore.config import Settings
from cremore.secretstore.isolation import (
    RecipientKeys,
    binding_for_record,
    credential_binding,
    validate_process_keys,
)
from cremore.secretstore.migrate import MigrationError, migrate
from cremore.secretstore.resolver import SecretRefError, SecretResolver
from cremore.secretstore.sealed import (
    SealedSecretError,
    SealingKeys,
    is_sealed,
    seal_fields,
    unseal,
)

LEGACY = SealingKeys(b"old-auth-master" * 3, b"old-fingerprint" * 3)
CONTROL = SealingKeys(b"new-control-key" * 3)
BINDING = credential_binding("github", {}, purposes=["exposure"], auth_method="token")
OTHER = credential_binding("github", {"host": "https://code.example.invalid"}, auth_method="token")
ACTION = credential_binding("github", {}, purposes=["remediation"], auth_method="github_app")


@pytest.fixture(scope="module")
def material():
    pairs = []
    for _index in range(4):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pairs.append((key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode(), key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()))
    return pairs


@pytest.fixture
def rings(material):
    recipients = [{**binding, "public_keys": [material[index][0]]}
                  for index, binding in enumerate((BINDING, OTHER, ACTION))]
    return {
        "policy": recipients,
        "api": RecipientKeys(recipients),
        "collector": RecipientKeys(recipients, [material[0][1]]),
        "other": RecipientKeys(recipients, [material[1][1]]),
        "remediator": RecipientKeys(recipients, [material[2][1]]),
        "migration": RecipientKeys(recipients, [item[1] for item in material[:3]]),
    }


def test_api_can_seal_but_no_api_other_group_or_remediator_can_open(rings):
    ref = seal_fields(rings["api"], {"token": "synthetic-connector"}, binding=BINDING)
    assert is_sealed(ref)
    assert unseal(rings["collector"], ref, binding=BINDING) == {"token": "synthetic-connector"}
    for role in ("api", "other", "remediator"):
        with pytest.raises(SealedSecretError, match="PRIVATE_KEY_UNAVAILABLE"):
            unseal(rings[role], ref, binding=BINDING)
    with pytest.raises(SealedSecretError, match="BINDING_REQUIRED"):
        unseal(rings["collector"], ref)
    for changed in (OTHER, ACTION, {**BINDING, "provider": "gitlab"}):
        with pytest.raises(SealedSecretError, match="BINDING_MISMATCH"):
            unseal(rings["collector"], ref, binding=changed)


def test_header_and_ciphertext_are_authenticated_even_when_all_keys_are_held(rings):
    ref = seal_fields(rings["api"], {"token": "synthetic"}, binding=BINDING)
    header, wrapped, body = ref.removeprefix("sealed:v3:").split(".")
    parsed = json.loads(base64.urlsafe_b64decode(header))
    parsed["binding"] = OTHER
    parsed["key"] = next(key for key, binding in rings["migration"].key_bindings.items()
                         if json.loads(binding) == OTHER)
    altered = "sealed:v3:" + ".".join((base64.urlsafe_b64encode(json.dumps(parsed).encode()).decode(), wrapped, body))
    with pytest.raises(SealedSecretError, match="ENVELOPE_INVALID"):
        unseal(rings["migration"], altered, binding=OTHER)
    raw = bytearray(base64.urlsafe_b64decode(body))
    raw[-1] ^= 1
    with pytest.raises(SealedSecretError, match="ENVELOPE_INVALID"):
        unseal(rings["collector"], "sealed:v3:" + ".".join((header, wrapped,
            base64.urlsafe_b64encode(raw).decode())), binding=BINDING)


def test_rotation_preserves_old_openers_without_cross_group_key_reuse(material, rings):
    old = seal_fields(rings["api"], {"token": "synthetic"}, binding=BINDING)
    policy = copy.deepcopy(rings["policy"])
    policy[0]["public_keys"].insert(0, material[3][0])
    rotated = RecipientKeys(policy, [material[0][1], material[3][1]])
    assert unseal(rotated, old, binding=BINDING)["token"] == "synthetic"
    fresh = seal_fields(rotated, {"token": "fresh"}, binding=BINDING)
    assert unseal(rotated, fresh, binding=BINDING)["token"] == "fresh"
    policy[1]["public_keys"] = [material[0][0]]
    with pytest.raises(SealedSecretError, match="RECIPIENT_POLICY_INVALID"):
        RecipientKeys(policy)


def test_vault_reference_is_bound_before_worker_reads_the_external_store(rings):
    calls = []

    class Vault:
        def read(self, path):
            calls.append(path)
            return {"token": "synthetic-vault"}

    resolver = SecretResolver(Vault(), rings["collector"]).bound(BINDING)
    ref = seal_fields(rings["api"], {"vault_ref": "vault://team/source"}, binding=BINDING)
    assert resolver.resolve(ref) == {"token": "synthetic-vault"}
    with pytest.raises(SecretRefError, match="MIGRATION_REQUIRED"):
        resolver.resolve("vault://another/source")
    with pytest.raises(SealedSecretError, match="BINDING_MISMATCH"):
        resolver.bound(OTHER).resolve(ref)
    assert calls == ["team/source"]


def test_legacy_shared_mode_remains_readable_but_isolated_resolver_never_falls_back(rings):
    ref = seal_fields(LEGACY, {"token": "old"})
    assert SecretResolver(sealing_key=LEGACY).resolve(ref) == {"token": "old"}
    with pytest.raises(SealedSecretError, match="MIGRATION_REQUIRED"):
        SecretResolver(sealing_key=rings["collector"]).bound(BINDING).resolve(ref)


@pytest.mark.parametrize("provider,method,context,changed", [
    ("github", "token", {}, {"host": "https://other.example.invalid"}),
    ("keycloak", "oauth_client", {"address": "https://sso.example.invalid", "realm": "staff", "api_path": "/auth"},
     {"api_path": "/other"}),
    ("vault", "token", {"address": "https://vault.example.invalid", "tls_ca_pem": "synthetic trusted CA"},
     {"tls_ca_pem": "synthetic different CA"}),
])
def test_target_roots_cannot_override_the_owners_authentication_authority(provider, method, context, changed):
    from cremore.onboarding.targets import target_id

    target = {**context, "version": 2, "roots": [{"id": target_id(changed), "target": changed}]}
    record = {"provider": provider, "auth_method": method, "purposes": [], "target": target}
    with pytest.raises(SealedSecretError, match="CREDENTIAL_AUTHORITY_MISMATCH"):
        binding_for_record(record)


@pytest.mark.parametrize("provider,method,purpose,context,roots", [
    ("github", "token", "exposure", {"host": "https://github.com"},
     [{"organization": "first"}, {"host": "https://GITHUB.com:443/", "organization": "second"}]),
    ("keycloak", "oauth_client", "identity", {"address": "https://sso.example.invalid", "realm": "staff", "api_path": "/auth"},
     [{"admin_events": False}, {"api_path": "/auth", "admin_events": True}]),
    ("vault", "token", "vault", {"address": "https://vault.example.invalid", "tls_ca_pem": "synthetic trusted CA"},
     [{"mounts": ["first"]}, {"tls_ca_pem": "synthetic trusted CA", "mounts": ["second"]}]),
])
def test_target_roots_keep_legitimate_scope_selection_with_the_same_authority(provider, method, purpose, context, roots):
    from cremore.onboarding.targets import target_id

    target = {**context, "version": 2, "roots": [
        {"id": target_id(root), "target": root, "purposes": [purpose]} for root in roots]}
    record = {"provider": provider, "auth_method": method, "purposes": [purpose], "target": target}
    assert binding_for_record(record) == credential_binding(provider, context, purposes=[purpose], auth_method=method)


def test_process_roles_cannot_hold_other_decryption_material(tmp_path, rings, material):
    policy = tmp_path / "public.json"
    private = tmp_path / "private.json"
    policy.write_text(json.dumps({"version": 1, "recipients": rings["policy"]}), encoding="utf-8")
    private.write_text(json.dumps({"version": 1, "private_keys": [material[0][1], material[1][1]]}), encoding="utf-8")
    api = Settings(ISOLATED_DEPLOYMENT=True, SEALING_PUBLIC_KEYS_FILE=str(policy),
                   CONTROL_SEALING_KEY="cd" * 32, FINGERPRINT_KEY="ab" * 32)
    validate_process_keys(api, "api")
    leaked = api.model_copy(update={"sealing_private_keys_file": str(private)})
    with pytest.raises(ValueError, match="CANNOT_HOLD_CONNECTOR"):
        validate_process_keys(leaked, "api")
    collector = api.model_copy(update={"control_sealing_key": "", "sealing_private_keys_file": str(private)})
    validate_process_keys(collector, "collector")
    with pytest.raises(ValueError, match="ROLE_MISMATCH"):
        validate_process_keys(collector, "remediator")
    with pytest.raises(ValueError, match="CANNOT_HOLD_CONTROL"):
        validate_process_keys(leaked, "collector")
    assert collector.sealing_keys.legacy is None and collector.sealing_keys.current is None
    assert api.sealing_keys.known_ids() != LEGACY.known_ids()


@pytest.mark.parametrize("role,held", [("collector", [0]), ("remediator", [2])])
def test_process_requires_every_policy_group_for_its_role(tmp_path, rings, material, role, held):
    policy = [*rings["policy"], {**OTHER, "purpose": "remediator", "public_keys": [material[3][0]]}]
    _api, worker = settings_files(tmp_path, policy, [material[index][1] for index in held])
    with pytest.raises(ValueError, match="CONNECTOR_ROLE_PRIVATE_KEY_SET_INCOMPLETE"):
        validate_process_keys(worker, role)


@pytest.mark.parametrize("role,held", [("collector", [0, 1]), ("remediator", [2])])
def test_process_accepts_all_of_its_role_keys_without_other_role_keys(tmp_path, rings, material, role, held):
    api, worker = settings_files(tmp_path, rings["policy"], [material[index][1] for index in held])
    validate_process_keys(worker, role)
    validate_process_keys(api, "api")
    validate_process_keys(api, "control")


def test_process_requires_current_key_for_every_role_group_during_rotation(tmp_path, rings, material):
    policy = copy.deepcopy(rings["policy"])
    policy[0]["public_keys"].insert(0, material[3][0])
    _api, worker = settings_files(tmp_path, policy, [material[0][1], material[1][1]])
    with pytest.raises(ValueError, match="CONNECTOR_CURRENT_PRIVATE_KEY_REQUIRED"):
        validate_process_keys(worker, "collector")


@pytest.fixture
def database():
    metadata = MetaData()
    defs = {
        "provider_connections": {"id": String, "provider": String, "edition": String, "auth_method": String,
            "target": JSON, "purposes": JSON, "plans": JSON, "secret_refs": JSON, "checks": JSON},
        "provider_onboarding_sessions": {"id": String, "data": JSON},
        "coverage_connections": {"id": String, "spec": JSON},
        "scan_jobs": {"id": String, "payload": JSON, "status": String, "error": String, "finished_at": DateTime},
        "scan_tasks": {"id": String, "run_id": String, "payload": JSON, "status": String, "error": String,
                       "finished_at": DateTime, "token": String, "lease_until": DateTime, "checkpoint": JSON},
        "connections": {"id": String, "provider": String, "name": String, "status": String,
                        "config": JSON, "secret_ref": String, "credential_evidence": JSON},
        "scope_profiles": {"id": String, "kind": String, "connection_id": String, "auth_revision": String},
        "gcp_oauth_sessions": {"id": String, "data": JSON},
        "installation_settings": {"key": String, "value": JSON},
        "finding_events": {"id": String, "note": String},
        "credentials": {"id": String, "fingerprint": String},
        "coverage_batches": {"id": String, "items": JSON},
    }
    tables = {name: Table(name, metadata, *(Column(key, type_, primary_key=index == 0)
        for index, (key, type_) in enumerate(columns.items()))) for name, columns in defs.items()}
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    legacy = seal_fields(LEGACY, {"token": "synthetic-old-connector"})
    owner = {"id": str(uuid.uuid4()), "provider": "github", "edition": "cloud", "auth_method": "token",
             "target": {}, "purposes": ["exposure"], "plans": {}, "secret_refs": {"credential": legacy}, "checks": {}}
    from cremore.onboarding.service import check_digest

    owner["checks"] = {"digest": check_digest(owner), "results": {"exposure": "kept"}}
    with engine.begin() as conn:
        conn.execute(tables["provider_connections"].insert(), owner)
        conn.execute(tables["provider_onboarding_sessions"].insert(), {"id": "draft", "data": owner})
        conn.execute(tables["coverage_connections"].insert(), {"id": "metadata", "spec": {"secret_refs": {"token": legacy}}})
        conn.execute(tables["scan_jobs"].insert(), {"id": "history", "status": "SUCCEEDED", "payload": {
            "secret_ref": legacy, "content": "unaltered synthetic content"}})
        conn.execute(tables["gcp_oauth_sessions"].insert(), {"id": "oauth", "data": {"pending": legacy, "sealed": legacy}})
        conn.execute(tables["installation_settings"].insert(), {"key": "gcp_oauth_client", "value": {"sealed": legacy}})
        conn.execute(tables["finding_events"].insert(), {"id": "event", "note": legacy})
        conn.execute(tables["credentials"].insert(), {"id": "credential", "fingerprint": "unchanged-fingerprint"})
        conn.execute(tables["coverage_batches"].insert(), {"id": "observations", "items": [{"sealed": legacy}]})
    yield engine, tables, legacy, owner
    engine.dispose()


def snapshot(engine, tables):
    with engine.connect() as conn:
        return {name: [dict(row) for row in conn.execute(select(table)).mappings()] for name, table in tables.items()}


def test_migration_covers_owners_drafts_metadata_jobs_oauth_control_and_is_idempotent(database, rings):
    engine, tables, old, owner = database
    before = snapshot(engine, tables)
    result = migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True)
    assert result["connector_references"] == 1
    after = snapshot(engine, tables)
    for name in ("finding_events", "credentials", "coverage_batches"):
        assert before[name] == after[name]
    ref = after["provider_connections"][0]["secret_refs"]["credential"]
    assert ref != old and unseal(rings["collector"], ref, binding=binding_for_record(owner))["token"] == "synthetic-old-connector"
    assert after["provider_onboarding_sessions"][0]["data"]["secret_refs"]["credential"] == ref
    assert after["coverage_connections"][0]["spec"]["secret_refs"]["token"] == ref
    assert after["scan_jobs"][0]["payload"]["secret_ref"] == ref
    for ref in after["gcp_oauth_sessions"][0]["data"].values():
        assert unseal(CONTROL, ref)["token"] == "synthetic-old-connector"
    assert migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True) == {
        "changed_rows": {}, "connector_references": 0}
    assert snapshot(engine, tables) == after


def test_missing_key_or_unknown_historical_ref_rolls_back_every_write(database, rings):
    engine, tables, _old, _owner = database
    before = snapshot(engine, tables)
    with pytest.raises(SealedSecretError, match="PRIVATE_KEY_UNAVAILABLE"):
        migrate(engine, LEGACY, rings["api"], CONTROL, offline=True, backup_confirmed=True)
    assert snapshot(engine, tables) == before
    orphan = seal_fields(LEGACY, {"token": "historic-other-connector"})
    with engine.begin() as conn:
        conn.execute(tables["scan_jobs"].insert(), {"id": "orphan", "status": "SUCCEEDED", "payload": {"secret_ref": orphan}})
    before = snapshot(engine, tables)
    with pytest.raises(MigrationError, match="UNOWNED_REFERENCE"):
        migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True)
    assert snapshot(engine, tables) == before
    migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True,
            bindings={hashlib.sha256(orphan.encode()).hexdigest(): OTHER})
    with pytest.raises(MigrationError, match="OFFLINE_AND_BACKUP"):
        migrate(engine, LEGACY, rings["migration"], CONTROL)


def test_unknown_setting_auth_location_stops_migration_without_touching_prior_rows(database, rings):
    engine, tables, old, _owner = database
    with engine.begin() as conn:
        conn.execute(tables["installation_settings"].insert(), {"key": "unclassified", "value": {"nested": old}})
    before = snapshot(engine, tables)
    with pytest.raises(MigrationError, match="UNCLASSIFIED_SETTING"):
        migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True)
    assert snapshot(engine, tables) == before


def test_v1_migration_carries_scope_approval_and_retires_work_without_rewriting_checkpoint(database, rings):
    from cremore.domain.models import Connection
    from cremore.scanning.scope import auth_revision
    from cremore.secretstore.sealed_test import legacy_seal

    engine, tables, _old, _owner = database
    old = legacy_seal(LEGACY.legacy, "synthetic-v1")
    source = Connection(id=uuid.uuid4(), provider="github", name="synthetic source", config={}, secret_ref=old)
    approval = auth_revision("source", source)
    with engine.begin() as conn:
        conn.execute(tables["connections"].insert(), {"id": str(source.id), "provider": source.provider,
            "name": source.name, "status": source.status, "config": {}, "secret_ref": old})
        conn.execute(tables["scope_profiles"].insert(), {"id": "approved", "kind": "source",
            "connection_id": str(source.id), "auth_revision": approval})
        conn.execute(tables["scan_jobs"].insert(), {"id": "running", "status": "RUNNING", "payload": {"secret_ref": old}})
        conn.execute(tables["scan_tasks"].insert(), {"id": "leased", "run_id": "running", "status": "RUNNING",
            "payload": {}, "token": "old-fence", "lease_until": datetime.now(UTC), "checkpoint": {"page": 3}})
    migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True,
            bindings={hashlib.sha256(old.encode()).hexdigest(): BINDING})
    after = snapshot(engine, tables)
    ref = after["connections"][0]["secret_ref"]
    assert unseal(rings["collector"], ref, binding=BINDING) == {"token": "synthetic-v1"}
    assert after["scope_profiles"][0]["auth_revision"] == auth_revision("source", source.model_copy(update={"secret_ref": ref}))
    assert after["scope_profiles"][0]["auth_revision"] != approval
    run = next(row for row in after["scan_jobs"] if row["id"] == "running")
    assert run["status"] == "CANCELLED" and run["error"] == "CREDENTIAL_SEALING_MIGRATED_REQUEUE"
    task = after["scan_tasks"][0]
    assert task["status"] == "CANCELLED" and task["token"] is None and task["lease_until"] is None
    assert task["checkpoint"] == {"page": 3}


def settings_files(tmp_path, policy, private, **changes):
    public_path = tmp_path / "public.json"
    private_path = tmp_path / "private.json"
    public_path.write_text(json.dumps({"version": 1, "recipients": policy}), encoding="utf-8")
    private_path.write_text(json.dumps({"version": 1, "private_keys": private}), encoding="utf-8")
    api = Settings(ISOLATED_DEPLOYMENT=True, SEALING_PUBLIC_KEYS_FILE=str(public_path),
                   CONTROL_SEALING_KEY="cd" * 32, FINGERPRINT_KEY="ab" * 32, **changes)
    return api, api.model_copy(update={"control_sealing_key": "", "sealing_private_keys_file": str(private_path),
                                       "worker_execution_role": "collector"})


def test_github_manifest_control_secret_is_erased_when_released_to_worker(tmp_path, rings, material):
    from cremore.db.repository import InMemoryRepository
    from cremore.onboarding import github_app
    from cremore.onboarding.github_app_test import KEY, github
    from cremore.onboarding.store import ProviderConnectionStore

    api, worker = settings_files(tmp_path, rings["policy"], [material[0][1]])
    repo = InMemoryRepository()
    begun = github_app.start(repo, api, {"browser_key": KEY, "purposes": ["exposure"],
                                       "target": {"organization": "acme"}}, "admin")
    session = {"session_id": begun["session_id"], "browser_key": KEY}
    github_app.convert(repo, api, {**session, "state": begun["state"], "code": "synthetic-code"}, "admin", github())
    pending = repo.get_setting(github_app.PREFIX + begun["session_id"])["value"]["sealed"]
    assert unseal(api.control_sealing_keys, pending)["app_id"] == "424242"
    made = github_app.complete(repo, api, session, "admin", github())
    record = ProviderConnectionStore(repo).get(made["provider_connection_id"])
    assert repo.get_setting(github_app.PREFIX + begun["session_id"])["value"]["sealed"] is None
    ref = record["secret_refs"]["credential"]
    assert unseal(worker.credential_sealing_keys, ref, binding=binding_for_record(record))["GITHUB_APP_ID"] == "424242"
    with pytest.raises(SealedSecretError, match="PRIVATE_KEY_UNAVAILABLE"):
        unseal(api.control_sealing_keys, ref)


@pytest.mark.parametrize("derived_enterprise", [False, True])
def test_enterprise_api_queues_refresh_without_credential_access_and_worker_publishes(tmp_path, material, derived_enterprise):
    from cremore.db.repository import InMemoryRepository
    from cremore.onboarding import github_enterprise
    from cremore.onboarding.github_enterprise_test import SETTINGS, GitHub, source
    from cremore.onboarding.store import ProviderConnectionStore

    repo = InMemoryRepository()
    connection_id = source(repo)
    store = ProviderConnectionStore(repo)
    record = store.get(connection_id)
    if derived_enterprise:
        target = dict(record["target"])
        target["auth"] = {"github_enterprise": target.pop("enterprise")}
        record = store.update(record["id"], record["revision"], "synthetic", target=target)
    binding = binding_for_record(record)
    policy = [{**binding, "public_keys": [material[0][0]]}]
    api, worker = settings_files(tmp_path, policy, [material[0][1]])
    fields = unseal(SETTINGS.sealing_keys, record["secret_refs"]["credential"])
    ref = seal_fields(api.credential_sealing_keys, fields, binding=binding)
    store.update(record["id"], record["revision"], "migration", secret_refs={"credential": ref})

    def forbidden():
        raise AssertionError("API must not call GitHub for stored credentials")

    assert github_enterprise.status(repo, api, connection_id, forbidden)["state"] == "REFRESHING"
    provider = GitHub()
    github_enterprise.sweep(repo, worker, provider.client)
    result = github_enterprise.status(repo, api, connection_id, forbidden)
    assert result["state"] == "READY" and result["refresh_pending"] is False
    assert result["organizations"]


def test_gcp_oauth_releases_only_collector_envelope_and_clears_pending_secret(tmp_path, material, monkeypatch):
    from cremore_gcp_provider import oauth
    from fastapi.testclient import TestClient

    from cremore.api import create_app
    from cremore.api.gcp_oauth_test import (
        BASE,
        BROWSER,
        FIELDS,
        TOKEN,
        begin,
        connection,
        oauth_settings,
    )
    from cremore.coverage.gcp_oauth_store import GcpOAuthStore
    from cremore.db.repository import InMemoryRepository
    from cremore.onboarding.store import ProviderConnectionStore

    binding = credential_binding("gcp", {}, purposes=["exposure"], auth_method="google_oauth")
    base = oauth_settings()
    api, worker = settings_files(tmp_path, [{**binding, "public_keys": [material[0][0]]}], [material[0][1]],
        API_TOKEN=TOKEN, GCP_OAUTH_CLIENT_ID=base.gcp_oauth_client_id,
        GCP_OAUTH_CLIENT_SECRET=base.gcp_oauth_client_secret, GCP_OAUTH_REDIRECT_URI=base.gcp_oauth_redirect_uri)
    repo = InMemoryRepository()
    monkeypatch.setattr(oauth, "exchange", lambda *_: (FIELDS.copy(), {"subject": "123"}))
    with TestClient(create_app(repo=repo, settings=api), headers={"Authorization": "Bearer " + TOKEN}) as client:
        owner_id = connection(client)
        started = begin(client, owner_id)
        finish = client.post(BASE + "finish", json={"session_id": started["session_id"], "browser_key": BROWSER,
            "state": started["state"], "code": "synthetic-code"})
        assert finish.status_code == 200, finish.text
        complete = client.post(BASE + "complete", json={"session_id": started["session_id"], "browser_key": BROWSER})
        assert complete.status_code == 200, complete.text
    record = ProviderConnectionStore(repo).get(owner_id)
    fields = unseal(worker.credential_sealing_keys, record["secret_refs"]["credential"], binding=binding_for_record(record))
    assert fields == FIELDS
    store = GcpOAuthStore(repo)
    with store.transaction() as conn:
        row = store._get(conn, "oauth_sessions", uuid.UUID(started["session_id"]))
    assert row["stage"] == "COMPLETED"
    assert set(row["data"]) == {"result"}


def test_machine_identity_migrates_to_its_pinned_collector_group(database, rings, material, monkeypatch):
    from cremore.identity import machine

    engine, tables, _old, _owner = database
    binding = {"purpose": "collector", "provider": "machine_identity", "authority": {
        "token_url": "https://id.example.invalid/token", "client_id": "synthetic-client"}}
    policy = [*rings["policy"], {**binding, "public_keys": [material[3][0]]}]
    ring = RecipientKeys(policy, [item[1] for item in material])
    # The machine module owns normalization; this test pins the migrator's dispatch.
    monkeypatch.setattr(machine, "machine_binding", lambda record: binding, raising=False)
    old = seal_fields(LEGACY, {"client_secret": "synthetic-idp"})
    with engine.begin() as conn:
        conn.execute(tables["installation_settings"].insert(), {"key": "machine_identity", "value": {
            "idp": {"token_url": binding["authority"]["token_url"], "client_id": "synthetic-client"}, "secret": old}})
    migrate(engine, LEGACY, ring, CONTROL, offline=True, backup_confirmed=True)
    after = snapshot(engine, tables)
    value = next(row["value"] for row in after["installation_settings"] if row["key"] == "machine_identity")
    assert unseal(ring, value["secret"], binding=binding) == {"client_secret": "synthetic-idp"}
    with pytest.raises(SealedSecretError, match="PRIVATE_KEY_UNAVAILABLE"):
        unseal(CONTROL, value["secret"])


def test_offline_key_rotation_rewraps_v3_once_without_changing_observations(database, rings, material):
    engine, tables, _old, _owner = database
    migrate(engine, LEGACY, rings["migration"], CONTROL, offline=True, backup_confirmed=True)
    before = snapshot(engine, tables)
    policy = copy.deepcopy(rings["policy"])
    policy[0]["public_keys"].insert(0, material[3][0])
    rotated = RecipientKeys(policy, [item[1] for item in material])
    migrate(engine, LEGACY, rotated, CONTROL, offline=True, backup_confirmed=True)
    after = snapshot(engine, tables)
    assert before["provider_connections"][0]["secret_refs"] != after["provider_connections"][0]["secret_refs"]
    assert before["finding_events"] == after["finding_events"]
    assert migrate(engine, LEGACY, rotated, CONTROL, offline=True, backup_confirmed=True)["changed_rows"] == {}
