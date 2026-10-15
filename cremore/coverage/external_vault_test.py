"""External vaults (JSON Lines and reader plugins) and per-connection Vault logins.

Synthetic data only: fake HTTP transports, a fake kubectl and fixture plugins.
"""

import base64
import io
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage import external_vault
from cremore.coverage.correlation import report, scope_revision
from cremore.coverage.external_vault import (
    ReaderProvider,
    VaultEntry,
    collect_external,
    jsonl_entries,
    load_reader,
)
from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, weakest_completeness
from cremore.coverage.readers.kubernetes_secrets import KubernetesSecretsReader
from cremore.coverage.store import CoverageError, CoverageStore
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import ResourceRef
from cremore.detection.engine import Engine, EngineConfig
from cremore.scanning.orchestrator import Orchestrator

KEY = b"k" * 32
TOKEN = "coverage-api-" + "z" * 32
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
GH2 = "ghp_" + "Zy9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8"
PLAIN = "synthetic-database-password-value-4471"


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def engine():
    return Engine(EngineConfig(fingerprint_key=KEY))


def contract():
    return Contract(engine_digest=engine().detection_digest).model_dump()


def external(**changes):
    fields = {"name": "Team 1Password", "provider": "external_vault", "product": "1Password", "prefixes": ["prod"]}
    return ConnectionSpec(**(fields | changes))


def lines(*rows):
    return io.BytesIO(b"".join(json.dumps(row).encode() + b"\n" for row in rows))


# --- the connection contract -------------------------------------------------

def test_external_vault_needs_a_product_and_a_declared_path_scope():
    assert external().prefixes == ["prod"]
    assert external(prefixes=[""]).prefixes == [""]  # the whole export, declared explicitly
    for changes, code in [({"product": ""}, "EXTERNAL_VAULT_PRODUCT_REQUIRED"),
                          ({"prefixes": []}, "EXTERNAL_VAULT_DECLARED_SCOPE_REQUIRED"),
                          ({"endpoint": "https://vault.example.test"}, "EXTERNAL_VAULT_SCOPE_IS_PATH_PREFIXES"),
                          ({"prefixes": ["../escape"]}, "INVALID_SCOPE_PATH"),
                          ({"product": "ghp_" + "x" * 36}, "UNSAFE_METADATA")]:
        with pytest.raises(ValidationError, match=code):
            external(**changes)
    with pytest.raises(ValidationError, match="PRODUCT_AND_READER_REQUIRE_EXTERNAL_VAULT"):
        ConnectionSpec(name="SM", provider="aws_secrets_manager", account_id="123456789012", regions=["us-east-1"],
                       product="Doppler")


def vault_spec(**changes):
    fields = {"name": "Other cluster", "provider": "vault", "endpoint": "https://vault-b.example.test",
              "mounts": [{"name": "secret", "kv_version": 2, "prefixes": ["app"]}], "server_collection": True}
    return ConnectionSpec(**(fields | changes))


def test_server_login_belongs_to_a_server_read_of_vault_and_names_a_file_not_a_path():
    spec = vault_spec(server_auth={"method": "jwt", "role": "cremore", "token_file": "vault-b"})
    assert spec.server_auth.mount == "jwt"
    for auth, code in [({"method": "kubernetes", "role": "cremore"}, "VAULT_LOGIN_ROLE_AND_TOKEN_FILE_REQUIRED"),
                       ({"method": "jwt", "role": "cremore", "token_file": "../etc/passwd"}, "String should match"),
                       ({"method": "jwt", "role": "cremore", "token_file": "a/b"}, "String should match"),
                       ({"method": "token", "role": "cremore"}, "TOKEN_LOGIN_TAKES_NO_ROLE")]:
        with pytest.raises(ValidationError, match=code):
            vault_spec(server_auth=auth)
    with pytest.raises(ValidationError, match="VAULT_SERVER_LOGIN_REQUIRES_SERVER_COLLECTION"):
        vault_spec(server_collection=False, server_auth={"method": "token"})
    with pytest.raises(ValidationError, match="VAULT_TOKEN_REQUIRES_TOKEN_LOGIN"):
        vault_spec(secret_refs={"vault_token": "sealed:v2:0123456789abcdef:AAAA"})
    with pytest.raises(ValidationError, match="TLS_CA_MUST_BE_A_PEM_CERTIFICATE"):
        vault_spec(tls_ca_pem="-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")


def test_weakest_completeness_orders_api_reader_operator():
    assert weakest_completeness(["API_LISTING", "READER_REPORTED"]) == "READER_REPORTED"
    assert weakest_completeness(["OPERATOR_DECLARED", "API_LISTING"]) == "OPERATOR_DECLARED"
    assert weakest_completeness([None, "UNKNOWN"]) is None


# --- JSON Lines --------------------------------------------------------------

def test_json_lines_are_strict_bounded_and_never_echoed():
    reasons = set()
    stream = io.BytesIO(b'{"path": "prod/a", "value": "x"}\n\n'
                        b'not json ' + PLAIN.encode() + b'\n'
                        b'{"path": "prod/b", "value": "x", "comment": "unknown field"}\n'
                        b'{"path": "prod/c", "value": "' + b"y" * 300 + b'"}\n'
                        b'{"path": "prod/d", "value": {"user": "a", "password": "b"}, "version": "7",'
                        b' "updated_at": "2026-09-01T00:00:00Z", "state": "PREVIOUS"}\n')
    entries = list(jsonl_entries(stream, max_line_bytes=200, reasons=reasons))
    assert [entry.path for entry in entries] == ["prod/a", "prod/d"]
    assert entries[1].state == "PREVIOUS" and entries[1].version == "7"
    assert reasons == {"INPUT_LINE_INVALID", "INPUT_LINE_TOO_LARGE"}
    assert PLAIN not in json.dumps(sorted(reasons))


def test_collection_fingerprints_in_scope_values_and_skips_the_rest():
    entries = [VaultEntry("prod/app/github", GH), VaultEntry("prod/app/db", PLAIN, version="3",
                                                               updated_at="2026-09-01T00:00:00+09:00"),
               VaultEntry("staging/app/github", GH2), VaultEntry("prod/app/github", GH),
               VaultEntry("prod/app/empty", ""), VaultEntry("prod/../x", GH),
               VaultEntry("prod/app/when", GH2, updated_at="yesterday")]
    out = collect_external(external(), engine(), entries)
    values = [item for item in out.items if item.evidence == "VALUE"]
    assert {item.reference for item in values} == {"prod/app/github", "prod/app/db", "prod/app/when"}
    # A value no detector names is still compared, as an opaque fingerprint.
    assert next(item for item in values if item.reference == "prod/app/db").credential_type == "OPAQUE_VALUE"
    assert out.skipped == 1  # staging/: outside the declared scope, not a gap in it
    assert {"INPUT_DUPLICATE_ENTRY", "INPUT_VALUE_INVALID", "INPUT_PATH_INVALID",
            "INPUT_TIMESTAMP_INVALID"} <= out.reasons
    assert out.status == "PARTIAL"
    serialized = json.dumps([item.model_dump() for item in out.items])
    assert GH not in serialized and GH2 not in serialized and PLAIN not in serialized
    clean = collect_external(external(), engine(), [VaultEntry("prod/app/github", GH)])
    assert clean.status == "COMPLETE" and clean.items[0].credential_type == "GITHUB_TOKEN"


def test_record_budget_stops_with_a_reason():
    out = collect_external(external(max_records=1), engine(), [VaultEntry("prod/a", GH), VaultEntry("prod/b", GH2)])
    assert "RECORD_LIMIT" in out.reasons and len(out.items) == 1


# --- the customer-side CLI ---------------------------------------------------

class Recorder:
    """A TestClient wrapper that keeps every request body the CLI sent."""

    def __init__(self, client):
        self.client, self.bodies = client, []

    def request(self, method, url, **kwargs):
        self.bodies.append(json.dumps(kwargs.get("json"), default=str))
        return self.client.request(method, url, **kwargs)

    def build_request(self, method, url, **kwargs):
        self.bodies.append(json.dumps(kwargs.get("json"), default=str))
        return self.client.build_request(method, url, **kwargs)

    def send(self, request, **kwargs):
        return self.client.send(request, **kwargs)

    def close(self):
        pass


def cli_stack(repo):
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    return Recorder(TestClient(app))


def expose(repo, material):
    eng = engine()
    Orchestrator(repo, engine=eng, config=eng.config).scan_resource(
        material.encode(), ResourceRef(source_type="inline", resource="synthetic", location="fixture"), verify=False)


def confirm_scope(repo):
    repo.put_setting("coverage_scope", {"confirmed": True,
                                        "revision": scope_revision(CoverageStore(repo).list_connections())}, "admin")


def test_json_lines_export_needs_the_operators_declaration_before_absence(repo):
    from cremore.cli.coverage import execute

    client = cli_stack(repo)
    expose(repo, GH2)  # exposed, and not in the export
    store = CoverageStore(repo)
    connection, token = store.create(external(), "admin")
    confirm_scope(repo)
    rows = [{"path": "prod/app/github", "value": GH}, {"path": "staging/other", "value": GH2}]
    result = execute("http://localhost", connection["id"], token, KEY, client=client, input_stream=lines(*rows))
    assert result["status"] == "PARTIAL" and result["reasons"] == ["COMPLETENESS_NOT_DECLARED"]
    assert result["completeness"] is None and result["outside_declared_scope"] == 1
    view = report(repo, contract(), fingerprint_key_id=None)
    assert view["summary"]["no_vault_match"] == 0 and view["absence_basis"] is None
    assert "COMPLETENESS_NOT_DECLARED" in view["scope_reasons"]
    # A value no detector names stays unresolved, like in any built-in vault,
    # and is still never sent as text.
    mixed = execute("http://localhost", connection["id"], token, KEY, client=client, declare_complete=True,
                    input_stream=lines(*rows, {"path": "prod/app/db", "value": PLAIN}))
    assert mixed["status"] == "PARTIAL" and mixed["completeness"] is None
    assert {"UNRECOGNIZED_MATERIAL", "UNRESOLVED_ITEMS"} <= set(mixed["reasons"])

    result = execute("http://localhost", connection["id"], token, KEY, client=client, input_stream=lines(*rows),
                     declare_complete=True)
    assert result["status"] == "COMPLETE" and result["completeness"] == "OPERATOR_DECLARED"
    view = report(repo, contract(), fingerprint_key_id=None)
    [row] = [row for row in view["items"] if row["origin"] == "EXPOSURE"]
    assert row["state"] == "NO_VAULT_MATCH" and row["absence_basis"] == "OPERATOR_DECLARED"
    assert view["absence_basis"] == "OPERATOR_DECLARED"
    state = next(item for item in view["connections"] if item["id"] == connection["id"])
    assert state["latest"]["completeness"] == "OPERATOR_DECLARED"
    # Nothing but fingerprints left this process, in any request.
    sent = "\n".join(client.bodies)
    assert GH not in sent and GH2 not in sent and PLAIN not in sent
    assert GH not in json.dumps(store.snapshots(connection["id"]), default=str)


def test_an_exported_value_matches_its_exposure(repo):
    from cremore.cli.coverage import execute

    client = cli_stack(repo)
    expose(repo, GH)
    connection, token = CoverageStore(repo).create(external(), "admin")
    confirm_scope(repo)
    execute("http://localhost", connection["id"], token, KEY, client=client,
            input_stream=lines({"path": "prod/app/github", "value": GH}), declare_complete=True)
    [row] = [row for row in report(repo, contract())["items"] if row["origin"] == "EXPOSURE"]
    assert row["state"] == "MATCHED" and row["locations"][0]["provider"] == "external_vault"
    assert row["locations"][0]["reference"] == "prod/app/github"


def test_cli_refuses_inputs_that_do_not_fit_the_connection(repo):
    from cremore.cli.coverage import execute

    client = cli_stack(repo)
    store = CoverageStore(repo)
    jsonl, token = store.create(external(), "admin")
    with pytest.raises(ValueError, match="INPUT_REQUIRED"):
        execute("http://localhost", jsonl["id"], token, KEY, client=client)
    with pytest.raises(ValueError, match="READER_OPTIONS_REQUIRE_A_READER"):
        execute("http://localhost", jsonl["id"], token, KEY, client=client, input_stream=lines(),
                reader_options={"context": "x"})
    kube, kube_token = store.create(external(reader="kubernetes_secrets", product="Kubernetes Secrets"), "admin")
    with pytest.raises(ValueError, match="INPUT_REQUIRES_EXTERNAL_VAULT_EXPORT"):
        execute("http://localhost", kube["id"], kube_token, KEY, client=client, declare_complete=True)
    # The server refuses a basis that does not match how the connection is read.
    run = store.start(kube["id"], 1, str(uuid.uuid4()), contract())
    with pytest.raises(CoverageError, match="COMPLETENESS_BASIS_MISMATCH"):
        store.finish(kube["id"], run["id"], Finish(batch_count=0, item_count=0, status="COMPLETE",
                                                   completeness="OPERATOR_DECLARED"))


def test_built_in_stores_record_an_api_listing_and_cannot_claim_a_declaration(repo):
    store = CoverageStore(repo)
    row, _ = store.create(ConnectionSpec(name="SM", provider="aws_secrets_manager", account_id="123456789012",
                                         regions=["us-east-1"]), "admin")
    run = store.start(row["id"], 1, str(uuid.uuid4()), contract())
    with pytest.raises(CoverageError, match="COMPLETENESS_BASIS_MISMATCH"):
        store.finish(row["id"], run["id"], Finish(batch_count=0, item_count=0, status="COMPLETE",
                                                  completeness="OPERATOR_DECLARED"))
    finished = store.finish(row["id"], run["id"], Finish(batch_count=0, item_count=0, status="COMPLETE"))
    assert finished["completeness"] == "API_LISTING"
    assert store.latest_run(row["id"])["completeness"] == "API_LISTING"


def test_a_store_read_by_the_secrets_an_operator_named_is_whole_by_that_list(repo):
    """AWS or GCP Secret Manager over the references an operator listed reads no list (owner decision 2026-10-08):
    the server records the operator's list as the basis, and a collector still cannot claim one."""
    store = CoverageStore(repo)
    for spec in (ConnectionSpec(name="SM", provider="aws_secrets_manager", account_id="123456789012", regions=["us-east-1"],
                                references=["arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"]),
                 ConnectionSpec(name="GCP", provider="gcp_secret_manager", project="synthetic-project",
                                references=["projects/synthetic-project/secrets/db"])):
        row, _ = store.create(spec, "admin")
        run = store.start(row["id"], 1, str(uuid.uuid4()), contract())
        with pytest.raises(CoverageError, match="COMPLETENESS_BASIS_MISMATCH"):
            store.finish(row["id"], run["id"], Finish(batch_count=0, item_count=0, status="COMPLETE",
                                                      completeness="OPERATOR_DECLARED"))
        finished = store.finish(row["id"], run["id"], Finish(batch_count=0, item_count=0, status="COMPLETE"))
        assert finished["completeness"] == "OPERATOR_DECLARED", spec.provider


def test_absence_carries_the_weakest_basis_across_stores(repo):
    from cremore.coverage.hasher import hash_value

    expose(repo, GH2)
    store = CoverageStore(repo)
    sm, _ = store.create(ConnectionSpec(name="SM", provider="aws_secrets_manager", account_id="123456789012",
                                        regions=["us-east-1"]), "admin")
    ext, _ = store.create(external(), "admin")
    arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db-Ab12Cd"
    run = store.start(sm["id"], 1, str(uuid.uuid4()), contract())
    items = hash_value(engine(), GH.encode(), {"reference": arn, "account_id": "123456789012",
                                               "region": "us-east-1", "version": "v1"}, max_bytes=1024)
    store.append(sm["id"], run["id"], Batch(index=0, items=items))
    store.finish(sm["id"], run["id"], Finish(batch_count=1, item_count=len(items), status="COMPLETE"))
    run = store.start(ext["id"], 1, str(uuid.uuid4()), contract())
    store.finish(ext["id"], run["id"], Finish(batch_count=0, item_count=0, status="COMPLETE",
                                              completeness="OPERATOR_DECLARED"))
    confirm_scope(repo)
    view = report(repo, contract())
    assert view["absence_basis"] == "OPERATOR_DECLARED" and view["summary"]["no_vault_match"] == 1
    store.change(ext["id"], 1, "admin", enabled=False)
    confirm_scope(repo)
    assert report(repo, contract())["absence_basis"] == "API_LISTING"


# --- reader plugins ----------------------------------------------------------

class Listed:
    """A fixture reader: lists its fixed entries and reports the listing whole."""

    def __init__(self, options):
        self.options, self.complete = options, False

    def entries(self, prefixes):
        yield VaultEntry("prod/app/github", GH, version="1")
        self.complete = self.options.get("complete") != "no"


FIXTURE = ReaderProvider(id="fixture_reader", api_version=1, build=Listed)


def fake_entry_points(monkeypatch, provider=FIXTURE, name="fixture_reader"):
    entry = SimpleNamespace(name=name, load=lambda: provider)
    monkeypatch.setattr(external_vault, "entry_points", lambda group: [entry] if group == external_vault.ENTRY_POINT_GROUP else [])


def test_plugins_load_only_when_allowed_and_must_match_the_contract(monkeypatch):
    fake_entry_points(monkeypatch)
    assert "kubernetes_secrets" in external_vault.providers()
    with pytest.raises(ValueError, match="VAULT_READER_UNAVAILABLE"):
        load_reader("missing", allow_plugins=("missing",))
    with pytest.raises(ValueError, match="VAULT_READER_NOT_ENABLED"):
        load_reader("fixture_reader")
    assert load_reader("fixture_reader", allow_plugins=("fixture_reader",)) is FIXTURE
    fake_entry_points(monkeypatch, provider=ReaderProvider(id="other", api_version=1, build=Listed))
    with pytest.raises(ValueError, match="VAULT_READER_CONTRACT_INCOMPATIBLE"):
        load_reader("fixture_reader", allow_plugins=("fixture_reader",))
    fake_entry_points(monkeypatch, name="Bad Name")
    with pytest.raises(ValueError, match="VAULT_READER_ID_INVALID"):
        external_vault.providers()
    fake_entry_points(monkeypatch, name="kubernetes_secrets")
    with pytest.raises(ValueError, match="VAULT_READER_ID_DUPLICATE"):
        external_vault.providers()


def test_cli_reader_reports_its_own_listing(repo, monkeypatch):
    from cremore.cli.coverage import execute

    fake_entry_points(monkeypatch)
    client = cli_stack(repo)
    store = CoverageStore(repo)
    connection, token = store.create(external(reader="fixture_reader", product="Fixture vault"), "admin")
    with pytest.raises(ValueError, match="VAULT_READER_NOT_ENABLED"):
        execute("http://localhost", connection["id"], token, KEY, client=client)
    failed = store.latest_run(connection["id"])
    assert failed["status"] == "FAILED" and failed["reasons"] == ["VAULT_READER_NOT_ENABLED"]
    result = execute("http://localhost", connection["id"], token, KEY, client=client, allow_readers=("fixture_reader",))
    assert result["status"] == "COMPLETE" and result["completeness"] == "READER_REPORTED"
    result = execute("http://localhost", connection["id"], token, KEY, client=client, allow_readers=("fixture_reader",),
                     reader_options={"complete": "no"})
    assert result["status"] == "PARTIAL" and "READER_LISTING_INCOMPLETE" in result["reasons"]
    assert GH not in "\n".join(client.bodies)


# --- the built-in Kubernetes reader ------------------------------------------

def secret(namespace, name, data, version="42"):
    return {"metadata": {"namespace": namespace, "name": name, "resourceVersion": version},
            "data": {key: base64.b64encode(value.encode()).decode() if value is not None else "!!not-base64!!"
                     for key, value in data.items()}}


def kubectl(listings, calls):
    def run(command, **kwargs):
        calls.append((command, kwargs))
        namespace = None if "--all-namespaces" in command else command[command.index("--namespace") + 1]
        items = listings.get(namespace)
        if items is None:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"Forbidden")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"items": items}).encode(), stderr=b"")
    return run


def test_kubernetes_reader_lists_namespaces_narrows_to_secrets_and_never_uses_a_shell():
    calls = []
    run = kubectl({"prod": [secret("prod", "db", {"password": PLAIN, "empty": ""}),
                            secret("prod", "gh", {"token": GH, "bad": None})]}, calls)
    reader = KubernetesSecretsReader({"context": "synthetic"}, run=run)
    entries = list(reader.entries(("prod",)))
    assert reader.complete is True
    assert [entry.path for entry in entries] == ["prod/db/password", "prod/gh/bad", "prod/gh/token"]
    assert entries[0].version == "42" and entries[2].value == GH.encode() and entries[1].value == ""
    command, kwargs = calls[0]
    assert command[:5] == ["kubectl", "get", "secrets", "-o", "json"] and "--context" in command
    assert "shell" not in kwargs and kwargs["capture_output"] is True
    narrowed = KubernetesSecretsReader({}, run=kubectl({"prod": [secret("prod", "db", {"password": PLAIN}),
                                                                secret("prod", "gh", {"token": GH})]}, []))
    assert [entry.path for entry in narrowed.entries(("prod/gh",))] == ["prod/gh/token"]
    everything = KubernetesSecretsReader({}, run=kubectl({None: [secret("a", "s", {"k": GH})]}, calls))
    assert [entry.path for entry in everything.entries(("",))] == ["a/s/k"] and everything.complete
    with pytest.raises(ValueError, match="READER_OPTION_UNKNOWN"):
        KubernetesSecretsReader({"kubeconfig": "x"})


def test_kubernetes_refusal_is_an_incomplete_listing_not_an_empty_one():
    reader = KubernetesSecretsReader({}, run=kubectl({"prod": [secret("prod", "gh", {"token": GH})]}, []))
    out, complete = external_vault.read_with(
        ReaderProvider(id="kubernetes_secrets", api_version=1, build=lambda options: reader),
        external(prefixes=["prod", "restricted"]), engine(), {})
    assert complete is False and "READER_LISTING_INCOMPLETE" in out.reasons and out.status == "PARTIAL"
    assert any(item.evidence == "VALUE" for item in out.items)


def test_a_failing_reader_reports_a_code_and_never_its_error_text():
    class Broken:
        complete = True

        def __init__(self, options):
            pass

        def entries(self, prefixes):
            yield VaultEntry("prod/a", GH)
            raise RuntimeError("vault said: " + PLAIN)

    out, complete = external_vault.read_with(ReaderProvider(id="x", api_version=1, build=Broken),
                                             external(), engine(), {})
    assert complete is False and {"READER_FAILED", "READER_LISTING_INCOMPLETE"} <= out.reasons
    assert PLAIN not in json.dumps(sorted(out.reasons))


# --- a server read with the connection's own Vault login ---------------------

def login_stack(repo, monkeypatch, tmp_path, *, store_url="https://vault-a.example.test", token_dir=True, **extra):
    from cremore.secretstore.resolver import SecretResolver
    from cremore.worker.worker import JobWorker
    calls = []

    def handle(request):
        calls.append(request)
        if request.url.path.endswith("/login"):
            body = json.loads(request.content)
            assert body == {"role": "cremore", "jwt": "projected.jwt.for.vault-b"}
            return httpx.Response(200, json={"auth": {"client_token": "hvs.connection-own", "lease_duration": 600}})
        assert request.headers["X-Vault-Token"] in ("hvs.connection-own", "hvs.sealed-token")
        if request.url.params.get("list"):
            return httpx.Response(200, json={"data": {"keys": ["token"]}})
        return httpx.Response(200, json={"data": {"data": {"value": GH}, "metadata": {"version": 3, "destroyed": False,
                                                                                     "deletion_time": ""}}})

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real(transport=httpx.MockTransport(handle)))
    directory = tmp_path / "vault-connections"
    directory.mkdir()
    (directory / "vault-b").write_text("projected.jwt.for.vault-b", encoding="ascii")
    install_file = tmp_path / "install-token"
    install_file.write_text("install.identity.jwt", encoding="ascii")
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex(), SECRET_STORE_URL=store_url,
                        SECRET_STORE_AUTH_MODE="kubernetes", SECRET_STORE_KUBERNETES_ROLE="install-role",
                        SECRET_STORE_KUBERNETES_TOKEN_FILE=str(install_file),
                        VAULT_CONNECTION_TOKEN_DIR=str(directory) if token_dir else "", **extra)
    app = create_app(repo=repo, settings=settings)
    worker = JobWorker(repo, orchestrator=app.state.orchestrator, settings=settings,
                       metadata_secret_resolver=SecretResolver(None, sealing_key=settings.sealing_keys))
    return TestClient(app), {"Authorization": "Bearer " + TOKEN}, worker, calls, directory, install_file


def collect(api, auth, worker, repo, connection_id):
    queued = api.post(f"/api/v1/coverage/connections/{connection_id}/collect", headers=auth)
    assert queued.status_code == 202, queued.text
    worker.process_next()
    return repo.get_job(uuid.UUID(queued.json()["job_id"]))


@pytest.mark.parametrize("method", ["kubernetes", "jwt"])
def test_a_connection_logs_in_as_itself_even_at_the_installation_stores_address(repo, monkeypatch, tmp_path, method):
    api, auth, worker, calls, _, _ = login_stack(repo, monkeypatch, tmp_path, store_url="https://vault-b.example.test")
    store = CoverageStore(repo)
    row = store.create(vault_spec(server_auth={"method": method, "role": "cremore", "token_file": "vault-b"}), "admin")[0]
    job = collect(api, auth, worker, repo, row["id"])
    assert job.status == "SUCCEEDED", job.error
    [run] = store.snapshots(row["id"])
    assert run["status"] == "COMPLETE" and run["completeness"] == "API_LISTING"
    assert calls[0].url.path == f"/v1/auth/{method}/login"
    assert all(str(request.url).startswith("https://vault-b.example.test/") for request in calls)
    headers = json.dumps([dict(request.headers) for request in calls])
    assert "install.identity.jwt" not in headers and "install-role" not in "".join(
        request.content.decode(errors="ignore") for request in calls)
    outputs = json.dumps(run, default=str) + json.dumps([j.payload for j in repo.list_jobs()], default=str)
    assert GH not in outputs and "hvs.connection-own" not in outputs


def test_a_token_accessor_gap_leaves_an_empty_kv_run_and_its_job_complete(repo, monkeypatch, tmp_path):
    from httpx._client import Client

    api, auth, worker, _calls, _, _ = login_stack(repo, monkeypatch, tmp_path, store_url="https://vault-b.example.test")

    def handle(request):
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={"auth": {"client_token": "hvs.connection-own", "lease_duration": 600}})
        if request.url.params.get("list"):
            return httpx.Response(200, json={"data": {"keys": []}})  # the KV prefix holds nothing
        return httpx.Response(403, json={"errors": ["permission denied"]})  # the accessor list is refused

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: Client(transport=httpx.MockTransport(handle)))
    store = CoverageStore(repo)
    row = store.create(vault_spec(include_token_accessors=True,
                                  server_auth={"method": "jwt", "role": "cremore", "token_file": "vault-b"}), "admin")[0]
    job = collect(api, auth, worker, repo, row["id"])
    [run] = store.snapshots(row["id"])
    # A management gap stays on the run but never fails the complete, empty KV listing or its job.
    assert run["status"] == "COMPLETE" and run["completeness"] == "API_LISTING"
    assert "TOKEN_ACCESSOR_LIST_FAILED" in run["reasons"]
    assert job.status == "SUCCEEDED", job.error


def test_a_login_file_must_stay_in_the_directory_and_never_be_the_installations(repo, monkeypatch, tmp_path):
    api, auth, worker, calls, directory, install_file = login_stack(repo, monkeypatch, tmp_path)
    store = CoverageStore(repo)
    outside = tmp_path / "elsewhere"
    outside.write_text("stolen.jwt", encoding="ascii")
    try:
        os.symlink(outside, directory / "escape")
        os.symlink(install_file, directory / "install")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available to this test user")
    for name, code in [("escape", "VAULT_CONNECTION_TOKEN_FILE_OUTSIDE_DIRECTORY"),
                       ("missing", "SECRET_STORE_WORKLOAD_TOKEN_UNAVAILABLE")]:
        row = store.create(vault_spec(name="c-" + name, server_auth={"method": "jwt", "role": "cremore",
                                                                     "token_file": name}), "admin")[0]
        job = collect(api, auth, worker, repo, row["id"])
        assert job.status == "FAILED" and code in (job.error or "")
    assert calls == []


def test_the_installations_own_token_file_is_refused(repo, monkeypatch, tmp_path):
    from cremore_vault_provider.connection_login import ConnectionLoginError, connection_token

    directory = tmp_path / "shared"
    directory.mkdir()
    (directory / "token").write_text("install.identity.jwt", encoding="ascii")
    spec = vault_spec(server_auth={"method": "kubernetes", "role": "cremore", "token_file": "token"})
    with pytest.raises(ConnectionLoginError, match="VAULT_CONNECTION_TOKEN_FILE_REFUSED"):
        connection_token(spec, None, token_dir=str(directory), install_token_file=str(directory / "token"))


def test_no_token_directory_means_no_request(repo, monkeypatch, tmp_path):
    api, auth, worker, calls, _, _ = login_stack(repo, monkeypatch, tmp_path, token_dir=False)
    row = CoverageStore(repo).create(vault_spec(server_auth={"method": "jwt", "role": "cremore",
                                                             "token_file": "vault-b"}), "admin")[0]
    job = collect(api, auth, worker, repo, row["id"])
    assert job.status == "FAILED" and "VAULT_CONNECTION_TOKEN_DIR_NOT_CONFIGURED" in (job.error or "")
    # The refused login is the run's own reason, where health reads it, never only an interruption.
    [run] = CoverageStore(repo).snapshots(row["id"])
    assert run["status"] == "FAILED" and run["reasons"] == ["VAULT_CONNECTION_TOKEN_DIR_NOT_CONFIGURED"]
    assert calls == []


def test_a_token_login_is_sealed_on_arrival_and_never_returned(repo, monkeypatch, tmp_path):
    from cremore.onboarding.fixtures_test import wizard

    api, auth, worker, calls, _, _ = login_stack(repo, monkeypatch, tmp_path)
    connection = {"provider": "vault", "purposes": ["vault"], "auth_method": "token",
                  "target": {"address": "https://vault-b.example.test", "mounts": ["secret"], "prefixes": ["app"]}}
    # A reference could name any secret the installation stores, and the token is sent to the cluster.
    smuggled = api.post("/api/v1/provider-connections", headers=auth,
                        json={**connection, "credential": {"vault_ref": "vault://cremore/sealing"}})
    assert smuggled.status_code == 422 and smuggled.json()["error"] == "CREDENTIAL_REFERENCE_NOT_ALLOWED"
    view = wizard(api, auth, {**connection, "credential": {"token": "hvs.sealed-token"}}, plans={"vault": {}})
    cid = view["created"][0]["id"]
    body = {key: value for key, value in CoverageStore(repo).get(uuid.UUID(cid))["spec"].items() if key != "secret_refs"}
    stored = CoverageStore(repo).get(uuid.UUID(cid))
    assert stored["spec"]["secret_refs"]["vault_token"].startswith("sealed:v2:")
    views = json.dumps(api.get("/api/v1/coverage", headers=auth).json())
    assert "hvs.sealed-token" not in views and "sealed:v2:" not in views
    # An edit that does not resend the reference or the login keeps them.
    kept = {key: value for key, value in body.items() if key != "server_auth"}
    edited = api.patch(f"/api/v1/coverage/connections/{cid}", headers=auth,
                       json={"revision": stored["revision"], "spec": {**kept, "name": "Renamed"}})
    assert edited.status_code == 200, edited.text
    after = CoverageStore(repo).get(uuid.UUID(cid))["spec"]
    assert after["secret_refs"] and after["server_auth"] == stored["spec"]["server_auth"]
    # The login is the provider connection's: an edit cannot switch it to another method.
    switched = api.patch(f"/api/v1/coverage/connections/{cid}", headers=auth, json={
        "revision": stored["revision"] + 1,
        "spec": {**body, "server_auth": {"method": "kubernetes", "role": "reader", "token_file": "vault-b"}}})
    assert switched.status_code == 409 and switched.json()["error"] == "CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION"
    job = collect(api, auth, worker, repo, cid)
    assert job.status == "SUCCEEDED", job.error
    assert calls and not any(request.url.path.endswith("/login") for request in calls)
    # A new token is the provider connection's: every collection it owns takes the new sealed value.
    changed = api.put(f"/api/v1/provider-connections/{view['id']}/credential", headers=auth,
                      json={"credential": {"token": "hvs.sealed-token-2"}})
    assert changed.status_code == 200, changed.text
    assert "hvs.sealed-token-2" not in changed.text
    renewed = CoverageStore(repo).get(uuid.UUID(cid))["spec"]["secret_refs"]["vault_token"]
    assert renewed.startswith("sealed:v2:") and renewed != stored["spec"]["secret_refs"]["vault_token"]
    events = {event.event_type for event in repo.list_events() if str(event.target_id) == view["id"]}
    assert "PROVIDER_CONNECTION_CREDENTIAL_CHANGED" in events


def test_redirects_are_never_followed_on_login(monkeypatch, tmp_path):
    from cremore_vault_provider.connection_login import connection_token
    from cremore_vault_provider.secretstore import SecretStoreError

    seen = []

    def handle(request):
        seen.append(str(request.url))
        return httpx.Response(307, headers={"Location": "https://attacker.example.test/v1/auth/jwt/login"})

    (tmp_path / "vault-b").write_text("projected.jwt", encoding="ascii")
    spec = vault_spec(server_auth={"method": "jwt", "role": "cremore", "token_file": "vault-b"})
    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
        source = connection_token(spec, client, token_dir=str(tmp_path))
        with pytest.raises(SecretStoreError, match="SECRET_STORE_AUTH_UNAVAILABLE"):
            source()
    assert seen == ["https://vault-b.example.test/v1/auth/jwt/login"]


def test_a_connection_ca_is_the_only_trust_for_its_cluster(tmp_path):
    import ssl

    from cremore_vault_provider.connection_login import tls_verify
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-vault-ca")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    context = tls_verify(vault_spec(tls_ca_pem=pem))
    assert isinstance(context, ssl.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED
    assert [item["subject"] for item in context.get_ca_certs()] == [((("commonName", "synthetic-vault-ca"),),)]
    assert tls_verify(vault_spec()) is True
