"""The GitHub CLI runs the product's adapter locally and hands a finished run to the collector API.

Synthetic throughout: a scripted GitHub, an in-memory product, no network.
"""

import io
import json
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore.coverage.metadata_models import MetadataPage
from cremore_github_provider.metadata import adapter, cli

from .fake import (
    AUDIT_TOKEN,
    ENTERPRISE,
    ORG,
    FakeBroker,
    FakeTransport,
    enterprise_responses,
    enterprise_spec,
    org_responses,
    spec,
)
from .test_adapter import NOW, key

SECRETS = {"app_id": "12345", "private_key": "Zm9vYmFyYmF6cXV4"}


def pem_file(tmp_path):
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = tmp_path / "app.pem"
    path.write_bytes(pem)
    return path


def spec_file(tmp_path, connection=None, name="spec.json"):
    path = tmp_path / name
    path.write_text((connection or spec()).model_dump_json(), encoding="utf-8")
    return path


def run_cli(argv, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err, **kwargs)
    return code, json.loads(out.getvalue() or "null"), json.loads(err.getvalue() or "null")


def test_cli_check_validates_a_spec_and_the_app_key_offline(tmp_path):
    pem = pem_file(tmp_path)
    code, result, _ = run_cli(["check", "--spec", str(spec_file(tmp_path)), "--app-id", "Iv1.8a61f9b3a7aba766",
                               "--private-key-file", str(pem)], environ={})
    assert code == 0 and result["ok"] and result["scopes"] == [f"organization:{ORG}"]
    body = json.loads(spec_file(tmp_path).read_text(encoding="utf-8"))
    (tmp_path / "bad.json").write_text(json.dumps({**body, "scopes": [{"kind": "organization", "id": "a/b"}]}))
    code, _, error = run_cli(["check", "--spec", str(tmp_path / "bad.json"), "--app-id", "1",
                              "--private-key-file", str(pem)], environ={})
    assert code == 2 and error["error"].startswith("GITHUB_")
    (tmp_path / "not.pem").write_text("not a key")
    code, _, error = run_cli(["check", "--spec", str(spec_file(tmp_path)), "--app-id", "1",
                              "--private-key-file", str(tmp_path / "not.pem")], environ={})
    assert (code, error) == (2, {"error": "GITHUB_APP_PRIVATE_KEY_INVALID"})
    code, _, error = run_cli(["check", "--spec", str(spec_file(tmp_path)), "--private-key-file", str(pem)], environ={})
    assert (code, error) == (2, {"error": "GITHUB_APP_ID_INVALID"})
    digests = enterprise_spec(capabilities=["inventory", "issuer_digest"], options={"include_provider_hashes": True})
    with pytest.raises(cli.CliError, match="GITHUB_CLI_PROVIDER_DIGESTS_NEED_THE_PRODUCT_KEY"):
        cli.load_spec(spec_file(tmp_path, digests, "digests.json"))


def test_cli_collect_resumes_from_its_directory_and_never_doubles_a_page(tmp_path):
    connection, out = spec(options={"sources": ["org_fgpat"]}), tmp_path / "run"
    responses = org_responses()
    limited = f"/orgs/{ORG}/personal-access-tokens/31/repositories?per_page=100"
    first = cli.collect(connection, SECRETS, out, wait=False, broker=FakeBroker(), now=lambda: NOW,
                        transport=FakeTransport(responses, failures={limited: "github_rate_limited"}))
    assert (first["status"], first["retry_after_seconds"]) == ("WAITING", 120)
    saved = json.loads((out / "checkpoint.json").read_text(encoding="utf-8"))
    lines = (out / "records.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == saved["records"] > 0
    # A crash after records were appended but before the checkpoint moved: they are dropped and read again.
    with (out / "records.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(lines[-1] + "\n")
    done = cli.collect(connection, SECRETS, out, transport=FakeTransport(responses), broker=FakeBroker(),
                       now=lambda: NOW)
    assert done["status"] == "COMPLETE" and done["request_id"] == first["request_id"]
    rows = [json.loads(line) for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == done["record_count"] and len({key(row) for row in rows}) == len(rows)
    assert any(row.get("identity", {}).get("object_id", "").startswith("fgpat:") for row in rows)
    with pytest.raises(cli.CliError, match="GITHUB_CLI_RUN_ALREADY_FINISHED"):
        cli.collect(connection, SECRETS, out, transport=FakeTransport(responses), broker=FakeBroker(), now=lambda: NOW)
    assert ORG in cli.export(out)["organizations"]
    assert run_cli(["export", "--out", str(tmp_path / "missing")])[2] == {"error": "GITHUB_CLI_RUN_NOT_FOUND"}
    other = tmp_path / "other"
    other.mkdir()
    (other / "run.json").write_text(json.dumps({"status": "WAITING", "spec_digest": "an-earlier-spec",
                                                "request_id": str(uuid.uuid4())}), encoding="utf-8")
    with pytest.raises(cli.CliError, match="GITHUB_CLI_SPEC_CHANGED"):
        cli.collect(connection, SECRETS, other, transport=FakeTransport({}), broker=FakeBroker(), now=lambda: NOW)


def test_cli_never_writes_a_secret_to_its_directory(tmp_path, monkeypatch):
    connection = enterprise_spec(capabilities=["inventory", "audit"], options={"include_audit_events": True})
    secrets = {**SECRETS, "audit_token": AUDIT_TOKEN}
    window = adapter._window(connection, NOW.isoformat())
    transport = FakeTransport(enterprise_responses(window=window), enterprise=ENTERPRISE)
    monkeypatch.setattr("cremore_github_provider.metadata.export_http.download", transport.download)
    run = cli.collect(connection, secrets, tmp_path / "run", transport=transport,
                      broker=FakeBroker(), now=lambda: NOW, sleep=lambda _: None)
    assert run["status"] in ("COMPLETE", "PARTIAL")
    written = "".join(path.read_text(encoding="utf-8") for path in (tmp_path / "run").iterdir())
    assert AUDIT_TOKEN not in written and SECRETS["private_key"] not in written

    # A page that echoes a secret is refused before anything of it is written (a token-shaped
    # value is already refused by the record model; the App key's text is not token-shaped).
    page = next(iter(adapter.collect_pages(spec(), secrets=SECRETS, checkpoint={}, check=lambda: None,
                                           transport=FakeTransport(org_responses()), broker=FakeBroker(),
                                           now=lambda: NOW)))
    leaked = page.records[0].model_dump()
    leaked["provenance"]["resource_id"] = "/" + SECRETS["private_key"]
    echo = MetadataPage.model_validate({"records": [leaked], "checkpoint": {}})
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([echo]))
    with pytest.raises(cli.CliError, match="PROVIDER_AUTH_VALUE_IN_METADATA"):
        cli.collect(connection, secrets, tmp_path / "echo")
    assert not (tmp_path / "echo" / "records.jsonl").read_text(encoding="utf-8")


def test_cli_submit_cannot_import_global_ids_as_machine_scope_evidence(tmp_path):
    from fastapi.testclient import TestClient

    from cremore.api import create_app
    from cremore.api.metadata_coverage_test import TOKEN
    from cremore.config import Settings
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.db.repository import InMemoryRepository

    repo = InMemoryRepository()
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32))
    with TestClient(app) as raw:
        from cremore.onboarding.fixtures_test import collection

        body = json.loads(spec(options={"sources": ["org_fgpat"]}).model_dump_json())
        row, collector_token = collection(repo, body)
        cid, environ = str(row["id"]), {"CREMORE_COLLECTOR_TOKEN": collector_token}
        config_path, out = tmp_path / "config.json", tmp_path / "run"
        code, result, error = run_cli(["config", "--api-url", "http://localhost", "--connection-id", cid,
                                       "--output", str(config_path)], environ=environ, client=raw)
        assert code == 0, error
        assert "vault://" not in config_path.read_text(encoding="utf-8")
        loaded, config = cli.load_spec(config_path)
        assert config["revision"] == result["revision"] == 1
        cli.collect(loaded, SECRETS, out, transport=FakeTransport(org_responses()), broker=FakeBroker(),
                    now=lambda: NOW)
        submit = ["submit", "--spec", str(config_path), "--out", str(out), "--api-url", "http://localhost"]
        code, _, error = run_cli(submit, environ=environ, client=raw)
        # A local export includes global App context. An external machine may
        # not attach such entity keys to an organization merely by labelling it.
        assert (code, error) == (2, {"error": "METADATA_OUTSIDE_APPROVED_SCOPE"})
        runs = MetadataStore(repo).connection_runs(uuid.UUID(cid))["items"]
        assert len(runs) == 1 and runs[0]["status"] == "RUNNING"
        assert runs[0]["item_count"] == 0
        assert list(MetadataStore(repo).iter_records(runs[0]["id"])) == []
        assert MetadataStore(repo).inventory()["total"] == 0
        # The same directory again is the same run (its request id), not a second one.
        assert run_cli(submit, environ=environ, client=raw)[0] == 2
        assert MetadataStore(repo).connection_runs(uuid.UUID(cid))["total"] == 1
        code, _, error = run_cli(submit, environ={"CREMORE_COLLECTOR_TOKEN": "wrong-token"}, client=raw)
        assert (code, error) == (2, {"error": "COLLECTOR_UNAUTHORIZED"})
        code, _, error = run_cli(["submit", "--spec", str(config_path), "--out", str(out),
                                  "--api-url", "http://example.com"], environ=environ, client=raw)
        assert (code, error) == (2, {"error": "HTTPS_API_URL_REQUIRED"})
