"""Offline integration: durable delivery, independent plugins, sanitized failures."""

import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.cli.siem import main
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, Exposure
from cremore.siem import SinkProvider, registry
from cremore.siem.config import ExportConfig, load_config
from cremore.siem.outbox import SiemOutbox
from cremore.siem.runner import Exporter


def observation(repo):
    credential = repo.upsert_credential(Credential(
        fingerprint="synthetic", credential_type="AWS_ACCESS_KEY", provider="aws",
        identifier="NEVER_EXPORT_IDENTIFIER", identifier_hint="NEVER_EXPORT_HINT"))
    exposure = repo.upsert_exposure(Exposure(
        credential_id=credential.id, source_type="inline", resource_name="NEVER_EXPORT_RESOURCE",
        location="NEVER_EXPORT_PATH", severity="HIGH", redacted_line="NEVER_EXPORT_CONTEXT"))
    return repo.upsert_finding(credential.id, exposure.id, "HIGH")


class RecordingSink:
    def __init__(self, *, fail=False):
        self.events = []
        self.closed = False
        self.fail = fail

    def send(self, event):
        self.events.append(event)
        if self.fail:
            raise RuntimeError("NEVER_EXPORT_PLUGIN_EXCEPTION")

    def close(self):
        self.closed = True


def entry(name, factory, imports):
    def load():
        imports.append(name)
        return factory()
    return SimpleNamespace(name=name, load=load)


def test_metadata_discovery_never_imports_disabled_plugins(monkeypatch):
    imports = []
    monkeypatch.setattr(registry, "entry_points", lambda **kw: [
        entry("team_sink", lambda: SinkProvider("team_sink", lambda _: RecordingSink()), imports)])
    assert "team_sink" in registry.providers()
    assert not imports
    with pytest.raises(ValueError, match="SIEM_PLUGIN_NOT_ENABLED"):
        registry.load_provider("team_sink")
    assert not imports
    assert registry.load_provider("team_sink", allow_plugins=("team_sink",)).id == "team_sink"
    assert imports == ["team_sink"]


@pytest.mark.parametrize("name", ["jsonl", "same"])
def test_duplicate_registration_rejected_before_import(monkeypatch, name):
    imports = []
    entries = [entry(name, lambda: None, imports)] * (1 if name == "jsonl" else 2)
    monkeypatch.setattr(registry, "entry_points", lambda **kw: entries)
    with pytest.raises(ValueError, match="SIEM_PLUGIN_ID_DUPLICATE"):
        registry.providers()
    assert not imports


@pytest.mark.parametrize("provider", [
    SinkProvider("different", lambda _: None),
    SinkProvider("team_sink", lambda _: None, api_version=2),
    SinkProvider("team_sink", lambda _: None, event_schema_versions=(2,)),
    object(),
])
def test_incompatible_plugin_rejected(monkeypatch, provider):
    monkeypatch.setattr(registry, "entry_points", lambda **kw: [
        entry("team_sink", lambda: provider, [])])
    with pytest.raises(ValueError, match="SIEM_PLUGIN_CONTRACT_INCOMPATIBLE"):
        registry.load_provider("team_sink", allow_plugins=("team_sink",))


def test_plugin_can_also_support_future_schema(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda **kw: [
        entry("team_sink", lambda: SinkProvider("team_sink", lambda _: None,
                                               event_schema_versions=(1, 2)), [])])
    assert registry.load_provider("team_sink", allow_plugins=("team_sink",)).api_version == 1


def test_destinations_retry_independently_without_raw_data(monkeypatch, caplog):
    repo = InMemoryRepository()
    finding = observation(repo)
    sinks = {"broken": RecordingSink(fail=True), "healthy": RecordingSink()}
    monkeypatch.setattr(registry, "entry_points", lambda **kw: [
        entry("team_sink", lambda: SinkProvider("team_sink", lambda options: sinks[options["name"]]), [])])
    config = ExportConfig.model_validate({"allow_plugins": ["team_sink"], "destinations": [
        {"id": name, "provider": "team_sink", "options": {"name": name}} for name in sinks]})
    with caplog.at_level("INFO"):
        exporter = Exporter(SiemOutbox(repo), config)
        result = exporter.run_once()
    assert (result.delivered, result.failed, result.lease_lost) == (1, 1, 0)
    sent = sinks["healthy"].events[0]
    assert sent["finding"]["id"] == str(finding.id)
    assert "NEVER_EXPORT" not in json.dumps(sent) + caplog.text
    assert sinks["broken"].events[0]["event_id"] == sent["event_id"]
    assert exporter.run_once().delivered == 0
    exporter.close()
    assert all(sink.closed for sink in sinks.values())


def test_sql_jsonl_cli_restart_preserves_acknowledgment(tmp_path, monkeypatch, capsys):
    url = "sqlite:///" + str(tmp_path / "siem.db")
    engine = make_engine(url)
    create_all(engine)
    finding = observation(SqlRepository(engine))
    engine.dispose()
    config = tmp_path / "siem.json"
    config.write_text(json.dumps({"destinations": [{"id": "soc", "provider": "jsonl"}]}))
    monkeypatch.setenv("SIEM_DATABASE_URL", url)
    assert main(["--config", str(config), "--once"]) == 0
    line = capsys.readouterr().out
    assert json.loads(line)["finding"]["id"] == str(finding.id)
    assert "NEVER_EXPORT" not in line
    assert main(["--config", str(config), "--once"]) == 0
    assert capsys.readouterr().out == ""


def test_isolated_siem_refuses_unrestricted_non_postgres_before_delivery(tmp_path, monkeypatch, capsys, caplog):
    url = "sqlite:///" + str(tmp_path / "siem-isolated.db")
    engine = make_engine(url)
    create_all(engine)
    observation(SqlRepository(engine))
    engine.dispose()
    config = tmp_path / "siem.json"
    config.write_text(json.dumps({"destinations": [{"id": "soc", "provider": "jsonl"}]}))
    monkeypatch.setenv("SIEM_DATABASE_URL", url)
    monkeypatch.setenv("ISOLATED_DEPLOYMENT", "true")
    assert main(["--config", str(config), "--once"]) == 1
    assert capsys.readouterr().out == ""
    assert "SIEM_EXPORTER_FAILED" in caplog.text


@pytest.mark.parametrize("payload", [
    {"schema_version": 2, "destinations": [{"id": "soc", "provider": "jsonl"}]},
    {"destinations": []},
    {"destinations": [{"id": "soc", "provider": "jsonl"}] * 2},
    {"destinations": [{"id": "bad\nname", "provider": "jsonl"}]},
    {"destinations": [{"id": "soc", "provider": "jsonl"}], "allow_plugins": ["unselected"]},
    {"destinations": [{"id": "soc", "provider": "jsonl"}], "batch_size": True},
])
def test_invalid_config_reports_no_input(payload, tmp_path):
    path = tmp_path / "siem.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="^SIEM_CONFIG_INVALID$"):
        load_config(str(path))


def test_cli_listing_does_not_need_database_or_scanner_keys(monkeypatch, capsys):
    monkeypatch.delenv("SIEM_DATABASE_URL", raising=False)
    assert main(["--list-sinks"]) == 0
    assert set(capsys.readouterr().out.splitlines()) >= {"jsonl", "http_json", "splunk_hec", "logscale"}


def test_sink_mutation_cannot_rewrite_outbox(monkeypatch):
    repo = InMemoryRepository()
    observation(repo)
    class MutatingSink(RecordingSink):
        def send(self, event):
            event.clear()
    monkeypatch.setattr("cremore.siem.runner.load_provider", lambda *args, **kwargs:
                        SinkProvider("mutable", lambda _: MutatingSink()))
    exporter = Exporter(SiemOutbox(repo), ExportConfig.model_validate({
        "destinations": [{"id": "soc", "provider": "mutable"}]}))
    assert exporter.run_once().delivered == 1
    event = SiemOutbox(repo).claim("another", limit=1)[0]["event"]
    assert event["event_type"] == "finding.created"
    uuid.UUID(event["event_id"])


def test_invalid_sink_candidate_is_closed_on_startup_failure(monkeypatch):
    closed = []
    monkeypatch.setattr("cremore.siem.runner.load_provider", lambda *args, **kwargs:
                        SinkProvider("invalid", lambda _: SimpleNamespace(close=lambda: closed.append(True))))
    with pytest.raises(ValueError, match="SIEM_SINK_CONFIGURATION_INVALID"):
        Exporter(None, ExportConfig.model_validate({
            "destinations": [{"id": "soc", "provider": "invalid"}]}))
    assert closed == [True]


def test_cli_http_delivery_logs_no_endpoint_path_or_token(tmp_path, monkeypatch, caplog):
    url = "sqlite:///" + str(tmp_path / "siem.db")
    engine = make_engine(url)
    create_all(engine)
    observation(SqlRepository(engine))
    engine.dispose()
    config = tmp_path / "siem.json"
    config.write_text(json.dumps({"destinations": [{"id": "soc", "provider": "http_json", "options": {
        "endpoint": "https://siem.example.invalid/PRIVATE_ENDPOINT_MARKER",
        "token_env": "SIEM_SYNTHETIC_TOKEN"}}]}))
    monkeypatch.setenv("SIEM_DATABASE_URL", url)
    monkeypatch.setenv("SIEM_SYNTHETIC_TOKEN", "PRIVATE_AUTH_MARKER")
    original = httpx.Client
    def client(**kwargs):
        return original(**kwargs, transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    monkeypatch.setattr("cremore.siem.sinks._http.httpx.Client", client)
    with caplog.at_level("INFO"):
        assert main(["--config", str(config), "--once"]) == 0
    assert "SIEM_BATCH" in caplog.text
    assert "PRIVATE_" not in caplog.text


def test_the_exporter_touches_its_liveness_file_each_pass(tmp_path, monkeypatch, capsys):
    url = "sqlite:///" + str(tmp_path / "siem.db")
    engine = make_engine(url)
    create_all(engine)
    engine.dispose()
    config = tmp_path / "siem.json"
    config.write_text(json.dumps({"destinations": [{"id": "soc", "provider": "jsonl"}]}))
    beat = tmp_path / "exporter.heartbeat"
    monkeypatch.setenv("SIEM_DATABASE_URL", url)
    monkeypatch.setenv("SIEM_HEARTBEAT_FILE", str(beat))
    assert main(["--config", str(config), "--once"]) == 0
    assert beat.exists()
    monkeypatch.setenv("SIEM_HEARTBEAT_FILE", str(tmp_path / "missing-dir" / "beat"))
    assert main(["--config", str(config), "--once"]) == 0  # an unwritable path never stops delivery
    capsys.readouterr()
