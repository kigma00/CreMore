"""What the API and worker processes actually wire up.

Nothing else covers this. `build_app` and `build_worker` decide which optional
services exist for an installation and what shape each one is handed over in,
and a mistake here does not crash: the worker's trigger loop swallows every
exception so queued scans keep running, and an unwired service looks the same
as one an Admin has switched off. Both failures are silence.

Building is deliberately offline -- no database, no AWS, no server.
"""

from __future__ import annotations

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

pytest.importorskip("fastapi")
pytest.importorskip("boto3")

from cremore.cli.api import build_app
from cremore.cli.worker import build_worker


def _settings(**overrides):
    return Settings(AUTH_MODE="local", API_TOKEN="0" * 32, FINGERPRINT_KEY="ab" * 32, **overrides)


def test_the_api_starts_with_every_optional_service_available():
    """Each investigation mode allows its service; an Admin still switches it on."""
    app = build_app(_settings(), InMemoryRepository())
    paths = {route.path for route in app.routes}
    assert "/api/v1/findings" in paths and "/healthz" in paths
    # The signed event webhook is gone; no route may reappear under that prefix.
    assert not any(path.startswith("/api/v1/scan-events") for path in paths)


def test_a_locked_investigation_leaves_its_service_unwired():
    """A hard lock must not depend on the dashboard switch to hold."""
    from cremore.api import create_app

    wired = {}
    original = create_app

    def record(**kwargs):
        wired.update(kwargs)
        return original(**kwargs)

    import cremore.api

    cremore.api.create_app = record
    try:
        build_app(_settings(), InMemoryRepository())
        assert wired["usage_service_factory"] is not None
        assert wired["potential_access_factory"] is not None
        assert wired["secrets_inventory_factory"] is not None

        wired.clear()
        build_app(_settings(AWS_USAGE_LOOKUP_MODE="disabled",
                            IAM_POTENTIAL_ACCESS_MODE="disabled",
                            AWS_SECRETS_INVENTORY_MODE="disabled"), InMemoryRepository())
        assert wired["usage_service_factory"] is None
        assert wired["potential_access_factory"] is None
        assert wired["secrets_inventory_factory"] is None
        assert wired["secret_metadata_factory"] is None
    finally:
        cremore.api.create_app = original


def test_the_worker_hands_every_service_over_in_the_shape_it_is_called_with():
    """The bug this exists for: the SQS client factory was passed where a client
    was expected, and the poll loop swallowed the AttributeError for good."""
    from cremore.scanning import trigger_settings

    repo = InMemoryRepository()
    worker = build_worker(_settings(), repo)

    # A factory, not a client: poll_sqs builds the client only once a binding
    # exists, so a worker with no queue never resolves a Region for one.
    assert callable(worker.sqs_client_factory)
    for name in ("receive_message", "delete_message"):
        assert not hasattr(worker.sqs_client_factory, name), "a client was passed where a factory belongs"
    # And it is not called while nothing is bound.
    assert trigger_settings.sqs_binding(worker.settings, repo) is None
    assert worker.poll_triggers() is None

    # Potential access is a provider taking one principal ARN.
    from cremore.risk.model import AWSPrivilegeSignal

    provider = worker.orchestrator.potential_access_provider
    assert callable(provider)
    signal = provider("arn:aws:iam::123456789012:user/example")
    assert isinstance(signal, AWSPrivilegeSignal) and signal.evaluated is False  # switched off


def test_the_worker_resolves_the_secret_scanning_credential_before_the_github_reader():
    """Second review 2026-09-26: the platform resolves the connection's secret reference; the
    GitHub library never sees it. An unresolvable reference is recorded, and nothing is sent."""
    from cremore.domain.models import ScanJob

    worker = build_worker(_settings(), InMemoryRepository())
    result = worker.secret_scanning_reader(ScanJob(kind="github-secret-scanning", payload={
        "provider": "github", "owner": "org", "repo": "app", "secret_ref": "vault://synthetic/missing"}))
    assert (result["collection_status"], result["reason_code"], result["target"]) == (
        "FAILED", "SECRET_UNAVAILABLE", "org/app")


def test_a_locked_queue_or_investigation_leaves_the_worker_without_it():
    locked = build_worker(_settings(SCAN_SQS_MODE="disabled",
                                    IAM_POTENTIAL_ACCESS_MODE="disabled"), InMemoryRepository())
    assert locked.sqs_client_factory is None
    assert locked.orchestrator.potential_access_provider is None


def test_a_bound_pubsub_or_service_bus_reader_is_built_once_and_a_locked_one_not_at_all(monkeypatch):
    from cremore_azure_provider import servicebus
    from cremore_gcp_provider import pubsub

    built = []
    monkeypatch.setattr(pubsub, "open_queue", lambda address: built.append(address) or object())
    monkeypatch.setattr(servicebus, "open_queue", lambda address: built.append(address) or object())
    worker = build_worker(_settings(), InMemoryRepository())
    opener = worker.queue_openers["pubsub"]
    first = opener("projects/acme-scans/subscriptions/a")
    assert opener("projects/acme-scans/subscriptions/a") is first  # every poll reuses its client and token
    assert opener("projects/acme-scans/subscriptions/b") is not first  # a rebinding reads the new one
    worker.queue_openers["servicebus"]("https://acme-events.servicebus.windows.net/q")
    assert built == ["projects/acme-scans/subscriptions/a", "projects/acme-scans/subscriptions/b",
                     "https://acme-events.servicebus.windows.net/q"]
    locked = build_worker(_settings(SCAN_PUBSUB_MODE="disabled", SCAN_SERVICEBUS_MODE="disabled"), InMemoryRepository())
    assert locked.queue_openers == {}


@pytest.mark.parametrize("build", [build_app, build_worker])
def test_building_touches_no_database_and_no_network(build, monkeypatch):
    """Both processes must be constructible before anything external answers."""
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("building must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    build(_settings(), InMemoryRepository())


@pytest.mark.parametrize("method", ["role", "runtime"])
@pytest.mark.parametrize("sdk_method,source", [
    ("iam-role", "iam-role"), ("container-role", "container-role"),
    ("assume-role-with-web-identity", "assume-role-with-web-identity"),
    ("sso", None), ("env", None), ("shared-credentials-file", None), ("custom-process", None),
])
def test_real_worker_wiring_preserves_workload_provenance_through_aws_onboarding(monkeypatch, method, sdk_method, source):
    import uuid
    from types import SimpleNamespace

    import boto3
    from cremore_aws_provider import aws_access, aws_identity

    from cremore.api.aws_support import default_identity_probe
    from cremore.onboarding import sessions

    account = "111111111111"
    role = f"arn:aws:iam::{account}:role/team/Scanner"
    calls = []

    def client(service, **kwargs):
        assert service in {"sts", "iam"}, "authentication must not read collection targets"

        def caller():
            calls.append("sts:GetCallerIdentity")
            return {"Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/Scanner/server"}

        def get_role(**kwargs):
            assert kwargs == {"RoleName": "Scanner"}
            calls.append("iam:GetRole")
            return {"Role": {"Arn": role}}

        return SimpleNamespace(get_caller_identity=caller, get_role=get_role)

    monkeypatch.setattr(boto3, "client", client)
    monkeypatch.setattr(boto3, "Session", lambda **_: SimpleNamespace(
        client=client, get_credentials=lambda: SimpleNamespace(method=sdk_method)))
    monkeypatch.setattr(aws_identity, "local_sso_session", lambda: {"region": None, "start_url": None})
    settings, repo = _settings(), InMemoryRepository()
    api_identity = default_identity_probe(settings)()
    assert api_identity["credential_source"] == source
    aws_access.save_approval(repo, aws_access.SCANNER, api_identity, "admin")
    worker = build_worker(settings, repo)
    browser_key = "synthetic-browser-key-for-worker-onboarding"
    view = sessions.create(repo, settings, {"provider": "aws", "auth_method": method, "browser_key": browser_key}, "admin")
    assert worker.process_next() is True
    view = sessions.read(repo, view["id"], {"browser_key": browser_key}, "admin")
    assert view["state"] == ("AUTHENTICATED" if source else "FAILED"), view
    if source is None:
        assert view["error"] == "AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED"
    current = worker.aws_identity()
    assert {k: current[k] for k in ("kind", "principal_arn", "credential_source")} == {
        k: api_identity[k] for k in ("kind", "principal_arn", "credential_source")}
    report = repo.get_setting(aws_identity.WORKER_IDENTITY_KEY)["value"]
    assert report["credential_source"] == source and report["checked_at"]
    assert set(calls) == {"sts:GetCallerIdentity", "iam:GetRole"}
    assert not repo.list_aws_accounts()
    assert repo.get_job(uuid.UUID(view["job_id"])).status == "SUCCEEDED"
