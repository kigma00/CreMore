"""How the worker entrypoint runs each execution role. Offline: no database, no AWS, no process is started."""

from __future__ import annotations

import pickle

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

pytest.importorskip("boto3")

from cremore.cli import worker as cli


def _settings(**overrides):
    return Settings(AUTH_MODE="local", API_TOKEN="0" * 32, FINGERPRINT_KEY="ab" * 32, **overrides)


def test_scanning_roles_run_a_supervisor_and_dedicated_roles_their_single_loop(monkeypatch):
    import os

    from cremore.identity import machine
    from cremore.worker import supervisor

    keepers, supervised = [], []
    monkeypatch.setattr(os, "environ", {**os.environ, "AWS_PROFILE": "operator"})

    def keeper(repo, settings, process):
        keepers.append(process)
        os.environ["AWS_PROFILE"] = "changed-by-the-keeper"  # what a keeper does to this process

    monkeypatch.setattr(machine, "start_keeper", keeper)
    monkeypatch.setattr(supervisor.Supervisor, "run", lambda self: supervised.append(self))
    repo = InMemoryRepository()
    settings = _settings(WORKER_CONCURRENCY=3, WORKER_HEARTBEAT_FILE="worker.heartbeat")
    worker = cli.build_worker(settings, repo)
    cli.serve(settings, repo, worker)
    [run] = supervised
    assert (run.worker, run.concurrency, run.target, run.heartbeat_path) == (
        worker, 3, cli.task_runner, "worker.heartbeat")
    # The control loop's own SDK calls (queues, the identity it reports) see the runners' machine identity.
    owner = f"worker:{worker.worker_id}"
    assert keepers == [owner]
    # Runners get the supervisor's name for their status rows and the identity environment from before its keeper.
    assert run.target_args[0] == owner and run.target_args[1]["AWS_PROFILE"] == "operator"
    assert set(run.target_args[1]) == set(machine.ENV_KEYS)
    # spawn hands the runner over by name, so it must stay a top-level function.
    assert pickle.loads(pickle.dumps(cli.task_runner)) is cli.task_runner

    control_settings = _settings(WORKER_EXECUTION_ROLE="control")
    control = cli.build_worker(control_settings, repo)
    loops = []
    control.run_forever = lambda **kwargs: loops.append(kwargs)
    cli.serve(control_settings, repo, control)
    assert loops == [{"heartbeat_path": control_settings.worker_heartbeat_file}]
    assert len(supervised) == 1 and len(keepers) == 1


def test_a_runner_keeper_never_writes_the_control_loops_token_files(monkeypatch, tmp_path):
    """A runner (re)starting while the IdP fails blanks its own token files, never the ones others read."""
    import os

    import httpx

    from cremore.identity import machine

    repo, settings = InMemoryRepository(), _settings()
    machine.save(repo, settings, {
        "idp": {"token_url": "https://idp.example.test/oauth2/v1/token", "client_id": "cremore-test",
                "scope": "cremore.workload"},
        "client_secret": "synthetic-client-secret",
        "aws": {"enabled": True, "role_arn": "arn:aws:iam::123456789012:role/CreMoreReader"},
        "gcp": {"enabled": False}, "azure": {"enabled": False}, "vault": []}, "admin")

    def idp(fail):
        def answer(_request):
            if fail:
                return httpx.Response(401, json={"error": "invalid_client"})
            return httpx.Response(200, json={"access_token": "synthetic-" + "t" * 40, "expires_in": 3600})
        return httpx.Client(transport=httpx.MockTransport(answer))

    shared = tmp_path / "identity"
    monkeypatch.setattr(os, "environ", {**os.environ, "CREMORE_MACHINE_IDENTITY_DIR": str(shared),
                                        "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/SetByTheControlLoop"})
    control = machine.Keeper(repo, settings, "worker:control", client=idp(fail=False), environ={})
    control.tick(now=1000.0)
    token = (shared / "aws").read_text()
    assert token

    cli._runner_identity(3, {"AWS_ROLE_ARN": None, "AWS_PROFILE": "operator"})
    runner = machine.Keeper(repo, settings, "worker:control:runner-3", client=idp(fail=True),
                            environ=dict(os.environ))
    assert runner.directory == shared / "runner-3"
    # Its start is the container's, not what the control loop's keeper set in this process.
    assert runner.original["AWS_ROLE_ARN"] is None and runner.original["AWS_PROFILE"] == "operator"
    runner.tick(now=1001.0)
    assert (shared / "runner-3" / "aws").read_text() == ""
    assert (shared / "aws").read_text() == token
