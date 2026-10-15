"""The IdP machine identity set in the dashboard: what an Admin may save, how a process keeps the tokens and
points the cloud SDKs at them, what it reports, and that no secret or token leaves it. Synthetic IdP only."""

import base64
import json
import os
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.identity import machine

TOKEN = "synthetic-admin-" + "0" * 32
ADMIN = {"Authorization": "Bearer " + TOKEN}
SECRET = "synthetic-client-" + "s" * 24
ROLE = "arn:aws:iam::123456789012:role/cremore/CreMoreIdp"
PROVIDER = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cremore/providers/okta-idp"
TENANT = "11111111-2222-3333-4444-555555555555"
APP = "66666666-7777-8888-9999-000000000000"


def settings():
    return Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)


def jwt(**claims) -> str:
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return ".".join([part({"alg": "RS256", "kid": "k1"}), part(claims), "c2lnbmF0dXJl"])


def idp(calls: list, *, fail=False, lifetime=3600):
    def handle(request: httpx.Request):
        form = dict(item.split("=", 1) for item in request.content.decode().split("&"))
        calls.append(form)
        if fail:
            return httpx.Response(401, json={"error": "invalid_client"})
        token = jwt(iss="https://idp.example.test/oauth2/aus1", sub="0oa-cremore",
                    aud=form.get("audience", "api%3A%2F%2Fcremore").replace("%3A", ":").replace("%2F", "/"), exp=int(time.time()) + lifetime)
        return httpx.Response(200, json={"access_token": token, "token_type": "Bearer", "expires_in": lifetime})
    return httpx.Client(transport=httpx.MockTransport(handle))


def body(**changes):
    out = {"idp": {"token_url": "https://idp.example.test/oauth2/aus1/v1/token", "client_id": "0oa-cremore", "scope": "cremore.workload"},
           "client_secret": SECRET,
           "aws": {"enabled": True, "role_arn": ROLE},
           "gcp": {"enabled": True, "provider": PROVIDER, "service_account": "cremore-reader@acme-prod.iam.gserviceaccount.com"},
           "azure": {"enabled": True, "tenant": TENANT, "client_id": APP},
           "vault": [{"name": "pay", "audience": "vault-pay"}]}
    out.update(changes)
    return out


def test_what_an_admin_may_save():
    ok = machine.validate(body(), None)
    assert ok["aws"]["role_arn"] == ROLE and ok["azure"]["audience"] == machine.AZURE_AUDIENCE
    for broken, code in (
        ({"aws": {"enabled": True}}, "MACHINE_IDENTITY_AWS_ROLE_ARN_INVALID"),
        ({"aws": {"enabled": True, "role_arn": "arn:aws:iam::123:role/x"}}, "MACHINE_IDENTITY_AWS_ROLE_ARN_INVALID"),
        ({"gcp": {"enabled": True, "provider": "projects/1/pools/x"}}, "MACHINE_IDENTITY_GCP_PROVIDER_INVALID"),
        ({"azure": {"enabled": True, "tenant": "not-a-guid", "client_id": APP}}, "MACHINE_IDENTITY_AZURE_TENANT_INVALID"),
        ({"vault": [{"name": "pay"}, {"name": "pay"}]}, "MACHINE_IDENTITY_VAULT_NAME_REPEATED"),
        ({"vault": [{"name": "../escape"}]}, "MACHINE_IDENTITY_VAULT_NAME_INVALID"),
        ({"idp": {"token_url": "http://idp.example.test/token", "client_id": "a"}}, "MACHINE_IDENTITY_TOKEN_URL_INVALID"),
        ({"idp": {"token_url": "https://idp.example.test/token", "client_id": "a", "auth_method": "private_key_jwt"}}, "MACHINE_IDENTITY_AUTH_METHOD_INVALID"),
    ):
        with pytest.raises(machine.MachineIdentityError) as refused:
            machine.validate(body(**broken), None)
        assert str(refused.value) == code
    # A binding turned off does not need its fields.
    assert machine.validate(body(aws={"enabled": False}), None)["aws"]["enabled"] is False


def test_the_secret_is_sealed_never_returned_and_required_while_in_use():
    repo, s = InMemoryRepository(), settings()
    with pytest.raises(machine.MachineIdentityError, match="MACHINE_IDENTITY_SECRET_REQUIRED"):
        machine.save(repo, s, {**body(), "client_secret": ""}, "admin")
    machine.save(repo, s, body(), "admin")
    stored = repo.get_setting(machine.KEY)["value"]
    assert SECRET not in json.dumps(stored) and stored["secret"]
    view = machine.public(repo.get_setting(machine.KEY))
    assert view["secret_saved"] is True and "secret" not in view and SECRET not in json.dumps(view)
    # A later save without a secret keeps the sealed one; a stale revision is refused.
    machine.save(repo, s, {**body(), "client_secret": None, "expected_revision": 1}, "admin")
    assert repo.get_setting(machine.KEY)["value"]["secret"] == stored["secret"]
    with pytest.raises(machine.MachineIdentityError, match="MACHINE_IDENTITY_CHANGED"):
        machine.save(repo, s, {**body(), "expected_revision": 1}, "admin")
    events = [event for event in repo.finding_events.values() if event.target_type == "machine_identity"]
    assert [event.event_type for event in events] == ["MACHINE_IDENTITY_CHANGED"] * 2
    assert all(SECRET not in (event.note or "") for event in events)


def test_a_process_keeps_the_tokens_and_points_each_sdk_at_them(tmp_path):
    repo, s = InMemoryRepository(), settings()
    machine.save(repo, s, body(), "admin")
    calls, environ = [], {"AWS_PROFILE": "operator", "AZURE_CLIENT_SECRET": "leftover"}
    keeper = machine.Keeper(repo, s, "worker:1", directory=tmp_path, client=idp(calls), environ=environ)
    keeper.tick(now=1000.0)
    assert {name for name in os.listdir(tmp_path)} >= {"aws", "gcp", "azure", "gcp.json", "vault"}
    assert os.listdir(tmp_path / "vault") == ["idp-pay"]
    # AWS reads only the web identity; Azure's workload identity is not shadowed by an old secret.
    assert environ["AWS_ROLE_ARN"] == ROLE and environ["AWS_WEB_IDENTITY_TOKEN_FILE"] == str(tmp_path / "aws")
    assert "AWS_PROFILE" not in environ and environ["AWS_CONFIG_FILE"] == os.devnull
    assert environ["AZURE_FEDERATED_TOKEN_FILE"] == str(tmp_path / "azure") and "AZURE_CLIENT_SECRET" not in environ
    config = json.loads((tmp_path / "gcp.json").read_text())
    assert config["audience"] == PROVIDER and config["credential_source"] == {"file": str(tmp_path / "gcp")}
    assert config["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
    assert config["service_account_impersonation_url"].endswith("cremore-reader@acme-prod.iam.gserviceaccount.com:generateAccessToken")
    assert environ["GOOGLE_APPLICATION_CREDENTIALS"] == str(tmp_path / "gcp.json")
    # Each binding asked for its own audience where one was set; the secret went only to the IdP.
    assert any(call.get("audience") == "vault-pay" for call in calls)
    assert all(call["client_secret"] == SECRET for call in calls)
    status = repo.get_setting(machine.STATUS_PREFIX + "worker:1")["value"]
    assert status["tokens"]["aws"]["state"] == "READY"
    assert status["tokens"]["aws"]["claims"]["iss"] == "https://idp.example.test/oauth2/aus1"
    assert status["tokens"]["vault:pay"]["claims"]["aud"] == "vault-pay"
    reported = json.dumps(status)
    assert SECRET not in reported and "c2lnbmF0dXJl" not in reported  # no token and no secret leave the process
    if sys.platform != "win32":
        assert (tmp_path / "aws").stat().st_mode & 0o777 == 0o600


def test_a_failed_idp_blocks_host_fallback_and_turning_a_cloud_off_restores_it(tmp_path):
    repo, s = InMemoryRepository(), settings()
    machine.save(repo, s, body(gcp={"enabled": False}, azure={"enabled": False}, vault=[]), "admin")
    environ = {"AWS_PROFILE": "operator", "AWS_ROLES_ANYWHERE_CONFIG": "previous-certificate-config"}
    failing = machine.Keeper(repo, s, "api:h", directory=tmp_path, client=idp([], fail=True), environ=environ)
    failing.tick(now=1000.0)
    assert environ["AWS_ROLE_ARN"] == ROLE and "AWS_PROFILE" not in environ
    assert "AWS_ROLES_ANYWHERE_CONFIG" not in environ
    assert (tmp_path / "aws").read_text() == ""
    status = repo.get_setting(machine.STATUS_PREFIX + "api:h")["value"]["tokens"]["aws"]
    assert status["state"] == "FAILED" and status["code"].startswith("OAUTH")
    keeper = failing
    keeper.client = idp([])
    keeper.tick(now=1005.0)
    assert environ["AWS_ROLE_ARN"] == ROLE and "AWS_PROFILE" not in environ
    machine.save(repo, s, body(aws={"enabled": False}, gcp={"enabled": False}, azure={"enabled": False}, vault=[]), "admin")
    keeper.tick(now=1006.0)
    assert "AWS_ROLE_ARN" not in environ and environ["AWS_PROFILE"] == "operator"
    assert environ["AWS_ROLES_ANYWHERE_CONFIG"] == "previous-certificate-config"


def test_claims_are_read_from_a_jwt_only():
    assert machine.claims("opaque-token-value") == {}
    assert machine.claims(jwt(iss="https://i", sub="s", aud=["a", "b"], exp=5)) == {"iss": "https://i", "sub": "s", "aud": ["a", "b"], "exp": 5}


def test_restart_and_identity_change_cannot_reuse_a_previous_tenant_token(tmp_path):
    repo, s = InMemoryRepository(), settings()
    machine.save(repo, s, body(), "admin")
    keeper = machine.Keeper(repo, s, "worker:first", directory=tmp_path, client=idp([]), environ={})
    keeper.tick(now=1000)
    assert (tmp_path / "aws").read_text()
    replacement = {**body(), "idp": {**body()["idp"], "client_id": "new-machine"}}
    machine.save(repo, s, replacement, "admin")
    environment = {"AWS_PROFILE": "unrelated", "AZURE_CLIENT_SECRET": "host-secret",
                   "GOOGLE_APPLICATION_CREDENTIALS": "host-adc"}
    restarted = machine.Keeper(repo, s, "worker:restarted", directory=tmp_path, client=idp([], fail=True), environ=environment)
    restarted.tick(now=2000)
    assert all((tmp_path / name).read_text() == "" for name in ("aws", "gcp", "azure"))
    assert "AWS_PROFILE" not in environment and "AZURE_CLIENT_SECRET" not in environment
    assert environment["GOOGLE_APPLICATION_CREDENTIALS"] == str(tmp_path / "gcp.json")


def test_setup_steps_name_the_issuer_subject_and_audience_seen():
    record = machine.validate(body(), None)
    observed = {"aws": {"claims": {"iss": "https://idp.example.test/oauth2/aus1", "sub": "0oa-cremore", "aud": "api://cremore"}},
                "gcp": {"claims": {"iss": "https://idp.example.test/oauth2/aus1", "sub": "0oa-cremore", "aud": "api://cremore"}},
                "azure": {"claims": {"iss": "https://idp.example.test/oauth2/aus1", "sub": "0oa-cremore"}}}
    steps = machine.setup_steps(record, observed, {"Version": "2012-10-17"})
    assert "--url https://idp.example.test/oauth2/aus1 --client-id-list api://cremore" in steps["aws"]
    assert "idp.example.test/oauth2/aus1:sub" in steps["aws"] and "put-role-policy --role-name CreMoreIdp" in steps["aws"]
    assert "--issuer-uri=https://idp.example.test/oauth2/aus1 --allowed-audiences=api://cremore" in steps["gcp"]
    assert "roles/iam.workloadIdentityUser" in steps["gcp"]
    assert '"audiences": ["api://AzureADTokenExchange"]' in steps["azure"] and APP in steps["azure"]
    assert "bound_subject=<subject>" in steps["vault:pay"]  # not seen yet: a placeholder, never a guess


def test_token_storage_failure_blocks_prior_identity_and_retries_reset(tmp_path, monkeypatch):
    from cremore.cli import token_refresher

    repo, s = InMemoryRepository(), settings()
    s.vault_connection_token_dir = str(tmp_path / "vault")
    machine.save(repo, s, body(), "admin")
    keeper = machine.Keeper(repo, s, "worker:storage", directory=tmp_path, client=idp([]), environ={})
    keeper.tick(now=1000)
    machine.save(repo, s, body(), "admin")
    original = token_refresher.write_token

    def fail(*args):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(token_refresher, "write_token", fail)
    assert keeper.tick(now=1001) == 5
    assert keeper.reset_pending
    for key in ("AWS_WEB_IDENTITY_TOKEN_FILE", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_FEDERATED_TOKEN_FILE"):
        assert keeper.environ[key] == os.devnull
    assert s.vault_connection_token_dir == keeper.blocked_vault_directory
    assert repo.get_setting(machine.STATUS_PREFIX + "worker:storage")["value"]["error"] == "TOKEN_WRITE_FAILED"
    monkeypatch.setattr(token_refresher, "write_token", original)
    keeper.tick(now=1006)
    assert not keeper.reset_pending and keeper.error is None
    assert s.vault_connection_token_dir == str(tmp_path / "vault")
    assert keeper.environ["AWS_WEB_IDENTITY_TOKEN_FILE"] == str(tmp_path / "aws")


def test_aws_setup_can_resolve_only_its_own_role_including_a_configured_path():
    import json
    import shlex

    role = "arn:aws:iam::123456789012:role/team/CreMoreIdp"
    record = machine.validate(body(aws={"enabled": True, "role_arn": role}), None)
    member = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "member-role"}]}
    commands = [shlex.split(line) for line in machine.setup_steps(record, {}, member)["aws"].splitlines()]
    create = next(command for command in commands if command[2] == "create-role")
    assert create[create.index("--path") + 1] == "/team/"
    put = next(command for command in commands if command[2] == "put-role-policy")
    policy = json.loads(put[put.index("--policy-document") + 1])
    assert policy["Statement"] == [*member["Statement"], {"Effect": "Allow", "Action": "iam:GetRole", "Resource": role}]
    assert len(member["Statement"]) == 1


def test_routes_are_admin_only_and_return_claims_never_tokens():
    repo = InMemoryRepository()
    app = create_app(repo=repo, settings=settings(), aws_identity_probe=lambda **kwargs: {"state": "NO_CREDENTIALS"})
    app.state.machine_identity_http_client = idp([])
    c = TestClient(app)
    path = "/api/v1/settings/machine-identity"
    assert c.get(path).status_code == 401
    assert c.get(path, headers=ADMIN).json()["configured"] is False
    saved = c.put(path, headers=ADMIN, json=body())
    assert saved.status_code == 200 and saved.json()["secret_saved"] is True and SECRET not in saved.text
    assert c.put(path, headers=ADMIN, json=body(aws={"enabled": True, "role_arn": "bad"})).status_code == 422
    assert c.put(path, headers=ADMIN, json={**body(), "expected_revision": 9}).status_code == 409
    tested = c.post(path + "/test", headers=ADMIN)
    assert tested.status_code == 200
    tokens = tested.json()["test"]["tokens"]
    assert tokens["aws"]["state"] == "READY" and tokens["aws"]["claims"]["sub"] == "0oa-cremore"
    assert "c2lnbmF0dXJl" not in tested.text and SECRET not in tested.text
    steps = c.get(path + "/setup", headers=ADMIN).json()["steps"]
    assert set(steps) == {"aws", "gcp", "azure", "vault:pay"} and "0oa-cremore" in steps["aws"]


def test_the_sql_repository_keeps_the_setting_its_revisions_and_the_process_reports(tmp_path):
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    repo, s = SqlRepository(engine), settings()
    machine.save(repo, s, body(gcp={"enabled": False}, azure={"enabled": False}), "admin")
    assert machine.public(repo.get_setting(machine.KEY))["revision"] == 1
    machine.save(repo, s, {**body(gcp={"enabled": False}, azure={"enabled": False}), "client_secret": None, "expected_revision": 1}, "admin")
    assert machine.public(repo.get_setting(machine.KEY))["revision"] == 2
    keeper = machine.Keeper(repo, s, "worker:sql", directory=tmp_path, client=idp([]), environ={})
    keeper.tick(now=10.0)
    reports = repo.list_settings(machine.STATUS_PREFIX)
    assert [item["value"]["process"] for item in reports] == ["worker:sql"]
    assert reports[0]["value"]["tokens"]["aws"]["state"] == "READY"
