"""The off-Kubernetes token refresher against a fake IdP token endpoint."""

import json
import logging
from urllib.parse import parse_qs

import httpx
import pytest

from cremore.cli import token_refresher

SECRET = "synthetic-idp-client-secret"


def test_short_tokens_renew_before_expiry_and_outages_back_off_after_expiry(tmp_path):
    class Grant:
        fail = False

        def fetch(self, client):
            if self.fail:
                raise ValueError("OAUTH_TOKEN_FAILED")
            return "synthetic-token", 10

    grant = Grant()
    token = token_refresher.Token("short", grant)
    assert token_refresher.refresh_due([token], tmp_path, None, now=0) == 5
    grant.fail = True
    token_refresher.refresh_due([token], tmp_path, None, now=5)
    token_refresher.refresh_due([token], tmp_path, None, now=10)
    assert token.due >= 20  # no every-second retry storm after expiration
    grant.fail = False
    token_refresher.refresh_due([token], tmp_path, None, now=token.due)
    assert token.failures == 0


def config(tmp_path, **item):
    body = {"directory": str(tmp_path / "identity"), "tokens": [{
        "name": "aws", "token_url": "https://idp.example/oauth2/default/v1/token", "client_id": "cremore-workload",
        "client_secret_env": "IDP_SECRET", "scope": "cremore.workload", **item}]}
    path = tmp_path / "refresher.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return str(path)


def idp(responses, seen):
    queue = iter(responses)

    def handle(request):
        seen.append(request)
        status, body = next(queue)
        return httpx.Response(status, json=body)
    return httpx.Client(transport=httpx.MockTransport(handle))


def test_tokens_are_written_atomically_and_refreshed_at_half_life(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("IDP_SECRET", SECRET)
    directory, tokens = token_refresher.load_config(config(tmp_path))
    seen = []
    client = idp([(200, {"access_token": "eyJ.first.sig", "token_type": "Bearer", "expires_in": 600}),
                  (200, {"access_token": "eyJ.second.sig", "token_type": "Bearer", "expires_in": 600})], seen)
    with caplog.at_level(logging.INFO, logger="cremore.token_refresher"):
        wait = token_refresher.refresh_due(tokens, directory, client, now=1000.0)
        assert (directory / "aws").read_text(encoding="ascii") == "eyJ.first.sig"
        assert wait == 300.0  # half the lifetime
        assert token_refresher.refresh_due(tokens, directory, client, now=1100.0) == 200.0  # not due: no request
        token_refresher.refresh_due(tokens, directory, client, now=1300.0)
    assert (directory / "aws").read_text(encoding="ascii") == "eyJ.second.sig"
    assert len(seen) == 2 and [p.name for p in directory.iterdir()] == ["aws"]  # no temporary files left
    form = parse_qs(seen[0].content.decode())
    assert form["grant_type"] == ["client_credentials"] and form["scope"] == ["cremore.workload"]
    assert SECRET not in caplog.text and "eyJ" not in caplog.text


def test_a_failed_refresh_keeps_the_last_token_and_backs_off_within_its_life(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("IDP_SECRET", SECRET)
    directory, tokens = token_refresher.load_config(config(tmp_path))
    client = idp([(200, {"access_token": "eyJ.first.sig", "expires_in": 100}),
                  (401, {"error": "invalid_client", "error_description": SECRET}),
                  (401, {"error": "invalid_client"}),
                  (200, {"access_token": "eyJ.third.sig", "expires_in": 100})], [])
    token_refresher.refresh_due(tokens, directory, client, now=0.0)
    with caplog.at_level(logging.WARNING, logger="cremore.token_refresher"):
        assert token_refresher.refresh_due(tokens, directory, client, now=50.0) == 5.0
        assert token_refresher.refresh_due(tokens, directory, client, now=55.0) == 10.0
    assert (directory / "aws").read_text(encoding="ascii") == "eyJ.first.sig"  # still usable until 100
    assert "OAUTH_TOKEN_FAILED" in caplog.text and SECRET not in caplog.text
    token_refresher.refresh_due(tokens, directory, client, now=65.0)
    assert (directory / "aws").read_text(encoding="ascii") == "eyJ.third.sig"
    assert tokens[0].failures == 0


def test_an_id_token_and_a_rotated_secret_file(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("first-secret\n", encoding="ascii")
    directory, tokens = token_refresher.load_config(config(
        tmp_path, client_secret_env=None, client_secret_file=str(secret_file), token_field="id_token",
        auth_method="client_secret_basic"))
    seen = []
    client = idp([(200, {"id_token": "eyJ.id.one", "expires_in": 60}), (200, {"id_token": "eyJ.id.two", "expires_in": 60})],
                 seen)
    token_refresher.refresh_due(tokens, directory, client, now=0.0)
    secret_file.write_text("second-secret", encoding="ascii")
    token_refresher.refresh_due(tokens, directory, client, now=31.0)
    assert (directory / "aws").read_text(encoding="ascii") == "eyJ.id.two"
    import base64
    assert [base64.b64decode(r.headers["authorization"].split()[1]).decode() for r in seen] == [
        "cremore-workload:first-secret", "cremore-workload:second-secret"]


@pytest.mark.parametrize("item", [
    {"name": "../escape"}, {"token_url": "http://idp.example/token"}, {"client_secret_file": "/run/secret"},
    {"client_secret_env": None}, {"token_field": "refresh_token"}, {"unknown": 1},
])
def test_configuration_is_refused_before_any_request(tmp_path, item):
    with pytest.raises(ValueError, match="REFRESHER_CONFIG_INVALID"):
        token_refresher.load_config(config(tmp_path, **item))


def test_once_reports_failure_with_its_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("IDP_SECRET", raising=False)
    real = httpx.Client
    monkeypatch.setattr(token_refresher.httpx, "Client",
                        lambda **kw: real(transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    assert token_refresher.main(["--config", config(tmp_path), "--once"]) == 2
    assert token_refresher.main(["--config", str(tmp_path / "missing.json"), "--once"]) == 1


def test_a_token_can_live_in_its_own_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("IDP_SECRET", SECRET)
    directory, tokens = token_refresher.load_config(config(tmp_path, name="vault-pay",
                                                           directory=str(tmp_path / "vault")))
    client = idp([(200, {"access_token": "eyJ.vault.sig", "expires_in": 60})], [])
    token_refresher.refresh_due(tokens, directory, client, now=0.0)
    assert (tmp_path / "vault" / "vault-pay").read_text(encoding="ascii") == "eyJ.vault.sig"
    assert not (directory / "vault-pay").exists()
