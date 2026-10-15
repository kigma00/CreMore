"""Vault KV v2 client tests with a fake HTTP client."""

from __future__ import annotations

import pytest

from cremore.secretstore import SecretStoreError, VaultKubernetesTokenSource, VaultKV


class FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeHTTP:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def get(self, url, headers=None, params=None, **kwargs):
        self.calls.append(("GET", url, headers, params))
        return self._resp

    def request(self, method, url, headers=None, json=None, **kwargs):
        self.calls.append((method, url, headers, json))
        return self._resp


def kv(resp):
    return VaultKV(FakeHTTP(resp), "https://vault.local", "s.token", mount="secret")


def test_read_returns_data_map():
    resp = FakeResp(200, {"data": {"data": {"AWS_ACCESS_KEY_ID": "AKIA...", "k": "v"}, "metadata": {"version": 3}}})
    store = kv(resp)
    data = store.read("vault-lab/rotate-demo")
    assert data["k"] == "v"
    # KV v2 path shape.
    assert store.client.calls[0][1] == "https://vault.local/v1/secret/data/vault-lab/rotate-demo"
    assert store.client.calls[0][2]["X-Vault-Token"] == "s.token"


def test_read_not_found():
    with pytest.raises(SecretStoreError) as e:
        kv(FakeResp(404)).read("missing")
    assert e.value.code == "SECRET_NOT_FOUND"


def test_read_forbidden():
    with pytest.raises(SecretStoreError) as e:
        kv(FakeResp(403)).read("secret")
    assert e.value.code == "SECRET_STORE_FORBIDDEN"


def test_write_returns_version():
    store = kv(FakeResp(200, {"data": {"version": 7}}))
    assert store.write("path", {"a": "b"}) == 7
    method, _url, _headers, body = store.client.calls[0]
    assert method == "POST"
    assert body == {"data": {"a": "b"}}


def test_unreachable_is_wrapped():
    class Boom:
        def get(self, *a, **k):
            raise RuntimeError("conn refused")

    store = VaultKV(Boom(), "https://vault.local", "t")
    with pytest.raises(SecretStoreError) as e:
        store.read("p")
    assert e.value.code == "SECRET_STORE_UNREACHABLE"


class SequenceHTTP:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def request(self, method, url, headers=None, json=None, params=None, **kwargs):
        self.calls.append((method, url, headers, json, params))
        return self.responses.pop(0)


def test_kubernetes_auth_caches_lease_and_refreshes(tmp_path):
    jwt_file = tmp_path / "token"
    jwt_file.write_text("projected.jwt", encoding="ascii")
    clock = [100.0]
    client = SequenceHTTP([
        FakeResp(200, {"auth": {"client_token": "hvs.first", "lease_duration": 120}}),
        FakeResp(200, {"auth": {"client_token": "hvs.second", "lease_duration": 120}}),
    ])
    source = VaultKubernetesTokenSource(
        client, "https://vault.local", "cremore-worker", token_file=str(jwt_file),
        monotonic=lambda: clock[0],
    )
    assert source() == "hvs.first"
    clock[0] = 150.0
    assert source() == "hvs.first" and len(client.calls) == 1
    clock[0] = 161.0
    assert source() == "hvs.second" and len(client.calls) == 2
    method, url, headers, body, _params = client.calls[0]
    assert method == "POST" and url.endswith("/v1/auth/kubernetes/login")
    assert headers is None and body == {"role": "cremore-worker", "jwt": "projected.jwt"}


def test_dynamic_vault_token_reauthenticates_once_after_403(tmp_path):
    jwt_file = tmp_path / "token"
    jwt_file.write_text("projected.jwt", encoding="ascii")
    auth = SequenceHTTP([
        FakeResp(200, {"auth": {"client_token": "hvs.first", "lease_duration": 600}}),
        FakeResp(200, {"auth": {"client_token": "hvs.second", "lease_duration": 600}}),
    ])
    source = VaultKubernetesTokenSource(auth, "https://vault.local", "worker",
                                        token_file=str(jwt_file))
    kv_http = SequenceHTTP([
        FakeResp(403),
        FakeResp(200, {"data": {"data": {"token": "provider-token"}}}),
    ])
    store = VaultKV(kv_http, "https://vault.local", source)
    assert store.read("github/app") == {"token": "provider-token"}
    assert len(auth.calls) == 2 and len(kv_http.calls) == 2
    assert kv_http.calls[0][2]["X-Vault-Token"] == "hvs.first"
    assert kv_http.calls[1][2]["X-Vault-Token"] == "hvs.second"


def test_kubernetes_auth_rejects_missing_or_invalid_workload_token(tmp_path):
    missing = VaultKubernetesTokenSource(SequenceHTTP([]), "https://vault.local", "worker",
                                         token_file=str(tmp_path / "missing"))
    with pytest.raises(SecretStoreError) as info:
        missing()
    assert info.value.code == "SECRET_STORE_WORKLOAD_TOKEN_UNAVAILABLE"


# -- the sealing master held in Vault ------------------------------------------
# An installation that already runs Vault can keep the master that seals stored
# connection credentials there instead of on its own disk. What these pin is
# that it is read from one named path, refused when it is not a usable key, and
# that moving to it never orphans what an earlier key sealed.

from cremore.secretstore.sealed import key_id, seal_token, unseal
from cremore_vault_provider.secretstore import kv_from_settings, sealing_master

MASTER = "ab" * 32
OLD_MASTER = "cd" * 32
FINGERPRINT = "ef" * 32
TOKEN = "synthetic-connection-token-" + "x" * 16


def secret(**fields):
    return FakeResp(200, {"data": {"data": fields, "metadata": {"version": 1}}})


def test_the_sealing_master_is_read_from_the_named_path_and_field():
    store = kv(secret(key=MASTER, note="not the key"))
    assert sealing_master(store, "cremore/sealing-key") == bytes.fromhex(MASTER)
    assert store.client.calls[0][1] == "https://vault.local/v1/secret/data/cremore/sealing-key"
    # A team whose secret already uses another field name says so.
    other = kv(secret(sealing_key=MASTER))
    assert sealing_master(other, "cremore/sealing-key", "sealing_key") == bytes.fromhex(MASTER)


@pytest.mark.parametrize("fields,code", [
    ({"other": MASTER}, "SEALING_KEY_VAULT_FIELD_MISSING"),
    ({"key": ""}, "SEALING_KEY_VAULT_FIELD_MISSING"),
    ({"key": "not hex"}, "SEALING_KEY_VAULT_FIELD_NOT_HEX"),
    ({"key": "ab" * 16}, "SEALING_KEY_VAULT_KEY_TOO_SHORT"),
])
def test_a_path_that_does_not_hold_a_usable_key_is_refused(fields, code):
    # Sealing every stored credential under a short or absent master is worse
    # than failing where an operator can see it.
    with pytest.raises(SecretStoreError) as info:
        sealing_master(kv(secret(**fields)), "cremore/sealing-key")
    assert info.value.code.startswith(code)


def test_the_client_is_built_the_way_the_deployment_configured_one():
    from cremore.config import Settings

    http = FakeHTTP(secret(key=MASTER))
    token_settings = Settings(FINGERPRINT_KEY=FINGERPRINT, SECRET_STORE_URL="https://vault.local/",
                              SECRET_STORE_TOKEN="s.token", SECRET_STORE_MOUNT="cremore")
    store = kv_from_settings(token_settings, http)
    assert store.read("x") == {"key": MASTER}
    assert http.calls[0][1] == "https://vault.local/v1/cremore/data/x"
    assert http.calls[0][2]["X-Vault-Token"] == "s.token"
    # Kubernetes auth logs in for its token instead of carrying a static one.
    workload = Settings(FINGERPRINT_KEY=FINGERPRINT, SECRET_STORE_URL="https://vault.local",
                        SECRET_STORE_AUTH_MODE="kubernetes", SECRET_STORE_KUBERNETES_ROLE="cremore")
    assert callable(kv_from_settings(workload, FakeHTTP(secret())).token)


def vault_settings(monkeypatch, at: dict[str, str], **env):
    """Settings whose Vault reads are answered from ``at``, keyed by path."""
    import cremore_vault_provider.secretstore as vault
    from cremore.config import Settings

    def fake_kv(settings, client=None):
        assert settings.secret_store_url == "https://vault.local"
        return kv(FakeResp(200, {}))

    def fake_master(store, path, field="key"):
        assert field == "key"
        return bytes.fromhex(at[path.strip()])

    monkeypatch.setattr(vault, "kv_from_settings", fake_kv)
    monkeypatch.setattr(vault, "sealing_master", fake_master)
    return Settings(FINGERPRINT_KEY=FINGERPRINT, SECRET_STORE_URL="https://vault.local",
                    SECRET_STORE_TOKEN="s.token", **env)


def test_a_vault_held_master_seals_instead_of_the_key_on_this_disk(monkeypatch):
    keys = vault_settings(monkeypatch, {"cremore/sealing-key": MASTER},
                          SEALING_KEY_VAULT_PATH="cremore/sealing-key",
                          SEALING_KEY=OLD_MASTER).sealing_keys
    assert keys.current == bytes.fromhex(MASTER)
    assert seal_token(keys, TOKEN).startswith("sealed:v2:" + key_id(bytes.fromhex(MASTER)))
    # The hex key it displaced still opens what it sealed, or moving the master
    # into Vault would orphan every credential written before the move.
    assert unseal(keys, seal_token(bytes.fromhex(OLD_MASTER), TOKEN)) == {"token": TOKEN}


def test_rotating_to_a_new_vault_path_keeps_the_old_one_readable(monkeypatch):
    before = seal_token(bytes.fromhex(OLD_MASTER), TOKEN)
    keys = vault_settings(monkeypatch, {"cremore/sealing-key": MASTER, "cremore/sealing-key-2024": OLD_MASTER},
                          SEALING_KEY_VAULT_PATH="cremore/sealing-key",
                          SEALING_KEY_VAULT_PATH_PREVIOUS="cremore/sealing-key-2024").sealing_keys
    assert unseal(keys, before) == {"token": TOKEN}
    assert keys.current_id == key_id(bytes.fromhex(MASTER)), "the previous path opens, it does not seal"


def test_no_vault_path_never_reaches_the_store(monkeypatch):
    import cremore_vault_provider.secretstore as vault
    from cremore.config import Settings

    def refuse(*args, **kwargs):
        raise AssertionError("the store must not be reached when no sealing path is configured")

    monkeypatch.setattr(vault, "kv_from_settings", refuse)
    keys = Settings(FINGERPRINT_KEY=FINGERPRINT, SECRET_STORE_URL="https://vault.local",
                    SECRET_STORE_TOKEN="s.token").sealing_keys
    assert keys.current == bytes.fromhex(FINGERPRINT)


def test_startup_refuses_a_sealing_path_with_no_store_to_read_it():
    from cremore.config import Settings

    with pytest.raises(ValueError, match="SEALING_KEY_VAULT_PATH requires SECRET_STORE_URL"):
        Settings(FINGERPRINT_KEY=FINGERPRINT, SEALING_KEY_VAULT_PATH="cremore/sealing-key").validate_sealing()
    # Configured for the worker but not for this process is the same gap.
    with pytest.raises(ValueError, match="requires SECRET_STORE_URL"):
        Settings(FINGERPRINT_KEY=FINGERPRINT, SECRET_STORE_URL="https://vault.local",
                 SEALING_KEY_VAULT_PATH_PREVIOUS="cremore/old").validate_sealing()
    with pytest.raises(ValueError, match="SEALING_KEY_VAULT_FIELD must name a field"):
        Settings(FINGERPRINT_KEY=FINGERPRINT, SEALING_KEY_VAULT_FIELD=" ").validate_sealing()
    Settings(FINGERPRINT_KEY=FINGERPRINT, SECRET_STORE_URL="https://vault.local",
             SECRET_STORE_TOKEN="s.token", SEALING_KEY_VAULT_PATH="cremore/sealing-key").validate_sealing()


@pytest.mark.parametrize("data", [None, [], "synthetic-value", 42])
def test_read_rejects_nonobject_secret_data(data):
    with pytest.raises(SecretStoreError, match="SECRET_STORE_MALFORMED"):
        kv(FakeResp(200, {"data": {"data": data}})).read("nested/path")


@pytest.mark.parametrize("path", ["", "../outside", "nested/../outside", "nested//item", "x\\y", "x\ny"])
def test_ambiguous_kv_paths_never_reach_http(path):
    store = kv(FakeResp(200, {"data": {"data": {}}}))
    with pytest.raises(SecretStoreError, match="SECRET_STORE_PATH_INVALID"):
        store.read(path)
    assert store.client.calls == []


def test_kv_path_is_quoted_and_leading_slashes_remain_supported():
    store = kv(FakeResp(200, {"data": {"data": {}}}))
    store.read("/nested/name?#/")
    assert store.client.calls[0][1] == "https://vault.local/v1/secret/data/nested/name%3F%23"


def test_vault_applies_timeout_and_refuses_redirects():
    import httpx

    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(307, headers={"location": "https://elsewhere.invalid/"})

    with httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
        store = VaultKV(client, "https://vault.local", "synthetic-token", timeout=3.0)
        with pytest.raises(SecretStoreError, match="SECRET_STORE_HTTP_307"):
            store.read("path")
    assert len(requests) == 1
    assert requests[0].extensions["timeout"]["read"] == 3.0
