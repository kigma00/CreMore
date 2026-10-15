"""Workload login and private CA survive authentication-first mount selection."""

import datetime as dt
import json
import ssl
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.config import Settings
from cremore.onboarding import check, sessions
from cremore.onboarding.sessions_test import KEY, body
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414
from cremore.secretstore.resolver import SecretResolver
from cremore_vault_provider import onboarding


def ca_certificate():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Synthetic test CA")])
    now = dt.datetime.now(dt.UTC)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())


@pytest.mark.parametrize("provider,method", [("vault", "kubernetes"), ("openbao", "jwt")])
def test_workload_authentication_then_mounts_preserves_ca_and_rotated_file(repo, tmp_path, provider, method):
    settings = Settings(FINGERPRINT_KEY="ab" * 32, VAULT_CONNECTION_TOKEN_DIR=str(tmp_path))
    token_file = tmp_path / "projected.jwt"
    token_file.write_text("synthetic.projected.first")
    ca, calls, tls_contexts = ca_certificate(), [], []

    def handler(request):
        calls.append(request.url.path)
        assert request.url.host == "vault.example.test"
        assert request.headers["x-vault-namespace"] == "team"
        if request.url.path == f"/v1/auth/{method}/login":
            assert json.loads(request.content) == {"role": "reader", "jwt": token_file.read_text()}
            return httpx.Response(200, json={"auth": {"client_token": "synthetic-vault-session", "lease_duration": 600}})
        assert request.headers["x-vault-token"] == "synthetic-vault-session"
        if request.url.path == "/v1/auth/token/lookup-self":
            return httpx.Response(200, json={"data": {"id": "not-saved"}})
        if request.url.path == "/v1/sys/mounts":
            return httpx.Response(200, json={"data": {"kv/": {"type": "kv", "options": {"version": "2"}},
                                                       "sys/": {"type": "system"}}})
        assert request.url.path == "/v1/sys/capabilities-self", "never read secret values in onboarding"
        return httpx.Response(200, json={p: ["read", "list"] for p in json.loads(request.content)["paths"]})

    def factory(**kwargs):
        assert set(kwargs) == {"verify"} and isinstance(kwargs["verify"], ssl.SSLContext)
        assert kwargs["verify"].verify_mode == ssl.CERT_REQUIRED and kwargs["verify"].check_hostname
        tls_contexts.append(kwargs["verify"])
        return httpx.Client(transport=httpx.MockTransport(handler))

    worker = SimpleNamespace(repo=repo, settings=settings, http_client_factory=factory,
                             metadata_secret_resolver=SecretResolver(sealing_key=settings.sealing_keys))

    def run(view):
        check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
        result = sessions.read(repo, view["id"], body(view), "admin")
        assert "synthetic.projected" not in json.dumps(result) and "synthetic-vault-session" not in json.dumps(result)
        return result

    view = run(sessions.create(repo, settings, {"browser_key": KEY, "provider": provider, "auth_method": method,
        "edition": "enterprise" if provider == "vault" else "self_managed",
        "context": {"address": "https://vault.example.test", "namespace": "team", "tls_ca_pem": ca},
        "credential": {"role": "reader", "token_file": token_file.name}}, "admin"))
    assert view["state"] == "AUTHENTICATED", view
    assert calls == [f"/v1/auth/{method}/login", "/v1/auth/token/lookup-self"]
    token_file.write_text("synthetic.projected.renewed")
    view = run(sessions.discover(repo, view["id"], body(view, purposes=["vault"]), "admin"))
    assert view["state"] == "LISTED" and len(view["roots"]) == 1, view.get("error")
    root = view["roots"][0]
    assert root["target"]["tls_ca_pem"] == ca.strip()
    view = run(sessions.inspect(repo, view["id"], body(view, target_ids=[root["id"]], plans={"vault": {}}), "admin"))
    assert view["state"] == "CHECKED" and not view["blockers"], view
    assert len(tls_contexts) == 3
    view = sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[]), "admin")
    result = sessions.complete(repo, settings, view["id"], body(view, name="Synthetic Vault"), "admin")
    from cremore.coverage.store import CoverageStore

    stored = CoverageStore(repo).get(uuid.UUID(result["children"][0]["id"]))["spec"]
    assert stored["server_auth"]["method"] == method and stored["tls_ca_pem"] == ca.strip()
    assert stored["mounts"][0]["name"] == "kv" and stored["secret_refs"] == {}


@pytest.mark.parametrize("case", ["outside", "installation", "missing"])
def test_authentication_cannot_read_installation_or_arbitrary_file(tmp_path, case):
    directory = tmp_path / "mounted"
    directory.mkdir()
    path = directory / "projected.jwt"
    path.write_text("synthetic.jwt")
    settings = SimpleNamespace(vault_connection_token_dir=str(directory), secret_store_auth_mode="kubernetes",
        secret_store_kubernetes_token_file=str(path) if case == "installation" else "")
    record = {"provider": "vault", "auth_method": "kubernetes", "target": {"address": "https://vault.example.test",
              "auth": {"role": "reader", "token_file": "projected.jwt"}}}
    if case == "outside":
        # A resolved path outside the configured directory is refused even if
        # the platform's public basename validation were bypassed.
        record["target"]["auth"]["token_file"] = "../elsewhere.jwt"
    elif case == "missing":
        record["target"]["auth"]["token_file"] = "missing.jwt"
    context = SimpleNamespace(settings=settings,
        http_client=lambda: httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("no network before file validation"))))
    if case == "outside":
        with pytest.raises(ValueError):
            onboarding.authenticate(record, {}, context)
    else:
        assert onboarding.authenticate(record, {}, context)["status"] == "MISSING"


def test_private_ca_rejects_private_keys_and_invalid_pem():
    for value in ("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"):
        with pytest.raises(onboarding.OnboardingValueError, match="VAULT_TLS_CA_MUST_BE_A_PEM_CERTIFICATE"):
            onboarding.auth_context("vault", "self_managed", {"address": "https://vault.example.test", "tls_ca_pem": value})


def test_mount_denial_is_not_an_empty_success():
    context = SimpleNamespace(settings=SimpleNamespace(), http_client=lambda: httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(403, json={"message": "private-response"}))))
    with pytest.raises(onboarding.OnboardingValueError, match="VAULT_MOUNTS_ACCESS_DENIED"):
        onboarding.discover({"auth_method": "token", "target": {"address": "https://vault.example.test"}},
                            {"credential": {"token": "synthetic-token"}}, context)


@pytest.mark.parametrize("provider,edition", [("vault", "enterprise"), ("openbao", "self_managed")])
def test_new_vault_setup_requires_own_login_and_kv_mount(provider, edition):
    from cremore.onboarding import service

    descriptor = next(d for d in onboarding.DESCRIPTORS if d["provider"] == provider)
    assert {m["id"] for m in descriptor["auth_methods"] if m.get("new_setup") is not False} == {
        "kubernetes", "jwt", "token"}
    with pytest.raises(service.OnboardingError, match="AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS"):
        service._method(provider, ["vault"], "customer_cli", edition, new_setup=True)
    assert service._method(provider, ["vault"], "customer_cli", edition)["id"] == "customer_cli"
    with pytest.raises(onboarding.OnboardingValueError, match="VAULT_MOUNT_REQUIRED"):
        onboarding.target(provider, edition, {"address": "https://vault.example.test", "mounts": []})
