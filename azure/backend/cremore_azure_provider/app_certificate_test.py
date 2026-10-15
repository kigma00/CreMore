"""The app registration certificate CreMore makes: sign-in assertions, key-roll proofs and the roll itself,
against a synthetic Microsoft Entra token endpoint and Microsoft Graph."""

import base64
import datetime as dt
import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from cremore.collectors.base import CollectorError
from cremore_azure_provider import app_certificate as ac

CLIENT = "11111111-2222-4333-8444-555555555555"
TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OBJECT = "99999999-8888-4777-8666-555555555555"
OLD_KEY = "12121212-3434-4545-8656-787878787878"
NEW_KEY = "abababab-cdcd-4efe-8fab-cdcdcdcdcdcd"
NOW = dt.datetime(2026, 9, 29, 3, 0, tzinfo=dt.UTC)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def made():
    return ac.make(CLIENT, TENANT, now=NOW)


def der_of(envelope):
    return ac.material(envelope)[1].public_bytes(Encoding.DER)


def test_a_made_certificate_holds_a_matching_key_and_says_only_public_things(made):
    envelope, shown = made
    assert envelope["auth_kind"] == "azure_certificate" and envelope["client_id"] == CLIENT
    assert "PRIVATE KEY" in envelope["private_key"] and "CERTIFICATE" in envelope["private_key"]
    _key, certificate = ac.material(envelope)
    der = certificate.public_bytes(Encoding.DER)
    assert shown["thumbprint"] == hashlib.sha1(der).hexdigest().upper()
    assert shown["sha256"] == hashlib.sha256(der).hexdigest()
    assert shown["not_after"] == "2027-03-28T03:00:00Z" and "PRIVATE" not in json.dumps(shown)
    # Another key with this certificate is refused, as is a text without both parts.
    other, _ = ac.make(CLIENT, TENANT, now=NOW)
    mixed = other["private_key"].split("-----BEGIN CERTIFICATE-----")[0] + shown["certificate"]
    for text in (mixed, shown["certificate"], "x"):
        with pytest.raises(ac.CertificateError, match="AZURE_CERTIFICATE_INVALID"):
            ac.material({"private_key": text})


def test_the_assertion_is_ps256_and_names_the_certificate_by_its_thumbprints(made):
    envelope, _ = made
    key, certificate = ac.material(envelope)
    token = ac.assertion(CLIENT, TENANT, key, certificate, now=1_800_000_000)
    der = der_of(envelope)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "PS256" and header["x5t#S256"] == b64url(hashlib.sha256(der).digest())
    assert header["x5t"] == b64url(hashlib.sha1(der).digest())
    claims = jwt.decode(token, certificate.public_key(), algorithms=["PS256"],
                        audience=f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
                        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False})
    assert claims["iss"] == claims["sub"] == CLIENT and claims["exp"] - claims["nbf"] == 300 and claims["jti"]


def entra(record, *, codes=None, status=200, token="t" * 40):
    def handler(request):
        if request.url.host == "login.microsoftonline.com":
            assert request.url.path == f"/{TENANT}/oauth2/v2.0/token"
            form = {key: value[0] for key, value in parse_qs(request.content.decode()).items()}
            record.append(form)
            if codes is not None:
                return httpx.Response(status, json={"error": "invalid_client", "error_codes": codes})
            return httpx.Response(200, json={"access_token": token, "expires_in": 3599, "token_type": "Bearer"})
        raise AssertionError(request.url)
    return handler


def test_a_token_is_asked_for_with_the_assertion_and_refusals_are_codes(made):
    envelope, _ = made
    sent = []
    client = httpx.Client(transport=httpx.MockTransport(entra(sent)))
    token, seconds = ac.request_token(client, envelope, ac.SCOPES["devops"])
    assert token == "t" * 40 and seconds == 3599
    form = sent[0]
    assert form["grant_type"] == "client_credentials" and form["client_id"] == CLIENT
    assert form["scope"] == "499b84ac-1321-427f-aa17-267ca6975798/.default"
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert jwt.decode(form["client_assertion"], ac.material(envelope)[1].public_key(), algorithms=["PS256"],
                      options={"verify_aud": False})["iss"] == CLIENT
    for codes, status, code in (([700027], 401, "AZURE_CERTIFICATE_NOT_REGISTERED"), ([700016], 400, "AZURE_APPLICATION_NOT_FOUND"),
                                ([90002], 400, "AZURE_TENANT_NOT_FOUND"), ([1], 400, "AZURE_TOKEN_REFUSED"),
                                ([], 503, "AZURE_TOKEN_UNAVAILABLE")):
        client = httpx.Client(transport=httpx.MockTransport(entra([], codes=codes, status=status)))
        with pytest.raises(ac.CertificateError) as failed:
            ac.request_token(client, envelope, ac.SCOPES["graph"])
        assert failed.value.code == code and failed.value.retryable == (status == 503)
    client = httpx.Client(transport=httpx.MockTransport(entra([], token="has space")))
    with pytest.raises(ac.CertificateError, match="AZURE_TOKEN_REFUSED"):
        ac.request_token(client, envelope, ac.SCOPES["graph"])


def test_a_token_source_keeps_its_token_and_a_content_scan_sees_the_code(made):
    envelope, _ = made
    sent = []
    source = ac.TokenSource(envelope, ac.SCOPES["arm"], client=httpx.Client(transport=httpx.MockTransport(entra(sent))))
    assert source() == source() == "t" * 40 and len(sent) == 1 and source.bearer
    content = ac.content_token("azure_devops", envelope)
    content.client = httpx.Client(transport=httpx.MockTransport(entra([], codes=[700027], status=401)))
    with pytest.raises(CollectorError, match="AZURE_CERTIFICATE_NOT_REGISTERED"):
        content()
    assert content.bearer and content.scope == ac.SCOPES["devops"]
    assert ac.content_token("azure_blob", envelope).scope == "https://storage.azure.com/.default"
    with pytest.raises(ac.CertificateError):
        ac.content_token("github", envelope)


def test_concurrent_readers_share_one_token_request(made, monkeypatch):
    envelope, _ = made
    asked, lock = [], threading.Lock()

    def request_token(_client, _envelope, _scope, *, timeout):
        with lock:
            asked.append(1)
        time.sleep(0.05)  # the other readers arrive while this one waits on Microsoft Entra
        return "t" * 40, 3599

    monkeypatch.setattr(ac, "request_token", request_token)
    source = ac.TokenSource(envelope, ac.SCOPES["storage"], client=object())
    with ThreadPoolExecutor(8) as pool:
        assert list(pool.map(lambda _: source(), range(8))) == ["t" * 40] * 8
    assert len(asked) == 1 and source.until > time.monotonic()

    def refused(*_args, **_kwargs):
        raise ac.CertificateError("AZURE_TOKEN_UNAVAILABLE", retryable=True)

    source.until = 0.0  # expired: a refused renewal keeps nothing half-written
    monkeypatch.setattr(ac, "request_token", refused)
    with pytest.raises(ac.CertificateError):
        source()
    assert (source.token, source.until) == ("t" * 40, 0.0)


def graph(made, calls, *, app_status=200, listed=True, add_status=200, remove_status=204):
    envelope, _ = made
    der = der_of(envelope)

    def handler(request):
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "graph-token", "expires_in": 3600})
        assert request.headers["Authorization"] == "Bearer graph-token"
        calls.append((request.method, request.url.path, request.content))
        if request.method == "GET":
            assert request.url.path == f"/v1.0/applications(appId='{CLIENT}')"
            assert request.url.params["$select"] == "id,keyCredentials"
            keys = [{"keyId": "00000000-0000-4000-8000-000000000001", "customKeyIdentifier": base64.b64encode(b"x" * 20).decode()}]
            if listed:
                keys.append({"keyId": OLD_KEY, "type": "AsymmetricX509Cert", "key": base64.b64encode(der).decode()})
            return httpx.Response(app_status, json={"id": OBJECT, "keyCredentials": keys})
        if request.url.path.endswith("/addKey"):
            return httpx.Response(add_status, json={"keyId": NEW_KEY, "type": "AsymmetricX509Cert"})
        assert request.url.path == f"/v1.0/applications/{OBJECT}/removeKey"
        return httpx.Response(remove_status)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_renewing_adds_the_next_certificate_with_a_proof_the_current_key_signs(made):
    envelope, shown = made
    calls = []
    result = ac.renew(envelope, client=graph(made, calls), now=NOW)
    method, path, body = calls[1]
    assert (method, path) == ("POST", f"/v1.0/applications/{OBJECT}/addKey")
    body = json.loads(body)
    new_der = der_of(result["envelope"])
    assert body["keyCredential"] == {"type": "AsymmetricX509Cert", "usage": "Verify", "displayName": "CreMore",
                                     "key": base64.b64encode(new_der).decode()}
    assert body["passwordCredential"] is None
    old_certificate = ac.material(envelope)[1]
    header = jwt.get_unverified_header(body["proof"])
    assert header["alg"] == "RS256" and header["kid"] == shown["thumbprint"]
    assert header["x5t"] == b64url(hashlib.sha1(der_of(envelope)).digest())
    claims = jwt.decode(body["proof"], old_certificate.public_key(), algorithms=["RS256"],
                        audience="00000002-0000-0000-c000-000000000000", options={"verify_nbf": False})
    assert claims["iss"] == OBJECT and claims["exp"] - claims["nbf"] == 600
    # Only the public certificate went to Microsoft; the new key stays in the envelope.
    assert "PRIVATE" not in json.dumps(body) and result["envelope"]["client_id"] == CLIENT
    assert result["public"]["thumbprint"] != shown["thumbprint"] and result["key_id"] == NEW_KEY
    assert result["retire"] == {"object_id": OBJECT, "key_id": OLD_KEY, "thumbprint": shown["thumbprint"],
                                "after": "2026-09-30T03:00:00Z"}


def test_renewing_says_why_it_cannot(made):
    envelope, _ = made
    for kwargs, code in (({"app_status": 403}, "AZURE_APPLICATION_READ_REQUIRED"),
                         ({"listed": False}, "AZURE_CERTIFICATE_NOT_ON_APPLICATION"),
                         ({"add_status": 400}, "AZURE_ADD_KEY_REFUSED"), ({"add_status": 503}, "AZURE_GRAPH_UNAVAILABLE")):
        with pytest.raises(ac.CertificateError) as failed:
            ac.renew(envelope, client=graph(made, [], **kwargs), now=NOW)
        assert failed.value.code == code


def test_retiring_removes_the_old_certificate_and_a_gone_one_is_done(made):
    envelope, _shown = made
    calls = []
    ac.retire(envelope, OBJECT, OLD_KEY, client=graph(made, calls))
    body = json.loads(calls[0][2])
    assert body["keyId"] == OLD_KEY
    claims = jwt.decode(body["proof"], ac.material(envelope)[1].public_key(), algorithms=["RS256"],
                        audience="00000002-0000-0000-c000-000000000000", options={"verify_nbf": False})
    assert claims["iss"] == OBJECT
    ac.retire(envelope, OBJECT, OLD_KEY, client=graph(made, [], remove_status=404))
    with pytest.raises(ac.CertificateError, match="AZURE_REMOVE_KEY_REFUSED"):
        ac.retire(envelope, OBJECT, OLD_KEY, client=graph(made, [], remove_status=400))


def test_a_key_credential_is_found_by_its_certificate_or_its_thumbprint(made):
    envelope, _ = made
    certificate = ac.material(envelope)[1]
    sha1 = hashlib.sha1(der_of(envelope)).digest()
    assert ac.key_id([{"keyId": OLD_KEY, "customKeyIdentifier": base64.b64encode(sha1).decode()}], certificate) == OLD_KEY
    assert ac.key_id([{"keyId": OLD_KEY.upper(), "customKeyIdentifier": base64.b64encode(sha1.hex().upper().encode()).decode()}],
                     certificate) == OLD_KEY
    assert ac.key_id([{"keyId": "not-a-guid", "customKeyIdentifier": base64.b64encode(sha1).decode()}, None], certificate) is None


def test_what_is_due_follows_the_certificate_and_the_old_one():
    generated = {"not_after": "2027-03-28T03:00:00Z"}
    assert ac.due(generated, None, NOW) is None
    assert ac.due(generated, None, dt.datetime(2027, 1, 27, 3, 1, tzinfo=dt.UTC)) == "renew"
    assert ac.due(generated, {"after": "2026-09-30T03:00:00Z"}, NOW) is None
    assert ac.due(generated, {"after": "2026-09-30T03:00:00Z"}, NOW + dt.timedelta(days=2)) == "retire"
    # An expired certificate cannot sign its own renewal; only a new upload helps.
    assert ac.due(generated, None, dt.datetime(2027, 4, 1, tzinfo=dt.UTC)) is None
    assert ac.due({}, None, NOW) is None


def signed_spec(provider, **body):
    from cremore.coverage.metadata_models import MetadataConnectionSpec

    ref = "vault://microsoft/app"
    return MetadataConnectionSpec.model_validate({
        "name": "Microsoft", "provider": provider, "edition": "cloud", "auth_type": "private_key_jwt",
        "secret_refs": {"client_id": ref, "private_key": ref, "tenant_id": ref}, **body})


def signed(made, service):
    """Microsoft Entra sign-in with the certificate, then one Microsoft service that sees the token."""
    envelope, _ = made
    seen = []

    def handler(request):
        if request.url.host == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            seen.append(("scope", form["scope"][0]))
            return httpx.Response(200, json={"access_token": "cert-token", "expires_in": 3600})
        seen.append(("authorization", request.headers["authorization"]))
        return service(request)

    secrets = {key: envelope[key] for key in ("client_id", "private_key", "tenant_id")}
    return secrets, httpx.Client(transport=httpx.MockTransport(handler)), seen


ENTRA_SPEC = {"origin": "https://graph.microsoft.com", "tenant": TENANT, "tenant_confirmed": True,
              "scopes": [{"kind": "organization", "id": TENANT}], "capabilities": ["inventory"]}


def test_the_microsoft_collections_sign_in_with_the_certificate(made):
    from cremore_azure_provider.devops_tokens import adapter as devops
    from cremore_azure_provider.entra import adapter as entra

    def graph(request):
        if request.url.path == "/v1.0/organization":
            return httpx.Response(200, json={"value": [{"id": TENANT}]})
        return httpx.Response(200, json={"value": []})

    secrets, client, seen = signed(made, graph)
    spec = signed_spec("azure_entra", **ENTRA_SPEC)
    pages = list(entra.collect_pages(spec, secrets=secrets, checkpoint=None, check=lambda: None, client=client))
    assert pages[-1].status == "COMPLETE"
    assert seen[0] == ("scope", "https://graph.microsoft.com/.default")
    assert {value for kind, value in seen if kind == "authorization"} == {"Bearer cert-token"}
    # A certificate collection without its references is refused, as is the worker identity with them.
    with pytest.raises(ValueError):
        list(entra.collect_pages(spec, secrets={}, checkpoint=None, check=lambda: None, client=client))

    secrets, client, seen = signed(made, lambda request: httpx.Response(200, json={"value": []}))
    spec = signed_spec("azure_devops", origin="https://vssps.dev.azure.com",
                       scopes=[{"kind": "organization", "id": "acme"}], capabilities=["inventory"])
    pages = list(devops.collect_pages(spec, secrets=secrets, checkpoint=None, check=lambda: None, client=client))
    assert pages[-1].status == "COMPLETE"
    assert seen[0] == ("scope", "499b84ac-1321-427f-aa17-267ca6975798/.default")
    assert {value for kind, value in seen if kind == "authorization"} == {"Bearer cert-token"}


def test_a_refused_certificate_is_the_reason_a_collection_gives(made):
    from cremore_azure_provider.entra import adapter as entra

    envelope, _ = made

    def refuse(request):
        return httpx.Response(401, json={"error": "invalid_client", "error_codes": [700027]})

    secrets = {key: envelope[key] for key in ("client_id", "private_key", "tenant_id")}
    pages = list(entra.collect_pages(signed_spec("azure_entra", **ENTRA_SPEC), secrets=secrets, checkpoint=None,
                                     check=lambda: None, client=httpx.Client(transport=httpx.MockTransport(refuse))))
    assert pages[-1].status == "FAILED" and pages[-1].reasons == ["AZURE_CERTIFICATE_NOT_REGISTERED"]
