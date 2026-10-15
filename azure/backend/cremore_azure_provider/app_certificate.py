"""A Microsoft Entra app registration certificate that CreMore makes, signs in with and renews itself.

CreMore makes an RSA key and a self-signed certificate for one app registration; only the certificate
leaves (the admin uploads it once, or the setup command does). Every Microsoft API is reached with a token
from the client credentials grant, authenticated by an assertion the key signs (PS256 with the SHA-256
certificate thumbprint, ``x5t#S256``). Before the certificate expires the worker adds the next one to the
application with Microsoft Graph ``addKey`` -- a proof of possession the current key signs; an application
needs no permission to roll its own keys, only Application.Read.All to find its own object -- keeps the new
key, and removes the old certificate with ``removeKey`` a day later, once runs that began with it are over.
Nothing here keeps or reports a key, token or response body; a failure is a code.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import re
import threading
import time
import uuid

import jwt

from cremore.http_client import HTTPResponseTooLarge, bounded_request

KIND = "azure_certificate"
LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"
# The audience of a key-roll proof (addKey, removeKey): the Microsoft Graph service principal.
POP_AUDIENCE = "00000002-0000-0000-c000-000000000000"
SCOPES = {"graph": GRAPH + "/.default", "arm": "https://management.azure.com/.default",
          "storage": "https://storage.azure.com/.default", "vault": "https://vault.azure.net/.default",
          # Azure DevOps, by its application ID (the resource https://app.vssps.visualstudio.com names).
          "devops": "499b84ac-1321-427f-aa17-267ca6975798/.default"}
# ponytail: fixed lifetimes; a tenant policy with a shorter maximum certificate lifetime refuses addKey
# (AZURE_ADD_KEY_REFUSED) -- make LIFETIME a connection option when one does.
LIFETIME = _dt.timedelta(days=180)
RENEW_BEFORE = _dt.timedelta(days=60)
RETIRE_AFTER = _dt.timedelta(hours=24)
# An old certificate that could not be removed for this long has expired; it is left to Microsoft Entra.
RETIRE_FOR = _dt.timedelta(days=30)
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_PEM = re.compile(r"-----BEGIN ([A-Z ]{1,40})-----\r?\n[A-Za-z0-9+/=\r\n]{1,16384}?-----END \1-----")
# Microsoft Entra sign-in error codes (AADSTS numbers) that name a fix; any other refusal is one code.
_SIGN_IN = {700027: "AZURE_CERTIFICATE_NOT_REGISTERED", 700016: "AZURE_APPLICATION_NOT_FOUND",
            90002: "AZURE_TENANT_NOT_FOUND", 900023: "AZURE_TENANT_NOT_FOUND",
            7000112: "AZURE_APPLICATION_DISABLED", 700024: "AZURE_CLOCK_SKEW",
            7000229: "AZURE_SERVICE_PRINCIPAL_MISSING", 500011: "AZURE_RESOURCE_NOT_IN_TENANT"}


# The secret roles a collection that signs in with the certificate names (one sealed envelope holds all three).
ROLES = frozenset({"client_id", "private_key", "tenant_id"})


class CertificateError(ValueError):
    """A stable code; never a response body, key or token."""

    def __init__(self, code, *, retryable=False):
        super().__init__(code)
        self.code, self.retryable = code, retryable


def signs_in(spec) -> bool:
    """Whether a collection signs in with the certificate CreMore made (rather than the worker's identity)."""
    return spec.auth_type == "private_key_jwt" and set(spec.secret_refs) == ROLES


def allowed(spec, *, public_cloud=True) -> bool:
    """The worker's own Azure identity without references, or -- in the public cloud, where CreMore signs in
    -- the certificate with its three roles."""
    return (spec.auth_type == "workload_identity" and not spec.secret_refs) or (public_cloud and signs_in(spec))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _iso(value) -> str:
    return value.astimezone(_dt.UTC).isoformat().replace("+00:00", "Z")


def make(client_id, tenant_id, *, now=None):
    """A new key and certificate: the envelope to seal, and what may be shown (``public``)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = (now or _dt.datetime.now(_dt.UTC)).replace(microsecond=0)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CreMore")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - _dt.timedelta(minutes=5)).not_valid_after(now + LIFETIME)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    pem = (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")
           + certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    envelope = {"auth_kind": KIND, "client_id": client_id, "tenant_id": tenant_id, "private_key": pem}
    return envelope, public(certificate)


def public(certificate) -> dict:
    """What the certificate says about itself: nothing here is secret."""
    from cryptography.hazmat.primitives.serialization import Encoding

    der = certificate.public_bytes(Encoding.DER)
    return {"certificate": certificate.public_bytes(Encoding.PEM).decode("ascii"),
            # The SHA-1 thumbprint is what the Microsoft Entra admin center shows for a certificate.
            "thumbprint": hashlib.sha1(der).hexdigest().upper(), "sha256": hashlib.sha256(der).hexdigest(),
            "not_before": _iso(certificate.not_valid_before_utc), "not_after": _iso(certificate.not_valid_after_utc)}


def ids(envelope):
    client_id, tenant_id = (envelope or {}).get("client_id"), (envelope or {}).get("tenant_id")
    if not all(isinstance(value, str) and GUID.fullmatch(value) for value in (client_id, tenant_id)):
        raise CertificateError("AZURE_CERTIFICATE_INVALID")
    return client_id, tenant_id


def material(envelope):
    """The key and the certificate an envelope holds (one PEM text), checked to belong together."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    text = (envelope or {}).get("private_key")
    if not isinstance(text, str) or len(text) > 32768:
        raise CertificateError("AZURE_CERTIFICATE_INVALID")
    blocks = {match.group(1): match.group(0) for match in _PEM.finditer(text)}
    try:
        key = load_pem_private_key(blocks["PRIVATE KEY"].encode("ascii"), password=None)
        certificate = x509.load_pem_x509_certificate(blocks["CERTIFICATE"].encode("ascii"))
        if (not isinstance(key, rsa.RSAPrivateKey)
                or key.public_key().public_numbers() != certificate.public_key().public_numbers()):
            raise ValueError
    except Exception:  # noqa: BLE001 -- parser errors can quote the key
        raise CertificateError("AZURE_CERTIFICATE_INVALID") from None
    return key, certificate


def _thumbprints(certificate):
    from cryptography.hazmat.primitives.serialization import Encoding

    der = certificate.public_bytes(Encoding.DER)
    return der, hashlib.sha1(der).digest(), hashlib.sha256(der).digest()


def assertion(client_id, tenant_id, key, certificate, *, now=None) -> str:
    """The client assertion: PS256, the certificate named by its SHA-256 (and, for older validators, SHA-1)
    thumbprint, valid for five minutes."""
    _der, sha1, sha256 = _thumbprints(certificate)
    now = int(time.time() if now is None else now)
    claims = {"aud": f"{LOGIN}/{tenant_id}/oauth2/v2.0/token", "iss": client_id, "sub": client_id,
              "jti": str(uuid.uuid4()), "nbf": now, "iat": now, "exp": now + 300}
    return jwt.encode(claims, key, algorithm="PS256", headers={"x5t#S256": _b64url(sha256), "x5t": _b64url(sha1)})


def proof(object_id, key, certificate, *, now=None) -> str:
    """A key-roll proof of possession, as Microsoft's own sample signs it: RS256, x5t and kid naming the
    certificate, issued by the application object, ten minutes long."""
    _der, sha1, _sha256 = _thumbprints(certificate)
    now = int(time.time() if now is None else now)
    return jwt.encode({"aud": POP_AUDIENCE, "iss": object_id, "nbf": now, "iat": now, "exp": now + 600}, key,
                      algorithm="RS256", headers={"x5t": _b64url(sha1), "kid": sha1.hex().upper()})


def _sign_in_refusal(response):
    if response.status_code in (408, 429) or response.status_code >= 500:
        return CertificateError("AZURE_TOKEN_UNAVAILABLE", retryable=True)
    try:
        codes = response.json().get("error_codes")
    except (ValueError, AttributeError):
        codes = None
    for code in codes if isinstance(codes, list) else []:
        if type(code) is int and code in _SIGN_IN:
            return CertificateError(_SIGN_IN[code])
    return CertificateError("AZURE_TOKEN_REFUSED")


def request_token(client, envelope, scope, *, timeout=30):
    """``(token, seconds)`` for one scope, from the client credentials grant with the certificate."""
    client_id, tenant_id = ids(envelope)
    key, certificate = material(envelope)
    form = {"grant_type": "client_credentials", "client_id": client_id, "scope": scope,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(client_id, tenant_id, key, certificate)}
    try:
        response = bounded_request(client, "POST", f"{LOGIN}/{tenant_id}/oauth2/v2.0/token", data=form,
                                   headers={"Accept": "application/json"}, timeout=timeout, follow_redirects=False,
                                   max_response_bytes=64 << 10)
    except Exception:  # noqa: BLE001 -- transport errors can quote the assertion
        raise CertificateError("AZURE_TOKEN_UNAVAILABLE", retryable=True) from None
    if response.status_code != 200:
        raise _sign_in_refusal(response)
    try:
        body = response.json()
        token, seconds = body["access_token"], int(body.get("expires_in", 3600))
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CertificateError("AZURE_TOKEN_REFUSED") from None
    if not isinstance(token, str) or not 1 <= len(token) <= 16384 or any(not 33 <= ord(c) <= 126 for c in token):
        raise CertificateError("AZURE_TOKEN_REFUSED")
    return token, max(60, min(seconds, 86400))


class TokenSource:
    """A token for one scope, fetched with the certificate and kept until shortly before it expires.

    A scan's concurrent readers share it: one asks Microsoft Entra while the others wait for that token.
    """

    # How a source that also takes personal access tokens (Azure DevOps) knows to send it as a bearer.
    bearer = True

    def __init__(self, envelope, scope, *, client=None, timeout=30):
        self.envelope, self.scope, self.client, self.timeout = dict(envelope or {}), scope, client, timeout
        self.token, self.until = None, 0.0
        self._lock = threading.Lock()

    def __call__(self):
        with self._lock:
            if self.token and time.monotonic() < self.until:
                return self.token
            client = self.client
            if client is None:
                import httpx

                client = httpx.Client(timeout=self.timeout, follow_redirects=False)
            try:
                token, seconds = request_token(client, self.envelope, self.scope, timeout=self.timeout)
            finally:
                if client is not self.client:
                    client.close()
            # Kept together, and only after a good answer.
            self.token, self.until = token, time.monotonic() + max(30, seconds - 300)
            return token


class ContentToken(TokenSource):
    """The same, for a content scan: a sign-in refusal is the scan's error code."""

    def __call__(self):
        from cremore.collectors.base import CollectorError

        try:
            return super().__call__()
        except CertificateError as exc:
            raise CollectorError(exc.code) from None


# The token a content source needs, by the source's provider.
_CONTENT = {"azure_blob": SCOPES["storage"], "azure_devops": SCOPES["devops"]}


def content_token(provider, envelope):
    scope = _CONTENT.get(provider)
    if scope is None:
        raise CertificateError("AZURE_CERTIFICATE_NOT_FOR_THIS_SOURCE")
    ids(envelope)
    return ContentToken(envelope, scope)


def _graph(client, token, method, path, *, refused, params=None, json=None, ok=(200,)):
    try:
        response = bounded_request(client, method, GRAPH + path, params=params, json=json,
                                   headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                                   timeout=30, follow_redirects=False, max_response_bytes=1 << 20)
    except HTTPResponseTooLarge:
        raise CertificateError("AZURE_GRAPH_RESPONSE_LIMIT") from None
    except Exception:  # noqa: BLE001 -- transport errors can carry the bearer
        raise CertificateError("AZURE_GRAPH_UNAVAILABLE", retryable=True) from None
    status = response.status_code
    if status in ok:
        if status == 204 or not response.content:
            return {}
        try:
            body = response.json()
        except ValueError:
            raise CertificateError("AZURE_GRAPH_INVALID_RESPONSE") from None
        if not isinstance(body, dict):
            raise CertificateError("AZURE_GRAPH_INVALID_RESPONSE")
        return body
    if status in (408, 429) or status >= 500:
        raise CertificateError("AZURE_GRAPH_UNAVAILABLE", retryable=True)
    raise CertificateError(refused.get(status, refused["*"]))


def key_id(entries, certificate):
    """The keyId of the application's key credential that is this certificate (by its DER, or by the
    thumbprint Microsoft keeps as its custom identifier), or None."""
    _der, sha1, sha256 = _thumbprints(certificate)
    for entry in entries if isinstance(entries, list) else []:
        found = str((entry or {}).get("keyId") or "").lower() if isinstance(entry, dict) else ""
        if not GUID.fullmatch(found):
            continue
        raw = entry.get("key")
        try:
            if isinstance(raw, str) and raw and hashlib.sha256(base64.b64decode(raw, validate=True)).digest() == sha256:
                return found
            named = base64.b64decode(entry.get("customKeyIdentifier") or "", validate=True)
        except (ValueError, TypeError):
            continue
        if named == sha1 or named.decode("ascii", "ignore").upper() == sha1.hex().upper():
            return found
    return None


def renew(envelope, *, client, now=None) -> dict:
    """Add the next certificate to the application with a proof the current key signs.

    Returns the new ``envelope`` and its ``public`` part, the new certificate's ``key_id`` when Microsoft
    names it, and what to ``retire`` later (the application object and the old certificate's keyId).
    """
    now = now or _dt.datetime.now(_dt.UTC)
    client_id, tenant_id = ids(envelope)
    key, certificate = material(envelope)
    token, _seconds = request_token(client, envelope, SCOPES["graph"])
    app = _graph(client, token, "GET", f"/v1.0/applications(appId='{client_id}')", params={"$select": "id,keyCredentials"},
                 refused={403: "AZURE_APPLICATION_READ_REQUIRED", 404: "AZURE_APPLICATION_NOT_FOUND",
                          "*": "AZURE_GRAPH_REFUSED"})
    object_id = str(app.get("id") or "").lower()
    if not GUID.fullmatch(object_id):
        raise CertificateError("AZURE_GRAPH_INVALID_RESPONSE")
    current = key_id(app.get("keyCredentials"), certificate)
    if current is None:
        # The token came with this certificate, so it sits on the service principal, not the application.
        raise CertificateError("AZURE_CERTIFICATE_NOT_ON_APPLICATION")
    new, shown = make(client_id, tenant_id, now=now)
    _new_key, new_certificate = material(new)
    der, _sha1, _sha256 = _thumbprints(new_certificate)
    added = _graph(client, token, "POST", f"/v1.0/applications/{object_id}/addKey", json={
        "keyCredential": {"type": "AsymmetricX509Cert", "usage": "Verify", "displayName": "CreMore",
                          "key": base64.b64encode(der).decode("ascii")},
        "passwordCredential": None, "proof": proof(object_id, key, certificate)},
        refused={"*": "AZURE_ADD_KEY_REFUSED"})
    named = str(added.get("keyId") or "").lower()
    return {"envelope": new, "public": shown, "key_id": named if GUID.fullmatch(named) else None,
            "retire": {"object_id": object_id, "key_id": current, "thumbprint": public(certificate)["thumbprint"],
                       "after": _iso(now + RETIRE_AFTER)}}


def retire(envelope, object_id, old_key_id, *, client) -> None:
    """Remove an old certificate with a proof the current key signs; one already gone is done."""
    if not GUID.fullmatch(str(object_id)) or not GUID.fullmatch(str(old_key_id)):
        raise CertificateError("AZURE_CERTIFICATE_INVALID")
    key, certificate = material(envelope)
    token, _seconds = request_token(client, envelope, SCOPES["graph"])
    try:
        _graph(client, token, "POST", f"/v1.0/applications/{object_id}/removeKey", ok=(200, 204),
               json={"keyId": old_key_id, "proof": proof(object_id, key, certificate)},
               refused={404: "AZURE_KEY_NOT_FOUND", "*": "AZURE_REMOVE_KEY_REFUSED"})
    except CertificateError as exc:
        if exc.code != "AZURE_KEY_NOT_FOUND":
            raise


def due(generated, retiring, now) -> str | None:
    """What the worker does next for a connection's certificate: ``renew`` in its last RENEW_BEFORE,
    ``retire`` once an old certificate's time has come, or nothing."""
    try:
        until = _dt.datetime.fromisoformat(str((generated or {})["not_after"]))
    except (KeyError, ValueError):
        return None
    if until <= now:
        return None  # expired: only a new certificate the admin uploads helps
    if until - now <= RENEW_BEFORE:
        return "renew"
    try:
        after = _dt.datetime.fromisoformat(str((retiring or {})["after"]))
    except (KeyError, ValueError):
        return None
    return "retire" if after <= now <= after + RETIRE_FOR else None
