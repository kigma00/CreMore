"""Okta in the connection wizard (cremore.onboarding): the departed-owner check's people.

A service app authenticates with ``private_key_jwt`` (and DPoP when the app requires
it) and holds only ``okta.users.read``. CreMore makes the key (``made_key``): the private
key is sealed at once and only the public JWK, with its ``kid``, is shown to paste into the
app; or the admin enters a key Okta generated (``private_key_jwt``). The check signs in and
reads one page of users with the collection's own reader.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re

_CLIENT = re.compile(r"[A-Za-z0-9._-]{1,128}")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")

_PEOPLE = {"name": "people_details", "kind": "bool", "default": True,
           "label": "Keep people's names, emails and departments (owners and contacts)",
           "label_ko": "사람 이름·이메일·부서 보관(담당자·연락 대상 표시)"}
# The organization's app list, read by a collection of its own once a day, suggests the services to connect. Off
# unless chosen: it needs okta.apps.read and a role that views applications, which the people listing does not.
_APPS = {"name": "apps", "kind": "bool", "default": False,
         "label": "Read the organization's app list to suggest the services to connect",
         "label_ko": "조직의 앱 목록을 읽어 연동할 서비스 제안"}

DESCRIPTORS = [{
    "provider": "okta",
    "label": "Okta", "label_ko": "Okta",
    "category": "identity",
    "editions": [{"id": "cloud", "label": "Okta", "label_ko": "Okta"}],
    "target": [{"name": "organization", "label": "Okta organization host", "label_ko": "Okta 조직 호스트",
                "kind": "text", "required": True, "hint": "acme.okta.com"}],
    "purposes": {"identity": {"permissions": [
        {"id": "users_read", "label": "okta.users.read", "label_ko": "okta.users.read"},
        {"id": "apps_read", "label": "okta.apps.read (app list option)", "label_ko": "okta.apps.read(앱 목록 옵션)",
         "option": "apps"}],
        "plan": [{"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes)",
                  "label_ko": "수집 주기(분)", "default": 5, "min": 0, "max": 10080}, _PEOPLE, _APPS]}},
    "auth_methods": [{"id": "made_key", "label": "Service app with a key CreMore makes",
                      "auth_first": {"context": ["organization"]},
                      "label_ko": "서비스 앱(CreMore가 만든 키)", "renewal": "AUTOMATIC", "generated": True,
                      "reference": False, "purposes": ["identity"],
                      "fields": [{"name": "client_id", "label": "Client ID", "label_ko": "클라이언트 ID", "kind": "text",
                                  "public": True}]},
                     {"id": "private_key_jwt", "reference_keys": ["client_id", "private_key"],
                      "auth_first": {"context": ["organization"]},
                      "label": "Service app with a private key", "label_ko": "개인 키 서비스 앱",
                      "renewal": "AUTOMATIC", "purposes": ["identity"],
                      "fields": [{"name": "client_id", "label": "Client ID", "label_ko": "클라이언트 ID", "kind": "text"},
                                 {"name": "private_key", "label": "Private key (PEM or JWK with kid)",
                                  "label_ko": "개인 키(PEM 또는 kid가 있는 JWK)", "kind": "multiline",
                                  "secret": True}]}],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    host = values.get("organization", "").strip().lower().removeprefix("https://").rstrip("/")
    if not _HOST.fullmatch(host):
        raise OnboardingValueError("OKTA_ORGANIZATION_HOST_INVALID")
    return {"organization": host}


auth_context = target


def authenticate(connection, secrets, context):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer
    from cremore_okta_provider.identity import reader

    model = MetadataConnectionSpec.model_validate({**spec(connection), "secret_refs": {
        "client_id": "vault://onboarding/check", "private_key": "vault://onboarding/check"}})
    client = context.http_client()
    read = reader(model, dict(secrets.get("credential") or {}), client, Pacer(model, lambda: None))
    try:
        read._authenticate()  # existing private_key_jwt/DPoP protocol; no people or apps are listed
        return {"status": "GRANTED", "subject": connection["target"]["organization"]}
    finally:
        read.close()
        client.close()


def discover(connection, secrets, context):
    selected = {"organization": connection["target"]["organization"]}
    return [{"target": selected, "label": selected["organization"]}], "COMPLETE"


# Okta's org domains (login.okta.com): the US military cell is okta.mil, not a .com.
_OKTA_DOMAIN = re.compile(r"[a-z0-9-]+\.(?:(?:okta|oktapreview|okta-emea|okta-gov)\.com|okta\.mil)")
# Okta's custom authorization servers: the default one, or an Okta object ID (aus + 17).
_AUTHORIZATION_SERVER = re.compile(r"/oauth2/(?:default|aus[0-9A-Za-z]{17})")


def sign_in_target(provider, issuer):
    """The organization people sign in with, when the console's sign-in issuer is Okta's: the org authorization
    server of an Okta domain (``https://acme.okta.com``) or a custom authorization server (``/oauth2/default``) on an
    Okta or custom domain, where the Management API answers too. An org authorization server on a custom domain
    looks like any other IdP and is not claimed (cremore.onboarding.sign_in)."""
    from urllib.parse import urlsplit

    parts = urlsplit(issuer)
    host, path = (parts.hostname or "").lower(), parts.path.rstrip("/")
    if (parts.scheme != "https" or parts.port not in (None, 443) or parts.query or parts.fragment or parts.username
            or not _HOST.fullmatch(host)):
        return None
    if (path == "" and _OKTA_DOMAIN.fullmatch(host)) or _AUTHORIZATION_SERVER.fullmatch(path):
        return {"organization": host}
    return None


def credential(provider, method, fields):
    from cremore_okta_provider.identity import signing_key

    client_id, key = fields.get("client_id", "").strip(), fields.get("private_key", "").strip()
    if not _CLIENT.fullmatch(client_id):
        raise OnboardingValueError("OKTA_CLIENT_ID_INVALID")
    try:
        signing_key(key)
    except ValueError:
        raise OnboardingValueError("OKTA_PRIVATE_KEY_INVALID") from None
    return {"credential": {"client_id": client_id, "private_key": key}}


def generate(provider, method, fields, target):
    """A 2048-bit RSA key for the service app: the private JWK is sealed; the public one, with the same ``kid``
    (its RFC 7638 thumbprint), is all anyone sees."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    client_id = str(fields.get("client_id") or "").strip()
    if not _CLIENT.fullmatch(client_id):
        raise OnboardingValueError("OKTA_CLIENT_ID_INVALID")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    required = {"e": numbers["e"], "kty": "RSA", "n": numbers["n"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    private = {**json.loads(RSAAlgorithm.to_jwk(key)), "kid": kid, "alg": "RS256"}
    public = {**required, "kid": kid, "alg": "RS256", "use": "sig"}
    made = {"public_jwk": public, "kid": kid, "created_at": _dt.datetime.now(_dt.UTC).isoformat()}
    return {"credential": {"client_id": client_id, "private_key": json.dumps(private)}}, made


def spec(connection, schedule=5, people=False, apps=False):
    """The people collection, or (``apps``) the collection of the organization's app list, whose objects are large
    (settings, credentials blocks) and so come in smaller pages."""
    host = connection["target"]["organization"]
    options = {"mode": "inventory",
               **({"sources": ["apps"], "page_size": 50} if apps else {"keep_profiles": True} if people else {})}
    return {"schema_version": 2, "provider": "okta", "name": f"Okta · {host}" + (" · apps" if apps else ""),
            "origin": f"https://{host}", "edition": "cloud", "tenant": host, "tenant_confirmed": True,
            "scopes": [{"kind": "organization", "id": host}], "capabilities": ["identity_status"],
            "auth_type": "private_key_jwt", "options": options, "schedule_minutes": schedule}


def check(connection, purpose, secrets, context):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer, ReadError
    from cremore_okta_provider.identity import reader

    refs = {"client_id": "vault://onboarding/check", "private_key": "vault://onboarding/check"}
    client = context.http_client()
    items = []
    try:
        # Each permission as its collection asks for it: users with okta.users.read, the app list with okta.apps.read;
        # one row each is enough to answer.
        for permission, source, apps in (("users_read", "users", False), ("apps_read", "apps", True)):
            plan = connection.get("checks", {}).get("requested_plans", {}).get(purpose)
            if apps and plan is not None and not plan.get("apps"):
                continue
            shape = spec(connection, apps=apps)
            shape["options"] = {**shape["options"], "page_size": 1}
            model = MetadataConnectionSpec.model_validate({**shape, "secret_refs": refs})
            read = reader(model, dict(secrets.get("credential") or {}), client, Pacer(model, lambda: None))
            try:
                read.read(model.scopes[0], source, None)
                items.append({"permission": permission, "status": "GRANTED"})
            except ReadError as exc:
                refused = exc.code.endswith(("_ACCESS_DENIED", "_TOKEN_REFUSED", "_CLIENT_ID_INVALID", "_KEY_INVALID"))
                items.append({"permission": permission, "status": "MISSING" if refused else "ERROR", "detail": exc.code})
            finally:
                read.close()
        return items
    finally:
        client.close()


def children(connection, purpose, plan):
    slots = {"client_id": "credential", "private_key": "credential"}
    schedule = plan.get("schedule_minutes", 5)
    out = [{"kind": "metadata", "purpose": purpose, "spec": spec(connection, schedule, bool(plan.get("people_details"))),
            "secret_slots": slots}]
    if plan.get("apps"):
        # Its own collection, at most once a day (or on demand like the people's): an app list it cannot read never
        # makes the people listing partial, which the departed-owner check needs complete.
        daily = max(schedule, 1440) if schedule else 0
        out.append({"kind": "metadata", "purpose": purpose, "spec": spec(connection, daily, apps=True),
                    "secret_slots": slots})
    return out
