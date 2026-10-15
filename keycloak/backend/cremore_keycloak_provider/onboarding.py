"""Keycloak in the connection wizard (cremore.onboarding): the departed-owner check's people.

A confidential client with a service account holds realm-management ``view-users``
(and ``view-events`` when admin events are read). The check signs in with client
credentials and reads one page of each, with the collection's own reader.

The app list option adds ``view-clients`` and a collection of the realm's clients of its own. It is off unless
chosen: before Keycloak 26.8.0 that role also reads client secrets. The check looks up the realm's public account
console and admin CLI clients by client ID, which carry no secret, instead of listing clients.
"""

from __future__ import annotations

import re

_CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,255}")
_SECRET = re.compile(r"[\x21-\x7e]{8,512}")
_REALM = re.compile(r"[A-Za-z0-9._-]{1,255}")

_PEOPLE = {"name": "people_details", "kind": "bool", "default": True,
           "label": "Keep people's names, emails and departments (owners and contacts)",
           "label_ko": "사람 이름·이메일·부서 보관(담당자·연락 대상 표시)"}
# The admin event filters CreMore sends (epoch dateFrom, direction) need Keycloak 26.2; the realm must save them.
_ADMIN_EVENTS = (("Read admin events (Keycloak 26.2+; Realm settings → Events → Admin events settings: Save events, "
                  "Include representation)"),
                 ("관리 이벤트 읽기(Keycloak 26.2 이상, Realm settings → Events → Admin events settings의 Save events·"
                  "Include representation 켜기)"))
_APPS = {"name": "apps", "kind": "bool", "default": False,
         "label": "Read the realm's client list to suggest the services to connect",
         "label_ko": "렐름의 클라이언트 목록을 읽어 연동할 서비스 제안"}

DESCRIPTORS = [{
    "provider": "keycloak",
    "label": "Keycloak", "label_ko": "Keycloak",
    "category": "identity",
    "editions": [{"id": "self_managed", "label": "Keycloak", "label_ko": "Keycloak"},
                 {"id": "cloud", "label": "Keycloak (hosted)", "label_ko": "Keycloak(호스팅)"}],
    "target": [
        {"name": "address", "label": "Keycloak address", "label_ko": "Keycloak 주소", "kind": "url", "required": True,
         "hint": "https://sso.example.com"},
        {"name": "realm", "label": "Realm", "label_ko": "렐름", "kind": "text", "required": True},
        {"name": "api_path", "label": "Path prefix (older versions: /auth)", "label_ko": "경로 접두어(예전 버전: /auth)",
         "kind": "text"},
        {"name": "admin_events", "label": _ADMIN_EVENTS[0], "label_ko": _ADMIN_EVENTS[1], "kind": "bool",
         "default": False},
    ],
    "purposes": {"identity": {"permissions": [
        {"id": "view_users", "label": "realm-management view-users", "label_ko": "realm-management view-users"},
        {"id": "view_events", "label": "realm-management view-events (admin events)",
         "label_ko": "realm-management view-events(관리 이벤트)", "option": "admin_events"},
        {"id": "view_clients", "label": "realm-management view-clients (client list option; before Keycloak 26.8.0 "
                                        "this role also returns client secrets)",
         "label_ko": "realm-management view-clients(클라이언트 목록 옵션, Keycloak 26.8.0 전에는 클라이언트 시크릿도 보임)",
         "option": "apps"}],
        "plan": [{"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes)",
                  "label_ko": "수집 주기(분)", "default": 60, "min": 0, "max": 10080}, _PEOPLE, _APPS,
                 {"name": "admin_events", "kind": "bool", "default": False, "target_default": "admin_events",
                  "label": _ADMIN_EVENTS[0], "label_ko": _ADMIN_EVENTS[1]}]}},
    "auth_methods": [{"id": "oauth_client", "reference_keys": ["client_id", "client_secret"],
                      "auth_first": {"context": ["address", "realm", "api_path"]},
                      "label": "Service account client", "label_ko": "서비스 계정 클라이언트",
                      "renewal": "AUTOMATIC", "purposes": ["identity"],
                      "fields": [{"name": "client_id", "label": "Client ID", "label_ko": "클라이언트 ID", "kind": "text"},
                                 {"name": "client_secret", "label": "Client secret", "label_ko": "클라이언트 시크릿",
                                  "kind": "secret", "secret": True}]}],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _origin(value):
    """The server's address as the collection keeps it: the host in lower case, no default port, no path."""
    from cremore.coverage.metadata_models import canonical_origin

    try:
        return canonical_origin(str(value or "").rstrip("/"))
    except ValueError:
        raise OnboardingValueError("KEYCLOAK_ADDRESS_INVALID") from None


def target(provider, edition, values):
    realm, path = values.get("realm", "").strip(), (values.get("api_path") or "").strip().rstrip("/")
    if not _REALM.fullmatch(realm):
        raise OnboardingValueError("KEYCLOAK_REALM_INVALID")
    if path and not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", path):
        raise OnboardingValueError("KEYCLOAK_PATH_INVALID")
    return {"address": _origin(values["address"]), "realm": realm, "api_path": path,
            "admin_events": bool(values.get("admin_events"))}


auth_context = target


def authenticate(connection, secrets, context):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer
    from cremore_keycloak_provider.identity import reader

    model = MetadataConnectionSpec.model_validate({**spec(connection), "secret_refs": {
        "client_id": "vault://onboarding/check", "client_secret": "vault://onboarding/check"}})
    client = context.http_client()
    read = reader(model, dict(secrets.get("credential") or {}), client, Pacer(model, lambda: None))
    try:
        read._authenticate()
        return {"status": "GRANTED", "subject": connection["target"]["realm"]}
    finally:
        read.close()
        client.close()


def discover(connection, secrets, context):
    # A realm service account does not need cross-realm administration.
    selected = {k: v for k, v in connection["target"].items() if k in {"address", "realm", "api_path", "admin_events"}}
    return [{"target": selected, "label": selected["realm"]}], "COMPLETE"


def sign_in_target(provider, issuer):
    """The realm people sign in with, when the console's sign-in issuer is a Keycloak realm's
    (``https://sso.example.com[/auth]/realms/<realm>``), as ``target`` keeps it (cremore.onboarding.sign_in). A path
    that names another product's realms (``/am/oauth2/realms/root/realms/alpha``) is not Keycloak's."""
    from urllib.parse import urlsplit

    parts = urlsplit(issuer)
    match = re.fullmatch(r"(?P<prefix>(?:/[A-Za-z0-9_-]+)*)/realms/(?P<realm>[A-Za-z0-9._-]{1,255})", parts.path.rstrip("/"))
    if (parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment or parts.username or not match
            or {"realms", "oauth2"} & set(match["prefix"].split("/"))):
        return None
    try:
        address = _origin(f"{parts.scheme}://{parts.netloc}")
    except OnboardingValueError:
        return None
    return {"address": address, "realm": match["realm"], "api_path": match["prefix"]}


def credential(provider, method, fields):
    client_id, secret = fields.get("client_id", "").strip(), fields.get("client_secret", "").strip()
    if not _CLIENT.fullmatch(client_id) or not _SECRET.fullmatch(secret):
        raise OnboardingValueError("KEYCLOAK_CLIENT_INVALID")
    return {"credential": {"client_id": client_id, "client_secret": secret}}


def spec(connection, schedule=60, people=False, apps=False):
    """The people collection, or (``apps``) the collection of the realm's client list."""
    target_ = connection["target"]
    events = bool(target_.get("admin_events")) and not apps
    # A client's full representation is large (certificates, mappers): the app list reads smaller pages.
    options = {"mode": "inventory", **({"api_path": target_["api_path"]} if target_.get("api_path") else {}),
               **({"include_audit_events": True} if events else {}),
               **({"sources": ["apps"], "page_size": 50} if apps else {"keep_profiles": True} if people else {})}
    return {"schema_version": 2, "provider": "keycloak",
            "name": f"Keycloak · {target_['realm']}" + (" · apps" if apps else ""),
            "origin": target_["address"], "edition": connection["edition"], "tenant": target_["realm"],
            "tenant_confirmed": True, "scopes": [{"kind": "realm", "id": target_["realm"]}],
            "capabilities": ["identity_status"] + (["audit"] if events else []),
            "auth_type": "oauth_client", "options": options, "schedule_minutes": schedule}


def check(connection, purpose, secrets, context):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer, ReadError
    from cremore_keycloak_provider.identity import reader

    plan = (connection.get("checks") or {}).get("requested_plans", {}).get(purpose)
    if plan is not None:
        connection = {**connection, "target": {**connection["target"], "admin_events": plan.get("admin_events", False)}}
    model = MetadataConnectionSpec.model_validate({**spec(connection), "secret_refs": {
        "client_id": "vault://onboarding/check", "client_secret": "vault://onboarding/check"}})
    client = context.http_client()
    items = []
    try:
        read = reader(model, dict(secrets.get("credential") or {}), client, Pacer(model, lambda: None))
        try:
            for permission, source in (("view_users", "users"), ("view_events", "admin_events")):
                if source == "admin_events" and not connection["target"].get("admin_events"):
                    items.append({"permission": permission, "status": "NOT_REPORTED", "detail": "ADMIN_EVENTS_OFF"})
                    continue
                try:
                    if source == "users":
                        read.lists_users()
                    else:
                        read.read(model.scopes[0], source, None)
                    items.append({"permission": permission, "status": "GRANTED"})
                except ReadError as exc:
                    refused = exc.code.endswith(("_ACCESS_DENIED", "_TOKEN_REFUSED", "_CLIENT_INVALID"))
                    items.append({"permission": permission, "status": "MISSING" if refused else "ERROR",
                                  "detail": exc.code})
            # view-clients without listing a client a secret could come with: the realm's public clients are seen by
            # that role alone (query-clients sees an empty list).
            if plan is not None and not plan.get("apps"):
                return items
            try:
                seen = read.finds_client(("account-console", "admin-cli"))
                items.append({"permission": "view_clients", "status": "GRANTED"} if seen else
                             {"permission": "view_clients", "status": "MISSING", "detail": "KEYCLOAK_VIEW_CLIENTS_REQUIRED"})
            except ReadError as exc:
                refused = exc.code.endswith(("_ACCESS_DENIED", "_TOKEN_REFUSED", "_CLIENT_INVALID"))
                items.append({"permission": "view_clients", "status": "MISSING" if refused else "ERROR",
                              "detail": exc.code})
        finally:
            read.close()
        return items
    finally:
        client.close()


def children(connection, purpose, plan):
    connection = {**connection, "target": {**connection["target"],
        "admin_events": plan.get("admin_events", connection["target"].get("admin_events", False))}}
    slots = {"client_id": "credential", "client_secret": "credential"}
    schedule = plan.get("schedule_minutes", 60)
    out = [{"kind": "metadata", "purpose": purpose, "spec": spec(connection, schedule, bool(plan.get("people_details"))),
            "secret_slots": slots}]
    if plan.get("apps"):
        # Its own collection, at most once a day (or on demand like the people's), so a list it cannot read never
        # makes the people listing partial.
        daily = max(schedule, 1440) if schedule else 0
        out.append({"kind": "metadata", "purpose": purpose, "spec": spec(connection, daily, apps=True),
                    "secret_slots": slots})
    return out
