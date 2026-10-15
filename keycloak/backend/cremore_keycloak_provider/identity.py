"""Keycloak Admin REST read with a confidential client's service account.

The service account needs the realm-management role ``view-users``, and ``view-events``
only when admin events are read. Users carry no time their ``enabled`` flag changed;
with admin events on (Realm settings → Events → Admin events settings: "Save events", and
"Include representation" to see what an update changed), a disable or delete names its
time. The admin event filters sent (epoch ``dateFrom``, ``direction``) need Keycloak 26.2.
Without them the departed-owner check uses the first collection that saw the change.

The realm's client list (``options.sources == ["apps"]``, its own collection) needs ``view-clients``. Before
Keycloak 26.8.0 that role also returns client secrets in the list (26.8.0 masks them for view-clients only): of each
client only its id, client ID, name and whether it is enabled are read out of the row, and the realm's own clients
are skipped.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlsplit

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.identity.idp import (
    App,
    Event,
    ReadError,
    Source,
    User,
    apps_only,
    status_error,
    utc_text,
)
from cremore.oauth_client import ClientCredentialsGrant

PROVIDER = "keycloak"
API_VERSION = "admin-v2"
CONTRACT_VERSION = "keycloak-users-v1"
USER_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
APP_ID = USER_ID
APP_KEY = "client_id"  # a SAML client's is its entity ID: urn:amazon:webservices
KEY_KINDS = frozenset({"IDP_USER_ID", "LOGIN", "EMAIL"})
_REALM = re.compile(r"[A-Za-z0-9._-]{1,255}")
DEFAULT_LOOKBACK_DAYS = 90
# Clients every realm has (Keycloak's Constants.defaultClients): Keycloak's own, never a service to connect.
REALM_CLIENTS = frozenset({"account", "account-console", "admin-cli", "broker", "realm-management",
                           "security-admin-console", "admin-permissions", "_system"})
SOURCES = (Source("users", "users", completes=True, shifts=True, enabled=lambda spec: not apps_only(spec)),
           Source("admin_events", "events", enabled=lambda spec: not apps_only(spec)),
           Source("clients", "apps", enabled=apps_only))


def validate_spec(spec):
    if spec.edition not in ("self_managed", "cloud") or not urlsplit(spec.origin).hostname:
        raise ValueError("KEYCLOAK_ORIGIN_REQUIRED")
    if len(spec.scopes) != 1 or spec.scopes[0].kind != "realm" or not _REALM.fullmatch(spec.scopes[0].id):
        raise ValueError("KEYCLOAK_ONE_REALM_SCOPE")
    if spec.tenant != spec.scopes[0].id or not spec.tenant_confirmed:
        raise ValueError("KEYCLOAK_TENANT_IS_THE_REALM")
    if spec.auth_type != "oauth_client" or set(spec.secret_refs) != {"client_id", "client_secret"}:
        raise ValueError("KEYCLOAK_SERVICE_ACCOUNT_CLIENT_REQUIRED")
    if (spec.options.mode != "inventory" or spec.options.page_size > 1000 or spec.options.sources not in ([], ["apps"])
            or (apps_only(spec) and (spec.options.keep_profiles or spec.options.include_audit_events))):
        raise ValueError("KEYCLOAK_COLLECTION_OPTION_NOT_SUPPORTED")


def user(spec, source, row):
    if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not isinstance(row.get("enabled"), bool):
        raise TypeError("KEYCLOAK_INVALID_USER")
    username = row.get("username") if isinstance(row.get("username"), str) else ""
    # A client's service account is a user named after the client; it is no person.
    if row.get("serviceAccountClientId") or username.startswith("service-account-"):
        return None
    keys = [("LOGIN", username)] if username else []
    verified = isinstance(row.get("email"), str) and row["email"] and row.get("emailVerified") is True
    if verified:
        keys.append(("EMAIL", row["email"]))
    name = " ".join(part for part in (row.get("firstName"), row.get("lastName")) if isinstance(part, str) and part)
    # Only an email the realm verified is one to write to.
    details = tuple((field, value) for field, value in (("display_name", name), ("email", row["email"] if verified else ""))
                    if value)
    return User(id=row["id"], raw_state="ENABLED" if row["enabled"] else "DISABLED",
                state="ACTIVE" if row["enabled"] else "DISABLED", keys=tuple(keys), profile=details)


def event(spec, source, row):
    """A user's disable, enable or delete from an admin event, or None when it says neither."""
    if not isinstance(row, dict) or row.get("resourceType") != "USER":
        return None
    path = row.get("resourcePath") if isinstance(row.get("resourcePath"), str) else ""
    match = re.fullmatch(r"users/([0-9a-f-]{36})", path)
    at = utc_text(row.get("time"))
    if not match or at is None:
        return None
    operation = row.get("operationType")
    if operation == "DELETE":
        change = "DELETED"
    elif operation == "UPDATE" and isinstance(row.get("representation"), str):
        try:
            enabled = json.loads(row["representation"]).get("enabled")
        except (ValueError, AttributeError):
            return None
        if not isinstance(enabled, bool):
            return None
        change = "ENABLED" if enabled else "DISABLED"
    else:
        return None
    ident = row.get("id")
    if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", ident):
        # Older servers return no event id; time, operation and user name the event.
        ident = hashlib.sha256(f"{row.get('time')}|{operation}|{path}".encode()).hexdigest()[:40]
    return Event(id=ident, user_id=match.group(1), change=change, at=at)


def app(spec, source, row):
    """A client as its name (or client ID), client ID -- a SAML client's is its entity ID -- and whether it is
    enabled. Nothing else in the row is read: before 26.8.0 it can hold the client's secret."""
    if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not isinstance(row.get("clientId"), str) \
            or not isinstance(row.get("enabled"), bool):
        raise TypeError("KEYCLOAK_INVALID_CLIENT")
    client_id = row["clientId"]
    # The master realm also holds a "<realm>-realm" client for every other realm it administers.
    if client_id in REALM_CLIENTS or (spec.scopes[0].id == "master" and client_id.endswith("-realm")):
        return None
    name = row.get("name") if isinstance(row.get("name"), str) and not row["name"].startswith("${") else ""
    return App(id=row["id"], raw_state="ENABLED" if row["enabled"] else "DISABLED",
               state="ACTIVE" if row["enabled"] else "DISABLED", name=name or client_id, key=client_id)


class Reader:
    def __init__(self, spec, secrets, client, pacer):
        self.spec, self.client, self.pacer, self.secrets = spec, client, pacer, secrets
        self.base = spec.origin + spec.options.api_path
        self.realm = quote(spec.scopes[0].id, safe="")
        self.token, self.expires = None, 0.0
        self.since = int((datetime.now(UTC) - timedelta(
            days=spec.options.audit_lookback_days or DEFAULT_LOOKBACK_DAYS)).timestamp() * 1000)

    def close(self):
        self.token = self.secrets = None

    def _authenticate(self):
        try:
            grant = ClientCredentialsGrant(
                token_url=self.base + "/realms/" + self.realm + "/protocol/openid-connect/token",
                client_id=self.secrets.get("client_id", ""), client_secret=self.secrets.get("client_secret", ""),
                auth_method="client_secret_basic")
        except ValueError:
            raise ReadError("KEYCLOAK_CLIENT_INVALID") from None
        self.pacer.before()
        try:
            self.token, lifetime = grant.fetch(self.client)
        except ValueError:
            raise ReadError("KEYCLOAK_TOKEN_REFUSED") from None
        # Keycloak's default access token lives five minutes; renew a little early.
        self.expires = time.monotonic() + max(30, lifetime - 30)

    def _json(self, path, params):
        for attempt in range(2):
            if self.token is None or time.monotonic() >= self.expires:
                self._authenticate()
            self.pacer.before()
            try:
                response = bounded_request(
                    self.client, "GET", self.base + "/admin/realms/" + self.realm + path, params=params,
                    headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                             "User-Agent": "CreMore-Identity/1.0"},
                    timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                    max_response_bytes=self.spec.options.max_response_bytes)
            except HTTPResponseTooLarge:
                raise ReadError("KEYCLOAK_RESPONSE_LIMIT") from None
            except Exception:  # noqa: BLE001 -- transport errors can carry the bearer
                raise ReadError("KEYCLOAK_UNAVAILABLE", retryable=True) from None
            if response.status_code == 401 and attempt == 0:
                self.token = None  # revoked or expired early: one fresh token, then give up
                continue
            break
        if response.status_code != 200:
            raise status_error("KEYCLOAK", response)
        try:
            return response.json()
        except (ValueError, RecursionError):
            raise ReadError("KEYCLOAK_INVALID_RESPONSE") from None

    def _get(self, path, params):
        rows = self._json(path, params)
        if not isinstance(rows, list) or len(rows) > self.spec.options.page_size:
            raise ReadError("KEYCLOAK_INVALID_RESPONSE")
        return rows

    def _count(self):
        # Without criteria both this count and the users list leave service accounts out (Keycloak UsersResource).
        total = self._json("/users/count", {})
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ReadError("KEYCLOAK_INVALID_RESPONSE")
        return total

    def finds_client(self, client_ids) -> bool:
        """Whether a lookup by client ID finds any of these clients, which only ``view-clients`` sees (``query-clients``
        sees none): the permission check, without listing a client a secret could come with."""
        return any(self._get("/clients", {"clientId": client_id}) for client_id in client_ids)

    def lists_users(self):
        """The permission check: one user row, without the counts a whole listing takes."""
        self._get("/users", {"first": 0, "max": 1, "briefRepresentation": "true"})

    def read(self, scope, source, cursor):
        if (scope not in self.spec.scopes or source not in ("users", "admin_events", "clients")
                or (source == "clients") != apps_only(self.spec)):
            raise ValueError("KEYCLOAK_OPERATION_OUT_OF_SCOPE")
        size = self.spec.options.page_size
        if source == "users":
            return self._users(cursor, size)
        if cursor and not cursor.isdecimal():
            raise ReadError("KEYCLOAK_INVALID_CURSOR")
        first = int(cursor) if cursor else 0
        if source == "clients":
            rows = self._get("/clients", {"first": first, "max": size})
        else:
            rows = self._get("/admin-events", {"resourceTypes": "USER", "operationTypes": ["UPDATE", "DELETE"],
                                               "dateFrom": str(self.since), "direction": "asc",
                                               "first": first, "max": size})
        # Offset pages: a short page is the last one.
        return rows, str(first + len(rows)) if len(rows) == size else ""

    def _users(self, cursor, size):
        """Users by offset, ordered by username. The server drops rows from a page after paging it (a user a federated
        LDAP no longer holds, one the caller may not view), so the next page starts a full page on and a short page
        proves nothing; a user deleted, added or renamed while the run pages shifts the rest. The listing ends on an
        empty page and names everyone only when it read as many rows as the realm counted before and after it, and no
        user twice (a rename moves a user past the offset and another one before it: the collector's ``shifts``).
        Otherwise it ends PARTIAL, which reads nobody's absence as departure."""
        if not cursor:
            first, read, total = 0, 0, self._count()
        elif match := re.fullmatch(r"(\d{1,9})\.(\d{1,9})\.(\d{1,9})", cursor):
            first, read, total = (int(value) for value in match.groups())
        else:
            raise ReadError("KEYCLOAK_INVALID_CURSOR")
        rows = self._get("/users", {"first": first, "max": size, "briefRepresentation": "true"})
        if rows:
            return rows, f"{first + size}.{read + len(rows)}.{total}"
        if read != total or self._count() != total:
            raise ReadError("KEYCLOAK_USER_COUNT_MISMATCH")
        return rows, ""


def reader(spec, secrets, client, pacer):
    return Reader(spec, secrets, client, pacer)
