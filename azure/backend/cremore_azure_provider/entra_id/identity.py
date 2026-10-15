"""Microsoft Graph user listings with User.Read.All and conditional Organization.Read.All.

``accountEnabled`` says whether a user can sign in; Graph keeps no time for when it
changed, so the departed-owner check dates a disable by the first collection that saw
it. A deleted user stays in deleted items for 30 days with ``deletedDateTime``; its
userPrincipalName there begins with the object id (no dashes), which is removed
before digesting. The object id is what Azure DevOps names as a user's originId.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, urlsplit

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.identity.idp import ReadError, Source, User, status_error, utc_text

from ..entra.normalization import guid
from ..entra.transport import CLOUDS, GUID, token_for_spec

PROVIDER = "entra_id"
API_VERSION = "v1.0"
CONTRACT_VERSION = "entra-id-users-v1"
USER_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
KEY_KINDS = frozenset({"IDP_USER_ID", "LOGIN", "EMAIL"})
PATHS = {"users": "/v1.0/users", "deleted_users": "/v1.0/directory/deletedItems/microsoft.graph.user"}
SELECT = {"users": "id,accountEnabled,userPrincipalName,mail,displayName,department,jobTitle",
          "deleted_users": "id,deletedDateTime,userPrincipalName,mail,displayName,department,jobTitle"}
SOURCES = (Source("users", "users", completes=True), Source("deleted_users", "users"))


def validate_spec(spec):
    if spec.edition != "cloud" or spec.origin not in CLOUDS:
        raise ValueError("ENTRA_ID_GRAPH_ORIGIN_REQUIRED")
    if (not spec.tenant_confirmed or not re.fullmatch(GUID, spec.tenant) or spec.tenant != spec.tenant.lower()
            or len(spec.scopes) != 1 or spec.scopes[0].kind != "organization" or spec.scopes[0].id != spec.tenant):
        raise ValueError("ENTRA_ID_CONFIRMED_TENANT_REQUIRED")
    from cremore_azure_provider import app_certificate as certificate

    if not certificate.allowed(spec, public_cloud=spec.origin == certificate.GRAPH):
        raise ValueError("ENTRA_ID_WORKLOAD_IDENTITY_REQUIRED")
    if spec.options.mode != "inventory" or spec.options.page_size > 999 or spec.options.include_audit_events:
        raise ValueError("ENTRA_ID_COLLECTION_OPTION_NOT_SUPPORTED")


def user(spec, source, row):
    if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not USER_ID.fullmatch(row["id"].lower()):
        raise ValueError("ENTRA_ID_INVALID_USER")
    object_id = row["id"].lower()
    login = row.get("userPrincipalName") if isinstance(row.get("userPrincipalName"), str) else ""
    if source == "deleted_users":
        login = login.removeprefix(object_id.replace("-", ""))
        state, raw, changed = "DELETED", "DELETED", utc_text(row.get("deletedDateTime"))
    else:
        if not isinstance(row.get("accountEnabled"), bool):
            raise ValueError("ENTRA_ID_INVALID_USER")
        state = "ACTIVE" if row["accountEnabled"] else "DISABLED"
        raw, changed = ("ENABLED" if row["accountEnabled"] else "DISABLED"), None
    keys = tuple((kind, value) for kind, value in (("LOGIN", login), ("EMAIL", row.get("mail")))
                 if isinstance(value, str) and value)
    details = tuple((field, row.get(name)) for field, name in (("display_name", "displayName"), ("email", "mail"),
                                                               ("department", "department"), ("title", "jobTitle"))
                    if isinstance(row.get(name), str) and row.get(name))
    return User(id=object_id, raw_state=raw, state=state, changed_at=changed, keys=keys, profile=details)


def event(spec, source, row):
    return None


def next_cursor(link, origin, path):
    if link in (None, ""):
        return ""
    target, base = urlsplit(link if isinstance(link, str) else ""), urlsplit(origin)
    tokens = parse_qs(target.query).get("$skiptoken", [])
    if (target.scheme != "https" or target.hostname != base.hostname or target.port not in (None, 443)
            or target.path != path or target.username or target.password or target.fragment or len(tokens) != 1):
        raise ReadError("ENTRA_ID_INVALID_CURSOR")
    return tokens[0]


def token_tenant(bearer):
    """The tenant (``tid``) a JWT access token names; None when it is not a readable JWT."""
    try:
        part = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (AttributeError, IndexError, ValueError, TypeError, RecursionError):
        return None
    tenant = claims.get("tid") if isinstance(claims, dict) else None
    return tenant.lower() if isinstance(tenant, str) else None


class Reader:
    def __init__(self, spec, secrets, client, pacer):
        self.spec, self.client, self.pacer = spec, client, pacer
        self.token = None
        from cremore_azure_provider import app_certificate as certificate

        if certificate.signs_in(spec):
            self.token = certificate.TokenSource(secrets, certificate.SCOPES["graph"], client=client)

    def close(self):
        self.token = None

    def read(self, scope, source, cursor):
        if scope not in self.spec.scopes or source not in PATHS:
            raise ValueError("ENTRA_ID_OPERATION_OUT_OF_SCOPE")
        if self.token is None:
            try:
                self.token = token_for_spec(self.spec)
            except ValueError:
                raise ReadError("ENTRA_ID_AZURE_EXTRA_REQUIRED") from None
        params = {"$select": SELECT[source], "$top": self.spec.options.page_size}
        if cursor:
            params["$skiptoken"] = cursor
        try:
            bearer = self.token()
        except Exception as exc:  # noqa: BLE001 -- credential errors can carry configuration values
            from cremore_azure_provider.app_certificate import CertificateError

            if isinstance(exc, CertificateError):
                raise ReadError(exc.code, retryable=exc.retryable) from None
            raise ReadError("ENTRA_ID_TOKEN_UNAVAILABLE", retryable=True) from None
        # Managed identities ignore the requested tenant; opaque tokens need Graph's organization confirmation.
        tenant = token_tenant(bearer)
        if tenant is None:
            self._confirm_tenant(bearer)
        elif tenant != self.spec.tenant.lower():
            raise ReadError("ENTRA_ID_TENANT_MISMATCH")
        self.pacer.before()
        try:
            response = bounded_request(self.client, "GET", self.spec.origin + PATHS[source], params=params,
                                       headers={"Authorization": "Bearer " + bearer, "Accept": "application/json",
                                                "User-Agent": "CreMore-Identity/1.0"},
                                       timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                                       max_response_bytes=self.spec.options.max_response_bytes)
        except HTTPResponseTooLarge:
            raise ReadError("ENTRA_ID_RESPONSE_LIMIT") from None
        except Exception:  # noqa: BLE001 -- transport errors can carry the bearer
            raise ReadError("ENTRA_ID_UNAVAILABLE", retryable=True) from None
        if response.status_code != 200:
            raise status_error("ENTRA_ID", response)
        try:
            payload = response.json()
        except (ValueError, RecursionError):
            raise ReadError("ENTRA_ID_INVALID_RESPONSE") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("value"), list) \
                or len(payload["value"]) > self.spec.options.page_size:
            raise ReadError("ENTRA_ID_INVALID_RESPONSE")
        return payload["value"], next_cursor(payload.get("@odata.nextLink"), self.spec.origin, PATHS[source])

    def _confirm_tenant(self, bearer):
        self.pacer.before()
        try:
            response = bounded_request(
                self.client, "GET", self.spec.origin + "/v1.0/organization", params={"$select": "id"},
                headers={"Authorization": "Bearer " + bearer, "Accept": "application/json"},
                timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                max_response_bytes=self.spec.options.max_response_bytes)
            if response.status_code != 200:
                raise ReadError("ENTRA_ID_TENANT_UNVERIFIED")
            payload = response.json()
        except Exception:  # noqa: BLE001 -- confirmation failures must not expose the bearer or list users
            raise ReadError("ENTRA_ID_TENANT_UNVERIFIED") from None
        organizations = payload.get("value") if isinstance(payload, dict) else None
        if (not isinstance(organizations, list) or len(organizations) != 1
                or not isinstance(organizations[0], dict)
                or guid(organizations[0].get("id")) != self.spec.tenant
                or payload.get("@odata.nextLink")):
            raise ReadError("ENTRA_ID_TENANT_MISMATCH")


def reader(spec, secrets, client, pacer):
    return Reader(spec, secrets, client, pacer)
