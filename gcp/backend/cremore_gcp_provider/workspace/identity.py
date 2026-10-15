"""Google Workspace users through the Admin SDK Directory API, read by a service account with domain-wide delegation
(admin.directory.user.readonly; the members of the console's role groups, for Google sign-in, with a token of its own
holding admin.directory.group.member.readonly).

The service account's key signs a JWT asking Google for a token that acts as a Workspace administrator (``sub``);
the Workspace admin console must allow the service account's client ID that one scope. Every listing shows what
that administrator can see, so it must be a super administrator (``isAdmin``): one limited to some organizational
units would make everyone else look gone. Users deleted in the last 20 days come first, from a listing that names
when (it is small, so a record budget met inside the full listing still leaves them read); then one listing of the
customer's users covers every domain it holds. A suspended or archived user counts as departed. The directory
keeps no time a user was suspended, so a suspension is dated by the first collection that saw it.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import quote

import jwt

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.identity.idp import ReadError, Source, User, cursor_text, status_error, utc_text

PROVIDER = "google_workspace"
API_VERSION = "directory_v1"
CONTRACT_VERSION = "google-workspace-users-v1"
SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
# Reading the members of the groups that give console roles to people who sign in with Google
# (cremore.identity.sign_in_groups), with a token of its own.
GROUP_SCOPE = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
ORIGIN = "https://admin.googleapis.com"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # never the key file's own token_uri
USERS_URL = ORIGIN + "/admin/directory/v1/users"
GROUPS_URL = ORIGIN + "/admin/directory/v1/groups"
MEMBERS_PAGE = 200  # the Members API's own limit
MEMBERS_PAGES = 100  # a role group of more than 20,000 people is read as unreadable
USER_ID = re.compile(r"[0-9]{6,32}")
KEY_KINDS = frozenset({"IDP_USER_ID", "EMAIL"})
SOURCES = (Source("deleted_users", "users"), Source("users", "users", completes=True))
PAGE_MAX = 500  # the Directory API's own limit
MAX_RECORDS = 250000  # the collection maximum; a larger directory ends PARTIAL, and absence then proves nothing
FIELDS = ("nextPageToken,users(id,primaryEmail,aliases,name/fullName,suspended,archived,deletionTime,"
          "organizations(primary,department,title))")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})+")
ADMIN = re.compile(rf"[A-Za-z0-9._%+'-]{{1,64}}@{DOMAIN.pattern}")
_SERVICE_ACCOUNT = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9][a-z0-9.-]{0,99}\.gserviceaccount\.com")
_RATE_LIMITS = frozenset({"userRateLimitExceeded", "rateLimitExceeded", "quotaExceeded"})
_API_OFF = frozenset({"accessNotConfigured", "SERVICE_DISABLED"})


def _refusal(response):
    """The ReadError for a non-200 Directory answer. Google also sends rate limits as 403 (userRateLimitExceeded,
    quotaExceeded), and a 403 when the service account's Cloud project has not turned on the Admin SDK API."""
    if response.status_code == 403:
        try:
            error = response.json()["error"]
            reasons = {item["reason"] for item in [*error.get("errors", []), *error.get("details", [])]
                       if isinstance(item, dict) and isinstance(item.get("reason"), str)}
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            reasons = set()
        if reasons & _RATE_LIMITS:
            return ReadError("GOOGLE_WORKSPACE_RATE_LIMITED", retryable=True)
        if reasons & _API_OFF:
            return ReadError("GOOGLE_WORKSPACE_API_NOT_ENABLED")
    return status_error("GOOGLE_WORKSPACE", response)


def validate_spec(spec):
    domain = spec.scopes[0].id if len(spec.scopes) == 1 else ""
    if spec.edition != "cloud" or spec.origin != ORIGIN:
        raise ValueError("GOOGLE_WORKSPACE_ORIGIN_IS_THE_ADMIN_API")
    if len(spec.scopes) != 1 or spec.scopes[0].kind != "organization" or not DOMAIN.fullmatch(domain):
        raise ValueError("GOOGLE_WORKSPACE_ONE_DOMAIN_SCOPE")
    if spec.tenant != domain or not spec.tenant_confirmed:
        raise ValueError("GOOGLE_WORKSPACE_TENANT_IS_THE_DOMAIN")
    if spec.auth_type != "private_key_jwt" or set(spec.secret_refs) != {"private_key", "username"}:
        raise ValueError("GOOGLE_WORKSPACE_DELEGATED_SERVICE_ACCOUNT_REQUIRED")
    if spec.options.include_audit_events or spec.options.mode != "inventory" or spec.options.page_size > PAGE_MAX:
        raise ValueError("GOOGLE_WORKSPACE_COLLECTION_OPTION_NOT_SUPPORTED")


def service_account(value):
    """(client email, signing key, key id) from a service account's JSON key; nothing else in it is used."""
    try:
        data = json.loads(value) if isinstance(value, str) and 0 < len(value) <= 16384 else None
    except (ValueError, RecursionError):  # 16 KiB of '[' nests past the recursion limit
        data = None
    if not isinstance(data, dict) or data.get("type") != "service_account":
        raise ValueError("GOOGLE_WORKSPACE_KEY_INVALID")
    email, pem, key_id = data.get("client_email"), data.get("private_key"), data.get("private_key_id")
    if (not isinstance(email, str) or not _SERVICE_ACCOUNT.fullmatch(email) or not isinstance(pem, str)
            or not isinstance(key_id, str) or not re.fullmatch(r"[0-9a-f]{40}", key_id)):
        raise ValueError("GOOGLE_WORKSPACE_KEY_INVALID")
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError  # Google signs service account JWTs with RS256 only
    except Exception:  # noqa: BLE001 -- key parsing errors can quote the key
        raise ValueError("GOOGLE_WORKSPACE_KEY_INVALID") from None
    return email, key, key_id


def client_id(value) -> str:
    """The service account's numeric client ID, which the admin console's domain-wide delegation names."""
    service_account(value)
    found = json.loads(value).get("client_id")
    return found if isinstance(found, str) and re.fullmatch(r"[0-9]{10,32}", found) else ""


def user(spec, source, row):
    if (not isinstance(row, dict) or not isinstance(row.get("id"), str) or not USER_ID.fullmatch(row["id"])
            or not isinstance(row.get("primaryEmail"), str) or not row["primaryEmail"]):
        raise ValueError("GOOGLE_WORKSPACE_INVALID_USER")
    if source == "deleted_users":
        raw, state, changed = "DELETED", "DELETED", utc_text(row.get("deletionTime"))
    elif row.get("suspended") is True:
        raw, state, changed = "SUSPENDED", "DISABLED", None
    elif row.get("archived") is True:
        raw, state, changed = "ARCHIVED", "DISABLED", None
    else:
        raw, state, changed = "ACTIVE", "ACTIVE", None
    aliases = [alias for alias in row.get("aliases") or [] if isinstance(alias, str) and alias] \
        if isinstance(row.get("aliases"), list) else []
    # ponytail: the collector keeps at most 16 keys (IDP_USER_ID + 15), so aliases past the 14th do not link
    keys = tuple(("EMAIL", address) for address in list(dict.fromkeys([row["primaryEmail"], *aliases]))[:15])
    name = row["name"].get("fullName") if isinstance(row.get("name"), dict) else None
    organizations = [item for item in row.get("organizations") or [] if isinstance(item, dict)] \
        if isinstance(row.get("organizations"), list) else []
    organization = next((item for item in organizations if item.get("primary") is True),
                        organizations[0] if organizations else {})
    details = tuple((field, value) for field, value in (
        ("display_name", name), ("email", row["primaryEmail"]), ("department", organization.get("department")),
        ("title", organization.get("title"))) if isinstance(value, str) and value)
    return User(id=row["id"], raw_state=raw, state=state, changed_at=changed, keys=keys, profile=details)


def event(spec, source, row):  # the directory keeps no status history of its own
    return None


class Reader:
    def __init__(self, spec, secrets, client, pacer, scope=SCOPE):
        self.spec, self.client, self.pacer, self.scope = spec, client, pacer, scope
        self.key, self.subject = secrets.get("private_key", ""), secrets.get("username", "")
        self.token, self.expires, self.super_admin = None, 0.0, None

    @property
    def requests(self):
        return self.pacer.requests

    def close(self):
        self.token = self.key = None

    def _admin(self):
        if not isinstance(self.subject, str) or not ADMIN.fullmatch(self.subject):
            raise ReadError("GOOGLE_WORKSPACE_ADMIN_INVALID")
        if self.subject.rpartition("@")[2].lower() != self.spec.tenant:
            # my_customer is the administrator's customer: an administrator of the labelled domain pins it.
            raise ReadError("GOOGLE_WORKSPACE_ADMIN_OUTSIDE_DOMAIN")
        return self.subject

    def _authenticate(self):
        subject = self._admin()
        try:
            email, key, key_id = service_account(self.key)
        except ValueError:
            raise ReadError("GOOGLE_WORKSPACE_KEY_INVALID") from None
        now = int(time.time())
        assertion = jwt.encode({"iss": email, "sub": subject, "scope": self.scope, "aud": TOKEN_URL, "iat": now,
                                "exp": now + 300}, key, algorithm="RS256", headers={"kid": key_id})
        self.pacer.before()
        try:
            response = bounded_request(self.client, "POST", TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
                headers={"Accept": "application/json"}, timeout=self.spec.options.timeout_seconds,
                follow_redirects=False, max_response_bytes=64 << 10)
        except Exception:  # noqa: BLE001 -- transport errors can carry the assertion
            raise ReadError("GOOGLE_WORKSPACE_TOKEN_UNAVAILABLE", retryable=True) from None
        if response.status_code != 200:
            if response.status_code in (429, 408) or response.status_code >= 500:
                raise status_error("GOOGLE_WORKSPACE_TOKEN", response)
            try:
                error = response.json().get("error", "")
            except (ValueError, AttributeError):
                error = ""
            # unauthorized_client / access_denied: the admin console does not allow this client the scope
            # (domain-wide delegation; Google's service-account OAuth error table names both).
            raise ReadError("GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED" if error in ("unauthorized_client", "access_denied")
                            else "GOOGLE_WORKSPACE_TOKEN_REFUSED")
        try:
            payload = response.json()
            token, lifetime = payload["access_token"], int(payload.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):  # expires_in 1e999 → inf
            raise ReadError("GOOGLE_WORKSPACE_TOKEN_REFUSED") from None
        if not isinstance(token, str) or not token or any(not 33 <= ord(c) <= 126 for c in token):
            raise ReadError("GOOGLE_WORKSPACE_TOKEN_REFUSED")
        self.token, self.expires = token, time.monotonic() + max(60, lifetime) - 60

    def _get(self, url, params):
        """One Directory API answer as JSON; a 401 gets one fresh token."""
        for attempt in range(2):
            if self.token is None or time.monotonic() >= self.expires:
                self._authenticate()
            self.pacer.before()
            try:
                response = bounded_request(self.client, "GET", url, params=params, headers={
                    "Authorization": "Bearer " + self.token, "Accept": "application/json",
                    "User-Agent": "CreMore-Identity/1.0"}, timeout=self.spec.options.timeout_seconds,
                    follow_redirects=False, max_response_bytes=self.spec.options.max_response_bytes)
            except HTTPResponseTooLarge:
                raise ReadError("GOOGLE_WORKSPACE_RESPONSE_LIMIT") from None
            except Exception:  # noqa: BLE001 -- transport errors can carry the bearer
                raise ReadError("GOOGLE_WORKSPACE_UNAVAILABLE", retryable=True) from None
            if response.status_code == 401 and attempt == 0:
                self.token = None  # revoked or expired early: one fresh token, then give up
                continue
            break
        if response.status_code != 200:
            raise _refusal(response)
        try:
            return response.json()
        except (ValueError, RecursionError):
            raise ReadError("GOOGLE_WORKSPACE_INVALID_RESPONSE") from None

    def _require_super_admin(self):
        """Once per reader: a listing proves who is gone only when it is the whole directory."""
        if self.super_admin is None:
            body = self._get(USERS_URL + "/" + quote(self._admin(), safe="@"), {"fields": "isAdmin"})
            self.super_admin = isinstance(body, dict) and body.get("isAdmin") is True
        if not self.super_admin:
            raise ReadError("GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN")

    def group_members(self, group) -> list[str]:
        """The addresses of the people in a group, those of the groups inside it included; never a group's own
        address. A reader made with GROUP_SCOPE asks for nothing else."""
        if self.scope != GROUP_SCOPE or not isinstance(group, str) or not ADMIN.fullmatch(group):
            raise ValueError("GOOGLE_WORKSPACE_OPERATION_OUT_OF_SCOPE")
        url, people, cursor = GROUPS_URL + "/" + quote(group.lower(), safe="@") + "/members", [], ""
        for _page in range(MEMBERS_PAGES):
            params = {"includeDerivedMembership": "true", "maxResults": MEMBERS_PAGE,
                      "fields": "nextPageToken,members(email,type)"}
            if cursor:
                params["pageToken"] = cursor
            body = self._get(url, params)
            rows = body.get("members", []) if isinstance(body, dict) else None
            cursor = body.get("nextPageToken", "") if isinstance(body, dict) else ""
            if not isinstance(rows, list) or len(rows) > MEMBERS_PAGE or not isinstance(cursor, str):
                raise ReadError("GOOGLE_WORKSPACE_INVALID_RESPONSE")
            people.extend(row["email"] for row in rows if isinstance(row, dict) and row.get("type") == "USER"
                          and isinstance(row.get("email"), str) and ADMIN.fullmatch(row["email"]))
            if not cursor:
                return people
            try:
                cursor_text(cursor)
            except ValueError:
                raise ReadError("GOOGLE_WORKSPACE_INVALID_CURSOR") from None
        raise ReadError("GOOGLE_WORKSPACE_GROUP_TOO_LARGE")

    def read(self, scope, source, cursor):
        if scope not in self.spec.scopes or source not in ("users", "deleted_users"):
            raise ValueError("GOOGLE_WORKSPACE_OPERATION_OUT_OF_SCOPE")
        params = {"customer": "my_customer", "maxResults": self.spec.options.page_size, "projection": "basic",
                  "fields": FIELDS}
        if source == "deleted_users":
            params["showDeleted"] = "true"
        if cursor:
            try:
                params["pageToken"] = cursor_text(cursor)
            except ValueError:
                raise ReadError("GOOGLE_WORKSPACE_INVALID_CURSOR") from None
        self._require_super_admin()
        body = self._get(USERS_URL, params)
        rows = body.get("users", []) if isinstance(body, dict) else None
        following = body.get("nextPageToken", "") if isinstance(body, dict) else ""
        if not isinstance(rows, list) or len(rows) > self.spec.options.page_size or not isinstance(following, str):
            raise ReadError("GOOGLE_WORKSPACE_INVALID_RESPONSE")
        return rows, following


def reader(spec, secrets, client, pacer):
    return Reader(spec, secrets, client, pacer)
