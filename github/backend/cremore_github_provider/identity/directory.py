"""GitHub SAML/SCIM external identities (GraphQL ``externalIdentities``).

An organization that signs members in through SAML SSO keeps, per member, the IdP's
NameID and, with SCIM, the IdP user name and emails, linked to the GitHub login that
claimed them. That link is what makes a GitHub token's owner a known person. GitHub shows
it (GraphQL ``ExternalIdentity``, SAML set on the organization) to an organization owner's
classic PAT with ``read:org`` (or ``admin:org``), authorized for SAML SSO, and to a GitHub
App installation with Members (read): the App's token is asked for that permission alone,
on the organization's own installation. Identities no member has claimed yet name no
login and are skipped.

An enterprise with managed users (EMU), or with SAML set on the enterprise (which takes over from its organizations'
own), keeps the same link for the whole enterprise, through its SAML or OIDC provider (``enterprise.ownerInfo``): a
login (for managed users ``handle_shortcode``) and the SCIM user name and emails the IdP provisioned it with. Reading
it needs an enterprise owner's classic PAT with ``read:enterprise`` (or ``admin:enterprise``), never an App; an
enterprise scope is read alone, never with organizations. A managed login is never derived from the IdP user name:
GitHub's normalization drops characters, so the login it computes can be someone else's. Enterprise Server sets SAML
on the instance and answers it as its enterprise's (``ownerInfo.samlIdentityProvider``, the same owner token); its
schema has no ``oidcProvider``, so a Server's query asks for SAML alone.
"""

from __future__ import annotations

import re

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.identity.idp import ReadError, Source, User, status_error

from ..github_auth import GitHubAppTokenSource, GitHubAuthError
from ..github_hosts import api_base
from ..metadata.http import retry_delay

PROVIDER = "github_identity"
API_VERSION = "graphql"
CONTRACT_VERSION = "github-external-identities-v1"
# GitHub logins: 1-39 alphanumerics or single hyphens, not at either end; a managed user's ends in _ and the
# enterprise's short code (3-8 alphanumerics), within the same 39.
USER_ID = re.compile(r"(?=.{1,39}\Z)[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9]))*(?:_[a-z0-9]{3,8})?")
KEY_KINDS = frozenset({"IDP_USER_ID", "SAML_NAME_ID", "SCIM_EXTERNAL_ID", "VERIFIED_EMAIL"})
SOURCES = (Source("external_identities", "users", completes=True),)
_IDENTITIES = """externalIdentities(first: $first, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          samlIdentity { nameId username givenName familyName emails { value } }
          scimIdentity { username givenName familyName emails { value } }
          user { login }
        }
      }"""
QUERY = ("query($org: String!, $first: Int!, $after: String) {\n  organization(login: $org) {\n"
         "    samlIdentityProvider {\n      " + _IDENTITIES + "\n    }\n  }\n}")
# A managed-user enterprise signs in through SAML or OIDC: whichever it has answers.
ENTERPRISE_QUERY = ("query($enterprise: String!, $first: Int!, $after: String) {\n  enterprise(slug: $enterprise) {\n"
                    "    ownerInfo {\n      samlIdentityProvider { " + _IDENTITIES + " }\n"
                    "      oidcProvider { " + _IDENTITIES + " }\n    }\n  }\n}")
SERVER_ENTERPRISE_QUERY = ("query($enterprise: String!, $first: Int!, $after: String) {\n  enterprise(slug: $enterprise) {\n"
                           "    ownerInfo {\n      samlIdentityProvider { " + _IDENTITIES + " }\n    }\n  }\n}")
_ORG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")


def graphql_url(origin):
    host = origin.removeprefix("https://")
    base = api_base(host)
    return base.removesuffix("/api/v3") + "/api/graphql" if base.endswith("/api/v3") else base + "/graphql"


def _throttled(response, payload):
    """GitHub's GraphQL rate limits: the primary one answers 200 with an error and x-ratelimit-remaining 0, a secondary
    one 200 or 403 with retry-after, x-ratelimit-reset or its message
    (docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api)."""
    if response.status_code == 429:
        return True
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if response.status_code == 200 and not errors:
        return False  # a page that spent the last point still carries its data
    headers = response.headers or {}
    if "retry-after" in headers or str(headers.get("x-ratelimit-remaining", "")).strip() == "0":
        return True
    said = [error for error in errors if isinstance(error, dict)] if isinstance(errors, list) else []
    messages = [str(error.get("message", "")) for error in said] + (
        [str(payload.get("message", ""))] if isinstance(payload, dict) else [])
    return any(error.get("type") == "RATE_LIMITED" for error in said) or any(
        "rate limit" in message.lower() for message in messages)


def validate_spec(spec):
    try:
        graphql_url(spec.origin)
    except ValueError:
        raise ValueError("GITHUB_IDENTITY_HOST_INVALID") from None
    if spec.edition not in ("cloud", "enterprise_cloud", "enterprise_server", "dedicated"):
        raise ValueError("GITHUB_IDENTITY_EDITION_UNSUPPORTED")
    if not spec.scopes or any(scope.kind not in ("organization", "enterprise") or not _ORG.fullmatch(scope.id)
                              for scope in spec.scopes):
        raise ValueError("GITHUB_IDENTITY_ORGANIZATION_SCOPE_REQUIRED")
    if any(scope.kind == "enterprise" for scope in spec.scopes):
        if len(spec.scopes) > 1:
            # One source per collection: an enterprise's SSO takes over from its organizations' own.
            raise ValueError("GITHUB_IDENTITY_ENTERPRISE_SCOPE_ALONE")
        if spec.edition not in ("enterprise_cloud", "dedicated", "enterprise_server"):
            raise ValueError("GITHUB_IDENTITY_ENTERPRISE_SCOPE_NEEDS_ENTERPRISE_CLOUD")
    if spec.auth_type == "github_app":
        if any(scope.kind == "enterprise" for scope in spec.scopes):
            # GitHub shows an enterprise's identities to its owners' classic tokens alone (Enterprise.ownerInfo).
            raise ValueError("GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN")
        if set(spec.secret_refs) != {"app_id", "installation_id", "private_key"}:
            raise ValueError("GITHUB_IDENTITY_APP_CREDENTIAL_REQUIRED")
    elif spec.auth_type != "bearer" or set(spec.secret_refs) != {"token"}:
        raise ValueError("GITHUB_IDENTITY_OWNER_TOKEN_REQUIRED")
    if spec.options.mode != "inventory" or spec.options.page_size > 100 or spec.options.include_audit_events:
        raise ValueError("GITHUB_IDENTITY_OPTION_NOT_SUPPORTED")


def user(spec, source, row):
    if not isinstance(row, dict):
        raise TypeError("GITHUB_IDENTITY_INVALID_NODE")
    login = (row.get("user") or {}).get("login") if isinstance(row.get("user"), dict) else None
    if not isinstance(login, str):
        return None  # not claimed by a member yet
    keys, said = [], {}
    for part, name_kind in (("samlIdentity", "SAML_NAME_ID"), ("scimIdentity", "SCIM_EXTERNAL_ID")):
        attributes = row.get(part) if isinstance(row.get(part), dict) else {}
        for field in ("nameId", "username"):
            if isinstance(attributes.get(field), str) and attributes[field]:
                keys.append((name_kind, attributes[field]))
        emails = [email["value"] for email in attributes.get("emails") or []
                  if isinstance(email, dict) and isinstance(email.get("value"), str) and email["value"]]
        keys.extend(("VERIFIED_EMAIL", value) for value in emails)
        name = " ".join(piece for piece in (attributes.get("givenName"), attributes.get("familyName"))
                        if isinstance(piece, str) and piece)
        said[part] = (name, emails[0] if emails else "")
    # SCIM (what the IdP provisioned) speaks for the person over SAML (what the last sign-in asserted).
    scim, saml = said["scimIdentity"], said["samlIdentity"]
    details = tuple(pair for pair in (("display_name", scim[0] or saml[0]), ("email", scim[1] or saml[1])) if pair[1])
    return User(id=login.lower(), raw_state="LINKED", state="ACTIVE", keys=tuple(dict.fromkeys(keys)),
                profile=details)


def event(spec, source, row):
    return None


class Reader:
    def __init__(self, spec, secrets, client, pacer):
        self.spec, self.client, self.pacer = spec, client, pacer
        self.token = secrets.get("token", "")
        self.app = ({name: secrets.get(name) for name in ("app_id", "installation_id", "private_key")}
                    if spec.auth_type == "github_app" else None)
        self.sources = {}  # the App's installation token, per organization
        self.url = graphql_url(spec.origin)

    def close(self):
        self.token = self.app = None
        self.sources.clear()

    def _bearer(self, organization):
        """The owner's classic token, or the App's token from its installation on ``organization``, for Members:
        read alone (minted outside the request budget, as the inventory's App tokens are)."""
        if self.app is None:
            if not re.fullmatch(r"[\x21-\x7e]{20,255}", self.token or ""):
                raise ReadError("GITHUB_IDENTITY_TOKEN_INVALID")
            return self.token
        try:
            if organization.lower() not in self.sources:
                self.sources[organization.lower()] = GitHubAppTokenSource(
                    lambda: self.client, self.app["app_id"], self.app["installation_id"], self.app["private_key"],
                    base_url=api_base(self.spec.origin), close_client=False, permissions={"members": "read"},
                    organization=organization)
            return self.sources[organization.lower()]()
        except GitHubAuthError as exc:
            raise ReadError("GITHUB_IDENTITY_" + exc.code.removeprefix("GITHUB_"),
                            retryable=exc.code == "GITHUB_APP_UNAVAILABLE") from None

    def read(self, scope, source, cursor):
        if scope not in self.spec.scopes or source != "external_identities":
            raise ValueError("GITHUB_IDENTITY_OPERATION_OUT_OF_SCOPE")
        # The budget and a cancellation are checked before an App token is minted for the page, not after.
        self.pacer.before()
        token = self._bearer(scope.id)
        enterprise = scope.kind == "enterprise"
        variables = {"enterprise" if enterprise else "org": scope.id, "first": self.spec.options.page_size,
                     "after": cursor or None}
        query = (SERVER_ENTERPRISE_QUERY if self.spec.edition == "enterprise_server" else ENTERPRISE_QUERY) \
            if enterprise else QUERY
        try:
            response = bounded_request(self.client, "POST", self.url, json={"query": query, "variables": variables},
                                       headers={"Authorization": "bearer " + token, "Accept": "application/json",
                                                "User-Agent": "CreMore-Identity/1.0"},
                                       timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                                       max_response_bytes=self.spec.options.max_response_bytes)
        except HTTPResponseTooLarge:
            raise ReadError("GITHUB_IDENTITY_RESPONSE_LIMIT") from None
        except Exception:  # noqa: BLE001 -- transport errors can carry the token
            raise ReadError("GITHUB_IDENTITY_UNAVAILABLE", retryable=True) from None
        payload = None
        try:
            payload = response.json()
        except (ValueError, RecursionError):
            if response.status_code == 200:
                raise ReadError("GITHUB_IDENTITY_INVALID_RESPONSE") from None
        if response.status_code in (200, 403, 429) and _throttled(response, payload):
            raise ReadError("GITHUB_IDENTITY_RATE_LIMITED", retryable=True, retry_after=retry_delay(response.headers))
        if response.status_code != 200:
            raise status_error("GITHUB_IDENTITY", response)
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if errors:
            kinds = {error.get("type") for error in errors if isinstance(error, dict)}
            root = "enterprise" if enterprise else "organization"
            if any(isinstance(error, dict) and error.get("type") == "NOT_FOUND"
                   and (error.get("path") or [None])[:1] == [root] for error in errors):  # a slug or login no one has
                raise ReadError("GITHUB_IDENTITY_ENTERPRISE_NOT_FOUND" if enterprise
                                else "GITHUB_IDENTITY_ORGANIZATION_NOT_FOUND")
            raise ReadError("GITHUB_IDENTITY_FORBIDDEN" if kinds & {"FORBIDDEN", "INSUFFICIENT_SCOPES"}
                            else "GITHUB_IDENTITY_QUERY_FAILED")
        data = (payload.get("data") or {}) if isinstance(payload, dict) else {}
        if enterprise:
            found = data.get("enterprise") if isinstance(data, dict) else None
            if not isinstance(found, dict):
                raise ReadError("GITHUB_IDENTITY_ENTERPRISE_NOT_FOUND")
            owner = found.get("ownerInfo")
            if not isinstance(owner, dict):
                raise ReadError("GITHUB_IDENTITY_FORBIDDEN")  # only an enterprise owner sees it
            providers = [owner.get(name) for name in ("samlIdentityProvider", "oidcProvider") if owner.get(name)]
            if not providers:
                raise ReadError("GITHUB_IDENTITY_SAML_NOT_ENABLED")
            provider = providers[0]
        else:
            organization = data.get("organization") if isinstance(data, dict) else None
            if not isinstance(organization, dict):
                raise ReadError("GITHUB_IDENTITY_ORGANIZATION_NOT_FOUND")
            provider = organization.get("samlIdentityProvider")
            if provider is None:
                raise ReadError("GITHUB_IDENTITY_SAML_NOT_ENABLED")
        connection = provider.get("externalIdentities") if isinstance(provider, dict) else None
        if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list) \
                or not isinstance(connection.get("pageInfo"), dict):
            raise ReadError("GITHUB_IDENTITY_INVALID_RESPONSE")
        nodes, info = connection["nodes"], connection["pageInfo"]
        if len(nodes) > self.spec.options.page_size:
            raise ReadError("GITHUB_IDENTITY_INVALID_RESPONSE")
        following = info.get("endCursor") if info.get("hasNextPage") is True else ""
        if info.get("hasNextPage") is True and not isinstance(following, str):
            raise ReadError("GITHUB_IDENTITY_INVALID_CURSOR")
        return nodes, following


def reader(spec, secrets, client, pacer):
    return Reader(spec, secrets, client, pacer)
