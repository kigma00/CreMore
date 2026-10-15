"""A scripted GitHub API surface. No network, no App key, no real organization."""

from __future__ import annotations

import csv
import io
from copy import deepcopy
from types import SimpleNamespace

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_github_provider.metadata.endpoints import validate_operation
from cremore_github_provider.metadata.http import SourceError

ORG = "CreMore-1"
OTHER_ORG = "CreMore-2"
ENTERPRISE = "cremore-enterprise"
REPO = "platform-api"
FULL = f"{ORG}/{REPO}"
API = "https://api.github.com"


class FakeTransport:
    """Answers only the paths a test scripted; anything else is a 404."""

    def __init__(self, responses=None, *, failures=None, enterprise="", check=None, api=API):
        self.responses = dict(responses or {})
        self.failures = dict(failures or {})
        self.enterprise = enterprise
        self.check = check or (lambda: None)
        self.api = api
        self.calls: list[tuple[str, str]] = []
        self.bearers: list[tuple[str, str]] = []
        self.requests = 0
        self.options = None

    def request(self, method, path, bearer, *, json=None):
        validate_operation(method, path, enterprise=self.enterprise)
        self.check()
        self.requests += 1
        self.calls.append((method, path))
        self.bearers.append((path, bearer))
        if path in self.failures:
            code = self.failures.pop(path)
            raise SourceError(code, retry_after=120 if code == "github_rate_limited" else None)
        if path not in self.responses:
            raise SourceError("github_http_404", status=404)
        value = self.responses[path]
        if isinstance(value, tuple):
            return deepcopy(value[0]), dict(value[1])
        return deepcopy(value), {}

    def wait(self, seconds):
        self.check()

    def response(self, method, path, bearer, *, json=None, export=False):
        assert export
        validate_operation(method, path, enterprise=self.enterprise, allow_export_create=True)
        self.check()
        self.requests += 1
        self.calls.append((method, path))
        self.bearers.append((path, bearer))
        if path in self.failures:
            raise SourceError(self.failures.pop(path))
        if method == "GET":
            return SimpleNamespace(status_code=302), {"location": "https://download.example/export"}
        if path not in self.responses:
            raise SourceError("github_http_404", status=404)
        value = self.responses[path]
        items, headers = value if isinstance(value, tuple) else (value, {})
        self.csv_body = export_csv(items)
        payload = {"export_id": "export-1", "status": "queued",
                   "as_of": headers.get("x-github-enterprise-credentials-generated-at", "2026-03-02T00:00:00Z")}
        return SimpleNamespace(status_code=202, json=lambda: payload), headers

    def download(self, *args, **kwargs):
        for start in range(0, len(self.csv_body), 64 << 10):
            self.check()
            yield self.csv_body[start:start + (64 << 10)]


# What GET /app answers for the synthetic App: its id, Client ID and requested permissions.
APP = {"id": 12345, "client_id": "Iv23liSynthetic00000", "slug": "cremore-metadata", "name": "CreMore metadata",
       "owner": ORG, "owner_type": "Organization",
       "permissions": {"administration": "read", "metadata": "read", "organization_administration": "read",
                       "organization_personal_access_tokens": "read"}}


class FakeBroker:
    def __init__(self, *, refused=(), app=None, installations=None):
        self._refused = {scope: "organization_installation_github_http_404" for scope in refused}
        self.issued = []
        # {org: installation_info()} this App's installation each organization lookup returns.
        self.installations = dict(installations or {})
        self._discovered = []
        # A code string makes GET /app fail with that code.
        self.identity = APP if app is None else app
        self.app_calls = 0

    def app(self):
        self.app_calls += 1
        if isinstance(self.identity, str):
            raise SourceError(self.identity)
        return deepcopy(self.identity)

    def token_for(self, scope, name=""):
        key = (scope, (name or "").lower())
        if key in self._refused:
            raise SourceError(self._refused[key])
        info = self.installations.pop(name, None) if scope == "org" else None
        if info is not None:
            self._discovered.append((scope, name, info))
            if info.get("suspended_at"):
                self._refused[key] = "organization_installation_suspended"
                raise SourceError(self._refused[key])
        self.issued.append(key)
        return "ghs_" + "t" * 36

    def discovered(self):
        found, self._discovered = self._discovered, []
        return found

    def app_jwt(self):
        return "app-jwt"

    def refused(self):
        return {key[0] + "|" + key[1]: value for key, value in self._refused.items()}

    def restore(self, refused):
        for key, value in (refused or {}).items():
            parts = key.split("|", 1)
            if len(parts) == 2:
                self._refused[(parts[0], parts[1])] = value

    def close(self):
        pass


def repository(name=REPO, org=ORG, *, identifier=501, visibility="private"):
    return {"id": identifier, "node_id": "R_1", "name": name, "full_name": f"{org}/{name}",
            "private": visibility != "public", "visibility": visibility,
            "html_url": f"https://github.com/{org}/{name}", "archived": False, "disabled": False,
            "default_branch": "main", "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z", "pushed_at": "2026-02-02T00:00:00Z",
            "owner": {"login": org, "id": 9, "type": "Organization"}}


SSH_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5jL7yVQ0hJ1K0d1Yy0tS8Wb5Fhk2pZ0mN3qR4sT5uV"
           " deploy@example")


def org_responses(org=ORG, *, enterprise=""):
    prefix = f"/orgs/{org}"
    return {
        prefix + "/credential-authorizations?per_page=100": [
            {"login": "octocat", "credential_id": 11, "credential_type": "personal access token",
             "authorized_credential_id": 21, "authorized_credential_title": "ci token",
             "scopes": ["repo", "read:org"], "credential_authorized_at": "2026-01-02T00:00:00Z",
             "token_last_eight": "abcd1234"},
            {"login": "octocat", "credential_id": 12, "credential_type": "SSH key",
             "authorized_credential_id": 22, "authorized_credential_title": "laptop",
             "fingerprint": "SHA256:aaaa", "credential_authorized_at": "2026-01-03T00:00:00Z"},
            {"login": "octocat", "credential_id": 13, "credential_type": "deploy key legacy",
             "authorized_credential_id": 23},
        ],
        prefix + "/personal-access-tokens?per_page=100": [
            {"id": 31, "token_id": 41, "token_name": "release", "repository_selection": "selected",
             "permissions": {"contents": "read", "metadata": "read"},
             "access_granted_at": "2026-02-01T00:00:00Z", "token_expired": False,
             "token_expires_at": "2026-12-01T00:00:00Z",
             "owner": {"login": "octocat", "id": 3, "type": "User"}},
        ],
        prefix + "/personal-access-tokens/31/repositories?per_page=100": [repository()],
        prefix + "/personal-access-token-requests?per_page=100": [
            {"id": 51, "token_id": 61, "token_name": "pending", "reason": "deploys",
             "created_at": "2026-03-01T00:00:00Z", "repository_selection": "all",
             "permissions": {"contents": "write"}},
        ],
        prefix + "/personal-access-token-requests/51/repositories?per_page=100": [repository()],
        prefix + "/installations?per_page=100": {"installations": [
            {"id": 71, "app_id": 5, "app_slug": "cremore", "target_id": 9,
             "target_type": "Organization", "repository_selection": "selected",
             "created_at": "2026-01-01T00:00:00Z", "permissions": {"contents": "read"},
             "events": ["push"], "account": {"login": org, "id": 9, "type": "Organization"}},
        ]},
        "/installation/repositories?per_page=100": {"repositories": [repository()]},
        prefix + "/actions/permissions/workflow": {
            "default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
        f"/repos/{org}/{REPO}/keys?per_page=100": [
            {"id": 81, "title": "deploy", "key": SSH_KEY, "verified": True, "read_only": True,
             "created_at": "2026-01-05T00:00:00Z", "enabled": True},
        ],
        f"/repos/{org}/{REPO}/actions/permissions/workflow": {
            "default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
        f"/repos/{org}/{REPO}/actions/permissions": {
            "enabled": True, "allowed_actions": "selected", "sha_pinning_required": False},
        f"/repos/{org}/{REPO}/actions/permissions/fork-pr-workflows-private-repos": {
            "run_workflows_from_fork_pull_requests": False,
            "send_write_tokens_to_workflows": False, "send_secrets_and_variables": False,
            "require_approval_for_fork_pr_workflows": True},
    }


def spec(**overrides):
    body = {
        "schema_version": 2, "name": "github org metadata", "provider": "github",
        "origin": "https://github.com", "edition": "enterprise_cloud", "tenant": "",
        "auth_type": "github_app",
        "secret_refs": {"app_id": "vault://github/app-id",
                        "private_key": "vault://github/private-key"},
        "scopes": [{"kind": "organization", "id": ORG}],
        "capabilities": ["inventory", "public_keys", "policy"],
        "options": {"mode": "organization", "page_size": 100},
        "max_records": 5000, "max_requests": 500, "max_pages": 400,
    }
    options = {**body["options"], **overrides.pop("options", {})}
    return MetadataConnectionSpec.model_validate({**body, **overrides, "options": options})


SECRETS = {"app_id": "12345", "private_key": "Zm9v"}
# A synthetic classic PAT for the Enterprise audit log; it only has the shape of one.
AUDIT_TOKEN = "ghp_" + "a" * 36


def drain(pages, *, limit=400):
    records, final = [], None
    for seen, page in enumerate(pages, start=1):
        if seen > limit:
            raise AssertionError("the adapter produced more pages than expected")
        records.extend(page.records)
        if page.status is not None:
            final = page
    return records, final


def inventory_row(identifier="inv-1", **overrides):
    return {"inventory_id": identifier, "credential_type": "classic_pat",
            "item_type": "credential", "credential_state": "active",
            "authorization_state": "currently_authorized", "effective_access_state": "effective",
            "enterprise_authorized": True, "authorization_count": 1,
            "authorized_organizations": [{"id": 9, "login": ORG}],
            "display_name": "release token", "owner": "octocat", "owner_type": "User",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z",
            "scopes": ["repo"], **overrides}


def export_csv(items):
    """Render synthetic inventory facts in the documented CSV wire format."""
    headers = ["credential_id", "hashed_token", "fingerprint", "item_type", "credential_type", "display_name",
               "owner_id", "owner", "owner_type", "application_id", "application", "credential_state", "created_at",
               "last_used_at", "expires_at", "expiry_status", "enterprise_authorized", "authorization_count",
               "age_days", "past_expiration_policy", "past_expiration_policy_basis", "scopes", "permissions",
               "repository_selection", "organization_id", "organization"]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, headers, lineterminator="\n")
    writer.writeheader()
    for item in items:
        values = {key: item.get(key) for key in headers}
        if values["credential_type"] == "github_app_installation":
            values["item_type"] = "token_issuer_principal"
        for key, value in values.items():
            if isinstance(value, bool):
                values[key] = str(value).lower()
            elif isinstance(value, list):
                values[key] = ";".join(value)
            elif isinstance(value, dict):
                values[key] = ";".join(f"{k}:{v}" for k, v in value.items())
        for org in item.get("authorized_organizations") or [{}]:
            writer.writerow({**values, "organization_id": org.get("id"), "organization": org.get("login")})
    return stream.getvalue().encode()


def audit_row(action="personal_access_token.access_granted", **overrides):
    return {"action": action, "_document_id": "doc-1", "created_at": "2026-03-01T00:00:00Z",
            "actor": "octocat", "actor_id": 3, "business": ENTERPRISE, "org": ORG,
            "token_id": 41, "programmatic_access_type": "fine_grained_personal_access_token",
            **overrides}


def enterprise_responses(*, orgs=(ORG,), audit=True, window=None):
    data = {
        f"/enterprises/{ENTERPRISE}/credentials/exports": (
            [inventory_row(), inventory_row("inv-2", item_type="token_issuer_principal",
                                            credential_type="github_app_installation")],
            {"x-github-enterprise-credentials-truncated": "true",
             "x-github-enterprise-credentials-generated-at": "2026-03-02T00:00:00Z"}),
        f"/enterprises/{ENTERPRISE}/apps/installable_organizations?per_page=100":
            [{"id": 9 + index, "login": name} for index, name in enumerate(orgs)],
    }
    for name in orgs:
        data[f"/enterprises/{ENTERPRISE}/apps/organizations/{name}/installations?per_page=100"] = [
            {"id": 91, "client_id": "Iv1.abc", "app_slug": "cremore",
             "repository_selection": "selected", "permissions": {"contents": "read"},
             "events": ["push"], "created_at": "2026-01-01T00:00:00Z"}]
        data[f"/enterprises/{ENTERPRISE}/apps/organizations/{name}/installations/91"
             "/repositories?per_page=100"] = [repository(org=name)]
        data[f"/enterprises/{ENTERPRISE}/apps/installable_organizations/{name}"
             "/accessible_repositories?per_page=100"] = [repository(org=name)]
        data.update(org_responses(name))
    if audit and window:
        from urllib.parse import urlencode
        phrase = urlencode({"include": "web", "order": "asc",
                            "phrase": "created:" + window[0] + ".." + window[1]})
        data[f"/enterprises/{ENTERPRISE}/audit-log?{phrase}&per_page=100"] = [audit_row()]
    return data


def enterprise_spec(**overrides):
    options = {"mode": "enterprise", **overrides.pop("options", {})}
    if ("audit" in overrides.get("capabilities", []) and "secret_refs" not in overrides
            and options.get("audit_scope", "both") != "organization"):
        # The Enterprise audit log accepts only a classic PAT; declare its role.
        overrides["secret_refs"] = {"app_id": "vault://github/app-id",
                                    "private_key": "vault://github/private-key",
                                    "audit_token": "vault://github/audit-token"}
    return spec(scopes=[{"kind": "enterprise", "id": ENTERPRISE}], options=options, **overrides)
