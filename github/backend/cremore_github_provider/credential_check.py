"""github connection identity check using the configured scanner credential."""
from __future__ import annotations

from cremore.collectors.base import error_label
from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED, CredentialCheck
from cremore.detection.safe_text import safe_fact_text
from cremore.http_client import bounded_request
from cremore_github_provider.github_auth import (
    GitHubAuthError,
    GitHubToken,
    github_token_evidence,
    github_token_scopes,
    resolve_github_token,
)


def check_github(client, token: GitHubToken, base_url: str = "https://api.github.com") -> CredentialCheck:
    try:
        resolved = resolve_github_token(token)
    except GitHubAuthError as exc:
        rejected = exc.code in ("GITHUB_APP_REJECTED", "GITHUB_APP_PRIVATE_KEY_INVALID")
        return CredentialCheck(REJECTED if rejected else INDETERMINATE, error=exc.code)
    if not resolved:
        return CredentialCheck(INDETERMINATE, error="NO_CREDENTIAL")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "Authorization": f"Bearer {resolved}"}
    detail = github_token_evidence(token)
    identity = getattr(token, "identity", None)
    if detail.get("credential_mode") == "GITHUB_APP" and callable(identity):
        # GET /app: the App the key signs for must be the configured App ID or Client ID.
        # Nothing of it is stored: owner and workspace feed the scan authorization revision
        # (cremore.scanning.scope.auth_revision), and the same credential must keep its approvals.
        try:
            identity()
        except GitHubAuthError as exc:
            rejected = exc.code in ("GITHUB_APP_REJECTED", "GITHUB_APP_IDENTITY_MISMATCH")
            return CredentialCheck(REJECTED if rejected else INDETERMINATE, error=exc.code)
    path = "/installation/repositories?per_page=1" \
        if detail.get("credential_mode") == "GITHUB_APP" else "/user"
    try:
        resp = bounded_request(client, "GET", base_url.rstrip("/") + path, headers=headers)
    except Exception as exc:  # noqa: BLE001 -- Provider failures yield a safe status/code, never credential-bearing exception text.
        return CredentialCheck(INDETERMINATE, error=error_label(exc))
    status = getattr(resp, "status_code", 0)
    if status == 401:
        return CredentialCheck(REJECTED, error="HTTP 401")
    if status != 200:
        return CredentialCheck(INDETERMINATE, error=f"HTTP {status}")
    try:
        body = resp.json()
    except Exception as exc:  # noqa: BLE001 -- Provider failures yield a safe status/code, never credential-bearing exception text.
        return CredentialCheck(INDETERMINATE, error=error_label(exc))
    if not isinstance(body, dict):
        return CredentialCheck(INDETERMINATE, error="MALFORMED_RESPONSE")

    def checked(owner, scopes):
        if len(scopes) > 100:
            return CredentialCheck(INDETERMINATE, error="UNSAFE_RESPONSE_METADATA")
        safe_owner = safe_fact_text(owner, secrets=(resolved,))
        safe_scopes = tuple(safe_fact_text(scope, secrets=(resolved,)) for scope in scopes)
        if (safe_owner is None or len(safe_owner) > 256
                or any(scope is None or len(scope) > 256 for scope in safe_scopes)):
            return CredentialCheck(INDETERMINATE, error="UNSAFE_RESPONSE_METADATA")
        return CredentialCheck(ACTIVE, owner=safe_owner, scopes=safe_scopes, detail=detail)

    if detail.get("credential_mode") == "GITHUB_APP":
        repositories = body.get("repositories") or []
        first = repositories[0] if isinstance(repositories, list) and repositories else {}
        owner = first.get("owner") if isinstance(first, dict) else None
        owner = owner.get("login", "") if isinstance(owner, dict) else ""
        return checked(owner, github_token_scopes(token))
    headers_out = getattr(resp, "headers", {}) or {}
    raw_scopes = headers_out.get("x-oauth-scopes") or headers_out.get("X-OAuth-Scopes") or ""
    if not isinstance(raw_scopes, str) or len(raw_scopes) > 8192:
        return CredentialCheck(INDETERMINATE, error="UNSAFE_RESPONSE_METADATA")
    scopes = tuple(s.strip() for s in raw_scopes.split(",") if s.strip())
    return checked(body.get("login", ""), scopes)
