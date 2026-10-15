"""GitHub's own secret-scanning alerts for a repository or organisation we own.

GitHub scans the repositories an installation owns, and its partner programme has
issuers verify a leaked token directly. When an alert exists, the provider has
established the exposure — a stronger statement than any pattern match of ours,
and one we cannot produce. ``publicly_leaked`` goes further: GitHub found the
same secret outside the repository as well.

Two boundaries decide everything here.

**The response carries the raw secret.** ``secret`` (and the locations endpoint)
return the credential in plaintext. This module never returns it, never logs it
and never stores it: the alert is reduced to a fixed list of metadata fields
before it leaves ``_alert``. Anything GitHub adds later is dropped by omission
rather than kept by default.

**A refusal is not an absence.** Secret scanning is free on public repositories
but needs GitHub Advanced Security on private and internal ones, and it can be
switched off per repository. Both answer 403/404, which must never be reported
as "no alerts". Those become ``UNSUPPORTED`` with the reason, so the dashboard
can say the check could not run rather than that the repository is clean.

https://docs.github.com/rest/secret-scanning/secret-scanning
"""

from __future__ import annotations

import datetime as _dt
import json

from cremore.detection.safe_text import safe_fact_text
from cremore_github_provider.collectors.github import fetch_json

MAX_PAGES = 10
PER_PAGE = 100
MAX_ALERTS = MAX_PAGES * PER_PAGE
MAX_RESULT_BYTES = 8 * 1024 * 1024
# GitHub's documented alert states and validity values; anything else is recorded
# as unknown rather than guessed into one of these.
STATES = ("open", "resolved")
VALIDITY = ("active", "inactive", "unknown")
# Kept from an alert. `secret`, `resolved_by` and the API-internal URLs are not
# here, and absence is how they stay out.
FIELDS = ("number", "created_at", "updated_at", "state", "resolution", "resolved_at",
          "secret_type", "secret_type_display_name", "validity", "publicly_leaked",
          "multi_repo", "push_protection_bypassed", "html_url")
NOT_ESTABLISHED = (
    ("A repository without alerts may simply not be scanned: secret scanning needs "
     "GitHub Advanced Security on private and internal repositories and can be switched off."),
    ("Alerts are GitHub's findings about its own repositories. They are not matched to "
     "this platform's findings, because matching would need the secret value, which is not stored."),
)


def _text(value, limit: int = 256, *, secrets=()) -> str:
    # Check the entire field before applying display limits; cutting first can
    # turn a rejected credential into a retained partial secret.
    value = str(value) if type(value) is int else value
    safe = safe_fact_text(value, secrets=secrets)
    return safe if safe is not None and len(safe) <= limit else ""


def _alert(raw: dict, repository: str, *, secrets=()) -> dict:
    """One alert reduced to metadata. The raw secret never reaches this dict."""

    if isinstance(raw.get("secret"), str):
        secrets = (*secrets, raw["secret"])
    out = {"repository": _text(repository, secrets=secrets)}
    for field in FIELDS:
        value = raw.get(field)
        out[field] = value if isinstance(value, bool) else _text(
            value, 2048 if field == "html_url" else 256, secrets=secrets)
    if out["state"] not in STATES:
        out["state"] = "unknown"
    if out["validity"] not in VALIDITY:
        out["validity"] = "unknown"
    return out


def _reason(label: str) -> tuple[str, str]:
    """(collection_status, reason_code) for a failed page read."""

    if label == "HTTP 404":
        # Secret scanning is off for this target, or the token cannot see it.
        return "UNSUPPORTED", "SECRET_SCANNING_NOT_ENABLED"
    if label == "HTTP 403":
        # No Advanced Security on a private repository, or the token lacks the scope.
        return "UNSUPPORTED", "NOT_AUTHORIZED"
    if label == "HTTP 401":
        return "FAILED", "CREDENTIAL_REJECTED"
    return "FAILED", label.replace(" ", "_").upper()[:64]


def collect(client, headers: dict, *, base_url: str, organization: str = "", repository: str = "",
            max_pages: int = MAX_PAGES, before_attempt=None, now=None, credential=None) -> dict:
    """Read the alerts GitHub raised for one organisation or repository (paced by ``credential``, fetch_json)."""

    if bool(organization) == bool(repository):
        raise ValueError("collect needs exactly one of organization or repository")
    scope = "ORGANIZATION" if organization else "REPOSITORY"
    target = organization or repository
    path = f"/orgs/{organization}" if organization else f"/repos/{repository}"
    result = {
        "scope": scope, "target": target, "alerts": [], "truncated": False, "reason_code": "",
        "collected_at": (now or _dt.datetime.now(_dt.UTC)).isoformat(),
        "limitations": list(NOT_ESTABLISHED),
    }
    alerts: list[dict] = []
    malformed, retained_bytes = False, 0
    # Both the alert value and the connection credential are forbidden in any
    # projected metadata field, including labels and repository names.
    authorization = next((value for key, value in headers.items() if key.casefold() == "authorization"), "")
    secrets = (authorization, authorization.partition(" ")[2]) if isinstance(authorization, str) else ()
    for page in range(1, min(MAX_PAGES, max(1, max_pages)) + 1):
        url = f"{base_url.rstrip('/')}{path}/secret-scanning/alerts?per_page={PER_PAGE}&page={page}"
        body, label = fetch_json(client, url, headers, before_attempt=before_attempt, credential=credential)
        if body is None:
            status, reason = _reason(label)
            # Pages already read stay; a later refusal makes the run partial, not empty.
            return {**result, "alerts": alerts, "counts": _counts(alerts),
                    "collection_status": "PARTIAL" if alerts else status, "reason_code": reason}
        if not isinstance(body, list):
            return {**result, "alerts": alerts, "counts": _counts(alerts),
                    "collection_status": "PARTIAL" if alerts else "FAILED", "reason_code": "UNEXPECTED_RESPONSE_SHAPE"}
        if len(body) > PER_PAGE:
            return {**result, "alerts": alerts, "counts": _counts(alerts), "collection_status": "PARTIAL",
                    "truncated": True, "reason_code": "RESPONSE_PAGE_LIMIT_EXCEEDED"}
        for item in body:
            if not isinstance(item, dict):
                malformed = True
                continue
            named = item.get("repository")
            name = named.get("full_name") if isinstance(named, dict) else None
            alert = _alert(item, name or (repository if scope == "REPOSITORY" else ""), secrets=secrets)
            retained_bytes += len(json.dumps(alert, ensure_ascii=True)) + 2
            if len(alerts) >= MAX_ALERTS or retained_bytes > MAX_RESULT_BYTES:
                return {**result, "alerts": alerts, "counts": _counts(alerts), "collection_status": "PARTIAL",
                        "truncated": True, "reason_code": "ALERT_RESULT_LIMIT_EXCEEDED"}
            alerts.append(alert)
        if len(body) < PER_PAGE:
            return {**result, "alerts": alerts, "counts": _counts(alerts),
                    "collection_status": "PARTIAL" if malformed else "COMPLETE",
                    "reason_code": "UNEXPECTED_RESPONSE_SHAPE" if malformed else ""}
    return {**result, "alerts": alerts, "counts": _counts(alerts), "collection_status": "PARTIAL",
            "truncated": True, "reason_code": "PAGE_LIMIT_REACHED"}


def _counts(alerts: list[dict]) -> dict:
    return {
        "alerts": len(alerts),
        "open": sum(alert["state"] == "open" for alert in alerts),
        "resolved": sum(alert["state"] == "resolved" for alert in alerts),
        # GitHub confirmed the secret still works.
        "validity_active": sum(alert["validity"] == "active" for alert in alerts),
        # GitHub found the same secret outside this repository as well.
        "publicly_leaked": sum(alert["publicly_leaked"] is True for alert in alerts),
        "push_protection_bypassed": sum(alert["push_protection_bypassed"] is True for alert in alerts),
    }


def unavailable(payload: dict, now=None) -> dict:
    """The recorded result when the connection's credential could not be provided."""
    organization = str(payload.get("org") or "")
    owner, repo = str(payload.get("owner") or ""), str(payload.get("repo") or "")
    return {"scope": "ORGANIZATION" if organization else "REPOSITORY",
            "target": organization or f"{owner}/{repo}", "alerts": [], "counts": _counts([]),
            "collection_status": "FAILED", "reason_code": "SECRET_UNAVAILABLE", "truncated": False,
            "collected_at": (now or _dt.datetime.now(_dt.UTC)).isoformat(),
            "limitations": list(NOT_ESTABLISHED)}


def run(payload: dict, *, http_client_factory=None, now=None) -> dict:
    """Dispatch a ``github-secret-scanning`` job payload whose credential is already resolved.

    Second review 2026-09-26: the platform worker resolves the connection's ``secret_ref``
    first (cremore/cli/worker.py, as the catalog lister does) and records ``unavailable()``
    when it cannot. This library only turns the resolved GitHub credential (a token or an
    App installation token source) into requests; the token is never persisted.
    """

    from cremore_github_provider.github_auth import GitHubAuthError, resolve_github_token

    if str(payload.get("provider", "")).lower() not in ("github", ""):
        raise ValueError("secret-scanning alerts are a GitHub read")
    if http_client_factory is None:
        raise ValueError("secret-scanning read requires an http client factory")
    base_url = str(payload.get("base_url") or "https://api.github.com")
    organization = str(payload.get("org") or "")
    owner, repo = str(payload.get("owner") or ""), str(payload.get("repo") or "")
    if not organization and not (owner and repo):
        raise ValueError("secret-scanning read needs an organization or an owner and repository")
    try:
        token = resolve_github_token(payload.get("token") or "")
    except GitHubAuthError:
        return unavailable(payload, now)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    client = http_client_factory()
    try:
        return collect(client, headers, base_url=base_url, organization=organization,
                       repository="" if organization else f"{owner}/{repo}", now=now,
                       credential=payload.get("token") or "")
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
