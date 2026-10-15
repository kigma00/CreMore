"""github metadata-only resource listing."""
from __future__ import annotations

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.scanning.catalog_projection import MAX_LISTED
from cremore.scanning.scope import resource
from cremore_github_provider.collectors.github import account_repos_path, fetch_json
from cremore_github_provider.github_auth import GitHubToken, resolve_github_token
from cremore_github_provider.github_hosts import host_from_api_base, web_base

_GH_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def _gh_get(client, url: str, token: GitHubToken, budget: RequestBudget):
    headers = dict(_GH_HEADERS)
    resolved = resolve_github_token(token)
    if resolved:
        headers["Authorization"] = f"Bearer {resolved}"
    return fetch_json(client, url, headers, before_attempt=budget.consume, credential=token)


def _repo_resource(kind, cid, info: dict, now, github_host: str = "") -> dict:
    full = info.get("full_name") or f"{(info.get('owner') or {}).get('login', '')}/{info.get('name', '')}"
    visibility = str(info.get("visibility") or ("private" if info.get("private") else "public")).upper()
    return resource(kind, cid, "GITHUB_REPOSITORY", full, full, info.get("html_url") or f"{web_base(github_host)}/{full}",
                    github_host or "github.com", now=now, organization_id=(info.get("owner") or {}).get("login"),
                    visibility=visibility,
                    archived=info.get("archived"), fork=info.get("fork"), language=info.get("language") or None,
                    topics=info.get("topics") if isinstance(info.get("topics"), list) else None,
                    default_branch=info.get("default_branch") or None, last_edited_at=info.get("pushed_at") or None,
                    **({"github_host": github_host} if github_host else {}))


def _github(payload, kind, cid, client, now, budget: RequestBudget) -> tuple[list[dict], str]:
    base = str(payload.get("base_url") or "https://api.github.com").rstrip("/")
    ghost = host_from_api_base(base)
    token = payload.get("token", "")
    org = payload.get("org")
    reference = payload.get("reference")
    if reference:
        owner, _, name = reference.partition("/")
        if not owner or not name or (org and owner.lower() != str(org).lower()) \
                or (not org and (owner, name) != (payload.get("owner"), payload.get("repo"))):
            raise CollectorError("OUT_OF_CONNECTION_SCOPE", reference)
        info, label = _gh_get(client, f"{base}/repos/{owner}/{name}", token, budget)
        if not isinstance(info, dict):
            denied = resource(kind, cid, "GITHUB_REPOSITORY", reference, reference, f"{web_base(ghost)}/{reference}",
                              ghost or "github.com", now=now, list_visibility="DENIED",
                              reason_code="INSUFFICIENT_PERMISSION", **({"github_host": ghost} if ghost else {}))
            return [denied], "PARTIAL"
        return [_repo_resource(kind, cid, info, now, ghost)], "PARTIAL"
    if not org:
        slug = f"{payload.get('owner', '')}/{payload.get('repo', '')}"
        info, label = _gh_get(client, f"{base}/repos/{slug}", token, budget)
        if not isinstance(info, dict):
            raise CollectorError("GITHUB_REPOSITORY_UNAVAILABLE", label)
        return [_repo_resource(kind, cid, info, now, ghost)], "COMPLETE"
    out, page, complete = [], 1, True
    path = f"/orgs/{org}/repos?per_page=100&page={{page}}"

    def get(url):
        return _gh_get(client, url, token, budget)

    while len(out) < MAX_LISTED:
        repos, label = get(base + path.format(page=page))
        if label == "HTTP 404" and path.startswith("/orgs/"):
            # not an organisation: a personal account
            path, complete = account_repos_path(get, base, org)
            continue
        if not isinstance(repos, list):
            raise CollectorError("GITHUB_ORG_LIST_FAILED", label)
        before = len(out)
        out.extend(_repo_resource(kind, cid, r, now, ghost) for r in repos if isinstance(r, dict) and r.get("name")
                   and str((r.get("owner") or {}).get("login") or org).lower() == str(org).lower())
        if len(out) == before and repos:
            return out, "PARTIAL"
        if len(repos) < 100:
            return out, "COMPLETE" if complete else "PARTIAL"
        page += 1
    return out[:MAX_LISTED], "PARTIAL"
