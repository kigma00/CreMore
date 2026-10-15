"""GitHub repository/organization scope and existing collector construction."""

import re

PROVIDER = "github"
SOURCE_TYPE = "github"
JOB_KINDS = ("github", "github-org")
RESOURCE_TYPES = ("GITHUB_REPOSITORY",)
SCOPE_KIND = "path"
FILTERS = ("organization_id", "visibility", "language", "topic", "archived", "fork", "edited_after", "edited_before")
CAPABILITY_ORDER = 1
STRUCTURED_CONFIG = False
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = False
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
# A listed object's revision is its git blob id (cremore.scanning.service caches by it).
CONTENT_ADDRESSED = True
CAPABILITY = {"id": "github", "name": "GitHub", "command": "github", "kind": "BATCH",
    "description": "One repository (owner/repo) or every repository of an organisation (org), via the REST API.",
    "credential_env": ["GITHUB_TOKEN"], "external_credential_env": ["GITHUB_TOKEN"],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = (
    ("Stopping use here does not revoke the token at GitHub. Delete or regenerate it under "
     "Settings → Developer settings → Personal access tokens (or uninstall the GitHub App)."),
    "https://github.com/settings/tokens")
GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def validate_config(cfg):
    if cfg.get("org") or cfg.get("owner") and cfg.get("repo"):
        return cfg
    raise ValueError("github connection requires either 'org' or 'owner'+'repo'")


def onboarding_coordinate(cfg):
    """The verified same-organization App hint changes token selection, never source/scope identity."""
    out = dict(cfg)
    if (out.get("auth_kind") == "GITHUB_APP" and isinstance(out.get("app_organization"), str)
            and out["app_organization"].lower() == str(out.get("org") or "").lower()):
        out.pop("app_organization")
    return out


def job_payload(cfg):
    from cremore_github_provider.github_hosts import api_base, normalize_host

    host = normalize_host(cfg.get("github_host"))
    where = {"github_host": host, "base_url": api_base(host)}
    if cfg.get("app_organization"):
        where["app_organization"] = cfg["app_organization"]
    if cfg.get("org"):
        return {"org": cfg["org"], "max_repos": cfg.get("max_repos", 1000), **where}
    return {"owner": cfg["owner"], "repo": cfg["repo"], "ref": cfg.get("ref", "HEAD"), **where}


def job_kind(cfg):
    return "github-org" if cfg.get("org") else "github"


def config_from_scope(scope, host=""):
    if not scope:
        raise ValueError("profile_ref for github must be owner/repo, an organization or a personal account")
    parts = scope.split("/")
    if not all(GITHUB_NAME_RE.match(p) for p in parts) or len(parts) > 2:
        raise ValueError("profile_ref for github must be owner/repo, an organization or a personal account")
    base = {"owner": parts[0], "repo": parts[1]} if len(parts) == 2 else {"org": parts[0]}
    if host:
        base["github_host"] = host
    return base


def scope_ref(cfg):
    return cfg["org"] if cfg.get("org") else f"{cfg.get('owner', '')}/{cfg.get('repo', '')}"


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None):
    from cremore.sources._collectors import object_limit
    from cremore_github_provider.collectors.github import GitHubCollector, GitHubOrgCollector

    if http_client_factory is None:
        raise ValueError(f"{job.kind} job requires an http client factory")
    if job.kind == "github-org":
        return GitHubOrgCollector(
            http_client_factory(), org=payload["org"], token=payload.get("token", ""),
            base_url=payload.get("base_url") or "https://api.github.com",
            max_repos=int(payload.get("max_repos", 1000)), max_object_bytes=object_limit(max_object_bytes),
            lazy=bool(payload.get("_lazy")), use_archive=payload.get("scan_mode", "BASELINE") == "BASELINE")
    return GitHubCollector(
        http_client_factory(), owner=payload["owner"], repo=payload["repo"], ref=payload.get("ref", "HEAD"),
        token=payload.get("token", ""), base_url=payload.get("base_url") or "https://api.github.com",
        max_object_bytes=object_limit(max_object_bytes), lazy=bool(payload.get("_lazy")),
        use_archive=payload.get("scan_mode", "BASELINE") == "BASELINE")


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None):
    from cremore.sources._collectors import object_limit
    from cremore_github_provider.collectors.github import GitHubCollector

    if http_client_factory is None:
        raise ValueError("scope job with a GitHub root requires an http client factory")
    owner, _, repo = root["provider_resource_id"].partition("/")
    return GitHubCollector(
        http_client_factory(), owner=owner, repo=repo, ref=root.get("ref") or "HEAD", token=payload.get("token", ""),
        base_url=payload.get("base_url") or "https://api.github.com",
        paths=root.get("paths") or [], excluded_paths=root.get("excluded_paths") or [],
        exact_paths=root.get("exact_paths"), max_object_bytes=object_limit(max_object_bytes),
        request_budget=request_budget, lazy=bool(payload.get("_lazy")),
        use_archive=payload.get("scan_mode", "BASELINE") == "BASELINE")


def changes_since(payload, root, cursor, *, http_client, request_budget):
    """Change feed: the branch head and the files changed since ``cursor`` (cremore.scanning.changes)."""
    from cremore_github_provider.changes import changes_since as read

    return read(payload, root, cursor, http_client=http_client, request_budget=request_budget)


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.collectors.base import CollectorError
    from cremore_github_provider.catalog import _github

    if http_client is None:
        raise CollectorError("NEEDS_CONFIGURATION", "no HTTP client")
    return _github(payload, kind, cid, http_client(), now, request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore_github_provider.credential_check import check_github

    return check_github(http_client_factory(), payload.get("token", "") or "",
                        base_url=str(payload.get("base_url") or "https://api.github.com"))


CONTEXT_MEMBER_PAGING = True


def exposure_context(payload, location, *, http_client, members=True, member_page=1):
    """What GitHub says about an exposed file: CODEOWNERS, its last commit, the repository's collaborators."""
    from cremore_github_provider.context import read

    return read(payload, location, http_client=http_client, members=members, member_page=member_page)


def queue_changes(body, attributes, roots):
    """A notification from the customer's own queue (cremore.scanning.triggers)."""
    from cremore_github_provider.changes import queue_changes as read

    return read(body, attributes, roots)
