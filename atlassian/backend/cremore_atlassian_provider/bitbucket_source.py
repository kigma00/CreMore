"""Bitbucket content-source configuration and existing collector construction."""

import re

from cremore.sources.validation import enterprise_fields, https_base

PROVIDER = "bitbucket"
FAMILY = "atlassian"
SOURCE_TYPE = "bitbucket"
JOB_KINDS = ("bitbucket",)
RESOURCE_TYPES = ("BITBUCKET_REPOSITORY",)
SCOPE_KIND = "path"
FILTERS = ()
CAPABILITY_ORDER = 3
STRUCTURED_CONFIG = True
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = True
# A pinned commit plus the object's location identifies its bytes. Commit IDs
# are not blob IDs: never share these results across different paths.
REVISION_CACHE = True
CAPABILITY = {"id": "bitbucket", "name": "Bitbucket", "command": "bitbucket", "kind": "BATCH",
    "description": "Approved Cloud or Data Center repositories and paths.",
    "credential_env": ["BITBUCKET_TOKEN"], "external_credential_env": ["BITBUCKET_TOKEN"],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None


def validate_config(cfg):
    out = enterprise_fields(cfg, {"workspace", "project", "repo", "base_url", "edition", "ref", "auth_type", "username",
                                  "max_changes"})
    out["edition"] = out.get("edition", "cloud")
    if out["edition"] not in ("cloud", "data_center"):
        raise ValueError("INVALID_BITBUCKET_EDITION")
    cloud = out["edition"] == "cloud"
    out["base_url"] = https_base(out.get("base_url", "https://api.bitbucket.org" if cloud else ""))
    if cloud and out["base_url"] != "https://api.bitbucket.org":
        raise ValueError("BITBUCKET_CLOUD_API_REQUIRED")
    key = "workspace" if cloud else "project"
    if not isinstance(out.get(key), str) or not re.fullmatch(r"[A-Za-z0-9_~-]{1,128}", out[key]):
        raise ValueError("BITBUCKET_WORKSPACE_OR_PROJECT_REQUIRED")
    if out.get("repo") and (not isinstance(out["repo"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", out["repo"]) or out["repo"] in (".", "..")):
        raise ValueError("INVALID_BITBUCKET_REPOSITORY")
    out["auth_type"] = out.get("auth_type", "bearer")
    if out["auth_type"] not in ("bearer", "api_token") or not cloud and out["auth_type"] != "bearer":
        raise ValueError("INVALID_BITBUCKET_AUTH")
    if out["auth_type"] == "api_token" and (not isinstance(out.get("username"), str) or not re.fullmatch(r"[^\s:@]+@[^\s:@]+", out["username"])):
        raise ValueError("BITBUCKET_API_TOKEN_EMAIL_REQUIRED")
    if "max_changes" in out and (cloud or type(out["max_changes"]) is not int or not 1 <= out["max_changes"] <= 100000):
        # Data Center's page.max.changes (default 1,000): a change list that long is cut without notice.
        raise ValueError("INVALID_BITBUCKET_MAX_CHANGES")
    out["ref"] = out.get("ref", "HEAD")
    if not isinstance(out["ref"], str) or not out["ref"] or len(out["ref"]) > 256 or any(ord(c) < 32 for c in out["ref"]):
        raise ValueError("INVALID_GIT_REF")
    return out


def job_payload(cfg):
    return {key: value for key, value in validate_config(cfg).items() if key != "declaration"} | {"provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    parts = scope.split("/", 1)
    return {"workspace": parts[0], **({"repo": parts[1]} if len(parts) == 2 else {})}


def scope_ref(cfg):
    return (cfg.get("workspace") or cfg.get("project", "")) + ("/" + cfg["repo"] if cfg.get("repo") else "")


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None):
    from cremore.sources._collectors import enterprise_collector

    return enterprise_collector(content_module(), payload, http_client_factory=http_client_factory,
                                max_object_bytes=max_object_bytes)


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None):
    from cremore.sources._collectors import enterprise_root

    owner, _, slug = root["provider_resource_id"].partition("/")
    if owner != payload["workspace" if payload["edition"] == "cloud" else "project"] or not slug:
        raise ValueError("BITBUCKET_ROOT_OUTSIDE_CONNECTION")
    root = {**root, "repo": slug}
    return enterprise_root(content_module(), payload, root, http_client_factory=http_client_factory,
                           max_object_bytes=max_object_bytes, request_budget=request_budget)


def content_module():
    from cremore_atlassian_provider import bitbucket_content
    return bitbucket_content


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.sources._collectors import enterprise_resources
    return enterprise_resources(content_module(), payload, kind, cid,
        http_client=http_client, now=now, request_budget=request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore.collectors.credential_probe import check_roots

    return check_roots(content_module().roots, payload, http_client_factory())


def exposure_context(payload, location, *, http_client, members=True):
    """What Bitbucket says about an exposed file: the last commit that changed it."""
    from cremore_atlassian_provider.bitbucket_context import read

    return read(payload, location, http_client=http_client, members=members)


def changes_since(payload, root, cursor, *, http_client, request_budget):
    """Change feed: the head and the files changed since ``cursor`` (cremore.scanning.changes)."""
    from cremore_atlassian_provider.bitbucket_changes import changes_since as read

    return read(payload, root, cursor, http_client=http_client, request_budget=request_budget)


def queue_changes(body, attributes, roots):
    """A notification from the customer's own queue (cremore.scanning.triggers)."""
    from cremore_atlassian_provider.bitbucket_changes import queue_changes as read

    return read(body, attributes, roots)
