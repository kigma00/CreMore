"""GitLab content-source configuration and existing collector construction."""

import re

from cremore.sources.validation import enterprise_fields, https_base, path

PROVIDER = "gitlab"
SOURCE_TYPE = "gitlab"
JOB_KINDS = ("gitlab",)
RESOURCE_TYPES = ("GITLAB_REPOSITORY",)
SCOPE_KIND = "path"
FILTERS = ()
CAPABILITY_ORDER = 4
STRUCTURED_CONFIG = True
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = True
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
# A listed object's revision is its git blob id (cremore.scanning.service caches by it).
CONTENT_ADDRESSED = True
CAPABILITY = {"id": "gitlab", "name": "GitLab", "command": "gitlab", "kind": "BATCH",
    "description": "Approved projects on GitLab.com, Self-Managed or Dedicated.",
    "credential_env": ["GITLAB_TOKEN"], "external_credential_env": ["GITLAB_TOKEN"],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None


def validate_config(cfg):
    out = enterprise_fields(cfg, {"project", "group", "base_url", "ref"})
    if bool(out.get("project")) == bool(out.get("group")):
        raise ValueError("GITLAB_PROJECT_OR_GROUP_REQUIRED")
    key = "project" if out.get("project") else "group"
    if not isinstance(out[key], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", out[key]):
        raise ValueError("INVALID_GITLAB_REFERENCE")
    out[key] = path(out[key])
    out["base_url"] = https_base(out.get("base_url", "https://gitlab.com"))
    out["ref"] = out.get("ref", "HEAD")
    if not isinstance(out["ref"], str) or not out["ref"] or len(out["ref"]) > 256 or any(ord(c) < 32 for c in out["ref"]):
        raise ValueError("INVALID_GIT_REF")
    return out


def job_payload(cfg):
    return {key: value for key, value in validate_config(cfg).items() if key != "declaration"} | {"provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    return {"project": scope}


def scope_ref(cfg):
    return cfg.get("group") or cfg.get("bucket") or cfg.get("project") or cfg.get("space") or ""


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None):
    from cremore.sources._collectors import enterprise_collector

    return enterprise_collector(content_module(), payload, http_client_factory=http_client_factory,
                                max_object_bytes=max_object_bytes)


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None):
    from cremore.sources._collectors import enterprise_root

    root = {**root, "project": root["provider_resource_id"]}
    return enterprise_root(content_module(), payload, root, http_client_factory=http_client_factory,
                           max_object_bytes=max_object_bytes, request_budget=request_budget)


def content_module():
    from cremore_gitlab_provider import content
    return content


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.sources._collectors import enterprise_resources
    return enterprise_resources(content_module(), payload, kind, cid,
        http_client=http_client, now=now, request_budget=request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore.collectors.credential_probe import check_roots

    return check_roots(content_module().roots, payload, http_client_factory())


def changes_since(payload, root, cursor, *, http_client, request_budget):
    """Change feed: the head and the files changed since ``cursor`` (cremore.scanning.changes)."""
    from cremore_gitlab_provider.changes import changes_since as read

    return read(payload, root, cursor, http_client=http_client, request_budget=request_budget)


CONTEXT_MEMBER_PAGING = True


def exposure_context(payload, location, *, http_client, members=True, member_page=1):
    """What GitLab says about an exposed file: CODEOWNERS, its last commit, the project's members."""
    from cremore_gitlab_provider.context import read

    return read(payload, location, http_client=http_client, members=members, member_page=member_page)


def queue_changes(body, attributes, roots):
    """A notification from the customer's own queue (cremore.scanning.triggers)."""
    from cremore_gitlab_provider.changes import queue_changes as read

    return read(body, attributes, roots)
