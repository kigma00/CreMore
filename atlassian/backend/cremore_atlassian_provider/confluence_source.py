"""Confluence content-source configuration and existing collector construction."""

import re

from cremore.sources.validation import enterprise_fields, https_base

PROVIDER = "confluence"
FAMILY = "atlassian"
SOURCE_TYPE = "confluence"
JOB_KINDS = ("confluence",)
RESOURCE_TYPES = ("CONFLUENCE_PAGE",)
SCOPE_KIND = "path"
FILTERS = ()
CAPABILITY_ORDER = 6
STRUCTURED_CONFIG = True
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = True
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
CAPABILITY = {"id": "confluence", "name": "Confluence", "command": "confluence", "kind": "BATCH",
    "description": "Approved Cloud or Data Center pages and readable attachments.",
    "credential_env": ["CONFLUENCE_TOKEN"], "external_credential_env": ["CONFLUENCE_TOKEN"],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None


def validate_config(cfg):
    out = enterprise_fields(cfg, {"space", "base_url", "site_url", "edition"})
    out["base_url"] = https_base(out.get("base_url", ""))
    if out.get("site_url"):
        out["site_url"] = https_base(out["site_url"])
    out["edition"] = out.get("edition", "cloud")
    if out["edition"] not in ("cloud", "data_center"):
        raise ValueError("INVALID_CONFLUENCE_EDITION")
    if not isinstance(out.get("space"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", out["space"]):
        raise ValueError("CONFLUENCE_SPACE_REQUIRED")
    if out["edition"] == "cloud" and (not out["space"].isdigit() or not out["base_url"].endswith("/wiki")):
        raise ValueError("CONFLUENCE_CLOUD_SPACE_ID_AND_WIKI_BASE_REQUIRED")
    return out


def job_payload(cfg):
    return {key: value for key, value in validate_config(cfg).items() if key != "declaration"} | {"provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    return {"space": scope}


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

    root = {**root, "page_id": root["provider_resource_id"]}
    return enterprise_root(content_module(), payload, root, http_client_factory=http_client_factory,
                           max_object_bytes=max_object_bytes, request_budget=request_budget)


def content_module():
    from cremore_atlassian_provider import confluence_content
    return confluence_content


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.sources._collectors import enterprise_resources
    return enterprise_resources(content_module(), payload, kind, cid,
        http_client=http_client, now=now, request_budget=request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore.collectors.credential_probe import check_roots

    return check_roots(content_module().roots, payload, http_client_factory())


def exposure_context(payload, location, *, http_client, members=True):
    """What Confluence says about an exposed page or attachment: who wrote its current version."""
    from cremore_atlassian_provider.confluence_context import read

    return read(payload, location, http_client=http_client, members=members)


def changes_since_batch(payload, roots, states, *, http_client, request_budget):
    """Change feed: which approved pages of the space changed since the last look (one CQL search)."""
    from cremore_atlassian_provider.confluence_changes import changes_since_batch as read

    return read(payload, roots, states, http_client=http_client, request_budget=request_budget)
