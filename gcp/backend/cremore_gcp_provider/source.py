"""Cloud Storage content-source configuration and existing collector construction."""

import re

from cremore.sources.validation import enterprise_fields

PROVIDER = "gcp"
SOURCE_TYPE = "gcp"
JOB_KINDS = ("gcp",)
RESOURCE_TYPES = ("GCS_BUCKET",)
SCOPE_KIND = "object"
FILTERS = ()
CAPABILITY_ORDER = 5
STRUCTURED_CONFIG = True
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = False
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
ACCESS_CONTEXT_SCOPE = "location"
CAPABILITY = {"id": "gcp", "name": "GCP Cloud Storage", "command": "gcp", "kind": "BATCH",
    "description": "Approved buckets using ADC or a connection token.",
    "credential_env": [], "external_credential_env": [],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None


def validate_config(cfg):
    out = enterprise_fields(cfg, {"project", "bucket"}, literal_paths=True)
    if not out.get("bucket") and not out.get("project"):
        raise ValueError("GCP_PROJECT_OR_BUCKET_REQUIRED")
    if out.get("bucket") and (not isinstance(out["bucket"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", out["bucket"])):
        raise ValueError("INVALID_GCS_BUCKET")
    if out.get("project") and (not isinstance(out["project"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", out["project"])):
        raise ValueError("INVALID_GCP_PROJECT")
    return out


def job_payload(cfg):
    return {key: value for key, value in validate_config(cfg).items() if key != "declaration"} | {"provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    return {"bucket": scope}


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

    root = {**root, "bucket": root["provider_resource_id"]}
    if root.get("all_current_objects"):
        root["prefixes"] = []
    return enterprise_root(content_module(), payload, root, http_client_factory=http_client_factory,
                           max_object_bytes=max_object_bytes, request_budget=request_budget)


def content_module():
    from cremore_gcp_provider import content
    return content


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.sources._collectors import enterprise_resources
    return enterprise_resources(content_module(), payload, kind, cid,
        http_client=http_client, now=now, request_budget=request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore_gcp_provider.credential_check import check_gcp

    return check_gcp(payload, http_client_factory())


def exposure_context(payload, location, *, http_client, members=True):
    from cremore_gcp_provider.context import read

    return read(payload, location, http_client=http_client, members=members)


def queue_changes(body, attributes, roots):
    """A notification from the customer's own queue (cremore.scanning.triggers)."""
    from cremore_gcp_provider.pubsub import storage_changes as read

    return read(body, attributes, roots)
