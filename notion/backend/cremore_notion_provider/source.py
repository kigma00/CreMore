"""Notion workspace/page scope and existing collector construction."""

PROVIDER = "notion"
SOURCE_TYPE = "notion"
JOB_KINDS = ("notion",)
RESOURCE_TYPES = ("NOTION_PAGE", "NOTION_DATA_SOURCE")
SCOPE_KIND = "page"
FILTERS = ("parent_id", "known_root_id", "edited_after", "edited_before")
CAPABILITY_ORDER = 2
STRUCTURED_CONFIG = False
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = False
CAPABILITY = {"id": "notion", "name": "Notion", "command": "notion", "kind": "BATCH",
    "description": "Pages shared with the connection.",
    "credential_env": ["NOTION_TOKEN"], "external_credential_env": ["NOTION_TOKEN"],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = (
    ("Stopping use here does not revoke the integration secret at Notion. Revoke or rotate it in "
     "Notion → Settings → Connections / My integrations."),
    "https://www.notion.so/my-integrations")


def validate_config(cfg):
    return cfg


def job_payload(cfg):
    return {"max_pages": cfg.get("max_pages", 1000)}


def job_kind(cfg):
    return "notion"


def config_from_scope(scope, host=""):
    return {}


def scope_ref(cfg):
    return "workspace"


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None):
    from cremore.sources._collectors import object_limit
    from cremore_notion_provider.collectors.notion import NotionCollector

    if http_client_factory is None:
        raise ValueError("notion job requires an http client factory")
    return NotionCollector(
        http_client_factory(), token=payload["token"], max_pages=int(payload.get("max_pages", 1000)),
        max_object_bytes=object_limit(max_object_bytes), watermark_since=payload.get("watermark_since"),
        failed_page_ids=payload.get("failed_keys"))


def approved_pages(root):
    """The page ids an approved root names, as it spells them; ``exact_page_ids`` narrows it."""
    if "exact_page_ids" in root:
        return list(root["exact_page_ids"])
    ids = ([root["provider_resource_id"]]
           if root.get("resource_type") == "NOTION_PAGE" and root.get("provider_resource_id") else [])
    if root.get("page_mode") != "PAGE_ONLY":
        ids += root.get("descendant_ids") or []
    return list(dict.fromkeys(ids))


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None):
    from cremore.sources._collectors import object_limit
    from cremore_notion_provider.collectors.notion import NotionCollector

    if http_client_factory is None:
        raise ValueError("scope job with a Notion root requires an http client factory")
    return NotionCollector(
        http_client_factory(), token=payload.get("token", ""), page_ids=approved_pages(root),
        max_object_bytes=object_limit(max_object_bytes), request_budget=request_budget,
        watermark_since=root.get("watermark_since"), failed_page_ids=root.get("failed_keys"),
        watched_keys=root.get("watched_keys"), page_meta=root.get("page_meta"))


def plan_metadata(payload, roots, *, http_client, request_budget):
    """Search-derived headers of the roots' approved pages, for a run's plan (cremore_notion_provider.search)."""
    from cremore_notion_provider.search import plan_metadata as read

    return read(payload, roots, http_client=http_client, request_budget=request_budget)


def changes_since_batch(payload, roots, states, *, http_client, request_budget):
    """Change feed: the approved pages edited since the last look, from one search walk."""
    from cremore_notion_provider.search import changes_since_batch as read

    return read(payload, roots, states, http_client=http_client, request_budget=request_budget)


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.collectors.base import CollectorError
    from cremore_notion_provider.catalog import _notion

    if http_client is None:
        raise CollectorError("NEEDS_CONFIGURATION", "no HTTP client")
    return _notion(payload, kind, cid, http_client(), now, request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore_notion_provider.credential_check import check_notion

    return check_notion(http_client_factory(), payload.get("token", "") or "")


def exposure_context(payload, location, *, http_client, members=True):
    """What Notion says about an exposed page: who last edited it (cremore.governance.ownership)."""
    from cremore_notion_provider.context import read

    return read(payload, location, http_client=http_client, members=members)
