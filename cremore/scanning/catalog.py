"""Metadata-only catalog dispatch through explicitly registered source libraries."""
from __future__ import annotations

import datetime as _dt
from collections.abc import Callable

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.scanning.catalog_projection import MAX_LISTED
from cremore.sources.registry import PROVIDERS

__all__ = ["MAX_LISTED", "list_resources"]

def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def list_resources(payload: dict, *, s3_client: Callable[[], object] | None = None,
                   http_client: Callable[[], object] | None = None, now: _dt.datetime | None = None,
                   request_budget: RequestBudget | None = None) -> tuple[list[dict], str]:
    """(resources, completeness) for a catalog-refresh payload.

    ``payload["reference"]`` narrows the work to confirming one already-approved
    reference; ``payload["query"]`` runs an explicit Notion title search. Both
    are merged into the catalog by the worker; a plain refresh replaces it.
    """

    provider = payload.get("provider", "")
    kind, cid = payload["connection_kind"], payload["connection_id"]
    now = now or _now()
    request_budget = request_budget or RequestBudget()
    module = PROVIDERS.get(provider)
    if module is None:
        raise CollectorError("UNSUPPORTED_PROVIDER", provider or "unknown")
    return module.list_resources(payload, kind, cid, s3_client=s3_client,
        http_client=http_client, now=now, request_budget=request_budget)


def _enterprise(payload, kind, cid, client, now, request_budget):
    from cremore.scanning.catalog_projection import enterprise_resources
    return enterprise_resources(PROVIDERS[payload["provider"]].content_module().roots,
        payload, kind, cid, client, now, request_budget)


def __getattr__(name):
    from importlib import import_module
    # Compatibility for existing private helper imports; provider code uses its own library.
    owners = {"_bucket": "aws", "_head": "aws", "_aws": "aws",
        "_gh_get": "github", "_repo_resource": "github", "_github": "github",
        "_notion_headers": "notion", "_notion_ok": "notion", "_title": "notion",
        "_notion_resource": "notion", "_notion": "notion"}
    if name not in owners:
        raise AttributeError(name)
    return getattr(import_module(f"cremore_{owners[name]}_provider.catalog"), name)
