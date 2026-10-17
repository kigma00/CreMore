"""Build existing collectors through the explicitly registered source modules.

The worker owns secret resolution and shared budgets. Each source owns its
constructor arguments and approved-root conversion; modules receive only the
clients already supplied by the caller.
"""

from __future__ import annotations

from collections.abc import Callable

from cremore.collectors.base import DEFAULT_MAX_OBJECT_BYTES, Collector, RequestBudget
from cremore.collectors.bytes_source import BytesCollector
from cremore.domain.models import ScanJob
from cremore.sources.registry import BY_JOB_KIND, BY_RESOURCE_TYPE

S3ClientFactory = Callable[[ScanJob], object]
HTTPClientFactory = Callable[[], object]


def build_collector(
    job: ScanJob,
    *,
    s3_client_factory: S3ClientFactory | None = None,
    s3_partition_factory: Callable[[ScanJob], str] | None = None,
    http_client_factory: HTTPClientFactory | None = None,
    secret_resolver: object | None = None,
    max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
) -> Collector:
    if max_object_bytes <= 0:
        raise ValueError("max_object_bytes must be positive")
    from cremore.secretstore.resolver import inject_secret

    payload = inject_secret(job.kind, job.payload or {}, secret_resolver,
                            github_client_factory=http_client_factory)
    clients = {"s3_client_factory": s3_client_factory, "http_client_factory": http_client_factory,
               "max_object_bytes": max_object_bytes}
    module = BY_JOB_KIND.get(job.kind)
    if module is not None:
        if module.PROVIDER == "aws":
            clients["s3_partition_factory"] = s3_partition_factory
        return module.build_collector(job, payload, **clients)
    if job.kind == "inline":
        return BytesCollector.one(
            (payload.get("text") or "").encode("utf-8"),
            source_type=payload.get("source_type", "inline"),
            resource=payload.get("resource_name", "inline"),
            location=payload.get("location", "inline"),
            exposure=payload.get("exposure", "unknown"),
        )
    if job.kind == "scope":
        return build_scoped(job, payload, s3_partition_factory=s3_partition_factory, **clients)
    raise ValueError(f"unknown job kind {job.kind!r}")


def build_scoped(
    job: ScanJob,
    p: dict,
    *,
    s3_client_factory=None,
    s3_partition_factory=None,
    http_client_factory=None,
    max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
) -> Collector:
    """Build one collector per approved root, sharing the profile's budgets."""
    from cremore.collectors.scoped import ScopedCollector

    budgets = p.get("budgets") or {}
    request_budget = RequestBudget(min(int(budgets.get("requests", 10_000)), int(p.get("max_requests", 100_000))))
    parts: list[Collector] = []
    for root in p.get("roots") or []:
        module = BY_RESOURCE_TYPE.get(root.get("resource_type"))
        if module is not None:
            extra = {"s3_partition_factory": s3_partition_factory} if module.PROVIDER == "aws" else {}
            parts.append(module.build_root(job, p, root, s3_client_factory=s3_client_factory,
                http_client_factory=http_client_factory, max_object_bytes=max_object_bytes,
                request_budget=request_budget, **extra))
    return ScopedCollector(parts, budget_bytes=budgets.get("bytes"), budget_seconds=budgets.get("seconds"))
