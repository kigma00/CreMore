"""Content collectors (Apache-2.0).

A collector yields the objects to scan as (ResourceRef, bytes) pairs. Each
provider (S3, a GitHub repository, a Notion workspace) has its own collector; all
share the :class:`Collector` protocol so the scan service is provider-agnostic.
"""

from importlib import import_module
from typing import TYPE_CHECKING

from cremore.collectors.base import CollectedObject, Collector
from cremore.collectors.bytes_source import BytesCollector

if TYPE_CHECKING:
    from cremore_aws_provider.collectors.s3 import S3Collector
    from cremore_github_provider.collectors.github import GitHubCollector, GitHubOrgCollector
    from cremore_notion_provider.collectors.notion import NotionCollector

__all__ = [
    "BytesCollector",
    "CollectedObject",
    "Collector",
    "GitHubCollector",
    "GitHubOrgCollector",
    "NotionCollector",
    "S3Collector",
]


def __getattr__(name: str):
    # Providers import our base contract; load compatibility exports only on demand.
    modules = {
        "S3Collector": "cremore_aws_provider.collectors.s3",
        "GitHubCollector": "cremore_github_provider.collectors.github",
        "GitHubOrgCollector": "cremore_github_provider.collectors.github",
        "NotionCollector": "cremore_notion_provider.collectors.notion",
    }
    if name not in modules:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(modules[name]), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
