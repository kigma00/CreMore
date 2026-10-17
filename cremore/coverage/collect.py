"""Compatibility exports for provider inventory functions and shared collection contracts."""
from cremore_aws_provider.coverage import collect_aws_vault, collect_iam, collect_usage

from cremore.coverage.collection import Collection, CollectionLimit, iso

__all__ = [
           "Collection",
           "CollectionLimit",
           "collect_aws_vault",
           "collect_iam",
           "collect_usage",
           "iso",
]
