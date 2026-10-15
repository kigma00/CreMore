"""Compatibility exports for provider inventory functions and shared collection contracts."""
from cremore_aws_provider.coverage import collect_aws_vault, collect_iam, collect_usage
from cremore_gcp_provider.coverage import collect_gcp
from cremore_vault_provider.coverage import collect_kv

from cremore.coverage.collection import Collection, CollectionLimit, iso

__all__ = [
           "Collection",
           "CollectionLimit",
           "collect_aws_vault",
           "collect_gcp",
           "collect_iam",
           "collect_kv",
           "collect_usage",
           "iso",
]
