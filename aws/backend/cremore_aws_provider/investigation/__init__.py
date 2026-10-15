"""AWS investigation: curated IAM potential-access evaluation (Apache-2.0)."""

from cremore_aws_provider.investigation.potential_access import (
    ACTION_CATALOG,
    PotentialAccess,
    PotentialAccessService,
    provider_from_service,
    to_risk_signal,
)
from cremore_aws_provider.investigation.secrets_manager import (
    SecretRecord,
    SecretsManagerInventory,
    SecretsManagerService,
)

__all__ = [
    "ACTION_CATALOG",
    "PotentialAccess",
    "PotentialAccessService",
    "SecretRecord",
    "SecretsManagerInventory",
    "SecretsManagerService",
    "provider_from_service",
    "to_risk_signal",
]
