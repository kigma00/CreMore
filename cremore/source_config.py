"""Compatibility exports for provider-owned source configuration."""

from cremore.sources.registry import (  # noqa: F401 -- compatibility exports
    RESOURCE_SOURCE,
    STRUCTURED_PROVIDERS,
)
from cremore.sources.validation import https_base, path  # noqa: F401 -- compatibility exports

PROVIDERS = STRUCTURED_PROVIDERS


def config(provider, value):
    from cremore.sources.registry import PROVIDERS as modules

    if provider not in PROVIDERS or not isinstance(value, dict):
        raise ValueError("UNSUPPORTED_PROVIDER")
    return modules[provider].validate_config(value)
