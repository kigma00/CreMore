"""What each provider connection accepts, so onboarding is not guesswork.

The dashboard cannot infer a provider's editions, scope kinds or secret roles
from the record model: those live in each adapter's validate_spec. This is the
ordered view of provider-owned descriptors. Every entry says what the provider
does not establish as plainly as what it does.
"""

from __future__ import annotations

from cremore.coverage.metadata_models import MetadataOptions
from cremore.coverage.providers import _ADAPTERS


def _descriptor(entry):
    # Onboarding and collection share the same option defaults. Provider-owned
    # overrides (including source selections) take precedence.
    defaults = entry.get("defaults", {})
    options = MetadataOptions().model_dump()
    return {**entry, "defaults": {**defaults, "options": {
        **{name: options[name] for name in entry.get("options", [])},
        **defaults.get("options", {}),
    }}}


PROVIDERS = tuple(_descriptor(registration.descriptor) for registration in _ADAPTERS.values())
_BY_NAME = {entry["provider"]: entry for entry in PROVIDERS}


def catalog():
    """Only providers whose adapter is actually installed are offered."""
    from cremore.coverage.providers import adapter_for
    from cremore.coverage.store import CoverageError

    result = []
    for entry in PROVIDERS:
        try:
            adapter_for(entry["provider"])
        except CoverageError:
            continue
        result.append(dict(entry))
    return result


def descriptor(provider):
    return _BY_NAME.get(provider)
