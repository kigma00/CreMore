"""Explicit in-process adapters; unknown providers never fall back to Vault."""

from dataclasses import dataclass
from importlib import import_module

from cremore_github_provider.metadata.descriptor import DESCRIPTOR as GITHUB
from cremore_notion_provider.metadata.descriptor import DESCRIPTOR as NOTION
from cremore_slack_provider.metadata.descriptor import DESCRIPTOR as SLACK

from cremore.coverage.collector_runtime import CollectorRuntime
from cremore.coverage.errors import CoverageError


@dataclass(frozen=True, slots=True)
class AdapterRegistration:
    module: str
    descriptor: dict[str, object]
    value_context: bool = False
    recollection: bool = False
    comparison: bool = False
    # Identity collectors receive the identity digester and retain keyed digests only.
    identity_digest: bool = False
    export_control: bool = False
    # A module whose credential_owner(row) names the account that owns an issued
    # credential, for the departed-owner check (cremore.identity.leavers).
    owners: str = ""


_ADAPTERS = {
    "github": AdapterRegistration("cremore_github_provider.metadata.adapter", GITHUB, value_context=True, export_control=True,
                                  recollection=True, owners="cremore_github_provider.metadata.owners"),
    "notion": AdapterRegistration("cremore_notion_provider.metadata.adapter", NOTION, comparison=True,
                                  owners="cremore_notion_provider.metadata.owners"),
    "slack": AdapterRegistration("cremore_slack_provider.metadata.adapter", SLACK, comparison=True),
}


def collector_for(provider: str) -> CollectorRuntime:
    registration = _ADAPTERS.get(provider)
    if registration is None:
        raise CoverageError("METADATA_ADAPTER_UNAVAILABLE")
    try:
        adapter = import_module(registration.module)
    except ImportError:
        raise CoverageError("METADATA_ADAPTER_UNAVAILABLE") from None
    if not all(callable(getattr(adapter, method, None)) for method in ("collect_pages", "validate_spec", "validate_record")):
        raise CoverageError("METADATA_ADAPTER_UNAVAILABLE")
    planner = getattr(adapter, "plan_recollection", None) if registration.recollection else None
    if registration.recollection and not callable(planner):
        raise CoverageError("METADATA_ADAPTER_UNAVAILABLE")
    comparison = getattr(adapter, "_compare_runs", None) if registration.comparison else None
    if registration.comparison and not callable(comparison):
        raise CoverageError("METADATA_ADAPTER_UNAVAILABLE")
    return CollectorRuntime(adapter=adapter, uses_value_context=registration.value_context,
                            uses_identity_digest=registration.identity_digest,
                            uses_export_control=registration.export_control,
                            planner=planner, comparison=comparison,
                            optional_secret_roles=frozenset(registration.descriptor.get("optional_secret_roles", ())))


def adapter_for(provider):
    """Compatibility entry point for provider-specific record/replay helpers."""
    return collector_for(provider).adapter


def validate_spec(spec):
    collector = collector_for(spec.provider)
    collector.validate_spec(spec)
    return collector.adapter


def validate_record(spec, record, *, trusted_discovery=False):
    adapter = validate_spec(spec)
    try:
        if not adapter.validate_record(spec, record):
            return False
        if not trusted_discovery:
            guard = getattr(adapter, "validate_machine_record", None)
            if guard is not None and not guard(spec, record):
                return False
    except (TypeError, ValueError):
        return False
    return True
