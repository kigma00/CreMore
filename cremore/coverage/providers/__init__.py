"""Explicit in-process adapters; unknown providers never fall back to Vault."""

from dataclasses import dataclass
from importlib import import_module

from cremore_atlassian_provider.metadata.descriptor import ATLASSIAN, BITBUCKET
from cremore_azure_provider.arm.descriptor import DESCRIPTOR as AZURE_RESOURCE_MANAGER
from cremore_azure_provider.devops_tokens.descriptor import DESCRIPTOR as AZURE_DEVOPS
from cremore_azure_provider.entra.descriptor import DESCRIPTOR as AZURE_ENTRA
from cremore_azure_provider.entra_id.descriptor import DESCRIPTOR as ENTRA_ID
from cremore_azure_provider.metadata.descriptor import DESCRIPTOR as AZURE_KEY_VAULT
from cremore_gcp_provider.metadata.descriptor import DESCRIPTOR as GCP
from cremore_gcp_provider.workspace.descriptor import DESCRIPTOR as GOOGLE_WORKSPACE
from cremore_github_provider.identity.descriptor import DESCRIPTOR as GITHUB_IDENTITY
from cremore_github_provider.metadata.descriptor import DESCRIPTOR as GITHUB
from cremore_gitlab_provider.metadata.descriptor import DESCRIPTOR as GITLAB
from cremore_keycloak_provider.descriptor import DESCRIPTOR as KEYCLOAK
from cremore_notion_provider.metadata.descriptor import DESCRIPTOR as NOTION
from cremore_okta_provider.descriptor import DESCRIPTOR as OKTA
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
    # Integration (ported from refactor/saas-libraries): records a machine submits must pass the
    # adapter's validate_machine_record, which must then exist when the adapter loads. Replaces
    # the `spec.provider == "gitlab"` check in validate_record with a registration fact.
    machine_guard: bool = False
    # Identity collectors (okta, keycloak, entra_id, google_workspace, github_identity) receive the
    # identity digester and keep emails and logins only as keyed digests.
    identity_digest: bool = False
    export_control: bool = False
    # A module whose credential_owner(row) names the account that owns an issued
    # credential, for the departed-owner check (cremore.identity.leavers).
    owners: str = ""


_ADAPTERS = {
    "gitlab": AdapterRegistration("cremore_gitlab_provider.metadata.adapter", GITLAB, value_context=True, comparison=True,
                                  machine_guard=True, owners="cremore_gitlab_provider.metadata.owners"),
    "gcp": AdapterRegistration("cremore_gcp_provider.metadata.adapter", GCP, value_context=True, comparison=True),
    # Its recollection is only the installation check (plan_recollection refuses any other retry).
    "github": AdapterRegistration("cremore_github_provider.metadata.adapter", GITHUB, value_context=True, export_control=True,
                                  recollection=True, owners="cremore_github_provider.metadata.owners"),
    "atlassian": AdapterRegistration(
        "cremore_atlassian_provider.metadata.adapter", ATLASSIAN, recollection=True, comparison=True,
        owners="cremore_atlassian_provider.metadata.owners"),
    "bitbucket": AdapterRegistration(
        "cremore_atlassian_provider.metadata.adapter", BITBUCKET, recollection=True, comparison=True),
    "azure_key_vault": AdapterRegistration(
        "cremore_azure_provider.metadata.adapter", AZURE_KEY_VAULT, value_context=True, comparison=True),
    "notion": AdapterRegistration("cremore_notion_provider.metadata.adapter", NOTION, comparison=True,
                                  owners="cremore_notion_provider.metadata.owners"),
    "slack": AdapterRegistration("cremore_slack_provider.metadata.adapter", SLACK, comparison=True),
    "azure_entra": AdapterRegistration("cremore_azure_provider.entra.adapter", AZURE_ENTRA),
    "azure_resource_manager": AdapterRegistration("cremore_azure_provider.arm.adapter", AZURE_RESOURCE_MANAGER, value_context=True),
    "azure_devops": AdapterRegistration("cremore_azure_provider.devops_tokens.adapter", AZURE_DEVOPS,
                                        owners="cremore_azure_provider.devops_tokens.owners"),
    "okta": AdapterRegistration("cremore_okta_provider.adapter", OKTA, machine_guard=True, identity_digest=True),
    "keycloak": AdapterRegistration("cremore_keycloak_provider.adapter", KEYCLOAK, machine_guard=True,
                                    identity_digest=True),
    "entra_id": AdapterRegistration("cremore_azure_provider.entra_id.adapter", ENTRA_ID, machine_guard=True,
                                    identity_digest=True),
    "github_identity": AdapterRegistration("cremore_github_provider.identity.adapter", GITHUB_IDENTITY,
                                           machine_guard=True, identity_digest=True),
    "google_workspace": AdapterRegistration("cremore_gcp_provider.workspace.adapter", GOOGLE_WORKSPACE,
                                            machine_guard=True, identity_digest=True),
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
    if registration.machine_guard and not callable(getattr(adapter, "validate_machine_record", None)):
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
            # Optional only for providers whose object grammar already proves
            # exact scope. GitLab root traversal needs the stricter guard, which
            # its registration declares (machine_guard). collector_for already
            # refuses a guarded adapter without it; this stays as defense in depth.
            if guard is None and _ADAPTERS[spec.provider].machine_guard:
                return False
            if guard is not None and not guard(spec, record):
                return False
    except (TypeError, ValueError):
        return False
    return True
