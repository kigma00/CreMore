"""Bind a worker's secret reader to the current provider-owned child.

The envelope's header is never used as an authorization source. The provider
owner and its child declaration determine where an existing credential may go.
Cloud IAM and separately mounted recipient keys remain the external boundary.
"""

from __future__ import annotations

import uuid

from cremore.secretstore.resolver import SecretRefError


def _refs(value):
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    return value.get("secret_refs") or ({"secret_ref": value["secret_ref"]} if value.get("secret_ref") else {})


def resolver_for_child(repo, kind, child_id, resolver, *, payload=None, spec=None, settings=None, job_kind=None):
    """Check credential ownership and outbound coordinates before decrypting.

Legacy callers preserve their existing resolver contract. An isolated reader
or v3 envelope requires an existing provider child and a matching current ref.
No provider request is made by this check.
"""
    supplied = spec.model_dump() if hasattr(spec, "model_dump") else spec or payload or {}
    supplied_refs = _refs(supplied)
    # Inline and workload-identity jobs open no stored connector credential.
    # Their scope/account authorization remains with the existing worker guards.
    if not supplied_refs:
        return resolver
    strict = bool(getattr(settings, "isolated_deployment", False))
    if not strict and not any(isinstance(ref, str) and ref.startswith("sealed:v3:")
                              for ref in supplied_refs.values()):
        return resolver
    if resolver is None or not child_id:
        raise SecretRefError("CREDENTIAL_OWNER_REQUIRED")

    from cremore.onboarding import catalog, children, targets
    from cremore.onboarding.store import ProviderConnectionStore, active_plans
    from cremore.secretstore.isolation import binding_for_record

    store = ProviderConnectionStore(repo)
    parent_id = store.parent_of(kind, child_id)
    owner = store.get(parent_id) if parent_id else None
    if owner is None or owner["status"] != "ACTIVE":
        raise SecretRefError("CREDENTIAL_OWNER_UNAVAILABLE")
    links = [link for link in store.children(parent_id)
             if link["kind"] == kind and str(link["child_id"]) == str(child_id)]
    if len(links) != 1:
        raise SecretRefError("CREDENTIAL_OWNER_REQUIRED")
    link = links[0]
    plans = active_plans(owner)
    if link["purpose"] not in plans:
        raise SecretRefError("CREDENTIAL_PURPOSE_DISABLED")
    expected_refs = {slot: owner["secret_refs"][role] for slot, role in (link.get("secret_slots") or {}).items()
                     if role in owner.get("secret_refs", {})}
    if supplied_refs != expected_refs or not children.points_at_credential(repo, owner, link):
        raise SecretRefError("CREDENTIAL_REFERENCE_CHANGED")
    try:
        candidates = targets.described(catalog.module(owner["provider"]), owner, link["purpose"],
                                       plans[link["purpose"]])
        if kind == "content":
            from cremore.domain.connections import job_payload_for, validate_connection
            from cremore.domain.models import Connection
            from cremore.sources.registry import BY_SOURCE, PROVIDERS

            source = repo.get_connection(uuid.UUID(str(child_id)))
            if source is None or source.status == "DISABLED":
                raise SecretRefError("CREDENTIAL_SOURCE_DISABLED")
            source_module = PROVIDERS[source.provider]
            if (supplied.get("provider", source.provider) != source.provider
                    or supplied.get("source_type", source_module.SOURCE_TYPE) != source_module.SOURCE_TYPE):
                raise SecretRefError("CREDENTIAL_SOURCE_TYPE_CHANGED")
            generic = {"scope", "credential-check", "catalog-refresh"}
            if source.provider == "github":
                generic.add("github-secret-scanning")
            if job_kind is not None and job_kind not in generic | set(source_module.JOB_KINDS):
                raise SecretRefError("CREDENTIAL_SOURCE_TYPE_CHANGED")
            # Every declared source configuration value must agree with the
            # persisted source and the outgoing payload. Root selection may add
            # fields to a payload, but cannot replace authentication authority.
            candidates = [c for c in candidates if c.get("kind") == kind
                          and BY_SOURCE[c["source_type"]].PROVIDER == source.provider]
            configs = []
            for candidate in candidates:
                declared = Connection(provider=source.provider, name=source.name,
                                      config=dict(candidate.get("config") or {}))
                validate_connection(declared)
                configs.append(declared.config)
            if source.config not in configs:
                raise SecretRefError("CREDENTIAL_AUTHORITY_CHANGED")
            expected_payload = job_payload_for(source)
            # Scope roots replace resource selections, never endpoints or login
            # hints. Also reject a new endpoint absent from the persisted source.
            for key in ("base_url", "host", "origin", "endpoint", "tenant", "tenant_id", "realm",
                        "workspace", "organization", "domain", "api_url", "server_url", "auth_kind",
                        "account", "app_organization", "auth_type", "username", "github_host", "edition"):
                if supplied.get(key) != expected_payload.get(key):
                    raise SecretRefError("CREDENTIAL_AUTHORITY_CHANGED")
        else:
            from cremore.coverage.metadata_models import MetadataConnectionSpec
            from cremore.coverage.models import ConnectionSpec

            model = MetadataConnectionSpec if kind == "metadata" else ConnectionSpec
            names = ("provider", "origin", "endpoint", "tenant", "auth_type", "server_auth", "tls_ca_pem")
            normalized = [model.model_validate({**c["spec"], "secret_refs": expected_refs}).model_dump()
                          for c in candidates if c.get("kind") == kind]
            if not any(all(supplied.get(k) == candidate.get(k) for k in names)
                       and (supplied.get("options") or {}).get("api_path") == (candidate.get("options") or {}).get("api_path")
                       for candidate in normalized):
                raise SecretRefError("CREDENTIAL_AUTHORITY_CHANGED")
        return resolver.bound(binding_for_record(owner))
    except SecretRefError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        raise SecretRefError("CREDENTIAL_OWNER_INVALID") from None
