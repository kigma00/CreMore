"""Azure DevOps Services and Server repository content-source configuration and collector construction."""

from urllib.parse import urlsplit

from cremore.sources.validation import enterprise_fields, https_base

PROVIDER = "azure_devops"
SOURCE_TYPE = "azure_devops"
JOB_KINDS = ("azure_devops",)
RESOURCE_TYPES = ("AZURE_DEVOPS_REPOSITORY", "AZURE_DEVOPS_TFVC")
SCOPE_KIND = "path"
FILTERS = ()
CAPABILITY_ORDER = 9
STRUCTURED_CONFIG = True
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = True
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
# A listed object's revision is its git blob id (cremore.scanning.service caches by it).
CONTENT_ADDRESSED = True
CAPABILITY = {"id": "azure_devops", "name": "Azure DevOps Repos", "command": "azure_devops", "kind": "BATCH",
    "description": "Approved Azure DevOps Services or Server Git repositories using a read-only personal access token, or the Microsoft connection's app.",
    "credential_env": ["AZURE_DEVOPS_TOKEN"], "external_credential_env": ["AZURE_DEVOPS_TOKEN"],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None


def validate_config(cfg):
    from cremore_azure_provider.devops_content import CLOUD, ORGANIZATION, valid_name

    out = enterprise_fields(cfg, {"organization", "project", "repository", "ref", "base_url", "version_control"})
    if out.setdefault("version_control", "git") not in ("git", "tfvc"):
        raise ValueError("INVALID_AZURE_DEVOPS_VERSION_CONTROL")
    if out["version_control"] == "tfvc" and ("repository" in out or "ref" in out):
        raise ValueError("TFVC_SCOPE_IS_THE_PROJECT_ROOT")
    out["base_url"] = https_base(out.get("base_url", CLOUD))
    host = (urlsplit(out["base_url"]).hostname or "").lower()
    if out["base_url"] != CLOUD and (host == "dev.azure.com" or host.endswith(".visualstudio.com")):
        raise ValueError("AZURE_DEVOPS_SERVICES_ADDRESS_IS_FIXED")
    # Services names an organization; a Server names a project collection.
    organization = out.get("organization")
    if not (ORGANIZATION.fullmatch(organization) if out["base_url"] == CLOUD and isinstance(organization, str)
            else out["base_url"] != CLOUD and valid_name(organization)):
        raise ValueError("INVALID_AZURE_DEVOPS_ORGANIZATION")
    if not valid_name(out.get("project")):
        raise ValueError("INVALID_AZURE_DEVOPS_PROJECT")
    if "repository" in out and not valid_name(out["repository"]):
        raise ValueError("INVALID_AZURE_DEVOPS_REPOSITORY")
    if "ref" in out and (not isinstance(out["ref"], str) or not out["ref"] or len(out["ref"]) > 256
                         or any(ord(c) < 33 for c in out["ref"]) or out["ref"].startswith("refs/")):
        raise ValueError("INVALID_GIT_REF")
    return out


def job_payload(cfg):
    return {key: value for key, value in validate_config(cfg).items() if key != "declaration"} | {"provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    from cremore_azure_provider.devops_content import TFVC_ROOT

    organization, _, rest = scope.partition("/")
    project, _, repository = rest.partition("/")
    if repository == TFVC_ROOT:
        return {"organization": organization, "project": project, "version_control": "tfvc"}
    return {"organization": organization, "project": project, **({"repository": repository} if repository else {})}


def scope_ref(cfg):
    repository = "$" if cfg.get("version_control") == "tfvc" else cfg.get("repository")
    return "/".join(part for part in (cfg.get("organization"), cfg.get("project"), repository) if part)


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None):
    from cremore.sources._collectors import enterprise_collector

    return enterprise_collector(content_module(), payload, http_client_factory=http_client_factory,
                                max_object_bytes=max_object_bytes)


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None):
    from cremore.sources._collectors import enterprise_root

    root = {**root, "repository": root["provider_resource_id"].rsplit("/", 1)[1]}
    return enterprise_root(content_module(), payload, root, http_client_factory=http_client_factory,
                           max_object_bytes=max_object_bytes, request_budget=request_budget)


def content_module():
    from cremore_azure_provider import devops_content
    return devops_content


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    from cremore.sources._collectors import enterprise_resources
    return enterprise_resources(content_module(), payload, kind, cid,
        http_client=http_client, now=now, request_budget=request_budget)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore.collectors.base import CollectorError, RequestBudget
    from cremore.collectors.credential_result import (
        ACTIVE,
        INDETERMINATE,
        REJECTED,
        CredentialCheck,
    )

    try:
        next(iter(content_module().roots(payload, http_client_factory(), RequestBudget(3))), None)
        entra = bool(getattr(payload.get("token"), "bearer", False))
        return CredentialCheck(ACTIVE, detail={"credential_mode": "AZURE_APP_CERTIFICATE" if entra else "PROVIDER_TOKEN",
                                               "refresh_supported": entra})
    except CollectorError as exc:
        error = {"401": "AZURE_DEVOPS_AUTHENTICATION_FAILED", "203": "AZURE_DEVOPS_AUTHENTICATION_FAILED",
                 "403": "AZURE_DEVOPS_PERMISSION_DENIED"}.get(exc.detail, exc.code)
        return CredentialCheck(REJECTED if exc.detail in ("401", "203") else INDETERMINATE, error=error)
    except Exception:  # noqa: BLE001 -- Expose a safe code, never credential-bearing provider exception text.
        return CredentialCheck(INDETERMINATE, error="SOURCE_IDENTITY_CHECK_FAILED")


def exposure_context(payload, location, *, http_client, members=True):
    """What Azure DevOps says about an exposed file: the last commit or changeset that changed it."""
    from cremore_azure_provider.devops_context import read

    return read(payload, location, http_client=http_client, members=members)


def changes_since(payload, root, cursor, *, http_client, request_budget):
    """Change feed: the head and the files changed since ``cursor`` (cremore.scanning.changes)."""
    from cremore_azure_provider.devops_changes import changes_since as read

    return read(payload, root, cursor, http_client=http_client, request_budget=request_budget)


def queue_changes(body, attributes, roots):
    """A notification from the customer's own queue (cremore.scanning.triggers)."""
    from cremore_azure_provider.devops_changes import queue_changes as read

    return read(body, attributes, roots)
