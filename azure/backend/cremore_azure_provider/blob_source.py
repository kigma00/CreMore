"""Azure Blob Storage content-source configuration and collector construction."""

from cremore.sources.validation import enterprise_fields

PROVIDER = "azure_blob"
SOURCE_TYPE = "azure_blob"
JOB_KINDS = ("azure_blob",)
RESOURCE_TYPES = ("AZURE_BLOB_CONTAINER",)
SCOPE_KIND = "object"
FILTERS = ()
CAPABILITY_ORDER = 8
STRUCTURED_CONFIG = True
# A Microsoft connection that signs in with its app certificate gives the source a sealed credential;
# one without reads with the worker's own Azure identity.
TOKEN_AUTH = True
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = False
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
CAPABILITY = {"id": "azure_blob", "name": "Azure Blob Storage", "command": "azure_blob", "kind": "BATCH",
    "description": "Approved storage account containers using the Microsoft connection's app certificate or the worker's Azure identity.",
    "credential_env": [], "external_credential_env": [],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None


def validate_config(cfg):
    from cremore_azure_provider.blob_content import ACCOUNT, CONTAINER

    out = enterprise_fields(cfg, {"account", "container"}, literal_paths=True)
    if not isinstance(out.get("account"), str) or not ACCOUNT.fullmatch(out["account"]):
        raise ValueError("INVALID_AZURE_STORAGE_ACCOUNT")
    if "container" in out and (not isinstance(out["container"], str) or not CONTAINER.fullmatch(out["container"])):
        raise ValueError("INVALID_AZURE_BLOB_CONTAINER")
    return out


def job_payload(cfg):
    return {key: value for key, value in validate_config(cfg).items() if key != "declaration"} | {"provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    account, _, container = scope.partition("/")
    return {"account": account, **({"container": container} if container else {})}


def scope_ref(cfg):
    return (cfg.get("account") or "") + ("/" + cfg["container"] if cfg.get("container") else "")


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None):
    from cremore.sources._collectors import enterprise_collector

    return enterprise_collector(content_module(), payload, http_client_factory=http_client_factory,
                                max_object_bytes=max_object_bytes)


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None):
    from cremore.sources._collectors import enterprise_root

    root = {**root, "container": root["provider_resource_id"].split("/", 1)[1]}
    if root.get("all_current_objects"):
        root["prefixes"] = []
    return enterprise_root(content_module(), payload, root, http_client_factory=http_client_factory,
                           max_object_bytes=max_object_bytes, request_budget=request_budget)


def content_module():
    from cremore_azure_provider import blob_content
    return blob_content


def exposure_context(payload, location, *, http_client, members=True):
    from cremore_azure_provider.blob_context import read

    return read(payload, location, http_client=http_client, members=members)


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
        mode = "AZURE_APP_CERTIFICATE" if callable(payload.get("token")) else "AZURE_WORKLOAD_IDENTITY"
        return CredentialCheck(ACTIVE, detail={"credential_mode": mode, "refresh_supported": True})
    except CollectorError as exc:
        error = {"401": "AZURE_AUTHENTICATION_FAILED", "403": "AZURE_STORAGE_PERMISSION_DENIED"}.get(exc.detail, exc.code)
        return CredentialCheck(REJECTED if exc.detail == "401" else INDETERMINATE, error=error)
    except ValueError as exc:
        return CredentialCheck(INDETERMINATE, error=str(exc) if str(exc) == "INSTALL_CREMORE_AZURE_EXTRA"
                               else "SOURCE_IDENTITY_CHECK_FAILED")
    except Exception:  # noqa: BLE001 -- Expose a safe code, never credential-bearing provider exception text.
        return CredentialCheck(INDETERMINATE, error="SOURCE_IDENTITY_CHECK_FAILED")


def queue_changes(body, attributes, roots):
    """A notification from the customer's own queue (cremore.scanning.triggers)."""
    from cremore_azure_provider.servicebus import blob_changes as read

    return read(body, attributes, roots)
