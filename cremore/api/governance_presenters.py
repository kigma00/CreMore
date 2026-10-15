"""Connection declarations and governance response projections."""

from __future__ import annotations

from cremore_aws_provider import aws_access

from cremore.api.http_support import (
    http_error,
    isoformat,
    utc_now,
)
from cremore.api.source_contract import (
    provider_to_source,
)
from cremore.secretstore.sealed import public_ref

DECLARATION_FIELDS = ("product_type", "auth_type", "base_url")


ENVIRONMENT_FIELDS = ("deployment_type", "account_kind", "plan", "topology", "partition",
                       "sso", "user_management", "api_base_url")


PURPOSES = {"DISCOVERY", "PROVIDER_INVENTORY", "AUDIT", "SECRET_MANAGER", "RESPONSE"}


def capability(implemented: bool, reason: str) -> dict:
    return {
        "supported": False,  # nothing is probed; support is never inferred
        "technical_support": "IMPLEMENTED" if implemented else "NOT_IMPLEMENTED",
        "availability": "NOT_PROBED",
        "reason": reason,
        "evidence_source": "CONFIGURATION",
        "scope": "CONNECTION",
    }


def governance_common(kind: str, connection_id: str, provider: str, source_type: str,
                       status: str, declaration: dict | None, created_at, updated_at,
                       capabilities: dict, **profile_extra) -> dict:
    declared = declaration or {"product_type": "UNKNOWN", "auth_type": "UNKNOWN", "base_url": ""}
    return {
        "persisted": False,
        "profile": {
            "kind": kind,
            "connection_id": connection_id,
            "provider": provider.upper(),
            "source_type": source_type,
            "product_type": declared.get("product_type", "UNKNOWN"),
            "auth_type": declared.get("auth_type", "UNKNOWN"),
            "base_url": declared.get("base_url", ""),
            "connected_at": isoformat(created_at) or "",
            "last_synced_at": isoformat(updated_at),
            "connection_status": status,
            "declaration_status": "DECLARED_NOT_VERIFIED" if declaration else "NOT_DECLARED",
            "declared": {k: v for k, v in declared.items() if k != "declared_at"},
            "declared_at": declared.get("declared_at"),
            **profile_extra,
        },
        "snapshot": {
            "schema_version": 1,
            "generated_at": utc_now().isoformat(),
            "mode": "REAL",
            "scan_coverage_type": "UNKNOWN",
            "scope": {"connection_id": connection_id, "connection_kind": kind},
            "capabilities": capabilities,
            "limitations": ["CONNECTOR_CAPABILITIES_NOT_PROBED"],
        },
    }


def governance_item_source(c) -> dict:
    declaration = (c.config or {}).get("declaration")
    caps = {
        "canScanContent": capability(True, "NO_ENDPOINT_EVIDENCE"),
        "canAuthenticateConnection": capability(bool(c.secret_ref) or c.provider in ("aws", "gcp"), "NO_ENDPOINT_EVIDENCE"),
        "canListCredentials": capability(c.provider == "gcp", "NO_ENDPOINT_EVIDENCE" if c.provider == "gcp" else "CONNECTOR_NOT_IMPLEMENTED"),
    }
    item = governance_common("source", str(c.id), c.provider, provider_to_source(c.provider),
                              c.status, declaration, c.created_at, c.updated_at, caps)
    # Plain connection fields for API users; a sealed token is shown only as a marker.
    item.update({"id": str(c.id), "provider": c.provider, "name": c.name, "status": c.status,
                 "config": {k: v for k, v in (c.config or {}).items() if k != "declaration"},
                 "secret_ref": public_ref(c.secret_ref), "last_error": c.last_error,
                 "last_verified_at": isoformat(c.last_verified_at)})
    return item


def governance_item_aws(a, settings, approvals: dict, secrets_inventory: bool = False) -> dict:
    caps = {
        "canAuthenticateConnection": capability(True, "NO_ENDPOINT_EVIDENCE"),
        "canScanContent": capability(True, "NO_ENDPOINT_EVIDENCE"),
        # The live switch, not a configuration ceiling: an Admin can turn the
        # Secrets Manager investigation on and off while this is displayed.
        "canReadSecretManager": capability(secrets_inventory, "NO_ENDPOINT_EVIDENCE"),
    }
    validation = aws_access.effective_validation(a, aws_access.SCANNER, approvals.get(aws_access.SCANNER))["status"]
    status = "DISABLED" if not a.enabled else ("READY" if validation == "VALID" else "PENDING")
    item = governance_common("aws", str(a.id), "aws", "aws-account", status, a.declaration,
                              a.created_at, a.updated_at, caps, account_id=a.account_id)
    item.update({"id": str(a.id), "provider": "aws", "name": a.name, "status": status,
                 "account_id": a.account_id, "scanner_role_arn": a.scanner_role_arn,
                 "validation_status": validation})
    return item


def clean_declaration(body: dict) -> dict:
    """Validate the dashboard's declaration form: fixed keys, bounded strings."""

    if not isinstance(body, dict):
        raise http_error(422, "declaration must be an object")

    def text(value, limit: int, what: str) -> str:
        if value is None:
            return ""
        if not isinstance(value, str) or len(value) > limit:
            raise http_error(422, f"{what} must be a string of at most {limit} characters")
        return value

    out = {k: text(body.get(k), 256, k) or ("" if k == "base_url" else "UNKNOWN") for k in DECLARATION_FIELDS}
    if out["base_url"] and not out["base_url"].startswith("https://"):
        raise http_error(422, "base_url must be an https:// URL")
    env = body.get("environment")
    if env is not None:
        if not isinstance(env, dict):
            raise http_error(422, "environment must be an object")
        cleaned = {k: text(env.get(k), 256, f"environment.{k}") for k in ENVIRONMENT_FIELDS if k in env}
        regions = env.get("regions") or []
        if (not isinstance(regions, list) or len(regions) > 32
                or any(not isinstance(r, str) or len(r) > 64 for r in regions)):
            raise http_error(422, "environment.regions must be at most 32 region names")
        cleaned["regions"] = regions
        out["environment"] = cleaned
    purposes = body.get("purposes") or []
    if not isinstance(purposes, list) or len(purposes) > 5 or any(p not in PURPOSES for p in purposes):
        raise http_error(422, f"purposes must be a subset of {sorted(PURPOSES)}")
    out["purposes"] = purposes
    out["declared_at"] = utc_now().isoformat()
    return out


def present_review(r) -> dict:
    return {
        "id": str(r.id),
        "finding_id": str(r.finding_id),
        "kind": r.kind,
        "status": r.status,
        "assignee": r.assignee,
        "question": r.question,
        "response": r.response,
        "created_by": r.created_by,
        "created_at": isoformat(r.created_at) or "",
        "resolved_at": isoformat(r.resolved_at),
    }


def present_rotation(j) -> dict:
    return {
        "id": str(j.id),
        "credential_id": str(j.credential_id),
        "status": j.status,
        "phase": j.phase,
        "requested_by": j.requested_by,
        "approved_by": j.approved_by,
        "error": j.error,
        "secret_arn": getattr(j, "secret_arn", ""),
        "user_name": getattr(j, "user_name", ""),
        "account_id": getattr(j, "account_id", ""),
        # The key *ids* are non-secret identifiers; secret material never appears.
        "old_key_id": getattr(j, "old_key_id", ""),
        "new_key_id": getattr(j, "new_key_id", "") or "",
        "pending_version": getattr(j, "pending_version", "") or "",
        "created_at": isoformat(j.created_at) or "",
        "updated_at": isoformat(j.updated_at) or "",
    }


def present_action(a) -> dict:
    return {
        "id": str(a.id),
        "finding_id": str(a.finding_id),
        "action_type": a.action_type,
        "status": a.status,
        "requested_by": a.requested_by,
        "confirmed_by": a.confirmed_by,
        "note": a.note,
        "created_at": isoformat(a.created_at) or "",
        "updated_at": isoformat(a.updated_at) or "",
    }


def available_actions(cred) -> list[str]:
    actions = ["ACKNOWLEDGE_OWNER"]
    if cred and cred.credential_type == "AWS_ACCESS_KEY":
        actions.append("ROTATE")
    return actions
