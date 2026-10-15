"""Small shared persistence rules for scan observations and finding rollups."""

from __future__ import annotations

import hashlib
import json

# Integration: INSTANCE_SOURCES is derived from each source module's INSTANCE_SCOPED in the registry and
# re-exported here for cremore.db.sql. The db package already loads the registry through cremore.domain,
# so this import adds no load cost (the registry itself never imports cremore.db).
from cremore.sources.registry import INSTANCE_SOURCES

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
OBSERVATION_METADATA = frozenset({
    "coverage_engine_digest", "coverage_policy_digest", "source_instance", "source_site", "gitlab_project_path", "bitbucket_edition",
    "collector_epoch", "source_type", "page_id", "notion_block_id", "exposure", "revision",
    "document_format", "document_extraction_status",
    "catalog_id", "rule_detection_digest", "risk_facts", "rescore", "detection_confidence", "detector_name", "fp_signal",
    "aws_material_kind",
    "aws_id_component_fingerprint", "aws_secret_component_fingerprint",
    "aws_session_fingerprint", "aws_session_material", "azure_sas",
    "verification_state", "verification_checked_at", "verification_last_confirmed", "verification_error", "verification_account",
    "verification_arn", "verification_user_id", "verification_scopes",
    "verification_login", "verification_id", "verification_name", "verification_capabilities",
    "verification_owner_name", "verification_owner_id", "verification_owner_kind",
    "verification_workspace", "verification_expires_at", "verification_host", "github_host",
    "verification_token_id",
})


def exposure_identity(exposure) -> str:
    """Unambiguous identity, including explicit NULLs and installation-local IDs."""
    fields = ("credential_id", "aws_account_id", "source_connection_id", "source_type",
              "resource_name", "location", "object_version")
    values = [exposure.get(k) if hasattr(exposure, "get") else getattr(exposure, k)
              for k in fields]
    encoded = json.dumps(values, default=str, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


LOCATION_FIELDS = ("source_type", "resource_name", "location", "object_version")
# INSTANCE_SOURCES (imported above): sources whose resource names repeat across installations;
# the instance is part of the location.


def exposure_location(exposure) -> tuple:
    """The physical place a credential sits, whichever connection or account observed it.

    Exposure rows stay per connection (each connection tracks its own removal);
    counts, scores and the dashboard treat rows sharing this key as one location.
    """
    get = exposure.get if hasattr(exposure, "get") else lambda key: getattr(exposure, key)
    instance = (get("metadata") or {}).get("source_instance", "") if get("source_type") in INSTANCE_SOURCES else ""
    return tuple(get(k) or "" for k in LOCATION_FIELDS) + (instance,)


def observation_metadata(existing: dict, incoming: dict) -> dict:
    """Only fresh observations may replace allowlisted evidence; keep legacy data."""
    if "revision" in incoming:
        # Fresh observations cannot retain obsolete parser/block evidence.
        replaced = {"document_format", "document_extraction_status"}
        if incoming.get("page_id"):
            replaced.add("notion_block_id")
        existing = {k: v for k, v in existing.items() if k not in replaced}
    if "aws_session_material" in incoming:
        # A fresh unbound/ambiguous observation must not retain an older token binding.
        existing = {k: v for k, v in existing.items() if k not in {"aws_session_fingerprint", "aws_session_material"}}
    state = incoming.get("verification_state")
    if state in ("not_attempted", "disabled"):
        # Passive scans do not invalidate an actual check or renew its time.
        incoming = {k: v for k, v in incoming.items() if not k.startswith("verification_")}
    elif state:
        # Replace one actual attempt atomically, keeping its last conclusive
        # predecessor when the new attempt fails (e.g. an expired session).
        previous = existing.get("verification_last_confirmed")
        if existing.get("verification_state") in {"verified", "restricted", "rejected"}:
            previous = {k: v for k, v in existing.items()
                        if k.startswith("verification_") and k != "verification_last_confirmed"}
            if "risk_facts" in existing:
                previous["risk_facts"] = existing["risk_facts"]
        existing = {k: v for k, v in existing.items()
                    if not k.startswith("verification_") and k not in {"risk_facts", "rescore"}}
        if previous:
            existing["verification_last_confirmed"] = previous
    return {**existing, **{k: v for k, v in incoming.items() if k in OBSERVATION_METADATA}}


def exposure_resource_key(exposure) -> str:
    fields = ("source_connection_id", "source_type", "resource_name", "location")
    values = [exposure.get(k) if hasattr(exposure, "get") else getattr(exposure, k) for k in fields]
    return hashlib.sha256(json.dumps(values, default=str, separators=(",", ":")).encode()).hexdigest()


def exposure_container_key(exposure) -> str:
    """Indexed physical root; Notion identity follows page IDs, not page titles."""
    get = exposure.get if hasattr(exposure, "get") else lambda key: getattr(exposure, key)
    source, resource = get("source_type"), get("resource_name")
    page_id = (get("metadata") or {}).get("page_id")
    if source == "notion" and page_id:
        resource = str(page_id).replace("-", "").lower()
    values = [get("source_connection_id"), source, resource]
    return hashlib.sha256(json.dumps(values, default=str, separators=(",", ":")).encode()).hexdigest()


def rollup_changes(finding, best: tuple, *, active: bool, unknown: bool) -> dict:
    """Presence is separate from credential retirement; never infer revocation."""
    changes = {"all_locations_removed": not active}
    severity, exposure_id = best
    if exposure_id is not None:
        changes["primary_exposure_id"] = exposure_id
        if not unknown or SEVERITY_RANK.get(severity, -1) >= SEVERITY_RANK.get(finding.severity, -1):
            changes["severity"] = severity
    if active and finding.workflow_status == "RESOLVED" and finding.resolution == "REMOVED_BY_RESCAN":
        changes.update(workflow_status="OPEN", resolution=None, resolved_at=None)
    return {k: v for k, v in changes.items() if getattr(finding, k) != v}
