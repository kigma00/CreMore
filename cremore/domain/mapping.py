"""Map a sanitized detection onto the platform's persistence model.

This is the seam between the detection engine and storage: a finding becomes a
:class:`Credential` identity plus an :class:`Exposure` at the location it was
found. No raw secret is carried across — only the fingerprint and masked hint.
"""

from __future__ import annotations

import uuid

from cremore.detection.models import ResourceRef, SanitizedDetection
from cremore.domain.models import (
    Credential,
    CredentialStatus,
    Exposure,
    ExposureStatus,
    Severity,
)

# Verification state -> the credential's recorded status.
_STATUS_FROM_VERIFICATION = {
    "verified": CredentialStatus.ACTIVE.value,
    "rejected": CredentialStatus.INACTIVE.value,
}


def credential_from_detection(det: SanitizedDetection) -> Credential:
    state = det.extra_safe_data.get("verification_state", "")
    return Credential(
        fingerprint=det.fingerprint,
        credential_type=det.credential_type,
        provider=det.provider or None,
        identifier=det.identifier or None,
        identifier_hint=det.identifier_hint or None,
        principal_arn=det.extra_safe_data.get("verification_arn") or None,
        credential_status=_STATUS_FROM_VERIFICATION.get(state, CredentialStatus.UNKNOWN.value),
    )


def exposure_from_detection(
    det: SanitizedDetection,
    resource: ResourceRef,
    credential_id: uuid.UUID,
    *,
    severity: str = Severity.UNKNOWN.value,
    source_connection_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
) -> Exposure:
    exposure = Exposure(
        credential_id=credential_id,
        source_type=resource.source_type,
        resource_name=resource.resource or resource.location,
        location=resource.location,
        object_version=resource.version_id or "",
        line_number=det.line_number,
        severity=severity,
        status=ExposureStatus.OPEN.value,
        resource_arn=resource.resource_arn or None,
        redacted_line=det.redacted_line or None,
        metadata={
            **det.extra_safe_data,
            "verification_state": det.extra_safe_data.get("verification_state", "not_attempted"),
            # Only collector-owned scoring/provenance fields cross this boundary.
            **{k: resource.metadata[k] for k in ("collector_epoch", "page_id", "exposure", "commit_sha", "blob_sha", "github_host", "source_instance", "source_site", "gitlab_project_path", "bitbucket_edition")
               if k in resource.metadata},
            **{k: resource.metadata[k] for k in ("document_format", "document_extraction_status")
               if k in resource.metadata},
            # Coordinates for the "open original" link (S3 console needs the bucket region).
            **({"region": resource.region} if getattr(resource, "region", "") else {}),
            "revision": resource.revision,
            # Detection confidence travels with the exposure so triage and the
            # risk model can treat a low-confidence passive match differently.
            "detection_confidence": det.confidence,
            "detector_name": det.detector_name,
        },
    )
    # The connection that produced the exposure is recorded for every source so
    # a complete rescan of that connection can retire what it no longer sees.
    exposure.source_connection_id = source_connection_id
    if resource.source_type in ("s3", "aws"):
        exposure.aws_account_id = _maybe_uuid(resource.account_id)
        exposure.first_scan_id = scan_id
        exposure.last_scan_id = scan_id
    else:
        exposure.first_source_scan_id = scan_id
        exposure.last_source_scan_id = scan_id
    return exposure


def _maybe_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value) if value else None
    except (ValueError, AttributeError):
        return None
