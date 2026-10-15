"""Saved, keyed component equality. No source reads or authentication attempts."""

import re

from cremore.risk.verification import latest_verification, timestamp

_FIELDS = {"AWS_ACCESS_KEY_ID": "aws_id_component_fingerprint",
           "AWS_SECRET_ACCESS_KEY": "aws_secret_component_fingerprint"}
_LIMIT = 50
_HEX64 = re.compile(r"[a-f0-9]{64}")


def _subject(credential, exposures) -> tuple[str, str, bool]:
    """(component type to search by, its fingerprint, whether only the shape matched).

    An AWS component is searched by its own credential identity. A value that
    merely has the AWS secret shape is searched by the component hash recorded on
    its exposures -- byte equality, never a claim that the value is AWS.
    """
    if credential.provider == "aws" and credential.credential_type in _FIELDS:
        return credential.credential_type, credential.fingerprint, False
    field = _FIELDS["AWS_SECRET_ACCESS_KEY"]
    for exposure in exposures:
        value = str((exposure.metadata or {}).get(field, ""))
        if _HEX64.fullmatch(value):
            return "AWS_SECRET_ACCESS_KEY", value, True
    return "", "", False


def _locations(rows):
    return [{"source_type": row.source_type, "resource": row.resource_name, "location": row.location,
             "version": row.object_version, "status": row.status,
             "observed_at": at.isoformat() if (at := timestamp(row.last_seen_at)) else None}
            for row in rows[:_LIMIT]]


def component_evidence(repo, credential, exposures):
    if not credential:
        return None
    complete = credential.provider == "aws" and credential.credential_type == "AWS_ACCESS_KEY"
    component_type, component_fingerprint, shape_only = ("", "", False) if complete else _subject(credential, exposures)
    if not complete and not component_fingerprint:
        return None
    finding = repo.get_finding_for_credential(credential.id)
    if not finding or finding.workflow_status == "FALSE_POSITIVE":
        return None
    if complete:
        candidates = [e for e in exposures if e.status != "FALSE_POSITIVE"]
    else:
        candidates = repo.find_component_pairs(component_type, component_fingerprint, _LIMIT + 1)
    truncated = len(candidates) > _LIMIT
    links, seen, stale = [], set(), False
    for evidence in candidates[:_LIMIT]:
        meta = evidence.metadata or {}
        if any(not re.fullmatch(r"[a-f0-9]{64}", str(meta.get(field, ""))) for field in _FIELDS.values()):
            # Observed before component fingerprints were recorded. Absence of
            # the field is missing evidence, not evidence that nothing is linked.
            stale = True
            continue
        if evidence.credential_id in seen:
            continue
        seen.add(evidence.credential_id)
        pair = repo.get_credential(evidence.credential_id)
        pair_finding = repo.get_finding_for_credential(evidence.credential_id)
        if not pair or not pair_finding or pair_finding.workflow_status == "FALSE_POSITIVE":
            continue
        components = []
        for kind, field in _FIELDS.items():
            part = repo.get_credential_by_fingerprint(meta[field], kind)
            part_finding = repo.get_finding_for_credential(part.id) if part else None
            if not part_finding or part_finding.workflow_status == "FALSE_POSITIVE":
                continue
            rows = [e for e in repo.exposures_for_credential(part.id) if e.status not in {"REMOVED", "FALSE_POSITIVE"}]
            if rows:
                truncated |= len(rows) > _LIMIT
                components.append({"credential_type": kind, "finding_id": str(part_finding.id),
                                   "locations": _locations(rows)})
        verification = latest_verification([evidence], pair)
        links.append({"pair_finding_id": str(pair_finding.id), "basis": "SAME_INPUT_OBSERVATION",
                      "pair_location": _locations([evidence])[0], "components": components,
                      "verification_state": verification.state,
                      "verification_checked_at": verification.checked_at.isoformat() if verification.checked_at else None})
    if complete and not any(link["components"] for link in links):
        return None  # A complete finding needs this panel only when separate parts were observed.
    if shape_only and not links:
        return None  # Nothing links it to AWS; saying so would only imply it might be.
    return {"status": "BOTH_COMPONENTS_OBSERVED" if any(len(link["components"]) == 2 for link in links)
            else "PAIR_EVIDENCE_FOUND" if links else "RELATION_UNCONFIRMED",
            "subject_component": component_type, "subject_matched_by_shape": shape_only,
            "truncated": truncated, "stale_evidence": stale, "links": links, "authentication_attempted": False}
