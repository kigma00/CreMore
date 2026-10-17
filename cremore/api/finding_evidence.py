"""Finding-detail evidence in the dashboard contract, from saved scan evidence.

* ``source_location``: where the credential sits and a link that opens the
  exact source with the viewer's own provider access (S3 console object,
  GitHub blob at the scanned commit and line, Notion page). Links are built
  only from stored coordinates, never from provider text.
* ``detection_details``: the verification facts recorded by the scan and the
  explainable model score (policy, per-axis points, adjustments).
* ``credential_metadata``: identity, expiry, scopes, observed use and
  potential access, each tied to where and when it was observed.
* ``merged_locations``: one entry per physical location when overlapping
  connections (an account and one of its repositories) found the same place.

Nothing here calls a provider.
"""

from __future__ import annotations

import datetime as _dt
import json as _json
import re
from dataclasses import replace
from urllib.parse import quote, urlencode

from cremore.db.scan_state import exposure_location
from cremore.governance.usage_sources import owner_usage_snapshot
from cremore.risk.verification import latest_verification

_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REPO = re.compile(r"^[\w.-]+/[\w.-]+$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_PAGE = re.compile(r"^[0-9a-f]{32}$")
_REGION = re.compile(r"^[a-z]{2,4}(?:-[a-z]+)+-\d$")
_PROVIDER = {"s3": "aws", "aws": "aws", "github": "github", "notion": "notion"}
_GITHUB_VARIANTS = {"ghp_": "github.pat.classic", "github_pat_": "github.pat.fine_grained",
                    "ghs_": "github.app.installation_token", "ghu_": "github.app.user_access_token",
                    "gho_": "github.oauth.access_token", "ghr_": "github.refresh_token"}


def _iso(value) -> str | None:
    if not isinstance(value, _dt.datetime):
        return None
    return (value if value.tzinfo else value.replace(tzinfo=_dt.UTC)).isoformat()


def _utc(value) -> _dt.datetime:
    if not isinstance(value, _dt.datetime):
        return _dt.datetime.min.replace(tzinfo=_dt.UTC)
    return value if value.tzinfo else value.replace(tzinfo=_dt.UTC)


def merged_locations(exposures) -> list[tuple]:
    """``(representative, rows)`` per physical location, in first-seen order.

    Rows stay per connection so each connection tracks its own removal; the most
    recent observation (seen or removed) stands for the location.
    """
    groups: dict[tuple, list] = {}
    for e in exposures:
        groups.setdefault(exposure_location(e), []).append(e)
    return [(max(rows, key=lambda e: max(_utc(e.last_seen_at), _utc(getattr(e, "removed_at", None)))), rows)
            for rows in groups.values()]


def removal_pending(representative, rows) -> bool:
    """Latest removal does not retire another connection's still-open observation."""
    return representative.status == "REMOVED" and any(row.status != "REMOVED" for row in rows)


# --- source location ------------------------------------------------------------


def source_location(exposure) -> dict:
    meta = exposure.metadata or {}
    provider = _PROVIDER.get(exposure.source_type, exposure.source_type)
    decoded = bool(meta.get("decoder_type"))
    line = exposure.line_number if isinstance(exposure.line_number, int) and exposure.line_number > 0 else None
    out = {
        "source_provider": provider,
        "coordinate_basis": "EXACT_ORIGINAL" if line and not decoded else "EXTRACTED_TEXT" if decoded else "UNCONFIRMED",
        "context_status": "REDACTED_LINE_ONLY",
        **({"line_start": line, "line_end": line} if line and not decoded else {}),
        **({"extracted_line_start": meta.get("decoded_line_number")} if decoded and meta.get("decoded_line_number") else {}),
    }
    link = {"status": "UNAVAILABLE", "requires_source_auth": True, "historical_content": False}
    if provider == "aws" and _BUCKET.fullmatch(exposure.resource_name or "") and exposure.location:
        query = {"prefix": exposure.location}
        if _REGION.fullmatch(str(meta.get("region") or "")):
            query["region"] = meta["region"]
        if exposure.object_version:
            query["versionId"] = exposure.object_version
            out.update(revision=exposure.object_version, revision_kind="S3_VERSION_ID")
        link.update(status="AVAILABLE" if exposure.object_version else "CURRENT_ONLY",
                    historical_content=bool(exposure.object_version),
                    url=f"https://s3.console.aws.amazon.com/s3/object/{exposure.resource_name}?{urlencode(query)}")
    elif provider == "github" and _REPO.fullmatch(exposure.resource_name or "") and exposure.location:
        from cremore_github_provider.github_hosts import api_base as _api_base
        from cremore_github_provider.github_hosts import web_base as _web_base
        host = meta.get("github_host") or ""
        sha = str(meta.get("commit_sha") or "").lower()
        if _SHA.fullmatch(sha):
            anchor = f"#L{line}" if line and not decoded else ""
            out.update(revision=sha, revision_kind="COMMIT_SHA", provider_instance_id=_api_base(host))
            link.update(status="AVAILABLE", historical_content=True,
                        url=f"{_web_base(host)}/{exposure.resource_name}/blob/{sha}/{quote(exposure.location)}{anchor}")
        else:
            link["reason_code"] = "COMMIT_NOT_RECORDED"
    elif provider == "notion" and _PAGE.fullmatch(str(meta.get("page_id") or "")):
        out["page_id"] = meta["page_id"]
        link.update(status="CURRENT_ONLY", url=f"https://www.notion.so/{meta['page_id']}")
    else:
        link["reason_code"] = "SOURCE_COORDINATES_NOT_RECORDED"
    out["original_link"] = link
    return out


# --- detection details ---------------------------------------------------------------


def _risk(exposure, cred, occurrences=None, *, verification=None) -> dict:
    meta = exposure.metadata or {}
    if str(meta.get("catalog_id") or "").startswith("custom-"):
        return {"severity_basis": "custom_rule", "effective_severity": exposure.severity}
    try:
        from cremore.risk import model as risk
        facts = risk.facts_from_snapshot(meta["risk_facts"])
        verification = verification or latest_verification([exposure], cred)
        facts = verification.apply(facts, credential=cred)
        if occurrences:  # current distinct locations, as the rescore counts them
            facts = replace(facts, exposure=replace(facts.exposure, occurrences=occurrences))
        result = risk.assess(facts, cred.fingerprint if cred else "")
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"severity_basis": "legacy", "effective_severity": exposure.severity}
    return {
        "risk_score": result.score,
        "risk_level": result.level,
        "risk_confidence": result.confidence,
        "risk_confidence_reasons": list(result.confidence_reasons),
        "risk_policy": result.policy_version,
        "risk_evidence": [f"{e.dimension} {e.points}/{e.max_points} {e.reason_code}" for e in result.evidence],
        "risk_overrides": [o.reason_code for o in result.overrides],
        "risk_missing_evidence": list(result.missing_evidence),
        "effective_severity": result.level,
        "severity_basis": "risk_model",
    }


def detection_details(exposure, cred, occurrences=None, *, verification=None) -> dict:
    meta = exposure.metadata or {}
    verification = verification or latest_verification([exposure], cred)
    out = {k: meta[k] for k in ("exposure", "decoder_type", "fp_signal") if meta.get(k)}
    if meta.get("aws_session_material") in ("COMPLETE", "UNBOUND", "AMBIGUOUS"):
        out["aws_session_material"] = meta["aws_session_material"]
    meta = verification.metadata
    if verification.state not in ("not_attempted", "disabled"):
        if meta.get("verification_arn"):  # AWS STS GetCallerIdentity
            out.update(verification_owner_name=meta["verification_arn"], verification_owner_id=meta.get("verification_user_id"),
                       verification_owner_kind="aws_iam_user" if ":user/" in meta["verification_arn"] else "aws_principal",
                       aws_account_id=meta.get("verification_account"))
        for key in ("owner_name", "owner_id", "owner_kind", "workspace", "context_owner_kind", "expires_at"):
            if meta.get(f"verification_{key}") and f"verification_{key}" not in out:
                out[f"verification_{key}"] = meta[f"verification_{key}"]
        if meta.get("verification_scopes"):
            out["verification_scopes"] = [s.strip() for s in str(meta["verification_scopes"]).split(",") if s.strip()]
    out.update(verification_state=verification.state, verification_checked_at=_iso(verification.checked_at),
               verification_reason=verification.reason)
    out.update(_risk(exposure, cred, occurrences, verification=verification))
    return {k: v for k, v in out.items() if v not in (None, "")}


# --- credential metadata ---------------------------------------------------------------


_PROBE_STATUS = {"ALLOWED", "DENIED", "UNREACHABLE"}


def _capabilities(raw) -> list[dict]:
    """Parse the stored capability-probe JSON into a bounded, safe list."""
    if not isinstance(raw, str) or not raw:
        return []
    try:
        rows = _json.loads(raw)
    except ValueError:
        return []
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        name, state = row.get("name"), row.get("status")
        if not isinstance(name, str) or len(name) > 64:
            continue
        entry = {"name": name, "status": state if state in _PROBE_STATUS or (isinstance(state, str) and state.startswith("HTTP_")) else "UNKNOWN"}
        if isinstance(row.get("count"), int) and not isinstance(row.get("count"), bool):
            entry["count"] = max(0, min(row["count"], 1000))
        out.append(entry)
        if len(out) >= 10:
            break
    return out


def _usage_complete(snapshot) -> bool:
    return (snapshot.get("collection_status") == "COMPLETE"
            and snapshot.get("region_discovery_status", "COMPLETE") == "COMPLETE"
            and all(row.get("status") == "COMPLETE" for row in snapshot.get("coverage") or []))


def credential_metadata(cred, exposures, *, verification=None) -> dict:
    verification = verification or latest_verification(exposures, cred)
    meta = verification.metadata
    observed = _iso(verification.checked_at)
    verified = verification.state in ("verified", "restricted")
    # why a field is empty when the provider confirmed nothing about the credential
    unconfirmed = {"rejected": "NOT_RETURNED", "indeterminate": "NOT_RETURNED",
                   "unsupported": "NOT_SUPPORTED"}.get(meta.get("verification_state"), "NOT_COLLECTED")
    provider = cred.provider or ""
    hint = cred.identifier_hint or ""
    status: dict[str, str] = {}
    out: dict = {"scopes": [], "limitations": [], "expiry_status": "UNKNOWN"}

    # identity returned by the provider at verification time
    if verified and (meta.get("verification_arn") or meta.get("verification_owner_name") or meta.get("verification_owner_id")):
        out.update(principal_source="PROVIDER_RESPONSE", principal_observed_at=observed)
        if meta.get("verification_arn"):
            out.update(principal_arn=meta["verification_arn"], principal_id=meta.get("verification_user_id"),
                       principal_kind="IAM_USER" if ":user/" in meta["verification_arn"] else "AWS_PRINCIPAL")
        else:
            out.update(principal_name=meta.get("verification_owner_name"), principal_id=meta.get("verification_owner_id"),
                       principal_kind=str(meta.get("verification_owner_kind") or "").upper() or None)
    else:
        status["principal_id"] = "NOT_RETURNED" if verification.state != "not_attempted" else "NOT_COLLECTED"

    # expiry
    if provider == "aws" and hint.startswith("AKIA"):
        status["expires_at"] = "NOT_APPLICABLE"
        out["expiry_status"] = "NO_PROVIDER_EXPIRY"
    elif verified and meta.get("verification_expires_at"):
        out["expires_at"] = {"at": meta["verification_expires_at"], "source": "PROVIDER_RESPONSE", "observed_at": observed}
        out["expiry_status"] = "EXPIRES"
    else:
        status["expires_at"] = "NOT_RETURNED" if verified else unconfirmed

    # permissions the provider reports for the credential itself
    if verified and meta.get("verification_scopes"):
        out.update(scopes=[s.strip() for s in str(meta["verification_scopes"]).split(",") if s.strip()],
                   scope_source="PROVIDER_RESPONSE", scope_observed_at=observed)
    elif provider == "aws":
        status["scopes"] = "NOT_APPLICABLE"  # IAM permissions come from the policy evaluation below
    elif verified:
        status["scopes"] = "NOT_EXPOSED_BY_PROVIDER"
    else:
        status["scopes"] = unconfirmed

    if provider == "github":
        out["credential_variant"] = next((v for p, v in _GITHUB_VARIANTS.items() if hint.startswith(p)), None)
    if meta.get("verification_host"):
        out["verification_host"] = meta["verification_host"]

    # Empirical capabilities: read-only calls the verified token itself could make
    # (only when capability probing is enabled and the provider hides permissions).
    capabilities = _capabilities(meta.get("verification_capabilities"))
    if capabilities:
        out.update(capabilities=capabilities, capability_source="TOKEN_PROBE", capability_observed_at=observed)
    elif provider in ("github", "notion") and verified and not out.get("scopes"):
        status["capabilities"] = "NOT_PROBED"

    # AWS: key metadata, observed use and potential access, only from the owner account
    snapshot = owner_usage_snapshot(cred)
    if provider == "aws":
        if snapshot is not None:
            at = snapshot.get("collected_at")
            key = snapshot.get("access_key") or {}
            if key.get("created_at"):
                out["created_at"] = {"at": key["created_at"], "source": "IAM_ACCESS_KEYS", "observed_at": at}
            else:
                status["created_at"] = "NOT_RETURNED"
            if key.get("status"):
                out.update(provider_status=str(key["status"]).upper(), provider_status_observed_at=at)
            last = snapshot.get("last_used") or {}
            if last.get("status") == "AVAILABLE" and last.get("at") and last.get("observed_at"):
                out["last_used_at"] = {"at": last["at"], "source": "IAM_ACCESS_KEY_METADATA",
                                       "observed_at": last["observed_at"]}
                out.update(last_used_service=last.get("service"), last_used_region=last.get("region"))
            else:
                no_information = last.get("status") == "NO_INFORMATION" and last.get("observed_at")
                status["last_used_at"] = "NOT_OBSERVED" if no_information else "NOT_COLLECTED"
                reason = last.get("status") if last.get("status") in {
                    "NO_INFORMATION", "DENIED", "FAILED", "NOT_REQUESTED",
                } else "NOT_COLLECTED"
                out["limitations"].append("IAM_GET_ACCESS_KEY_LAST_USED_" + reason)
            uses = sorted(e.get("event_time") for e in snapshot.get("events") or []
                          if e.get("outcome") == "SUCCEEDED" and e.get("event_time"))
            if last_success := (snapshot.get("summary") or {}).get("last_success"):
                uses = [last_success]
            if uses:
                out["last_observed_use_at"] = {"at": uses[-1], "source": "CLOUDTRAIL_OBSERVED_USE", "observed_at": at}
            else:
                status["last_observed_use_at"] = "NOT_OBSERVED" if _usage_complete(snapshot) else "NOT_COLLECTED"
            from cremore_aws_provider.investigation.permission_evidence import permission_snapshot

            permissions = permission_snapshot(snapshot, cred.principal_arn)
            if permissions.get("potential_access"):
                out["potential_access"] = permissions["potential_access"]
            if permissions.get("identity_policies"):
                out["identity_policies"] = permissions["identity_policies"]
            else:
                status["identity_policies"] = "NOT_COLLECTED"
        else:
            for key in ("created_at", "last_used_at", "last_observed_use_at", "provider_status", "identity_policies"):
                status[key] = "NOT_COLLECTED"
            out["limitations"].append("OWNER_ACCOUNT_LOOKUP_NOT_COLLECTED")
    else:
        status.setdefault("created_at", "NOT_EXPOSED_BY_PROVIDER" if verified else unconfirmed)
        status.setdefault("last_used_at", "NOT_EXPOSED_BY_PROVIDER" if verified else unconfirmed)
        status.setdefault("provider_status", "NOT_COLLECTED")
    if cred.credential_type == "AZURE_SAS_TOKEN":
        _sas_fields(out, status, exposures)
    out["field_status"] = status
    return {k: v for k, v in out.items() if v not in (None, "")}


def _sas_fields(out, status, exposures):
    """What the SAS itself states: signed expiry, permissions and issuer. Not validity."""
    seen = [e for e in exposures if isinstance((e.metadata or {}).get("azure_sas"), dict)]
    if not seen:
        return
    latest = max(seen, key=lambda e: _iso(e.last_seen_at) or "")
    sas, at = latest.metadata["azure_sas"], _iso(latest.last_seen_at)
    if sas.get("expiry"):
        out.update(expires_at={"at": sas["expiry"], "source": "SAS_TOKEN_FIELDS", "observed_at": at},
                   expiry_status="EXPIRES")
        status.pop("expires_at", None)
    scopes = [f"{name}={sas[key]}" for key, name in (("permissions", "sp"), ("resource", "sr"), ("services", "ss"),
                                                     ("resource_types", "srt"), ("policy", "si")) if sas.get(key)]
    if scopes:
        out.update(scopes=scopes, scope_source="SAS_TOKEN_FIELDS", scope_observed_at=at)
        status.pop("scopes", None)
    principal = sas.get("signer_object_id") or sas.get("account")
    if principal and not out.get("principal_source"):
        out.update(principal_source="SAS_TOKEN_FIELDS", principal_observed_at=at,
                   principal_kind="ENTRA_PRINCIPAL" if sas.get("signer_object_id") else "STORAGE_ACCOUNT",
                   **({"principal_id": principal} if sas.get("signer_object_id") else {"principal_name": principal}))
        status.pop("principal_id", None)


# --- the path one exposed credential travels --------------------------------
#
# Six observations in the order they happen, not a guess at what an attacker did.
# Each stage reports one of four states and the evidence behind it. A stage this
# installation has not collected says so rather than reading as safe, and none of
# them is a likelihood: the product has no basis for one and saying otherwise
# would make an unchecked stage look measured.
PATH_REVISION = "cremore-exposure-path-v1"
OBSERVED, NOT_OBSERVED, NOT_COLLECTED, UNDETERMINED = "OBSERVED", "NOT_OBSERVED", "NOT_COLLECTED", "UNDETERMINED"
_REACH_RANK = {"public": 3, "public_inherited": 2, "internal": 1}
_USABLE = {"verified": (OBSERVED, "VALID"), "restricted": (OBSERVED, "RESTRICTED"),
           "rejected": (OBSERVED, "REJECTED"), "expired": (OBSERVED, "EXPIRED"),
           "indeterminate": (UNDETERMINED, "INDETERMINATE"), "unsupported": (NOT_COLLECTED, "NOT_SUPPORTED"),
           "disabled": (NOT_COLLECTED, "VERIFICATION_OFF"), "not_attempted": (NOT_COLLECTED, "NOT_ATTEMPTED")}


def _used_stage(cred, metadata, status) -> dict:
    """Observed use: CloudTrail for an AWS key, the org audit log for a GitHub token."""

    from cremore_aws_provider.investigation.usage import TECHNIQUES, classify_call

    recorded = status.get("last_observed_use_at")
    snapshot = owner_usage_snapshot(cred) if cred.provider == "aws" else None
    if snapshot is not None:
        events = [e for e in (snapshot.get("events") or []) if isinstance(e, dict)]
        counts: dict[str, int] = {}
        for event in events:
            if technique := classify_call(event.get("event_name")):
                counts[technique] = counts.get(technique, 0) + 1
        summary = snapshot.get("summary") or {}
        counts = summary.get("techniques", counts)
        total = summary.get("events", len(events))
        if not total and not _usage_complete(snapshot):
            return {"stage": "USED", "state": NOT_COLLECTED, "source": "CLOUDTRAIL_OBSERVED_USE",
                    "events": 0, "denied_events": 0, "techniques": [],
                    "reason": (snapshot.get("collection_status") or NOT_COLLECTED)
                    if snapshot.get("collection_status") != "COMPLETE" else "PARTIAL"}
        return {"stage": "USED", "state": OBSERVED if total else NOT_OBSERVED, "source": "CLOUDTRAIL_OBSERVED_USE",
                "events": total, "denied_events": summary.get("denied", sum(e.get("outcome") == "DENIED" for e in events)),
                "last_at": (metadata.get("last_observed_use_at") or {}).get("at"),
                "techniques": [{"technique_id": t, "technique_name": TECHNIQUES[t][0], "events": n}
                               for t, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]}
    audit = metadata.get("audit_evidence") or {}
    # Only an exact token-hash match attributes an audit entry to this credential.
    if audit.get("match_basis") == "EXACT_TOKEN_HASH" and audit.get("events"):
        return {"stage": "USED", "state": OBSERVED, "source": "GITHUB_ORG_AUDIT_LOG",
                "events": len(audit["events"]), "denied_events": 0, "techniques": [],
                "last_at": max((e.get("event_at") or "") for e in audit["events"]) or None}
    return {"stage": "USED", "state": NOT_COLLECTED, "source": "", "events": 0, "denied_events": 0,
            "techniques": [], "reason": recorded or "NOT_COLLECTED"}


def exposure_path(cred, exposures, *, finding=None, verification=None, metadata=None) -> dict:
    """The six stages, each from evidence this installation already holds."""

    rows = list(exposures or [])
    metadata = metadata or {}
    status = metadata.get("field_status") or {}
    verification = verification or latest_verification(rows, cred)
    firsts = [e.first_seen_at for e in rows if e.first_seen_at]
    lasts = [e.last_seen_at for e in rows if e.last_seen_at]
    levels = [str((e.metadata or {}).get("exposure") or "unknown") for e in rows]
    reach = max(levels, key=lambda level: _REACH_RANK.get(level, 0)) if levels else "unknown"
    usable, outcome = _USABLE.get(verification.state, (NOT_COLLECTED, "NOT_ATTEMPTED"))
    policies = metadata.get("identity_policies") or {}
    summary = policies.get("summary") or {}
    removed = sum(1 for e in rows if e.removed_at)

    potential = metadata.get("potential_access") or {}
    if policies.get("collection_status") in ("COMPLETE", "PARTIAL"):
        privileged = {"stage": "PRIVILEGED", "state": OBSERVED, "source": "IAM_IDENTITY_POLICIES",
                      "quarantine_policies": summary.get("quarantine_policies") or [],
                      "allows_every_action": bool(summary.get("allow_all_policies")),
                      "denies_every_action": bool(summary.get("deny_all_policies")),
                      "collection_status": policies.get("collection_status") or ""}
    elif potential.get("collection_status") in ("COMPLETE", "PARTIAL"):
        privileged = {"stage": "PRIVILEGED", "state": OBSERVED, "source": "IAM_SIMULATE_PRINCIPAL_POLICY",
                      "collection_status": potential["collection_status"], "quarantine_policies": [],
                      "allowed_actions": sum(row.get("decision") == "ALLOWED" for row in potential.get("actions", []))}
    elif metadata.get("scopes"):
        privileged = {"stage": "PRIVILEGED", "state": OBSERVED, "source": "PROVIDER_SCOPES",
                      "quarantine_policies": [], "scopes": len(metadata["scopes"])}
    else:
        privileged = {"stage": "PRIVILEGED", "state": NOT_COLLECTED, "source": "", "quarantine_policies": [],
                      "reason": policies.get("collection_status") or potential.get("collection_status")
                      or status.get("identity_policies") or status.get("scopes") or "NOT_COLLECTED"}

    if finding is not None and finding.all_locations_removed:
        gone = (OBSERVED, "ALL_LOCATIONS_REMOVED")
    elif removed:
        gone = (OBSERVED, "SOME_LOCATIONS_REMOVED")
    elif rows:
        gone = (NOT_OBSERVED, "STILL_PRESENT")
    else:
        gone = (NOT_COLLECTED, "NOT_COLLECTED")

    stages = [
        {"stage": "EXPOSED", "state": OBSERVED if rows else NOT_COLLECTED, "locations": len(rows),
         "first_seen_at": _iso(min(firsts)) if firsts else None,
         "last_seen_at": _iso(max(lasts)) if lasts else None},
        {"stage": "REACHABLE", "state": OBSERVED if _REACH_RANK.get(reach) else UNDETERMINED,
         "level": reach.upper() if _REACH_RANK.get(reach) else "UNKNOWN",
         "public_locations": sum(_REACH_RANK.get(level, 0) >= 2 for level in levels),
         "undetermined_locations": sum(not _REACH_RANK.get(level, 0) for level in levels)},
        {"stage": "USABLE", "state": usable, "outcome": outcome, "checked_at": _iso(verification.checked_at)},
        privileged,
        _used_stage(cred, metadata, status) if cred is not None else
        {"stage": "USED", "state": NOT_COLLECTED, "source": "", "events": 0, "denied_events": 0,
         "techniques": [], "reason": "NOT_COLLECTED"},
        # Removing the location is not revoking the credential; the two are
        # reported apart everywhere else and stay apart here.
        {"stage": "REMOVED", "state": gone[0], "outcome": gone[1], "removed_locations": removed,
         "locations": len(rows)},
    ]
    return {"revision": PATH_REVISION, "stages": stages,
            "observed": sum(stage["state"] == OBSERVED for stage in stages)}
