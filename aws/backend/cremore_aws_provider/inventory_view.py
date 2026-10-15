"""Read-only, account-scoped projection of saved AWS credential evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from cremore.coverage.aws_scheduling import connection_job, scheduled_refusal
from cremore.coverage.models import ConnectionSpec, Observation, digest, in_scope
from cremore.coverage.store import CoverageError, CoverageStore, utc
from cremore_aws_provider import aws_access, aws_inventory_settings

MAX_OBSERVATIONS = 250000
MAX_EVIDENCE_ITEMS = 100
# What IAM reported a key or service credential to be; stale, conflicting or truncated evidence no longer says it.
_PROVIDER_STATES = ("Active", "Inactive", "Expired")
_FLAGS = ("password_enabled", "mfa_active", "access_key_1_active", "access_key_2_active",
          "cert_1_active", "cert_2_active")
_REPORT_FIELDS = {"generated_at", "user_created_at", "password_last_used_at", "password_last_changed_at",
                  "password_next_rotation_at", "field_status", "access_keys", "certificates"}
_LAST_USED_FIELDS = {"status", "checked_at", "service", "region", "reason"}
_OPERATION_SOURCES = {"LIST_USERS": "IAM_INVENTORY", "LIST_ACCESS_KEYS": "IAM_ACCESS_KEYS",
    "LIST_SERVICE_CREDENTIALS": "IAM_SERVICE_CREDENTIALS", "CREDENTIAL_REPORT": "IAM_CREDENTIAL_REPORT",
    "GET_ACCESS_KEY_LAST_USED": "IAM_INVENTORY", "IAM_IDENTITY_POLICIES": "IAM_IDENTITY_POLICIES",
    "LOOKUP_EVENTS": "EVENT_HISTORY", "READ_TRAIL_LOGS": "TRAIL_S3"}


def _stamp(value):
    if not value:
        return ""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return utc(value).isoformat()


def _codes(values):
    return {value for value in values if isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", value)}


def _connections(store, account):
    return sorted((row for row in store.list_connections()
        if row["spec"].get("schema_version", 1) == 1
        and row["spec"].get("provider") in ("aws_iam", "aws_cloudtrail")
        and row["spec"].get("account_id") == account.account_id), key=lambda row: str(row["id"]))


def _reasons(connection, latest, now):
    reasons = set()
    if not connection["enabled"]:
        reasons.add("CONNECTION_DISABLED")
    if not latest:
        return reasons | {"NEVER_COLLECTED"}
    if latest["revision"] != connection["revision"]:
        reasons.add("SCOPE_CHANGED")
    if latest["status"] != "COMPLETE":
        reasons.add("COLLECTION_" + latest["status"])
    if not latest["finished_at"] or utc(latest["started_at"]) + timedelta(
            hours=connection["spec"].get("freshness_hours", 24)) < now:
        reasons.add("STALE_OR_RUNNING")
    return reasons | _codes(latest["reasons"])


def _summary(repo, account, connections, runs, settings, now, refusal):
    reasons = {refusal} if refusal else set()
    for connection in connections:
        reasons.update(_reasons(connection, runs[str(connection["id"])][0], now))
    latest = [pair[0] for pair in runs.values() if pair[0]]
    successes = [pair[1] for pair in runs.values() if pair[1]]
    config = aws_inventory_settings.config(settings, repo)
    schedule = 0
    if config["installation_allows"]:
        for row in connections:
            spec = ConnectionSpec.model_validate(row["spec"])
            if row["enabled"] and not scheduled_refusal(repo, settings, spec):
                minutes = spec.schedule_minutes or (config["interval_minutes"]
                    if spec.schedule_source == "installation" else 0)
                if minutes and (not schedule or minutes < schedule):
                    schedule = minutes
    statuses = {run["status"] for run in latest}
    if refusal:
        status = "BLOCKED"
    elif not latest:
        status = "NEVER_COLLECTED"
        reasons.add(status)
    elif "RUNNING" in statuses:
        status = "RUNNING"
    elif statuses == {"FAILED"}:
        status = "FAILED"
    elif statuses != {"COMPLETE"} or len(latest) != len(connections):
        status = "PARTIAL"
    else:
        status = "STALE" if reasons else "COMPLETE"
    return {"status": status, "last_success_at": max((_stamp(run["finished_at"]) for run in successes), default=None),
            "last_attempt_at": max((_stamp(run["started_at"]) for run in latest), default=None),
            "schedule_minutes": schedule, "reasons": sorted(reasons)}


def inventory_summary(repo, account, settings=None, now=None):
    """Account-list status without loading any saved observation batches."""
    now = utc(now or datetime.now(UTC))
    store = CoverageStore(repo)
    connections = _connections(store, account)
    runs = {str(row["id"]): (store.latest_run(row["id"]), store.latest_run(row["id"], status="COMPLETE"))
            for row in connections}
    refusal = aws_access.use_refusal(account, aws_access.SCANNER, aws_access.approval(repo, aws_access.SCANNER, settings))
    return _summary(repo, account, connections, runs, settings, now, refusal)


def key_owner(repo, identifier, *, settings=None, now=None):
    """Resolve one exact key from complete saved IAM inventory, without AWS I/O.

    A missing, conflicting or incomplete result is unknown, never proof that a
    key does not exist. The aggregate snapshot limit also bounds this lookup.
    """
    from cremore_aws_provider.investigation.usage import KeyOwner

    if not re.fullmatch(r"AKIA[A-Z0-9]{16}", identifier or ""):
        return None
    now = utc(now or datetime.now(UTC))
    store = CoverageStore(repo)
    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    accounts = {account.account_id for account in repo.list_aws_accounts()
                if not aws_access.use_refusal(account, aws_access.SCANNER, approved)}
    remaining, matches = MAX_OBSERVATIONS, {}
    for connection in store.list_connections():
        raw_spec = connection["spec"]
        if (raw_spec.get("schema_version", 1) != 1 or raw_spec.get("provider") != "aws_iam"
                or not connection["enabled"] or raw_spec.get("account_id") not in accounts):
            continue
        snapshots = store.snapshots(connection["id"], limit=1, max_items=remaining)
        latest = snapshots[0] if snapshots else None
        if _reasons(connection, latest, now) or latest["truncated"]:
            return None
        remaining -= len(latest["items"])
        spec = ConnectionSpec.model_validate(raw_spec)
        for raw in latest["items"]:
            try:
                item = Observation.model_validate(raw)
            except ValidationError:
                return None
            if item.identifier != identifier or item.evidence != "ISSUED" or item.credential_type != "AWS_ACCESS_KEY":
                continue
            if item.version_state != "CURRENT" or not in_scope(spec, item):
                return None
            arn = item.principal_arn or item.reference
            owner = KeyOwner(item.account_id, arn, arn.rsplit("/", 1)[-1] if ":user/" in arn else "")
            evidence = {"source": "IAM_INVENTORY", "connection_id": str(connection["id"]),
                        "run_id": str(latest["id"]), "observed_at": _stamp(latest["finished_at"])}
            matches[owner] = evidence
            if len(matches) > 1:
                return None
    return next(iter(matches.items())) if matches else None


@dataclass(frozen=True)
class _Evidence:
    item: Observation
    current: bool
    observed_at: str
    rank: tuple


def _one(values):
    values = {value for value in values if value}
    return (next(iter(values)) if len(values) == 1 else ""), len(values) > 1


def _source(item):
    if item.evidence == "ISSUED":
        return "IAM_SERVICE_CREDENTIALS" if item.credential_type == "AWS_SERVICE_CREDENTIAL" else "IAM_ACCESS_KEYS"
    return "CLOUDTRAIL_STS_ISSUANCE" if item.evidence == "SESSION_ISSUED" else "CLOUDTRAIL_SESSION_USE"


def _principal(evidence):
    item = evidence.item
    result = {"principal_arn": item.principal_arn or item.reference,
              "principal_name": "root" if item.evidence == "ROOT_STATUS" else item.reference.rsplit("/", 1)[-1],
              "created_at": (item.iam_report.user_created_at if item.iam_report else
                             item.created_at if item.evidence == "USER_STATUS" else ""),
              "evidence_source": "IAM_CREDENTIAL_REPORT", "current_evidence": evidence.current,
              **{field: getattr(item, field) for field in _FLAGS}}
    if item.iam_report:
        result["iam_report"] = item.iam_report.model_dump(include=_REPORT_FIELDS)
    return result


def _record(evidence, account_id, now, limitations):
    evidence.sort(key=lambda row: row.rank)
    identity = evidence[0].item
    temporary = identity.identifier.startswith("ASIA")
    issued = [row for row in evidence if row.item.evidence == "ISSUED"]
    sessions = [row for row in evidence if row.item.session]
    issuance = [row for row in sessions if row.item.evidence == "SESSION_ISSUED" and row.item.session.outcome == "SUCCEEDED"]
    successful = [row for row in sessions if row.item.evidence == "USAGE" and row.item.session.outcome == "SUCCEEDED"]
    latest_iam = issued[-1] if issued else None
    record = {"match_id": identity.identifier, "identifier_hint": identity.identifier[:4] + "…" + identity.identifier[-4:],
              "credential_type": identity.credential_type, "account_id": account_id,
              "credential_class": "TEMPORARY_STS" if temporary else
                  "SERVICE_SPECIFIC" if identity.credential_type == "AWS_SERVICE_CREDENTIAL" else "LONG_LIVED",
              "provider_status": "OBSERVED_ISSUANCE" if issuance else "OBSERVED_SESSION" if temporary else "UNKNOWN",
              "evidence_source": _source(latest_iam.item if latest_iam else issuance[-1].item if issuance else evidence[-1].item),
              "current_evidence": latest_iam.current if latest_iam else any(row.current for row in evidence),
              "field_status": {"current_validity": "NOT_VERIFIABLE", "potential_access": "NOT_COLLECTED"}}
    fields = record["field_status"]
    conflict = False
    if latest_iam:
        record.update(principal_arn=latest_iam.item.principal_arn or latest_iam.item.reference,
                      issuer_account_id=account_id, service=latest_iam.item.service,
                      observed_provider_status=latest_iam.item.state,
                      provider_status_observed_at=latest_iam.observed_at)
        if latest_iam.current:
            record["provider_status"] = latest_iam.item.state
        candidates = [row for row in issued if row.current or row.rank == latest_iam.rank]
        for field, values in (
            ("principal_arn", (row.item.principal_arn or row.item.reference for row in candidates)),
            ("provider_status", (row.item.state for row in candidates)),
        ):
            _, multiple = _one(values)
            if multiple:
                record[field] = "UNKNOWN" if field == "provider_status" else ""
                fields[field] = "STALE_OR_CONFLICTING"
                record["current_evidence"] = False
                limitations.add("INVENTORY_MATCH_AMBIGUOUS")
        record["created_at"] = next((_stamp(row.item.created_at) for row in reversed(issued) if row.item.created_at), "")
        used = max((row for row in issued if row.item.last_used_at),
                   key=lambda row: _stamp(row.item.last_used_at), default=None)
        if used:
            record.update(last_used_at=_stamp(used.item.last_used_at),
                          last_used_service=used.item.iam_last_used.service if used.item.iam_last_used else used.item.service,
                          last_used_region=used.item.iam_last_used.region if used.item.iam_last_used else used.item.region)
        lookup = next((row.item.iam_last_used for row in reversed(issued) if row.item.iam_last_used), None)
        if lookup:
            record["iam_last_used"] = lookup.model_dump(include=_LAST_USED_FIELDS)
            fields["last_used_at"] = {"DENIED": "ACCESS_DENIED", "FAILED": "COLLECTION_FAILED",
                                      "NOT_REQUESTED": "NOT_COLLECTED"}.get(lookup.status, lookup.status)
    else:
        record["principal_arn"], conflict = _one(row.item.principal_arn for row in evidence)
        if conflict:
            record["current_evidence"] = False
            fields["principal_arn"] = "STALE_OR_CONFLICTING"
    if temporary:
        for row in sessions:
            session = row.item.session
            owners = {arn.split(":", 5)[4] for arn in (session.issuer_arn, session.session_arn)
                      if len(arn.split(":", 5)) == 6}
            if session.issuer_account_id:
                owners.add(session.issuer_account_id)
            if (len(owners) > 1 or (session.recipient_account_id and session.recipient_account_id != account_id)
                    or (session.session_arn and row.item.principal_arn and session.session_arn != row.item.principal_arn)):
                conflict = True
                fields["issuer_account_id"] = "STALE_OR_CONFLICTING"
    for field, values in (
        ("issuer_account_id", (row.item.session.issuer_account_id for row in sessions)),
        ("recipient_account_id", (row.item.session.recipient_account_id for row in sessions)),
        ("issuer_arn", (row.item.session.caller_arn for row in issuance)),
        ("session_issuer_arn", (row.item.session.issuer_arn for row in sessions)),
        ("source_identity", (row.item.session.source_identity for row in sessions)),
    ):
        value, multiple = _one(values)
        if value and field not in record:
            record[field] = value
        if multiple:
            fields[field] = "STALE_OR_CONFLICTING"
            record["current_evidence"] = False
            conflict = True
    for field, values in (
        ("issued_at", (_stamp(row.item.session.issued_at) for row in issuance)),
        ("created_at", (_stamp(row.item.session.issued_at) for row in sessions)),
        ("expires_at", (_stamp(row.item.session.expires_at) for row in issuance)),
    ):
        if not temporary:
            continue
        value, multiple = _one(values)
        record[field] = value
        if multiple:
            conflict = True
            fields[field] = "STALE_OR_CONFLICTING"
    first_use = [_stamp(row.item.session.first_used_at or row.item.last_used_at) for row in successful]
    last_use = [_stamp(row.item.session.last_used_at or row.item.last_used_at) for row in successful]
    record["first_observed_use_at"] = min((value for value in first_use if value), default="")
    record["last_observed_use_at"] = max((value for value in last_use if value), default="")
    # Denied/unknown events remain observations, never successful-use timestamps.
    seen = [_stamp(value) for row in evidence for value in
            ((row.item.session.issued_at,) if row.item.evidence == "SESSION_ISSUED" and row.item.session else
             (row.item.session.first_used_at, row.item.session.last_used_at) if row.item.session else
             (row.item.last_used_at or row.observed_at,)) if value]
    record["first_seen_at"] = min(seen, default="")
    record["last_seen_at"] = max(seen, default="")
    expiry = record.get("expires_at", "")
    if expiry and any(value and value > expiry for value in
                      (record.get("issued_at"), record.get("created_at"), record["last_observed_use_at"])):
        conflict = True
    if temporary and conflict:
        record["expires_at"] = ""
        record["current_evidence"] = False
        fields["expires_at"] = "STALE_OR_CONFLICTING"
        limitations.add("INVENTORY_LIFECYCLE_CONFLICT")
    record["expiry_status"] = ("EXPIRED" if record["expires_at"] <= now.isoformat() else "NOT_EXPIRED") \
        if temporary and record.get("expires_at") else "UNKNOWN"
    for field, values in (
        ("evidence_sources", {_source(row.item) for row in evidence} | {row.item.session.evidence_source for row in sessions}),
        ("observed_regions", {row.item.region for row in evidence if row.item.region}),
        ("evidence_event_ids", {row.item.session.event_id for row in sessions}),
    ):
        record[field] = sorted(values)[:MAX_EVIDENCE_ITEMS]
        if len(values) > MAX_EVIDENCE_ITEMS:
            limitations.add("SESSION_EVIDENCE_CONFLICT_OR_CAPPED")
    record["principal_name"] = record.get("principal_arn", "").rsplit("/", 1)[-1]
    if record["principal_name"].endswith(":root"):
        record["principal_name"] = "root"
    for field in ("principal_arn", "issuer_account_id", "recipient_account_id", "issuer_arn", "session_issuer_arn",
                  "source_identity", "created_at", "issued_at", "expires_at", "last_used_at", "last_used_service",
                  "last_used_region", "first_observed_use_at", "last_observed_use_at"):
        fields.setdefault(field, "AVAILABLE" if record.get(field) else "NOT_RECORDED")
    if not temporary:
        fields.update(expires_at="NOT_APPLICABLE", issued_at="NOT_APPLICABLE")
    if not record["current_evidence"]:
        fields["provider_status"] = "STALE_OR_CONFLICTING"
        if record["provider_status"] in _PROVIDER_STATES:
            record["provider_status"] = "UNKNOWN"
    return record


def _refresh(repo, account, connections, saved):
    jobs = [job for row in connections if (job := connection_job(repo, row["id"], active=True))]
    if not jobs:
        jobs = [job for row in connections if (job := connection_job(repo, row["id"]))]
    job = max(jobs, key=lambda value: (_stamp(value.created_at), str(value.id)), default=None)
    if not job:
        return None
    def result_status(candidate):
        state = "RUNNING" if candidate.status == "CANCELLING" else candidate.status
        if state == "SUCCEEDED":
            match = next((run for runs in saved.values() for run in runs if run["request_id"] == str(candidate.id)), None)
            state = match["status"] if match and match["status"] in ("COMPLETE", "PARTIAL") else "FAILED"
        return state if state in ("QUEUED", "RUNNING", "COMPLETE", "PARTIAL") else "FAILED"

    statuses = {result_status(candidate) for candidate in jobs}
    status = next(value for value in ("RUNNING", "QUEUED", "FAILED", "PARTIAL", "COMPLETE") if value in statuses)
    result = {"id": str(job.id), "aws_account_id": str(account.id), "status": status,
              "requested_at": _stamp(job.created_at), "started_at": _stamp(job.started_at),
              "finished_at": _stamp(job.finished_at), "attempts": int(job.status != "QUEUED")}
    if status == "FAILED":
        result["error_code"] = "SCANNER_ROLE_UNAVAILABLE" if any(candidate.error == "SCANNER_ROLE_UNAVAILABLE" for candidate in jobs) else "AWS_INVENTORY_REFRESH_FAILED"
    return result


def inventory_response(repo, account, *, settings=None, now=None, offset=0, limit=5000, snapshot_revision=""):
    """Project bounded saved facts; paging never silently removes unreturned rows."""
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 5000:
        raise CoverageError("INVALID_INVENTORY_PAGE")
    now = utc(now or datetime.now(UTC))
    store = CoverageStore(repo)
    connections = _connections(store, account)
    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    refusal = aws_access.use_refusal(account, aws_access.SCANNER, approved)
    saved, runs, revisions = {}, {}, []
    credentials, principals, roots = {}, {}, {}
    coverage, windows = [], []
    limitations = {"INVENTORY_IS_METADATA_NOT_EXPOSURE", "ROOT_KEYS_NOT_ENUMERATED"}
    remaining, truncated, invalid = MAX_OBSERVATIONS, False, False
    regions = sorted({region for row in connections for region in row["spec"].get("regions", [])})
    for connection in connections:
        cid = str(connection["id"])
        snapshots = store.snapshots(connection["id"], max_items=remaining)
        saved[cid] = snapshots
        remaining -= sum(len(run["items"]) for run in snapshots)
        truncated |= any(run["truncated"] for run in snapshots)
        latest = snapshots[0] if snapshots else None
        runs[cid] = (latest, store.latest_run(connection["id"], status="COMPLETE"))
        reasons = _reasons(connection, latest, now)
        limitations.update(reasons)
        spec = ConnectionSpec.model_validate(connection["spec"])
        if spec.provider == "aws_cloudtrail":
            limitations.add("STS_OBSERVED_SESSIONS_ONLY")
            if latest:
                end = utc(latest["started_at"])
                windows.append((end - timedelta(days=spec.window_days), end))
        operation_rows = []
        for run in snapshots:
            current = bool(not refusal and not reasons and latest and run["id"] == latest["id"])
            observed_at = _stamp(run["finished_at"] or run["started_at"])
            for raw in run["items"]:
                try:
                    item = Observation.model_validate(raw)
                except ValidationError:
                    limitations.add("INVENTORY_INVALID_SAVED_OBSERVATION")
                    invalid = True
                    continue
                # A stored connection may have been edited: retain old facts only
                # within the selected account and mark out-of-scope facts historical.
                if item.account_id != account.account_id:
                    continue
                valid = current and item.version_state == "CURRENT" and in_scope(spec, item)
                evidence = _Evidence(item, valid, observed_at,
                    (observed_at, run["sequence"], cid, str(run["id"])))
                if item.evidence in ("ISSUED", "SESSION_ISSUED", "USAGE"):
                    credentials.setdefault((item.credential_type, item.identifier), []).append(evidence)
                elif item.evidence in ("USER_STATUS", "ROOT_STATUS"):
                    target = roots if item.evidence == "ROOT_STATUS" else principals
                    key = item.principal_arn or item.reference
                    previous = target.get(key)
                    if previous is None or evidence.rank > previous.rank:
                        target[key] = evidence
                elif item.operation and latest and run["id"] == latest["id"]:
                    operation_rows.append({"source": _OPERATION_SOURCES[item.operation.name],
                        "operation": item.operation.name, "region": item.region,
                        "status": item.operation.status, "records_observed": item.operation.records,
                        "requests": item.operation.requests, "error_code": item.operation.reason,
                        "connection_id": cid})
        coverage.extend(operation_rows or [{"source": "IAM_INVENTORY" if spec.provider == "aws_iam" else
            "TRAIL_S3" if spec.cloudtrail_source == "s3" else "EVENT_HISTORY",
            "status": latest["status"] if latest else "NOT_COLLECTED", "records_observed": latest["item_count"] if latest else 0,
            "error_code": next(iter(sorted(_codes(latest["reasons"])))) if latest and _codes(latest["reasons"]) else None,
            "connection_id": cid}])
        revisions.append({"id": cid, "revision": connection["revision"], "enabled": connection["enabled"],
                          "spec": connection["spec"], "reasons": sorted(reasons), "runs": [
            {"id": str(run["id"]), "revision": run["revision"], "status": run["status"],
             "item_count": run["item_count"], "loaded": len(run["items"]), "reasons": sorted(_codes(run["reasons"]))}
            for run in snapshots]})
    records = [_record(credentials[key], account.account_id, now, limitations) for key in sorted(credentials)]
    users = [_principal(principals[key]) for key in sorted(principals)]
    root_rows = [_principal(roots[key]) for key in sorted(roots)]
    if refusal:
        limitations.add(refusal)
    if truncated:
        limitations.add("INVENTORY_OBSERVATION_LIMIT_REACHED")
    if truncated or invalid:
        for row in records + users + root_rows:
            row["current_evidence"] = False
            if row.get("provider_status") in _PROVIDER_STATES:
                row["provider_status"] = "UNKNOWN"
    summary = _summary(repo, account, connections, runs, settings, now, refusal)
    revision = digest({"account": {field: getattr(account, field) for field in
        ("account_id", "enabled", "access_revision", "validation_key", "validation_status", "source",
         "org_state", "org_present", "in_deployment_scope")}, "approval_revision": approved.get("revision") if approved else None,
        "refusal": refusal, "connections": revisions, "truncated": truncated, "invalid": invalid,
        "expiry": [(row["match_id"], row["expiry_status"]) for row in records if row["credential_class"] == "TEMPORARY_STS"]})
    if snapshot_revision and snapshot_revision != revision:
        raise CoverageError("INVENTORY_SNAPSHOT_CHANGED")
    inventory = None
    completed = [run for snapshots in saved.values() for run in snapshots if run["finished_at"]]
    if completed:
        observed = [run for run in completed if run["status"] in ("COMPLETE", "PARTIAL")]
        status = summary["status"]
        if status in ("STALE", "BLOCKED") or truncated or invalid:
            status = "PARTIAL"
        inventory = {"account_id": account.account_id, "collection_status": status,
            "collected_at": max(_stamp(run["finished_at"]) for run in observed or completed),
            "report_generated_at": max((row.get("iam_report", {}).get("generated_at", "") for row in users + root_rows), default=""),
            "window_start": min((_stamp(start) for start, _ in windows), default=""),
            "window_end": max((_stamp(end) for _, end in windows), default=""), "regions": regions,
            "records": records[offset:offset + limit], "iam_users": users[offset:offset + limit], "root_status": root_rows,
            "total": len(records), "iam_user_total": len(users), "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < max(len(records), len(users)) else None,
            "snapshot_revision": revision, "coverage": coverage, "limitations": sorted(limitations)}
    return {"inventory": inventory, "refresh": _refresh(repo, account, connections, saved), "regions": regions}
