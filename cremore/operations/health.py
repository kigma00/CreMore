"""One health view over every connection: authentication, renewal, expiry, freshness.

Read-only. It reads the stores that already exist -- content connections, their jobs
and change-feed cursors, schema 1/2 coverage connections and their runs, AWS accounts and the
worker's AWS identity report -- and changes nothing. Only codes, times and the
names the dashboard already shows leave it; never provider text or a secret.
"""

from __future__ import annotations

import datetime as _dt
import math

AUTH_STATES = ("READY", "EXPIRING", "REAUTH_REQUIRED", "PERMISSION_LIMITED",
               "SECRET_UNAVAILABLE", "DISABLED", "UNKNOWN")
# EXTERNAL: a customer-side collector holds the credential, so CreMore sees only
# whether its uploads keep arriving. UNKNOWN: nothing has reported the identity.
RENEWALS = ("AUTO", "MANUAL", "HUMAN_SESSION", "EXTERNAL", "UNKNOWN")
FRESHNESS = ("FRESH", "STALE", "NEVER_COLLECTED", "NOT_SCHEDULED")
EXPIRY_STAGES = ("NONE", "D14", "D3", "EXPIRED")
KINDS = ("CONTENT", "METADATA", "VAULT", "AWS_ACCOUNT", "AWS_INVENTORY")
LAST_STATUSES = ("FAILED", "NOT_COLLECTED", "PARTIAL", "COMPLETE")
EXPIRY_PREFIX = "connection-expiry:"
# A scheduled content connection is stale after three missed intervals and never
# sooner than a day (design 4.1); coverage keeps its own freshness_hours contract.
STALE_FLOOR_HOURS = 24
WORKER_REPORT_TTL = _dt.timedelta(seconds=300)
# A change feed failing this long is an operations alert: until a look succeeds the change scans of its failing roots wait.
FEED_ALERT_AFTER = _dt.timedelta(hours=1)
AWS_INVENTORY = ("aws_iam", "aws_cloudtrail")
_AUTO_AUTH_TYPES = ("github_app", "adc", "workload_identity", "google_oauth")
_REAUTH_CODES = frozenset({
    "NO_CREDENTIALS", "NO_CREDENTIAL", "AUTH_EXPIRED", "CREDENTIAL_REJECTED", "AWS_SCANNER_IDENTITY_CHANGED",
    "GCP_OAUTH_SETUP_REQUIRED", "GCP_OAUTH_SCOPE_REQUIRED", "GCP_OAUTH_OFFLINE_ACCESS_REQUIRED",
    "GCP_AMBIENT_CREDENTIALS_REQUIRED", "AZURE_KEY_VAULT_AMBIENT_CREDENTIALS_REQUIRED",
})
_PRIORITY = ("SECRET_UNAVAILABLE", "REAUTH_REQUIRED", "PERMISSION_LIMITED")
# present_connection's older content states, in the shared vocabulary.
_CONTENT_STATES = {"READY": "READY", "DISABLED": "DISABLED", "REAUTH_REQUIRED": "REAUTH_REQUIRED",
                   "SECRET_UNAVAILABLE": "SECRET_UNAVAILABLE", "AUTH_EXPIRED": "REAUTH_REQUIRED",
                   "AUTH_LIFETIME_TOO_SHORT": "READY", "AUTH_FRESHNESS_UNKNOWN": "UNKNOWN"}


def classify(code: str | None) -> str | None:
    """The authentication state a failure code implies, or None when it is not about authentication."""
    if not code:
        return None
    if code.startswith("AWS_ROLES_ANYWHERE_"):
        return "REAUTH_REQUIRED"
    if code in ("SECRET_UNAVAILABLE", "METADATA_SECRET_UNAVAILABLE") or code.startswith("SECRET_STORE_"):
        return "SECRET_UNAVAILABLE"
    if code in _REAUTH_CODES or "REAUTH" in code or code.endswith(
            ("_REJECTED", "AUTHENTICATION_FAILED", "UNAUTHORIZED", "LOGIN_REQUIRED")):
        return "REAUTH_REQUIRED"
    if "PERMISSION" in code or "DENIED" in code or "FORBIDDEN" in code or code.endswith("NOT_AUTHORIZED"):
        return "PERMISSION_LIMITED"
    return None


def worst(codes) -> tuple[str | None, str | None]:
    """The most severe authentication state among codes, with the code that implies it."""
    implied = {code: classify(code) for code in codes or ()}
    for state in _PRIORITY:
        for code in sorted(implied):
            if implied[code] == state:
                return state, code
    return None, None


def utc(value):
    if isinstance(value, str):
        try:
            value = _dt.datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, _dt.datetime):
        return None
    return value.replace(tzinfo=_dt.UTC) if value.tzinfo is None else value.astimezone(_dt.UTC)


def _iso(value):
    value = utc(value)
    return value.isoformat() if value else None


def expiry_stage(expires_at, renewal: str, now) -> str:
    """How close a credential that does not renew itself is to expiring."""
    if expires_at is None or renewal == "AUTO":
        return "NONE"
    left = expires_at - now
    if left <= _dt.timedelta(0):
        return "EXPIRED"
    if left <= _dt.timedelta(days=3):
        return "D3"
    return "D14" if left <= _dt.timedelta(days=14) else "NONE"


def aws_identity_hold(repo, now=None) -> str | None:
    """Why AWS work must wait: an expired sign-in or an identity change nobody approved."""
    from cremore_aws_provider.aws_identity import APPROVED_IDENTITY_KEY, WORKER_IDENTITY_KEY

    approved, record = repo.get_setting(APPROVED_IDENTITY_KEY), repo.get_setting(WORKER_IDENTITY_KEY)
    if not approved or not record or record["updated_at"] is None:
        return None
    if (utc(now) or _dt.datetime.now(_dt.UTC)) - utc(record["updated_at"]) > WORKER_REPORT_TTL:
        return None
    worker = record["value"] or {}
    renewal = worker.get("renewal_health") or {}
    if renewal.get("state") == "ERROR":
        return renewal.get("error_code") or "AWS_ROLES_ANYWHERE_RENEWAL_FAILED"
    if worker.get("state") in ("LOGIN_REQUIRED", "NO_CREDENTIALS"):
        return "AWS_LOGIN_REQUIRED"
    if worker.get("state") == "READY" and worker.get("match_key") != approved["value"].get("match_key"):
        return "AWS_SCANNER_IDENTITY_CHANGED"
    return None


def aws_renewal(repo) -> str:
    """How the worker's own AWS identity renews, from its last report."""
    from cremore_aws_provider.aws_identity import WORKER_IDENTITY_KEY

    worker = ((repo.get_setting(WORKER_IDENTITY_KEY) or {}).get("value")) or {}
    if worker.get("state") == "LOGIN_REQUIRED" or worker.get("kind") == "IDENTITY_CENTER":
        return "HUMAN_SESSION"
    return {"IAM_ROLE": "AUTO", "IAM_USER": "MANUAL", "ROOT": "MANUAL"}.get(worker.get("kind"), "UNKNOWN")


def _freshness(success_at, stale_after_hours: int, now) -> str:
    if success_at is None:
        return "NEVER_COLLECTED"
    return "STALE" if now - utc(success_at) > _dt.timedelta(hours=stale_after_hours) else "FRESH"


def _item(key, kind, ident, provider, name, *, state, reason, renewal, now, expires_at=None, declared=None,
          success_at=None, failure_at=None, failure_code=None, last_status="NOT_COLLECTED",
          freshness="NOT_SCHEDULED", stale_after_hours=None) -> dict:
    source = "PROVIDER" if expires_at else None
    if expires_at is None and declared:
        expires_at, source = utc(declared), "OPERATOR"
    stage = expiry_stage(expires_at, renewal, now)
    # A credential not used yet (UNKNOWN) expires all the same: it is warned like a working one.
    if state in ("READY", "UNKNOWN") and stage == "EXPIRED":
        state, reason = "REAUTH_REQUIRED", "AUTH_EXPIRED"
    elif state in ("READY", "UNKNOWN") and stage in ("D14", "D3"):
        state, reason = "EXPIRING", "AUTH_EXPIRING"
    return {"key": key, "kind": kind, "id": str(ident), "provider": provider, "name": name,
            "auth_state": state, "auth_reason": reason, "auth_renewal": renewal,
            "expires_at": _iso(expires_at), "expires_source": source, "expiry_stage": stage,
            "last_success_at": _iso(success_at), "last_failure_at": _iso(failure_at),
            "last_failure_code": failure_code, "last_status": last_status,
            "freshness": freshness, "stale_after_hours": stale_after_hours}


def _content_items(repo, settings, now, declared, aws, hold):
    from cremore.api.source_presenters import present_connection
    from cremore.domain.models import CONTENT_SCAN_KINDS
    from cremore.scanning import trigger_settings, triggers
    from cremore.scanning.scope import job_error_code, job_is_partial

    kinds = tuple(kind for kind in CONTENT_SCAN_KINDS if kind != "inline")
    successes = repo.latest_connection_jobs(kinds, "SUCCEEDED")
    failures = repo.latest_connection_jobs(kinds, "FAILED")
    intervals = {}
    if trigger_settings.schedules_on(settings, repo):
        # Only a profile the schedule poller would actually run sets an interval; one without a full-scan
        # cadence of its own follows the installation default.
        default, _start = trigger_settings.full_scan(settings, repo)
        for profile in repo.list_scheduled_profiles(default):
            cadences = [v for v in (profile.schedule_minutes, triggers.full_scan_cadence(profile, default)) if v]
            if profile.state == "READY" and profile.approved_at and profile.approved_by and cadences:
                minutes = min(cadences)
                known = intervals.get(profile.connection_id, minutes)
                intervals[profile.connection_id] = min(known, minutes)
    for c in repo.list_connections():
        view = present_connection(c)
        auth = view["connection_auth"]
        state = _CONTENT_STATES.get(auth["state"], "UNKNOWN")
        reason = auth["reason_code"] if state not in ("READY", "DISABLED") else None
        success, failure = successes.get(c.id), failures.get(c.id)
        if failure and success and utc(failure.finished_at) <= utc(success.finished_at):
            failure = None
        failure_code = (job_error_code(failure) or "SCAN_FAILED") if failure else None
        implied, checked_at = classify(failure_code), utc(auth["checked_at"])
        if state != "DISABLED" and implied and (checked_at is None or utc(failure.finished_at) > checked_at):
            state, reason = implied, failure_code
        elif state == "UNKNOWN" and success and not failure:
            state = "READY"  # a scan that read the source proves the credential worked
        if view["credential_source"] == "GITHUB_APP" or auth["refresh_supported"]:
            renewal = "AUTO"
        elif view["source_type"] == "s3":
            renewal = aws  # S3 reads use the scanner's own AWS identity
            if hold and state != "DISABLED":
                state, reason = "REAUTH_REQUIRED", hold
        elif view["credential_source"] == "OPERATOR_MOUNTED_ENV" and not c.secret_ref:
            renewal = "AUTO"  # ambient workload identity (GCS, Azure Blob)
        else:
            renewal = "MANUAL"
        interval = intervals.get(c.id)
        if state == "DISABLED" or not interval:
            freshness, stale_after = "NOT_SCHEDULED", None
        else:
            stale_after = max(STALE_FLOOR_HOURS, math.ceil(3 * interval / 60))
            freshness = _freshness(success.finished_at if success else None, stale_after, now)
        # A run partial only for the upgrade hold (policy_held_only) waits, as planned, for the next full scan.
        partial = success and job_is_partial(success) and not (success.coverage or {}).get("policy_held_only")
        last_status = ("FAILED" if failure else "PARTIAL" if partial else "COMPLETE" if success else "NOT_COLLECTED")
        yield _item(f"content:{c.id}", "CONTENT", c.id, view["source_type"], c.name, state=state, reason=reason,
                    renewal=renewal, now=now, expires_at=utc(auth["expires_at"]),
                    declared=declared.get(f"content:{c.id}"), success_at=success.finished_at if success else None,
                    failure_at=failure.finished_at if failure else None, failure_code=failure_code,
                    last_status=last_status, freshness=freshness, stale_after_hours=stale_after)


def _coverage_parts(row, entry, now) -> dict:
    """Authentication and freshness one coverage connection's runs show."""
    spec, finished, success = row["spec"], entry.get("finished"), entry.get("success")
    implied, code = worst(finished["reasons"]) if finished and finished["status"] != "COMPLETE" else (None, None)
    if not row["enabled"]:
        state, reason = "DISABLED", None
    elif implied:
        state, reason = implied, code
    else:
        state, reason = ("READY" if success else "UNKNOWN"), None
    failed = finished if finished and finished["status"] == "FAILED" else None
    failure_code = (code or (sorted(failed["reasons"]) or ["COLLECTION_FAILED"])[0]) if failed else None
    if not row["enabled"]:
        freshness, stale_after = "NOT_SCHEDULED", None
    else:
        stale_after = max(int(spec.get("freshness_hours") or 24),
                          math.ceil(3 * int(spec.get("schedule_minutes") or 0) / 60))
        # The run's start, as the existing comparison judges currentness.
        freshness = _freshness(success["started_at"] if success else None, stale_after, now)
    return {"state": state, "reason": reason, "success_at": success["finished_at"] if success else None,
            "failure_at": failed["finished_at"] if failed else None, "failure_code": failure_code,
            "last_status": finished["status"] if finished else "NOT_COLLECTED",
            "freshness": freshness, "stale_after": stale_after}


def _coverage_renewal(spec, settings, aws) -> str:
    if spec.get("schema_version", 1) == 2:
        refreshes = "refresh_token" in (spec.get("secret_refs") or {})
        return "AUTO" if spec.get("auth_type") in _AUTO_AUTH_TYPES or refreshes else "MANUAL"
    if spec["provider"] in AWS_INVENTORY or spec.get("server_collection") and spec["provider"].startswith("aws_"):
        return aws
    if spec.get("server_collection"):
        # Vault/OpenBao: the connection's own login -- a token an admin replaces, or a role the worker logs in with --
        # else the installation's own secret store login.
        method = (spec.get("server_auth") or {}).get("method")
        if method:
            return "MANUAL" if method == "token" else "AUTO"
        return "AUTO" if getattr(settings, "secret_store_auth_mode", "token") == "kubernetes" else "MANUAL"
    return "EXTERNAL"


def _coverage_items(repo, settings, now, declared, aws, hold):
    from cremore_aws_provider import aws_access

    from cremore.coverage.store import CoverageStore

    store = CoverageStore(repo)
    runs = store.latest_runs()
    accounts = {account.account_id: account for account in repo.list_aws_accounts()}
    inventory: dict[str, list] = {}
    for row in store.list_connections():
        spec, entry = row["spec"], runs.get(row["id"], {})
        schema = spec.get("schema_version", 1)
        if schema == 1 and spec["provider"] in AWS_INVENTORY and spec.get("account_id") in accounts:
            inventory.setdefault(spec["account_id"], []).append((row, entry))  # shown on its account
            continue
        kind = "METADATA" if schema == 2 else "AWS_INVENTORY" if spec["provider"] in AWS_INVENTORY else "VAULT"
        part = _coverage_parts(row, entry, now)
        yield _item(f"coverage:{row['id']}", kind, row["id"], spec["provider"], spec["name"], state=part["state"],
                    reason=part["reason"], renewal=_coverage_renewal(spec, settings, aws), now=now,
                    declared=declared.get(f"coverage:{row['id']}"), success_at=part["success_at"],
                    failure_at=part["failure_at"], failure_code=part["failure_code"],
                    last_status=part["last_status"], freshness=part["freshness"],
                    stale_after_hours=part["stale_after"])
    approval = aws_access.approval(repo, aws_access.SCANNER, settings)
    for account in accounts.values():
        result = aws_access.effective_validation(account, aws_access.SCANNER, approval)
        if not account.enabled:
            state, reason = "DISABLED", None
        elif hold:
            state, reason = "REAUTH_REQUIRED", hold
        elif result["status"] == "VALID":
            state, reason = "READY", None
        elif result["status"] == "INVALID":
            state = classify(result["detail"]) or "PERMISSION_LIMITED"
            reason = result["detail"] or "ACCOUNT_NOT_VALIDATED"
        else:
            state, reason = "UNKNOWN", result["detail"] or result["status"]
        parts = [_coverage_parts(row, entry, now) for row, entry in inventory.get(account.account_id, ())
                 if row["enabled"]]
        limited = sorted((p for p in parts if p["state"] in _PRIORITY), key=lambda p: _PRIORITY.index(p["state"]))
        if state == "READY" and limited:
            state, reason = limited[0]["state"], limited[0]["reason"]
        fields = {"last_status": "NOT_COLLECTED", "freshness": "NOT_SCHEDULED"}
        if parts and account.enabled:
            successes = [p["success_at"] for p in parts]
            failed = [p for p in parts if p["failure_at"]]
            newest = max(failed, key=lambda p: utc(p["failure_at"])) if failed else None
            fields = {"success_at": None if None in successes else min(successes, key=utc),
                      "failure_at": newest and newest["failure_at"],
                      "failure_code": newest and newest["failure_code"],
                      "last_status": min((p["last_status"] for p in parts), key=LAST_STATUSES.index),
                      "freshness": min((p["freshness"] for p in parts), key=("STALE", "NEVER_COLLECTED", "FRESH").index),
                      "stale_after_hours": min(p["stale_after"] for p in parts)}
        renewal = "HUMAN_SESSION" if account.access == aws_access.SSO_PERMISSION_SET else aws
        yield _item(f"aws_account:{account.id}", "AWS_ACCOUNT", account.id, "aws", account.name, state=state,
                    reason=reason, renewal=renewal, now=now, declared=declared.get(f"aws_account:{account.id}"),
                    **fields)


def evaluate(repo, settings, *, now=None) -> list[dict]:
    """Every connection's health, in a stable order."""
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    declared = {record["key"][len(EXPIRY_PREFIX):]: (record["value"] or {}).get("expires_at")
                for record in repo.list_settings(EXPIRY_PREFIX)}
    declared = {key: value for key, value in declared.items() if value}
    aws, hold = aws_renewal(repo), aws_identity_hold(repo, now)
    items = [*_content_items(repo, settings, now, declared, aws, hold),
             *_coverage_items(repo, settings, now, declared, aws, hold)]
    from cremore_aws_provider.aws_identity import WORKER_IDENTITY_KEY

    report = repo.get_setting(WORKER_IDENTITY_KEY) or {}
    renewed = (report.get("value") or {}).get("renewal_health") or {}
    checked = utc(report.get("updated_at"))
    if checked and now - checked <= WORKER_REPORT_TTL:
        for item in items:
            if item["provider"] not in {"aws", "s3", "aws_iam", "aws_cloudtrail", "aws_secrets_manager", "aws_ssm"} or item["auth_state"] == "DISABLED":
                continue
            if item["auth_renewal"] == "EXTERNAL":
                continue  # Customer-side collectors do not use this worker's certificate.
            if renewed.get("state") == "ERROR":
                item.update(auth_state="REAUTH_REQUIRED", auth_reason=renewed.get("error_code"))
            elif renewed.get("state") == "EXPIRING" and item["auth_state"] in {"READY", "UNKNOWN"}:
                item.update(auth_state="EXPIRING", auth_reason="AWS_ROLES_ANYWHERE_CERTIFICATE_EXPIRING")
            if renewed:
                item["renewal_health"] = renewed
    return sorted(items, key=lambda item: (KINDS.index(item["kind"]), item["name"].lower(), item["id"]))


def summarize(items) -> dict:
    def count(field, values):
        counts = dict.fromkeys(values, 0)
        for item in items:
            counts[item[field]] = counts.get(item[field], 0) + 1
        return counts

    return {"total": len(items), "auth_states": count("auth_state", AUTH_STATES),
            "freshness": count("freshness", FRESHNESS), "renewals": count("auth_renewal", RENEWALS),
            "expiry_stages": count("expiry_stage", EXPIRY_STAGES)}


def alerts(items, settings) -> list[dict]:
    """Operations alerts the older content-only roll-up does not raise."""
    out = []
    for item in items:
        resource = {"resource_type": "connection" if item["kind"] == "CONTENT" else item["kind"].lower(),
                    "resource_id": item["id"]}
        if item["kind"] != "CONTENT" and item["auth_state"] not in ("READY", "DISABLED", "UNKNOWN"):
            out.append({"code": f"{item['kind']}_{item['auth_state']}", **resource})
        elif item["kind"] == "CONTENT" and item["auth_state"] == "EXPIRING":
            out.append({"code": "CONTENT_EXPIRING", **resource})
        if item["freshness"] == "STALE":
            out.append({"code": f"{item['kind']}_STALE", **resource})
    # A person's sign-in cannot keep a shared server collecting around the clock.
    if getattr(settings, "auth_mode", "local") == "oidc" and any(
            item["auth_renewal"] == "HUMAN_SESSION" and item["auth_state"] != "DISABLED" for item in items):
        out.append({"code": "HUMAN_SESSION_IN_SERVER_DEPLOYMENT", "resource_type": "aws_identity",
                    "resource_id": "worker"})
    return out


def feed_alerts(repo, settings, items, *, now=None) -> list[dict]:
    """One alert per content connection whose change feed has failed for over FEED_ALERT_AFTER: the change scans of its
    failing roots wait until a look succeeds, while its other roots and its scheduled scans go on. It counts every root
    failing now and dates the earliest failure, earliest first. Only codes, counts and times leave."""
    from cremore.collectors.base import RATE_LIMITED, UNAVAILABLE
    from cremore.scanning import changes

    now = utc(now) or _dt.datetime.now(_dt.UTC)
    live = {item["id"]: item for item in items if item["kind"] == "CONTENT" and item["auth_state"] != "DISABLED"}
    failing = {}
    for connection, error, roots, since in changes.failing_roots(repo, settings, now=now):
        connection, since = str(connection), utc(since)
        if connection in live and since is not None:
            codes, total, first = failing.get(connection, (set(), 0, since))
            failing[connection] = (codes | {error or "CHANGE_FEED_FAILED"}, total + roots, min(first, since))
    out = []
    for connection, (codes, roots, since) in sorted(failing.items(), key=lambda item: (item[1][2], item[0])):
        if now - since <= FEED_ALERT_AFTER:
            continue
        why = ("RATE_LIMITED" if codes <= {RATE_LIMITED, "NOTION_RATE_LIMITED"}
               else "UNAVAILABLE" if codes <= {UNAVAILABLE} else "FAILING")
        out.append({"code": f"CHANGE_FEED_{why}", "resource_type": "connection", "resource_id": connection,
                    "provider": live[connection]["provider"], "failing_roots": roots, "failing_since": since.isoformat(),
                    "error_codes": sorted(codes)})
    return out
