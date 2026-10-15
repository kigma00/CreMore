"""Optional Control Tower context and bounded lifecycle notifications.

Events request a fresh Organizations/role check; they never approve an account.
The regular discovery interval remains the authoritative fallback.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime

from cremore_aws_provider import aws_org_settings
from cremore_aws_provider.aws_identity import error_code
from cremore_aws_provider.aws_org_context import (
    SUMMARY_KEY,
    Reader,
    account_context,
    put_account_context,
    refresh_org_context,
)

CONTEXT_KEY = "aws-controltower-context"
EVENT_KEY = "aws-controltower-lifecycle"
_TARGET = re.compile(r"^arn:aws(?:-[a-z]+)*:organizations::[0-9]{12}:(ou|account)/(o-[a-z0-9]+)/([^/]+)$")
_EVENTS = {"CreateManagedAccount": "createManagedAccountStatus",
           "UpdateManagedAccount": "updateManagedAccountStatus",
           "RegisterOrganizationalUnit": "registerOrganizationalUnitStatus",
           "DeregisterOrganizationalUnit": "deregisterOrganizationalUnitStatus",
           "EnableBaseline": "enableBaselineStatus", "ResetEnabledBaseline": "resetEnabledBaselineStatus",
           "UpdateEnabledBaseline": "updateEnabledBaselineStatus", "DisableBaseline": "disableBaselineStatus"}


def unavailable_context(repo, error):
    previous = (repo.get_setting(CONTEXT_KEY) or {}).get("value") or {}
    summary = {**previous, "status": "PARTIAL", "reason": error_code(error)}
    for account in repo.list_aws_accounts():
        old = account_context(repo, account.account_id)["control_tower"]
        put_account_context(repo, account.account_id, "control_tower",
                            {**old, "status": "PARTIAL", "reason": error_code(error)})
    repo.put_setting(CONTEXT_KEY, summary, "aws-discovery")
    return summary


def _baseline(row):
    status = (row.get("statusSummary") or {}).get("status", "UNKNOWN")
    drift = (((row.get("driftStatusSummary") or {}).get("types") or {}).get("inheritance") or {}).get("status")
    return {"baseline_arn": str(row.get("arn") or "")[:2048],
            "baseline_version": str(row.get("baselineVersion") or "")[:64],
            "account_status": status if status in ("SUCCEEDED", "FAILED", "UNDER_CHANGE") else "UNKNOWN",
            "drift_status": str(drift)[:64] if drift else None}


def collect_context(repo, org_client, control_tower_client, *, check=None, now=None):
    """Filter AWSControlTowerBaseline; other baseline types do not prove enrollment."""
    now = (now or datetime.now(UTC)).isoformat()
    org = (repo.get_setting(SUMMARY_KEY) or {}).get("value") or {}
    if not org:
        org = refresh_org_context(repo, org_client, check=check)
    try:
        if not org.get("organization_id"):
            raise ValueError("AWS_ORGANIZATION_CONTEXT_REQUIRED")
        reader = Reader(control_tower_client, check)
        baseline_ids = {row["arn"] for row in reader.pages("list_baselines", "baselines", maxResults=100)
                        if row.get("name") == "AWSControlTowerBaseline"}
        ous, accounts, parent_ous = {}, {}, {}
        if baseline_ids:
            for row in reader.pages("list_enabled_baselines", "enabledBaselines", includeChildren=True,
                                    maxResults=100, filter={"baselineIdentifiers": sorted(baseline_ids)}):
                if row.get("baselineIdentifier") not in baseline_ids:
                    continue
                details = reader.call("get_enabled_baseline", enabledBaselineIdentifier=row["arn"])["enabledBaselineDetails"]
                if details.get("arn") != row["arn"] or details.get("baselineIdentifier") not in baseline_ids:
                    raise ValueError("AWS_CONTROL_TOWER_BASELINE_MISMATCH")
                target = _TARGET.fullmatch(str(details.get("targetIdentifier") or ""))
                if not target or target[2] != org["organization_id"]:
                    raise ValueError("AWS_CONTROL_TOWER_TARGET_MISMATCH")
                kind, _, target_id = target.groups()
                if kind == "ou":
                    ous[target_id] = details
                    parent_ous[details["arn"]] = target_id
                elif re.fullmatch(r"[0-9]{12}", target_id):
                    accounts[target_id] = details
        summary = {"status": "COMPLETE", "last_successful_at": now, "reason": None,
                   "registered_ou_ids": sorted(ou for ou, row in ous.items()
                                               if (row.get("statusSummary") or {}).get("status") == "SUCCEEDED")}
        for account in repo.list_aws_accounts():
            context = account_context(repo, account.account_id)["organization"]
            path = context.get("path", []) if context.get("status") == "COMPLETE" else []
            observed = accounts.get(account.account_id)
            parent = parent_ous.get((observed or {}).get("parentIdentifier"))
            if parent not in summary["registered_ou_ids"]:
                parent = next((node["id"] for node in reversed(path)
                               if node["id"] in summary["registered_ou_ids"]), None)
            value = {"status": "COMPLETE", "last_successful_at": now, "reason": None,
                     "registered_ou_id": parent,
                     "registered_ou_name": next((node["name"] for node in path if node["id"] == parent), None),
                     "account_status": "NOT_OBSERVED", "baseline_arn": None, "baseline_version": None,
                     "drift_status": None}
            if observed:
                value.update(_baseline(observed))
            put_account_context(repo, account.account_id, "control_tower", value)
    except Exception as exc:  # noqa: BLE001 -- optional context preserves prior facts with explicit uncertainty
        return unavailable_context(repo, exc)
    repo.put_setting(CONTEXT_KEY, summary, "aws-discovery")
    return summary


def _lifecycle_event(body, management_account_id, region):
    if (not isinstance(body, dict) or body.get("source") != "aws.controltower"
            or body.get("detail-type") != "AWS Service Event via CloudTrail"
            or body.get("account") != management_account_id or body.get("region") != region):
        raise ValueError("AWS_CONTROL_TOWER_EVENT_OUT_OF_SCOPE")
    detail = body.get("detail") or {}
    if (not isinstance(detail, dict) or detail.get("eventSource") != "controltower.amazonaws.com"
            or detail.get("eventType") != "AwsServiceEvent" or detail.get("awsRegion") != region
            or detail.get("eventName") not in _EVENTS):
        raise ValueError("AWS_CONTROL_TOWER_EVENT_UNSUPPORTED")
    statuses = detail.get("serviceEventDetails") or {}
    status = statuses.get(_EVENTS[detail["eventName"]]) if isinstance(statuses, dict) else None
    if not isinstance(status, dict):
        raise TypeError("AWS_CONTROL_TOWER_EVENT_INVALID_STATUS")
    state = status.get("state")
    if "Baseline" in detail["eventName"]:
        state = ((status.get("enabledBaselineDetails") or {}).get("statusSummary") or {}).get("status")
    if state != "SUCCEEDED":
        raise ValueError("AWS_CONTROL_TOWER_EVENT_NOT_SUCCEEDED")
    return {"id": str(uuid.UUID(str(body.get("id")))), "event": detail["eventName"]}


def _locked(repo, operation):
    from cremore.db.settings_store import locked_settings

    with locked_settings(repo, setting_key=aws_org_settings.KEY) as bound:
        state = (bound.get_setting(EVENT_KEY) or {}).get("value") or {}
        return operation(bound, state)


def rediscovery_pending(repo):
    return ((repo.get_setting(EVENT_KEY) or {}).get("value") or {}).get("pending_request")


def request_rediscovery(repo, *, source="SETTINGS_CHANGED"):
    """A local settings change uses the same durable wakeup as lifecycle events."""
    def request(bound, state):
        state["pending_request"] = {"id": str(uuid.uuid4()), "event": source,
                                    "requested_at": datetime.now(UTC).isoformat()}
        bound.put_setting(EVENT_KEY, state, "aws-discovery")
    _locked(repo, request)


def complete_rediscovery(repo, request_id):
    def complete(bound, state):
        if (state.get("pending_request") or {}).get("id") == request_id:
            state["pending_request"] = None
            bound.put_setting(EVENT_KEY, state, "aws-discovery")
    _locked(repo, complete)


def poll_lifecycle_events(repo, settings, client_factory, *, now=None):
    """ACK only after durable rediscovery; client_factory takes the home region."""
    from cremore.scanning import trigger_settings
    config = aws_org_settings.config(settings, repo)
    result = {"acknowledged": 0, "failed": 0, "requested": 0}
    queue = config["lifecycle_queue_url"]
    if not (aws_org_settings.effective(settings, repo) and config["control_tower_enabled"] and queue
            and config["lifecycle_queue_acknowledged"] and getattr(settings, "scan_sqs_allowed", False)):
        return result
    if queue == trigger_settings.config(settings, repo)["sqs"]["queue_url"]:
        return {**result, "reason": "AWS_CONTROL_TOWER_SEPARATE_QUEUE_REQUIRED"}
    org = (repo.get_setting(SUMMARY_KEY) or {}).get("value") or {}
    management_id = org.get("management_account_id")
    if not isinstance(management_id, str) or not re.fullmatch(r"[0-9]{12}", management_id):
        return {**result, "reason": "AWS_CONTROL_TOWER_MANAGEMENT_ACCOUNT_UNKNOWN"}
    region = config["control_tower_region"]
    client = client_factory(region)
    messages = client.receive_message(QueueUrl=queue, MaxNumberOfMessages=10,
                                      WaitTimeSeconds=0, VisibilityTimeout=60)
    for message in messages.get("Messages", [])[:10]:
        try:
            raw = message.get("Body")
            if not isinstance(raw, str) or len(raw.encode()) > 65536:
                raise ValueError("AWS_CONTROL_TOWER_EVENT_TOO_LARGE")
            event = _lifecycle_event(json.loads(raw), management_id, region)
            def accept(bound, state, event=event):
                recent = state.get("recent_ids", [])
                if event["id"] in recent:
                    return False
                state.update(recent_ids=[*recent[-127:], event["id"]], pending_request={**event,
                             "requested_at": (now or datetime.now(UTC)).isoformat()})
                bound.put_setting(EVENT_KEY, state, "aws-controltower-event")
                return True
            if _locked(repo, accept):
                result["requested"] += 1
            client.delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
            result["acknowledged"] += 1
        except Exception:  # noqa: BLE001 -- invalid/undurable input remains unacknowledged for queue redrive
            result["failed"] += 1
    return result
