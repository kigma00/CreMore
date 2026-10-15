"""Observed use of a discovered AWS access key.

Two read-only sources, both documented AWS APIs:

* ``cloudtrail:LookupEvents`` filtered by ``AccessKeyId`` in every enabled
  region — management events from the last 90 days (the event-history limit).
* ``iam:GetAccessKeyLastUsed`` — the key's last-used time, service and region.

The result is *observed* evidence and is kept apart from potential access
(IAM simulation) by the dashboard. Coverage is reported per region and never
claimed complete when a lookup failed or hit the per-region cap.

https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from time import sleep

from cremore_aws_provider.aws_identity import (
    AwsLoginRequired,
    collection_error_code,
    is_login_required,
)

# CloudTrail event history covers 90 days; regions capped so one refresh
# stays bounded even in an account with every opt-in region enabled.
WINDOW_DAYS = 90
DEFAULT_REGION_LIMIT = 25
DEFAULT_EVENTS_PER_REGION = 1000
_PAGE = 50
_REGION_BYTES = 1024 * 1024
_FALLBACK_REGIONS = ("us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1",
                     "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2")


@dataclass(frozen=True)
class LastUsed:
    at: _dt.datetime | None
    service: str = ""
    region: str = ""
    status: str = "AVAILABLE"
    observed_at: str = field(default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat())
    error_code: str = ""

    def snapshot(self) -> dict:
        out = {"status": self.status, "observed_at": self.observed_at}
        if self.error_code:
            out["error_code"] = self.error_code
        if self.status == "AVAILABLE" and self.at is not None:
            out.update(at=self.at.isoformat(), service=self.service, region=self.region)
        return out


def normalize_last_used(info: dict) -> LastUsed:
    """Normalize one IAM response without losing failures at the caller's I/O boundary."""
    if not isinstance(info, dict) or not {"ServiceName", "Region"}.issubset(info):
        raise ValueError("INVALID_LAST_USED_METADATA")
    at = info.get("LastUsedDate")
    if isinstance(at, str):
        at = _dt.datetime.fromisoformat(at)
    if at is not None and (not isinstance(at, _dt.datetime) or at.tzinfo is None):
        raise ValueError("INVALID_LAST_USED_TIME")
    values = []
    for name, pattern in (("ServiceName", r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}"),
                          ("Region", r"[a-z][a-z0-9-]{0,63}")):
        value = info[name]
        if value == "N/A":
            value = ""
        elif not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("INVALID_LAST_USED_METADATA")
        values.append(value)
    return LastUsed(at=at, service=values[0], region=values[1], status="AVAILABLE" if at else "NO_INFORMATION")


@dataclass(frozen=True)
class KeyOwner:
    """Which connected account and IAM identity an access key id belongs to."""

    account_id: str
    principal_arn: str = ""
    user_name: str = ""


# IAM reports a key belonging to another account exactly as it reports one that
# never existed. Those are answers about this account, not collection failures.
_NOT_IN_ACCOUNT = frozenset({"NoSuchEntity", "NoSuchEntityException", "ValidationError"})


def _owner_of(iam, session, account_id: str, user_name: str) -> KeyOwner | None:
    """The principal behind a key this account's IAM just acknowledged."""

    if user_name:
        try:
            arn = str(((iam.get_user(UserName=user_name) or {}).get("User") or {}).get("Arn") or "")
        except Exception as exc:
            if is_login_required(exc):
                raise AwsLoginRequired() from exc
            # Never synthesize one: a guessed ARN drops the IAM path, which
            # SimulatePrincipalPolicy and policy reads need exactly.
            arn = ""
        return KeyOwner(account_id, arn, user_name)
    # IAM returns no user name for an account root key. Read the partition from
    # CreMore's own identity rather than assuming the commercial one.
    try:
        caller = str((session.client("sts").get_caller_identity() or {}).get("Arn") or "")
    except Exception as exc:
        if is_login_required(exc):
            raise AwsLoginRequired() from exc
        return None
    parts = caller.split(":")
    return KeyOwner(account_id, f"arn:{parts[1]}:iam::{account_id}:root") if len(parts) > 2 and parts[1] else None


def resolve_key_owner(open_session, account_ids, access_key_id: str) -> tuple[KeyOwner | None, list[dict]]:
    """Find which connected account owns ``access_key_id``. Read-only, no secret.

    ``iam:GetAccessKeyLastUsed`` takes the key id alone -- the non-secret half of
    an AWS credential -- and answers for the account CreMore's own scanner role is
    in. So an identifier observed without its secret can still be resolved to a
    real owner, and no discovered material is ever sent anywhere or used to
    authenticate. Accounts CreMore cannot open are recorded as unchecked: "not
    searched" is not "not there".

    Returns the owner (or None) and one attempt record per account.
    """

    attempts: list[dict] = []
    for account_id in account_ids:
        try:
            session = open_session(account_id)
        except AwsLoginRequired:
            raise
        except Exception as exc:  # noqa: BLE001 -- provider failures become safe incomplete evidence
            attempts.append({"account_id": account_id, "status": "NOT_CHECKED",
                             "error_code": collection_error_code(exc)})
            continue
        try:
            iam = session.client("iam")
            answer = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            if not isinstance(answer, dict) or ("UserName" in answer and not isinstance(answer["UserName"], str)) \
                    or (not answer.get("UserName") and not isinstance(answer.get("AccessKeyLastUsed"), dict)):
                raise ValueError("KEY_OWNER_RESPONSE_MALFORMED")
        except Exception as exc:
            if is_login_required(exc):
                raise AwsLoginRequired() from exc
            code = collection_error_code(exc)
            attempts.append({"account_id": account_id, "error_code": code,
                             "status": "NOT_IN_ACCOUNT" if code in _NOT_IN_ACCOUNT else "NOT_CHECKED"})
            continue
        owner = _owner_of(iam, session, account_id, str(answer.get("UserName") or ""))
        if owner is None:
            attempts.append({"account_id": account_id, "status": "NOT_CHECKED",
                             "error_code": "OWNER_PARTITION_NOT_READ"})
            continue
        attempts.append({"account_id": account_id, "status": "OWNER"})
        return owner, attempts
    return None, attempts


def require_usage_session(snapshot: dict) -> None:
    """Refuse to replace saved evidence with an expired scanner session's result.

    Only collection errors count. An ExpiredToken in an observed CloudTrail
    event describes the investigated key, not the scanner's session.
    """
    codes = [snapshot.get("region_discovery_error")]
    codes.extend(row.get("error_code") for row in snapshot.get("coverage") or [])
    for name in ("potential_access", "access_key", "cloudtrail_lake"):
        codes.append((snapshot.get(name) or {}).get("error_code"))
    codes.extend(row.get("error_code") for row in (snapshot.get("identity_policies") or {}).get("errors") or [])
    if any(is_login_required(code) for code in codes):
        raise AwsLoginRequired()


def _iso(value) -> str:
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.UTC)
        return value.isoformat()
    return str(value or "")


def access_key_metadata(session, cred, user_name: str = "") -> dict:
    """Status and creation time of this exact key (iam:ListAccessKeys for its user, read-only)."""
    arn = cred.principal_arn or ""
    # The owner lookup names the user outright; a verified ARN carries it in its path.
    user = user_name or (arn.rsplit("/", 1)[-1] if ":user/" in arn else "")
    if not user:
        return {"collection_status": "NOT_APPLICABLE"}
    try:
        # An IAM user has at most two access keys, so one page is complete.
        page = session.client("iam").list_access_keys(UserName=user)
    except Exception as exc:  # noqa: BLE001 -- recorded as a safe code, never provider text
        return {"collection_status": "FAILED", "error_code": collection_error_code(exc)}
    for key in page.get("AccessKeyMetadata", []):
        if key.get("AccessKeyId") == cred.identifier:
            created = key.get("CreateDate")
            return {"collection_status": "COMPLETE", "status": str(key.get("Status") or ""),
                    "created_at": _iso(created) if hasattr(created, "isoformat") else None}
    return {"collection_status": "COMPLETE", "status": "NOT_FOUND"}


def credential_class(access_key_id: str) -> str:
    if access_key_id.startswith("AKIA"):
        return "LONG_LIVED"
    if access_key_id.startswith("ASIA"):
        return "TEMPORARY_STS"
    return "UNKNOWN"


def _address_kind(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
        return "IPV6" if ip.version == 6 else "IPV4"
    except ValueError:
        return "AWS_INTERNAL" if address == "AWS Internal" or address.endswith((".amazonaws.com", ".amazonaws.com.cn")) else "HOSTNAME"


def event_outcome(event_name, error_code) -> str:
    """Keep non-authorization failures out of denied counts without extending the public enum."""
    if error_code:
        code = str(error_code).rsplit(".", 1)[-1]
        return "DENIED" if code in {
            "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedException", "VpceAccessDenied",
        } else "UNKNOWN"
    return "SUCCEEDED" if event_name else "UNKNOWN"


def event_from_lookup(entry: dict, region: str) -> dict:
    """One CloudTrail event in the dashboard's CredentialUsageEvent shape."""

    raw: dict = {}
    try:
        raw = json.loads(entry.get("CloudTrailEvent") or "{}")
    except (TypeError, ValueError):
        raw = {}
    raw = _mapping(raw)
    identity = _mapping(raw.get("userIdentity"))
    session = _mapping(identity.get("sessionContext"))
    issuer = _mapping(session.get("sessionIssuer"))
    attributes = _mapping(session.get("attributes"))
    read_only = raw.get("readOnly")
    error_code = raw.get("errorCode")
    address = str(raw.get("sourceIPAddress") or "")
    category = str(raw.get("eventCategory") or "Management")
    out = {
        "event_id": str(entry.get("EventId") or raw.get("eventID") or ""),
        "event_time": _iso(entry.get("EventTime") or raw.get("eventTime")),
        "region": str(raw.get("awsRegion") or region),
        "evidence_source": "EVENT_HISTORY",
        "event_category": "DATA" if category.lower() == "data" else "MANAGEMENT",
        "event_source": str(entry.get("EventSource") or raw.get("eventSource") or ""),
        "event_name": str(entry.get("EventName") or raw.get("eventName") or ""),
        "access_mode": "READ" if read_only is True else "WRITE" if read_only is False else "UNKNOWN",
        "outcome": event_outcome(raw.get("eventName"), error_code),
        "resources": [{"type": r.get("ResourceType"), "name": r.get("ResourceName")}
                      for r in (entry.get("Resources") or []) if isinstance(r, dict)],
    }
    if error_code:
        out["error_code"] = str(error_code)
    if address:
        out["source_address"] = address
        out["source_address_kind"] = _address_kind(address)
    if identity.get("arn"):
        out["principal_arn"] = str(identity["arn"])
    name = identity.get("userName") or entry.get("Username")
    if name:
        out["principal_name"] = str(name)
    if issuer.get("arn"):
        out["session_issuer_arn"] = str(issuer["arn"])
    if session.get("sourceIdentity"):
        out["source_identity"] = str(session["sourceIdentity"])
    if attributes.get("creationDate"):
        out["session_created_at"] = _iso(attributes["creationDate"])
    return out


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


class CredentialUsageService:
    def __init__(self, cloudtrail_factory: Callable[[str], object], ec2_client=None, iam_client=None, *,
                 region_limit: int = DEFAULT_REGION_LIMIT, events_per_region: int = DEFAULT_EVENTS_PER_REGION,
                 workers: int = 8, now: Callable[[], _dt.datetime] | None = None) -> None:
        self.cloudtrail_factory = cloudtrail_factory
        self.ec2 = ec2_client
        self.iam = iam_client
        self.region_limit = max(1, region_limit)
        self.events_per_region = max(1, events_per_region)
        self.workers = max(1, workers)
        self.now = now or (lambda: _dt.datetime.now(_dt.UTC))

    # --- regions --------------------------------------------------------------

    def regions(self) -> tuple[list[str], str, str]:
        """(regions, discovery_status, error). Falls back to a fixed list."""

        if self.ec2 is None:
            return list(_FALLBACK_REGIONS)[: self.region_limit], "FALLBACK", "EC2_CLIENT_NOT_CONFIGURED"
        try:
            page = self.ec2.describe_regions(AllRegions=False)
            rows = page.get("Regions")
            if not isinstance(rows, list) or any(not isinstance(r, dict) or not isinstance(r.get("RegionName"), str)
                                                or not r["RegionName"] for r in rows):
                raise ValueError("REGION_RESPONSE_MALFORMED")
            names = sorted({r["RegionName"] for r in rows})
        except Exception as exc:  # noqa: BLE001 -- provider failures become safe incomplete evidence
            return list(_FALLBACK_REGIONS)[: self.region_limit], "FALLBACK", collection_error_code(exc)
        if not names:
            return [], "FAILED", "REGIONS_NOT_RETURNED"
        if len(names) > self.region_limit:
            return names[: self.region_limit], "CAPPED", "REGION_LIMIT_REACHED"
        return names, "COMPLETE", ""

    # --- last used ------------------------------------------------------------

    def last_used(self, access_key_id: str) -> LastUsed:
        if self.iam is None or not access_key_id:
            return LastUsed(at=None, status="NOT_REQUESTED", observed_at=_iso(self.now()))
        try:
            info = (self.iam.get_access_key_last_used(AccessKeyId=access_key_id) or {}).get("AccessKeyLastUsed") or {}
            return replace(normalize_last_used(info), observed_at=_iso(self.now()))
        except Exception as exc:
            if is_login_required(exc):
                raise AwsLoginRequired() from exc
            code = collection_error_code(exc)
            return LastUsed(at=None, status="DENIED" if event_outcome("", code) == "DENIED" else "FAILED",
                            observed_at=_iso(self.now()), error_code=code)

    # --- events ---------------------------------------------------------------

    def _lookup_region(self, region: str, access_key_id: str, start: _dt.datetime, end: _dt.datetime) -> dict:
        collected_at = _iso(self.now())
        coverage = {"region": region, "status": "COMPLETE", "event_scope": "MANAGEMENT",
                    "evidence_source": "EVENT_HISTORY", "events_collected": 0,
                    "window_start": _iso(start), "window_end": _iso(end), "collected_at": collected_at}
        events: list[dict] = []
        saved_bytes = 2  # JSON array delimiters; raw responses and cursors are never stored.
        try:
            client = self.cloudtrail_factory(region)
            token, seen = None, set()
            for _ in range(100):
                kwargs = {"LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
                          "StartTime": start, "EndTime": end, "MaxResults": _PAGE}
                if token:
                    kwargs["NextToken"] = token
                page = client.lookup_events(**kwargs)
                rows = page.get("Events")
                if not isinstance(rows, list) or any(not isinstance(entry, dict) for entry in rows):
                    raise ValueError("CLOUDTRAIL_RESPONSE_MALFORMED")
                remaining = self.events_per_region - len(events)
                for entry in rows[:remaining]:
                    event = event_from_lookup(entry, region)
                    event_bytes = len(json.dumps(event).encode("utf-8")) + 2
                    if saved_bytes + event_bytes > _REGION_BYTES:
                        coverage.update(status="CAPPED", error_code="BYTE_LIMIT_REACHED")
                        break
                    events.append(event)
                    saved_bytes += event_bytes
                    if event["outcome"] == "UNKNOWN" and not event.get("error_code"):
                        coverage.update(status="PARTIAL", error_code="EVENT_DETAILS_UNAVAILABLE")
                if coverage.get("error_code") == "BYTE_LIMIT_REACHED":
                    break
                token = page.get("NextToken")
                if len(rows) > remaining or (token and len(events) >= self.events_per_region):
                    coverage.update(status="CAPPED", error_code="EVENT_LIMIT_REACHED")
                    break
                if not token:
                    break
                if not isinstance(token, str) or len(token) > 4096 or token in seen:
                    raise ValueError("CLOUDTRAIL_PAGINATION_INCOMPLETE")
                seen.add(token)
                # LookupEvents allows two requests/second/account/region. Other
                # concurrent lookups still rely on the SDK's bounded retries.
                sleep(0.55)
            else:
                coverage.update(status="CAPPED", error_code="PAGE_LIMIT_REACHED")
        except Exception as exc:  # noqa: BLE001 -- provider failures become safe incomplete evidence
            coverage["status"] = "FAILED"
            coverage["error_code"] = collection_error_code(exc)
        coverage["events_collected"] = len(events)
        return {"coverage": coverage, "events": events}

    def collect(self, access_key_id: str, principal_arn: str = "") -> dict:
        """The dashboard's CredentialUsage snapshot for one access key."""

        end = self.now()
        start = end - _dt.timedelta(days=WINDOW_DAYS)
        regions, discovery, discovery_error = self.regions()
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(regions)))) as pool:
            results = list(pool.map(lambda r: self._lookup_region(r, access_key_id, start, end), regions))
        coverage = [r["coverage"] for r in results]
        events = [e for r in results for e in r["events"]]
        events.sort(key=lambda e: e.get("event_time", ""), reverse=True)
        failed = sum(1 for c in coverage if c["status"] == "FAILED")
        capped = sum(1 for c in coverage if c["status"] == "CAPPED")
        complete = sum(1 for c in coverage if c["status"] == "COMPLETE")
        status = "FAILED" if not regions or failed == len(regions) else "PARTIAL" if (
            complete != len(regions) or discovery != "COMPLETE"
        ) else "COMPLETE"
        snapshot = {
            "credential_class": credential_class(access_key_id),
            "collection_status": status,
            "region_discovery_status": discovery,
            "event_scope": "MANAGEMENT",
            "window_start": _iso(start),
            "window_end": _iso(end),
            "collected_at": _iso(end),
            "regions_discovered": len(regions),
            "regions_complete": complete,
            "regions_failed": failed,
            "regions_capped": capped,
            "events_per_region": self.events_per_region,
            "events": events,
            "coverage": coverage,
            # Scenario graphs are derived views the dashboard renders when
            # present; none are computed here (honest empty list).
            "scenarios": [],
            "cloudtrail_lake": {"configured": False, "status": "NOT_CONFIGURED",
                                "event_scope": "MANAGEMENT_AND_DATA", "evidence_source": "CLOUDTRAIL_LAKE",
                                "events_collected": 0},
            "potential_access": {"collection_status": "NOT_COLLECTED", "evidence_level": "POTENTIAL",
                                 "method": "IAM_SIMULATE_PRINCIPAL_POLICY",
                                 "scope": "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_RESOURCES",
                                 "limitations": [], "actions": []},
        }
        if discovery_error:
            snapshot["region_discovery_error"] = discovery_error
        if principal_arn:
            snapshot["potential_access"]["principal_arn"] = principal_arn
        return snapshot


def potential_access_view(access) -> dict:
    """A PotentialAccess result in the dashboard's CredentialPotentialAccess shape."""

    return {
        "collection_status": access.collection_status,
        "evidence_level": "POTENTIAL",
        "method": access.method,
        "scope": access.scope,
        "principal_arn": access.principal_arn,
        **({"evaluated_role_arn": access.evaluated_role_arn} if access.evaluated_role_arn else {}),
        "evaluated_at": _iso(_dt.datetime.now(_dt.UTC)),
        **({"error_code": access.error_code} if access.error_code else {}),
        "limitations": list(access.limitations),
        "effective_access": "NOT_EVALUATED",
        "assessment_version": 3,
        "resource_arns": ["*", *(named.resource for named in access.named_resources)],
        # Whether the ARNs the principal's own policies name were all simulated too.
        "named_resources_complete": access.named_resources_complete,
        "named_resources": [{"resource": named.resource, "actions": list(named.actions), "allowed": list(named.allowed),
                             "explicit_deny": list(named.explicit_deny),
                             "missing_context_values": list(named.missing_context_values),
                             "resource_policy": named.resource_policy,
                             **({"key_policy_blocks": list(named.key_policy_blocks)} if named.key_policy_blocks else {}),
                             **({"conditional": list(named.conditional)} if named.conditional else {})}
                            for named in access.named_resources],
        "request_context": "NOT_SUPPLIED",
        "assessment_status": "MISSING_CONTEXT" if any(a.missing_context_values for a in access.actions)
        else "SIMULATION_ONLY",
        "actions": [{"action": a.action, "service": a.action.split(":", 1)[0], "decision": a.decision,
                     "risk": a.risk, "missing_context_values": list(a.missing_context_values),
                     "resource_scope": a.resource_scope, **({"resources": list(a.resources)} if a.resources else {}),
                     **({"organizations_allowed": a.organizations_allowed}
                        if a.organizations_allowed is not None else {}),
                     **({"permissions_boundary_allowed": a.permissions_boundary_allowed}
                        if a.permissions_boundary_allowed is not None else {})} for a in access.actions],
    }


def empty_usage(access_key_id: str = "") -> dict:
    """The snapshot served before any lookup ran (or when lookups are disabled)."""

    return {
        "credential_class": credential_class(access_key_id),
        "collection_status": "NOT_COLLECTED",
        "event_scope": "MANAGEMENT",
        "regions_discovered": 0, "regions_complete": 0, "regions_failed": 0, "regions_capped": 0,
        "events": [], "coverage": [], "scenarios": [],
        "cloudtrail_lake": {"configured": False, "status": "NOT_CONFIGURED", "event_scope": "MANAGEMENT_AND_DATA",
                            "evidence_source": "CLOUDTRAIL_LAKE", "events_collected": 0},
        "potential_access": {"collection_status": "NOT_COLLECTED", "evidence_level": "POTENTIAL",
                             "method": "IAM_SIMULATE_PRINCIPAL_POLICY",
                             "scope": "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_RESOURCES", "limitations": [], "actions": []},
    }


# --- what an observed call belongs to ---------------------------------------
#
# The ATT&CK technique an AWS API call belongs to, keyed by CloudTrail event
# name. This states the technique a call *belongs to*; it never states that an
# attack happened. An operator creates access keys, reads secrets and lists
# buckets too, and this cannot tell the two apart. Calls outside the table stay
# unclassified, which ordinary traffic mostly is.
#
# https://attack.mitre.org/matrices/enterprise/cloud/iaas/
# ponytail: event name only. Separating an operator's CreateAccessKey from an
# attacker's needs the request parameters and the caller's usual pattern; add
# that when the counts alone stop being enough to start an investigation.
TECHNIQUE_REVISION = "cremore-observed-call-techniques-v1"
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1087.004": ("Account Discovery: Cloud Account", (
        "GetCallerIdentity", "ListUsers", "ListRoles", "ListGroups", "ListAccessKeys",
        "GetAccountSummary", "GetAccountAuthorizationDetails", "ListAccounts", "DescribeOrganization")),
    "T1580": ("Cloud Infrastructure Discovery", (
        "DescribeInstances", "DescribeRegions", "DescribeVpcs", "DescribeSecurityGroups",
        "DescribeSnapshots", "DescribeImages", "DescribeDBInstances", "ListFunctions", "ListClusters")),
    "T1619": ("Cloud Storage Object Discovery", (
        "ListBuckets", "ListObjects", "ListObjectsV2", "ListObjectVersions", "GetBucketAcl", "GetBucketPolicy")),
    "T1098.001": ("Account Manipulation: Additional Cloud Credentials", (
        "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile", "CreateRole",
        "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy", "AddUserToGroup",
        "UpdateAssumeRolePolicy", "CreateServiceSpecificCredential", "CreateVirtualMFADevice")),
    "T1555.006": ("Credentials from Password Stores: Cloud Secrets Management Stores", (
        "GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath")),
    "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", (
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs",
        "DeleteDetector", "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteLogGroup")),
    "T1537": ("Transfer Data to Cloud Account", (
        "ModifySnapshotAttribute", "ModifyImageAttribute", "SharedSnapshotCopyInitiated",
        "PutBucketPolicy", "PutBucketAcl")),
    "T1530": ("Data from Cloud Storage", ("GetObject", "CopyObject", "SelectObjectContent")),
}
_BY_EVENT = {name: technique for technique, (_label, names) in TECHNIQUES.items() for name in names}


def classify_call(event_name) -> str:
    """The technique id an AWS API call belongs to, or ``""`` when unclassified."""

    return _BY_EVENT.get(str(event_name or ""), "")


def classify_events(snapshot: dict) -> dict:
    """Label each observed call with its technique and count the labels.

    Applied when a snapshot is read rather than when it is collected, so
    snapshots saved before this mapping existed are labelled the same way and no
    stored evidence is rewritten.
    """

    events = snapshot.get("events")
    if not isinstance(events, list):
        return snapshot
    labelled, counts = [], {}
    for event in events:
        if not isinstance(event, dict):
            labelled.append(event)
            continue
        technique = classify_call(event.get("event_name"))
        labelled.append({**event, "technique_id": technique} if technique else event)
        if technique:
            counts[technique] = counts.get(technique, 0) + 1
    if "summary" in snapshot:
        from cremore_aws_provider.investigation.usage_pages import finish_view

        return {**finish_view({**snapshot}), "collection_status": snapshot["collection_status"], "events": labelled}
    observed = [{"technique_id": technique, "technique_name": TECHNIQUES[technique][0], "events": count}
                for technique, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    return {**snapshot, "events": labelled,
            "techniques": {"revision": TECHNIQUE_REVISION, "observed": observed,
                           "classified_events": sum(counts.values()), "total_events": len(events)}}
