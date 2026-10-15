"""Event encodings a destination can ask for: OCSF 1.3.0, CEF and LEEF.

``native`` (schema v1) stays the default. OCSF is offered where a class fits the
meaning (design decision 11): findings, a departed owner's credential and vault
verdicts become Detection Finding (class 2004), administrator actions become API
Activity (class 6003), and connection, collection, heartbeat and delivery events
have no fitting class, so they stay native. CEF (ArcSight) and LEEF 2.0 (QRadar)
encode the native event for syslog receivers.

Only fields the native event already carries are used: internal UUIDs, known
codes, counts and times. Nothing here adds a name, path or secret.

References: https://schema.ocsf.io/1.3.0/classes/detection_finding,
https://schema.ocsf.io/1.3.0/classes/api_activity, ArcSight "Implementing ArcSight
Common Event Format (CEF)", IBM QRadar "Log Event Extended Format (LEEF)".
"""

from __future__ import annotations

from datetime import datetime

from cremore.siem.contract import DeliveryError, event_family

OCSF_VERSION = "1.3.0"
PRODUCT_NAME = "CreMore"
PRODUCT_VERSION = "0.1.0"
FORMATS = ("native", "ocsf")

_SEVERITY_ID = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
_SEVERITY_NAME = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
_CLOSED = ("RESOLVED", "FALSE_POSITIVE", "IGNORED")
_FINDING_STATUS = {"OPEN": (1, "New"), "ACKNOWLEDGED": (2, "In Progress"), "RESOLVED": (4, "Resolved"),
                   "FALSE_POSITIVE": (3, "Suppressed"), "IGNORED": (3, "Suppressed")}
_ABSENT = ("NO_VAULT_MATCH", "IDENTIFIER_NOT_OBSERVED", "PUBLIC_CERTIFICATE_NOT_OBSERVED")
_PRESENT = ("MATCHED", "IDENTIFIER_ONLY", "PUBLIC_CERTIFICATE_MATCH")
_ACTIVITY = {1: "Create", 2: "Update", 3: "Close"}
_API_ACTIVITY = {1: "Create", 3: "Update", 4: "Delete"}


def _ms(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise DeliveryError("INVALID_EVENT_TIME") from None
    if parsed.tzinfo is None:
        raise DeliveryError("INVALID_EVENT_TIME")
    return int(parsed.timestamp() * 1000)


def _metadata(event: dict) -> dict:
    metadata = {"version": OCSF_VERSION, "uid": event["event_id"], "log_name": event["event_type"],
                "product": {"name": PRODUCT_NAME, "vendor_name": PRODUCT_NAME, "version": PRODUCT_VERSION}}
    if event.get("installation_id"):
        metadata["tenant_uid"] = event["installation_id"]
    return metadata


def _finding(event: dict, *, activity: int, uid: str, title: str, types: list, severity_id: int,
             status: tuple[int, str], resources: list, unmapped: dict, message: str) -> dict:
    return {
        "category_uid": 2, "category_name": "Findings",
        "class_uid": 2004, "class_name": "Detection Finding",
        "activity_id": activity, "activity_name": _ACTIVITY[activity],
        "type_uid": 2004 * 100 + activity, "type_name": "Detection Finding: " + _ACTIVITY[activity],
        "time": _ms(event["occurred_at"]),
        "severity_id": severity_id, "severity": _SEVERITY_NAME[severity_id],
        "status_id": status[0], "status": status[1],
        "message": message,
        "finding_info": {"uid": uid, "title": title, "types": types,
                         "analytic": {"type_id": 1, "type": "Rule", "uid": types[0]}},
        "resources": [item for item in resources if item.get("uid")],
        "metadata": _metadata(event),
        "unmapped": {key: value for key, value in unmapped.items() if value is not None},
    }


def _finding_event(event: dict) -> dict:
    finding, credential = event["finding"], event["credential"]
    created = event["event_type"] == "finding.created"
    closing = (not created and finding["workflow_status"] in _CLOSED
               and finding.get("previous_workflow_status") not in _CLOSED)
    activity = 1 if created else 3 if closing else 2
    kind = credential["credential_type"]
    ocsf = _finding(event, activity=activity, uid=finding["id"], title="Exposed credential: " + kind,
                    types=[kind], severity_id=_SEVERITY_ID.get(finding["severity"], 0),
                    status=_FINDING_STATUS.get(finding["workflow_status"], (0, "Unknown")),
                    resources=[{"uid": finding["credential_id"], "type": "Credential"}],
                    unmapped={"credential": credential, "exposure": event.get("exposure"),
                              "change": event.get("change"), "finding": finding},
                    message="Credential exposure " + ("found" if created else "forwarded" if event["event_type"] == "finding.forwarded"
                                                      else "updated"))
    time_field = "created_time" if created else "modified_time"
    ocsf["finding_info"][time_field] = ocsf["time"]
    if event.get("exposure", {}).get("source_type"):
        ocsf["finding_info"]["data_sources"] = [event["exposure"]["source_type"]]
    return ocsf


def _verdict_event(event: dict) -> dict:
    verdict = event["verdict"]
    state = verdict["state"]
    severity = 3 if state in _ABSENT else 1
    status = (1, "New") if state in _ABSENT else (4, "Resolved") if state in _PRESENT else (0, "Unknown")
    return _finding(event, activity=1 if verdict["previous_state"] is None else 2, uid=verdict["ref"],
                    title="Vault storage verdict: " + state, types=["coverage.verdict"], severity_id=severity,
                    status=status, resources=[{"uid": verdict.get("credential_id"), "type": "Credential"},
                                              {"uid": verdict.get("entity_id"), "type": "Issued credential"}],
                    unmapped={"verdict": verdict}, message="Vault storage verdict changed")


def _orphan_event(event: dict) -> dict:
    orphan = event["orphan"]
    verdict = orphan["verdict"]
    severity = {"USED_AFTER_DEPARTURE": 5, "ACTIVE": 4}.get(verdict, 2)
    status = (4, "Resolved") if verdict == "REVOKED_OR_EXPIRED" else (1, "New")
    return _finding(event, activity=1 if orphan.get("previous_verdict") is None else 2, uid=orphan["ref"],
                    title="Departed owner's credential: " + verdict, types=["identity.credential_orphaned"],
                    severity_id=severity, status=status,
                    resources=[{"uid": orphan.get("credential_ref"), "type": "Credential"},
                               {"uid": orphan.get("person_ref"), "type": "Person"}],
                    unmapped={"orphan": orphan}, message="Credential of a departed owner")


def _audit_event(event: dict) -> dict:
    audit = event["audit"]
    action = audit["action"]
    activity = (1 if action.endswith(("_CREATED", "_ADDED", "_SET", "_REGISTERED", "_CONNECTED")) else
                4 if action.endswith(("_DELETED", "_REMOVED", "_REVOKED", "_CLEARED", "_DISCONNECTED")) else 3)
    resources = [{"uid": audit["target_id"], "type": audit["target_type"]}] if audit.get("target_id") else []
    return {
        "category_uid": 6, "category_name": "Application Activity",
        "class_uid": 6003, "class_name": "API Activity",
        "activity_id": activity, "activity_name": _API_ACTIVITY[activity],
        "type_uid": 6003 * 100 + activity, "type_name": "API Activity: " + _API_ACTIVITY[activity],
        "time": _ms(event["occurred_at"]),
        "severity_id": 1, "severity": "Informational",
        "status_id": 1, "status": "Success",
        "message": "Administrator action " + action,
        "actor": {"user": {"uid": audit["actor_ref"]}},
        "api": {"operation": action, "service": {"name": PRODUCT_NAME}},
        # The audit trail does not record where a request came from.
        "src_endpoint": {"name": "unknown"},
        "resources": resources,
        "metadata": _metadata(event),
        "unmapped": {key: audit[key] for key in ("id", "finding_id", "from_status", "to_status") if audit.get(key)},
    }


_OCSF = {"finding.created": _finding_event, "finding.updated": _finding_event, "finding.forwarded": _finding_event,
         "finding.reappeared": _finding_event, "finding.location_added": _finding_event,
         "coverage.verdict_changed": _verdict_event, "identity.credential_orphaned": _orphan_event,
         "audit.action": _audit_event}


def to_ocsf(event: dict) -> dict | None:
    """The OCSF form of an event, or None where no class fits and native stays."""
    build = _OCSF.get(event.get("event_type"))
    if build is None:
        return None
    try:
        return build(event)
    except (KeyError, TypeError):
        raise DeliveryError("INVALID_EVENT") from None


def encode(event: dict, form: str) -> dict:
    if form == "native":
        return event
    if form == "ocsf":
        return to_ocsf(event) or event
    raise DeliveryError("INVALID_EVENT")


# --- CEF and LEEF -------------------------------------------------------------

def severity(event: dict) -> int:
    """0-10, most important highest, shared by CEF, LEEF and syslog."""
    kind = event.get("event_type", "")
    if kind.startswith("finding."):
        return {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}.get(event.get("finding", {}).get("severity"), 1)
    if kind == "identity.credential_orphaned":
        return {"USED_AFTER_DEPARTURE": 9, "ACTIVE": 7}.get(event.get("orphan", {}).get("verdict"), 3)
    if kind == "coverage.verdict_changed":
        return 5 if event.get("verdict", {}).get("state") in _ABSENT else 2
    if kind == "audit.chain_anchor":
        return 1 if event.get("audit", {}).get("chain_state") == "INTACT" else 9
    return {"connection.auth_failed": 6, "collection.failed": 6, "collection.stale": 6,
            "connection.auth_expiring": 4, "siem.delivery_backlog": 6, "audit.action": 3}.get(kind, 2 if kind.endswith(
                "recovered") else 1)


def syslog_severity(event: dict) -> int:
    """RFC 5424 severity: 2 critical, 3 error, 4 warning, 5 notice, 6 informational."""
    value = severity(event)
    return 2 if value >= 9 else 3 if value >= 7 else 4 if value >= 5 else 5 if value >= 3 else 6


_NAMES = {
    "finding.created": "Credential exposure found", "finding.updated": "Credential finding updated",
    "finding.reappeared": "Credential exposure reappeared", "finding.location_added": "Credential exposure in a new location",
    "finding.forwarded": "Credential finding forwarded", "connection.auth_failed": "Connection authentication failed", "connection.auth_recovered": "Connection authentication recovered",
    "connection.auth_expiring": "Connection credential expiring", "collection.failed": "Collection failed",
    "collection.stale": "Collection stale", "collection.recovered": "Collection recovered",
    "platform.heartbeat": "Platform heartbeat", "siem.delivery_backlog": "SIEM delivery backlog",
    "siem.delivery_recovered": "SIEM delivery recovered", "siem.test": "SIEM test event",
    "audit.action": "Administrator action", "coverage.verdict_changed": "Vault storage verdict changed",
    "audit.chain_anchor": "Audit trail chain anchor",
    "identity.credential_orphaned": "Credential of a departed owner",
}

# CEF extension key, label, path in the native event. cs1-cs6 carry labels;
# cn1-cn3 are numbers. The same labels are the LEEF keys.
_FIELDS = {
    "finding": [("cs1", "findingId", "finding.id"), ("cs2", "credentialId", "finding.credential_id"),
                ("cs3", "credentialType", "credential.credential_type"), ("cs4", "workflowStatus", "finding.workflow_status"),
                ("cs5", "sourceType", "exposure.source_type"), ("act", "change", "change"),
                ("cn1", "lineNumber", "exposure.line_number")],
    "connection": [("cs1", "connectionId", "connection.id"), ("cs2", "connectionKind", "connection.kind"),
                   ("cs3", "provider", "connection.provider"), ("cs4", "authState", "health.auth_state"),
                   ("cs5", "reason", "health.reason"), ("act", "freshness", "health.freshness")],
    "platform": [("cn1", "workersAlive", "platform.workers_alive"), ("cn2", "queuedJobs", "platform.queued_jobs"),
                 ("cn3", "oldestQueuedSeconds", "platform.oldest_queued_seconds")],
    "siem": [("cs1", "destination", "delivery.destination"), ("cs5", "lastErrorCode", "delivery.last_error_code"),
             ("cn1", "pending", "delivery.pending"), ("cn2", "held", "delivery.held"), ("cs2", "nonce", "test.nonce")],
    "audit": [("act", "action", "audit.action"), ("cs1", "targetType", "audit.target_type"),
              ("cs2", "targetId", "audit.target_id"), ("suid", "actorRef", "audit.actor_ref"),
              ("cs4", "fromStatus", "audit.from_status"), ("cs5", "toStatus", "audit.to_status"),
              # audit.chain_anchor has no target: cs1 and cs2 carry the head's and the start's MACs there.
              ("cs3", "chainState", "audit.chain_state"), ("cs1", "chainMac", "audit.chain_mac"),
              ("cs2", "genesisMac", "audit.genesis_mac"), ("cn1", "chainSeq", "audit.chain_seq"),
              ("cn2", "anchorNo", "audit.anchor_no"), ("cn3", "openProblems", "audit.open_problems")],
    "coverage": [("cs1", "verdictRef", "verdict.ref"), ("cs2", "state", "verdict.state"),
                 ("cs3", "previousState", "verdict.previous_state"), ("cs4", "credentialType", "verdict.credential_type"),
                 ("cs5", "absenceBasis", "verdict.absence_basis")],
    "identity": [("cs1", "orphanRef", "orphan.ref"), ("cs2", "verdict", "orphan.verdict"),
                 ("cs3", "credentialRef", "orphan.credential_ref"), ("cs4", "personRef", "orphan.person_ref"),
                 ("cs5", "provider", "orphan.provider")],
}
_FIELDS["collection"] = _FIELDS["connection"]


def _path(event: dict, path: str):
    node = event
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _fields(event: dict) -> list[tuple[str, str, str]]:
    out = []
    for key, label, path in _FIELDS.get(event_family(event.get("event_type")), []):
        value = _path(event, path)
        if value is not None and value != "":
            out.append((key, label, str(value)))
    if event.get("installation_id"):
        out.append(("cs6", "installationId", str(event["installation_id"])))
    return out


def _ascii(value: str) -> str:
    if not value.isascii():
        raise DeliveryError("INVALID_EVENT")
    return value


def _cef_header(value: str) -> str:
    return _ascii(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(value: str) -> str:
    return (_ascii(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def to_cef(event: dict) -> str:
    """CEF:0 with rt (epoch ms), externalId, cat and labelled custom strings."""
    kind = event.get("event_type", "")
    extension = [("rt", str(_ms(event.get("occurred_at")))), ("externalId", str(event.get("event_id", ""))),
                 ("cat", event_family(kind))]
    for key, label, value in _fields(event):
        extension.append((key, value))
        if key.startswith(("cs", "cn")):
            extension.append((key + "Label", label))
    header = "|".join(_cef_header(part) for part in (
        "CEF:0", PRODUCT_NAME, PRODUCT_NAME, PRODUCT_VERSION, kind, _NAMES.get(kind, kind), str(severity(event))))
    return header + "|" + " ".join(f"{key}={_cef_value(value)}" for key, value in extension)


def to_leef(event: dict) -> str:
    """LEEF 2.0 with a tab delimiter (x09); devTime in epoch milliseconds needs no format."""
    kind = event.get("event_type", "")
    attributes = [("devTime", str(_ms(event.get("occurred_at")))), ("cat", event_family(kind)),
                  ("sev", str(max(1, severity(event)))), ("eventId", str(event.get("event_id", "")))]
    attributes += [(label, value) for _key, label, value in _fields(event)]
    for key, value in attributes:
        if any(char in _ascii(value) for char in "\t\r\n") or "|" in kind:
            raise DeliveryError("INVALID_EVENT")
    header = "|".join(("LEEF:2.0", PRODUCT_NAME, PRODUCT_NAME, PRODUCT_VERSION, _ascii(kind), "x09"))
    return header + "|" + "\t".join(f"{key}={value}" for key, value in attributes)
