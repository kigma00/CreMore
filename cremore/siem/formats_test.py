"""OCSF 1.3.0, CEF and LEEF encodings, checked against the published requirements.

The required-attribute lists below were read from the OCSF schema server
(https://schema.ocsf.io/api/1.3.0/classes/detection_finding and .../api_activity,
objects metadata, product, finding_info, actor, user, network_endpoint) on
2026-09-28, without optional profiles.
"""

import json

import pytest

from cremore.siem.contract import DeliveryError
from cremore.siem.formats import encode, severity, syslog_severity, to_cef, to_leef, to_ocsf

DETECTION_FINDING_REQUIRED = {"activity_id", "category_uid", "class_uid", "finding_info", "metadata", "severity_id",
                              "time", "type_uid"}
API_ACTIVITY_REQUIRED = {"activity_id", "actor", "api", "category_uid", "class_uid", "metadata", "severity_id",
                         "src_endpoint", "time", "type_uid"}
INSTALLATION = "0b5c6a0e-8a8f-4d9a-9e5b-2c0a4e1f7b62"

CREATED = {
    "schema_version": 1, "event_id": "b21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "finding.created",
    "occurred_at": "2026-09-24T03:00:00Z", "product": "CreMore", "installation_id": INSTALLATION,
    "finding": {"id": "11111111-1111-4111-8111-111111111111", "credential_id": "22222222-2222-4222-8222-222222222222",
                "severity": "HIGH", "workflow_status": "OPEN"},
    "credential": {"provider": "github", "credential_type": "GITHUB_TOKEN", "status": "UNKNOWN"},
    "exposure": {"id": "33333333-3333-4333-8333-333333333333", "source_type": "github",
                 "source_connection_id": "44444444-4444-4444-8444-444444444444", "aws_account_id": None, "line_number": 12},
}
RESOLVED = {
    "schema_version": 1, "event_id": "c21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "finding.updated",
    "occurred_at": "2026-09-25T03:00:00+00:00", "product": "CreMore", "installation_id": INSTALLATION, "change": "WORKFLOW",
    "finding": {"id": "11111111-1111-4111-8111-111111111111", "credential_id": "22222222-2222-4222-8222-222222222222",
                "severity": "HIGH", "previous_severity": None, "workflow_status": "RESOLVED",
                "previous_workflow_status": "OPEN"},
    "credential": {"provider": "github", "credential_type": "GITHUB_TOKEN", "status": "Revoked", "previous_status": None},
}
AUDIT = {
    "schema_version": 1, "event_id": "d21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "audit.action",
    "occurred_at": "2026-09-25T04:00:00Z", "product": "CreMore", "installation_id": INSTALLATION,
    "audit": {"id": "55555555-5555-4555-8555-555555555555", "action": "COVERAGE_VAULT_TOKEN_SET",
              "target_type": "coverage_connection", "target_id": "66666666-6666-4666-8666-666666666666",
              "finding_id": None, "actor_ref": "77777777-7777-5777-8777-777777777777",
              "from_status": None, "to_status": None},
}
VERDICT = {
    "schema_version": 1, "event_id": "e21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "coverage.verdict_changed",
    "occurred_at": "2026-09-25T05:00:00Z", "product": "CreMore", "installation_id": INSTALLATION,
    "verdict": {"ref": "88888888-8888-5888-8888-888888888888", "origin": "EXPOSURE",
                "credential_id": "22222222-2222-4222-8222-222222222222",
                "finding_id": "11111111-1111-4111-8111-111111111111", "entity_id": None,
                "credential_type": "GITHUB_TOKEN", "state": "NO_VAULT_MATCH", "previous_state": "MATCHED",
                "match_basis": "NONE", "absence_basis": "OPERATOR_DECLARED"},
}
HEALTH = {
    "schema_version": 1, "event_id": "f21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "connection.auth_failed",
    "occurred_at": "2026-09-27T10:36:00Z", "product": "CreMore", "installation_id": INSTALLATION,
    "connection": {"id": "44444444-4444-4444-8444-444444444444", "kind": "CONTENT", "provider": "github"},
    "health": {"auth_state": "REAUTH_REQUIRED", "previous_auth_state": "READY", "reason": "GITHUB_APP_REJECTED",
               "auth_renewal": "AUTO", "expiry_stage": "NONE", "expires_at": None, "freshness": "FRESH",
               "last_status": "COMPLETE", "last_success_at": "2026-09-27T10:20:00Z", "last_failure_code": None,
               "recovered_from": None},
}


def test_a_new_finding_is_an_ocsf_detection_finding_create():
    ocsf = to_ocsf(CREATED)
    assert DETECTION_FINDING_REQUIRED <= set(ocsf)
    assert (ocsf["class_uid"], ocsf["category_uid"], ocsf["activity_id"], ocsf["type_uid"]) == (2004, 2, 1, 200401)
    assert ocsf["time"] == 1790218800000  # 2026-09-24T03:00:00Z in epoch milliseconds
    assert (ocsf["severity_id"], ocsf["severity"], ocsf["status_id"], ocsf["status"]) == (4, "High", 1, "New")
    assert {"uid", "title"} <= set(ocsf["finding_info"])
    assert ocsf["finding_info"]["uid"] == CREATED["finding"]["id"]
    assert ocsf["finding_info"]["created_time"] == ocsf["time"] and ocsf["finding_info"]["data_sources"] == ["github"]
    assert ocsf["metadata"]["version"] == "1.3.0" and ocsf["metadata"]["product"]["vendor_name"] == "CreMore"
    assert ocsf["metadata"]["tenant_uid"] == INSTALLATION and ocsf["metadata"]["uid"] == CREATED["event_id"]
    assert ocsf["resources"] == [{"uid": CREATED["finding"]["credential_id"], "type": "Credential"}]
    assert ocsf["unmapped"]["exposure"]["line_number"] == 12


def test_a_resolved_finding_closes_it():
    ocsf = to_ocsf(RESOLVED)
    assert (ocsf["activity_id"], ocsf["type_uid"], ocsf["status_id"], ocsf["status"]) == (3, 200403, 4, "Resolved")
    assert ocsf["finding_info"]["modified_time"] == ocsf["time"]
    suppressed = to_ocsf({**RESOLVED, "finding": {**RESOLVED["finding"], "workflow_status": "FALSE_POSITIVE"}})
    assert (suppressed["status_id"], suppressed["status"]) == (3, "Suppressed")
    reopened = to_ocsf({**RESOLVED, "finding": {**RESOLVED["finding"], "workflow_status": "OPEN",
                                                "previous_workflow_status": "RESOLVED"}})
    assert (reopened["activity_id"], reopened["type_uid"]) == (2, 200402)


def test_a_forwarded_finding_is_an_update_that_closes_nothing_and_names_nobody():
    import datetime as dt
    import types
    import uuid

    from cremore.siem.events import finding_forwarded

    finding = types.SimpleNamespace(id=uuid.UUID(RESOLVED["finding"]["id"]), credential_id=uuid.UUID(RESOLVED["finding"]["credential_id"]),
                                    severity="HIGH", workflow_status="RESOLVED")
    credential = types.SimpleNamespace(provider="github", credential_type="GITHUB_TOKEN", credential_status="Revoked")
    event = {**finding_forwarded(finding, credential, now=dt.datetime(2026, 9, 29, tzinfo=dt.UTC),
                                 request_id=uuid.uuid4()), "installation_id": INSTALLATION}
    ocsf = to_ocsf(event)
    assert (ocsf["activity_id"], ocsf["status_id"], ocsf["message"]) == (2, 4, "Credential exposure forwarded")
    cef = to_cef(event)
    assert "|finding.forwarded|Credential finding forwarded|8|" in cef and "act=FORWARDED" in cef
    assert "suid=" not in cef  # who sent it is on the audit.action event that goes with it


def test_an_administrator_action_is_ocsf_api_activity():
    ocsf = to_ocsf(AUDIT)
    assert API_ACTIVITY_REQUIRED <= set(ocsf)
    assert (ocsf["class_uid"], ocsf["category_uid"], ocsf["activity_id"], ocsf["type_uid"]) == (6003, 6, 1, 600301)
    assert ocsf["api"]["operation"] == "COVERAGE_VAULT_TOKEN_SET"
    assert ocsf["actor"] == {"user": {"uid": AUDIT["audit"]["actor_ref"]}}
    # network_endpoint needs at least one identifying attribute.
    assert set(ocsf["src_endpoint"]) & {"ip", "uid", "name", "hostname", "svc_name"}
    assert ocsf["resources"] == [{"uid": AUDIT["audit"]["target_id"], "type": "coverage_connection"}]
    removal = to_ocsf({**AUDIT, "audit": {**AUDIT["audit"], "action": "COVERAGE_VAULT_TOKEN_REMOVED"}})
    assert (removal["activity_id"], removal["type_uid"]) == (4, 600304)


def test_a_vault_verdict_is_a_detection_finding_and_health_stays_native():
    ocsf = to_ocsf(VERDICT)
    assert DETECTION_FINDING_REQUIRED <= set(ocsf) and ocsf["type_uid"] == 200402
    assert (ocsf["severity_id"], ocsf["status_id"]) == (3, 1)
    assert ocsf["unmapped"]["verdict"]["absence_basis"] == "OPERATOR_DECLARED"
    assert to_ocsf(HEALTH) is None
    assert encode(HEALTH, "ocsf") is HEALTH and encode(CREATED, "native") is CREATED
    with pytest.raises(DeliveryError, match="INVALID_EVENT_TIME"):
        to_ocsf({**CREATED, "occurred_at": "2026-09-24T03:00:00"})


def test_ocsf_adds_nothing_the_native_event_did_not_carry():
    for event in (CREATED, RESOLVED, AUDIT, VERDICT):
        native = set(json.dumps(event).replace('"', " ").split())
        for token in json.dumps(to_ocsf(event)).replace('"', " ").split():
            value = token.strip(",:{}[]")
            # Every identifier or code in the OCSF output is from the event or the fixed schema vocabulary.
            if len(value) == 36 and value.count("-") == 4:
                assert value in native, value


def test_cef_header_and_extension_are_escaped_per_the_standard():
    assert to_cef(CREATED) == (
        "CEF:0|CreMore|CreMore|0.1.0|finding.created|Credential exposure found|8|"
        "rt=1790218800000 externalId=b21e4c6a-ce3f-54e7-9320-02d31ddc9568 cat=finding "
        "cs1=11111111-1111-4111-8111-111111111111 cs1Label=findingId "
        "cs2=22222222-2222-4222-8222-222222222222 cs2Label=credentialId "
        "cs3=GITHUB_TOKEN cs3Label=credentialType cs4=OPEN cs4Label=workflowStatus "
        "cs5=github cs5Label=sourceType cn1=12 cn1Label=lineNumber "
        f"cs6={INSTALLATION} cs6Label=installationId")
    tricky = {**HEALTH, "event_type": "connection.auth_failed",
              "health": {**HEALTH["health"], "reason": "A=B\\C"}}
    assert "cs5=A\\=B\\\\C" in to_cef(tricky)
    with pytest.raises(DeliveryError, match="INVALID_EVENT"):
        to_cef({**HEALTH, "health": {**HEALTH["health"], "reason": "한글"}})


def test_leef_two_uses_a_tab_delimiter_and_epoch_device_time():
    assert to_leef(AUDIT) == (
        "LEEF:2.0|CreMore|CreMore|0.1.0|audit.action|x09|"
        "devTime=1790308800000\tcat=audit\tsev=3\teventId=d21e4c6a-ce3f-54e7-9320-02d31ddc9568\t"
        "action=COVERAGE_VAULT_TOKEN_SET\ttargetType=coverage_connection\t"
        "targetId=66666666-6666-4666-8666-666666666666\tactorRef=77777777-7777-5777-8777-777777777777\t"
        f"installationId={INSTALLATION}")
    with pytest.raises(DeliveryError, match="INVALID_EVENT"):
        to_leef({**HEALTH, "health": {**HEALTH["health"], "reason": "A\tB"}})


def test_one_severity_scale_feeds_cef_leef_and_syslog():
    assert [severity(e) for e in (CREATED, RESOLVED, AUDIT, VERDICT, HEALTH)] == [8, 8, 3, 5, 6]
    assert [syslog_severity(e) for e in (CREATED, AUDIT, VERDICT, HEALTH)] == [3, 5, 4, 4]
    critical = {**CREATED, "finding": {**CREATED["finding"], "severity": "CRITICAL"}}
    assert (severity(critical), syslog_severity(critical)) == (10, 2)
    beat = {"event_type": "platform.heartbeat", "occurred_at": "2026-09-27T10:40:00Z"}
    assert (severity(beat), syslog_severity(beat)) == (1, 6)
