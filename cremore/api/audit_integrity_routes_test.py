"""GET /api/v1/audit/integrity and its acknowledgement: who may verify the audit trail and who may accept a
problem, the anchor it checks against, and what the API itself writes into the chain."""

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import GROUPS, oidc_settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import FindingEvent
from cremore.operations import audit_integrity

PATH = "/api/v1/audit/integrity"


def bearer(issuer, role):
    return {"Authorization": "Bearer " + issuer.mint(sub=role, groups=(GROUPS[role],))}


def test_analysts_verify_the_chain_and_only_admins_accept_its_problems(issuer):
    repo = InMemoryRepository()
    settings = oidc_settings()
    client = TestClient(create_app(repo=repo, settings=settings, oidc_http_client=issuer))
    # The API attached its key: what it writes is authenticated.
    repo.record_finding_event(FindingEvent(target_type="connection_health", actor="alice", event_type="CONNECTION_EXPIRY_DECLARED"))
    audit_integrity.seal(repo, settings)
    key, repo.audit_key = repo.audit_key, None
    forged = repo.record_finding_event(FindingEvent(target_type="action_plan", actor="mallory", event_type="ACTION_PLAN_APPROVED"))
    repo.audit_key = key
    audit_integrity.seal(repo, settings)

    assert client.get(PATH, headers=bearer(issuer, "viewer")).status_code == 403
    analyst, admin = bearer(issuer, "analyst"), bearer(issuer, "admin")
    report = client.get(PATH, headers=analyst).json()
    assert report["state"] == "UNAUTHENTICATED" and report["head"]["seq"] == 3
    [problem] = report["problems"]
    assert (problem["kind"], problem["seq"], problem["event_id"]) == ("UNAUTHENTICATED", 3, str(forged.id))

    head = report["head"]
    matched = client.get(PATH, params={"anchor_seq": head["seq"], "anchor_mac": head["mac"]}, headers=analyst).json()
    assert matched["anchor"] == {"seq": 3, "state": "MATCHED"}
    for params in ({"anchor_seq": 2}, {"anchor_seq": 0, "anchor_mac": head["mac"]},
                   {"anchor_seq": 2, "anchor_mac": head["mac"].upper()}, {"anchor_seq": 2, "anchor_mac": "zz"}):
        refused = client.get(PATH, params=params, headers=analyst)
        assert refused.status_code == 422 and "ANCHOR_INVALID" in refused.text, params

    assert problem["ack"].startswith(f"UNAUTHENTICATED@event:{forged.id}#")
    body = {"items": [problem["ack"]], "reason": "row written by the API replica before its upgrade"}
    assert client.post(PATH + "/acknowledge", json=body, headers=analyst).status_code == 403
    from cremore.coverage.metadata_linkage_test import TOKEN

    secret_reason = "pasted by mistake " + TOKEN.decode()
    for wrong in ({"items": ["seq:3"], "reason": "x"}, {"items": [problem["ack"]] * 2, "reason": "x"},
                  {"items": [problem["ack"]], "reason": " "}, {"items": [], "reason": "x"},
                  {"items": ["MAC_MISMATCH@seq:1#" + "0" * 32], "reason": "not a problem now"},
                  {"items": [problem["ack"]], "reason": secret_reason}):
        refused = client.post(PATH + "/acknowledge", json=wrong, headers=admin)
        assert refused.status_code == 422 and TOKEN.decode() not in refused.text, wrong
    assert client.post(PATH + "/acknowledge", json=body, headers=admin).json() == {"acknowledged": 1}
    # The acknowledgement empties the one-minute cache: the next check reads it at once.
    after = client.get(PATH, headers=analyst).json()
    assert after["state"] == "INTACT" and after["open_problems"] == 0 and after["problems"][0]["acknowledged"] is True
