"""Departed-owner routes: reading is for analysts, decisions for administrators, AWS keys via action plans."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.api.dashboard_test import _review
from cremore.db.repository import InMemoryRepository
from cremore.identity import leavers
from cremore.identity import leavers_test as synthetic


def _bearer(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def client(issuer, repo, monkeypatch=None, **settings):
    if monkeypatch is not None:
        # The API evaluates with the coverage comparison; this one names the synthetic IAM key.
        monkeypatch.setattr(leavers, "_report_rows", lambda *args: [synthetic.AWS_ROW])
    app = create_app(repo=repo, settings=oidc_settings(FINGERPRINT_KEY=synthetic.KEY.hex(), **settings),
                     oidc_http_client=issuer)
    return TestClient(app)


def seeded(**settings_overrides):
    repo = InMemoryRepository()
    synthetic.seed(repo)
    synthetic.evaluate(repo, report_rows=[synthetic.AWS_ROW])
    return repo


def test_analysts_read_the_lists_and_viewers_cannot(issuer):
    repo = seeded()
    c = client(issuer, repo)
    analyst, viewer = _bearer(issuer, "ann", "g-analysts"), _bearer(issuer, "vic", "g-viewers")
    assert c.get("/api/v1/leavers/summary", headers=viewer).status_code == 403
    summary = c.get("/api/v1/leavers/summary", headers=analyst).json()
    assert (summary["departed"], summary["orphans"], summary["candidates"]) == (1, 3, 1)
    assert summary["by_verdict"]["USED_AFTER_DEPARTURE"] == 1
    assert summary["retention_days"] == 365
    assert [source["provider"] for source in summary["sources"]] == ["okta"]
    listed = c.get("/api/v1/leavers/orphans", headers=analyst).json()
    assert [item["verdict"] for item in listed["items"]] == ["USED_AFTER_DEPARTURE", "ACTIVE", "REVOKED_OR_EXPIRED"]
    assert listed["items"][0]["ticket_id"] and listed["items"][0]["actionable"] is False
    assert "action" not in (listed["items"][0]["credential"] or {})
    only = c.get("/api/v1/leavers/orphans?verdict=ACTIVE", headers=analyst).json()
    assert only["total"] == 1 and only["facets"]["verdict"][0] == "USED_AFTER_DEPARTURE"
    people = c.get("/api/v1/leavers/people", headers=analyst).json()["items"]
    assert people[0]["idp_user_id"] == "00udana00001" and people[0]["verdicts"]["ACTIVE"] == 1
    assert people[0]["accounts"][0]["provider"] == "notion"
    candidates = c.get("/api/v1/leavers/candidates", headers=analyst).json()["items"]
    assert candidates[0]["account_provider"] == "aws" and candidates[0]["person"]["idp_user_id"] == "00udana00001"


def test_an_idps_app_list_is_no_source_of_people(issuer):
    from cremore.coverage.metadata_store import MetadataStore

    repo = seeded()
    records, status = synthetic.okta_apps()
    synthetic.save(MetadataStore(repo), synthetic.okta.spec(name="okta apps", **synthetic.okta.APPS_SPEC), records,
                   status=status)
    summary = client(issuer, repo).get("/api/v1/leavers/summary", headers=_bearer(issuer, "ann", "g-analysts")).json()
    assert [source["name"] for source in summary["sources"]] == ["okta"]  # the people collection alone


def test_only_an_administrator_confirms_a_link_and_it_is_audited(issuer, monkeypatch):
    repo = seeded()
    c = client(issuer, repo, monkeypatch)
    analyst, admin = _bearer(issuer, "ann", "g-analysts"), _bearer(issuer, "adam", "g-admins")
    candidate = c.get("/api/v1/leavers/candidates", headers=analyst).json()["items"][0]
    body = {"account_ref": candidate["account_ref"], "person_ref": candidate["person_ref"], "decision": "CONFIRMED"}
    assert c.post("/api/v1/leavers/links", headers=analyst, json=body).status_code == 403
    assert c.post("/api/v1/leavers/links", headers=admin, json={**body, "decision": "MAYBE"}).status_code == 422
    assert c.post("/api/v1/leavers/links", headers=admin, json={**body, "person_ref": str(uuid.uuid4())}).status_code == 404
    assert c.post("/api/v1/leavers/links", headers=admin, json=body).json()["decision"] == "CONFIRMED"
    # A decided link leaves the candidates at once, before the next check.
    assert c.get("/api/v1/leavers/candidates", headers=analyst).json()["items"] == []
    assert c.get("/api/v1/leavers/summary", headers=analyst).json()["candidates"] == 0
    result = c.post("/api/v1/leavers/evaluate", headers=admin).json()
    assert result["orphans"] == 4
    aws = c.get("/api/v1/leavers/orphans?provider=aws", headers=analyst).json()["items"]
    assert aws[0]["verdict"] == "USED_AFTER_DEPARTURE" and aws[0]["actionable"] is True
    actions = [row["action"] for row in c.get("/api/v1/audit", headers=admin).json()]
    assert "LEAVER_LINK_CONFIRMED" in actions and "LEAVER_EVALUATED" in actions
    cleared = c.delete("/api/v1/leavers/links", headers=admin,
                       params={"account_ref": body["account_ref"], "person_ref": body["person_ref"]})
    assert cleared.json()["decision"] is None


def test_a_departed_owners_aws_key_is_disabled_only_through_an_approved_plan(issuer, monkeypatch):
    repo = seeded()
    c = client(issuer, repo, monkeypatch)
    admin, remediator = _bearer(issuer, "adam", "g-admins"), _bearer(issuer, "rita", "g-remediators")
    candidate = c.get("/api/v1/leavers/candidates", headers=admin).json()["items"][0]
    c.post("/api/v1/leavers/links", headers=admin, json={"account_ref": candidate["account_ref"],
                                                          "person_ref": candidate["person_ref"], "decision": "CONFIRMED"})
    c.post("/api/v1/leavers/evaluate", headers=admin)
    aws = c.get("/api/v1/leavers/orphans?provider=aws", headers=admin).json()["items"][0]
    notion = c.get("/api/v1/leavers/orphans?provider=notion", headers=admin).json()["items"][0]
    assert c.get(f"/api/v1/leavers/orphans/{notion['ref']}/action-plans", headers=admin).status_code == 409
    policy = c.get(f"/api/v1/leavers/orphans/{aws['ref']}/action-plans", headers=admin).json()["policy"]
    assert policy["execution_enabled"] is False and policy["reason_code"] == "OWNER_DEPARTED"
    # The same operational review every key action needs before it can be approved.
    body = {"idempotency_key": str(uuid.uuid4()), "operational_review": _review(datetime.now(UTC))}
    assert c.post(f"/api/v1/leavers/orphans/{aws['ref']}/action-plans", headers=admin,
                  json={**body, "action_type": "DELETE_ACCESS_KEY"}).status_code == 422
    plan = c.post(f"/api/v1/leavers/orphans/{aws['ref']}/action-plans", headers=remediator, json=body).json()
    assert (plan["status"], plan["action_type"], plan["reason_code"]) == ("PENDING_APPROVAL", "DISABLE_ACCESS_KEY",
                                                                          "OWNER_DEPARTED")
    # The same two-person flow as every key action: the planner cannot approve it.
    assert c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=remediator,
                  json={"plan_hash": plan["plan_hash"]}).status_code == 403
    approved = c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=admin,
                      json={"plan_hash": plan["plan_hash"]}).json()
    assert approved["status"] == "APPROVED"
    blocked = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=remediator,
                     json={"plan_hash": plan["plan_hash"]})
    assert blocked.status_code in (403, 409) and "EXECUTION" in blocked.text.upper()


def test_evaluation_needs_the_fingerprint_key_only_once(issuer):
    repo = InMemoryRepository()
    c = client(issuer, repo)
    result = c.post("/api/v1/leavers/evaluate", headers=_bearer(issuer, "adam", "g-admins")).json()
    assert result["people"] == 0 and result["orphans"] == 0


def test_the_published_result_expires_with_its_people(issuer):
    repo = InMemoryRepository()
    store, _idp, notion = synthetic.seed(repo)
    synthetic.evaluate(repo)
    synthetic.revoke_all(store, notion)
    later = synthetic.DEPARTED_AT + timedelta(days=366)
    leavers.evaluate(repo, synthetic.SETTINGS, now=later, fingerprint_key=synthetic.KEY, report_rows=[])
    c = client(issuer, repo)
    analyst = _bearer(issuer, "ann", "g-analysts")
    assert c.get("/api/v1/leavers/orphans", headers=analyst).json()["total"] == 0
    assert c.get("/api/v1/leavers/candidates", headers=analyst).json()["items"] == []


def test_analysts_read_the_directory_and_viewers_cannot(issuer, monkeypatch):
    from cremore.api import conftest
    from cremore.identity.people_directory_test import TEAM, setup

    monkeypatch.setattr(conftest, "ISSUER", TEAM.oidc_issuer_url)
    memory = InMemoryRepository()
    setup(memory)
    setup(memory, host="other.okta.com")
    c = TestClient(create_app(repo=memory, settings=oidc_settings(), oidc_http_client=issuer))
    viewer = {"Authorization": "Bearer " + issuer.mint(sub="vic", groups=("g-viewers",), issuer=TEAM.oidc_issuer_url)}
    analyst = {"Authorization": "Bearer " + issuer.mint(sub="ann", groups=("g-analysts",), issuer=TEAM.oidc_issuer_url)}
    assert c.get("/api/v1/people", headers=viewer).status_code == 403
    body = c.get("/api/v1/people?q=person", headers=analyst).json()
    assert [person["email"] for person in body["items"]] == ["person00000@acme.test"]
    assert body["directory"]["status"] == "READY" and body["total"] == 1
    assert c.get("/api/v1/people?limit=0", headers=analyst).status_code == 422
