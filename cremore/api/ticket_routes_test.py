"""The owner's approval asked in the company's ticket system, through the API, with a plugin adapter (a synthetic
one, cremore.ticketing.ticketing_test): an Admin sets it up (its secrets never come back) and checks it; a remediator
asks the owner in a ticket, audited before it opens; with company sign-in the owner cannot be one of the people on the
security side of the plan, told apart by address."""

import json

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.app_test import auth, client
from cremore.api.conftest import oidc_settings
from cremore.api.contact_routes_test import bearer
from cremore.api.owner_approval_routes_test import add_plan, events
from cremore.db.repository import InMemoryRepository
from cremore.ticketing import sweep as ticket_sweep
from cremore.ticketing.contract import TicketError
from cremore.ticketing.ticketing_test import SETUP, TOKEN, Tickets
from cremore.ticketing.ticketing_test import (
    plugin as plugin,  # noqa: PLC0414 -- the installed fake adapter
)


def signed_in(issuer, sub, group, email=None, **claims):
    extra = {"email": email, **claims} if email else None
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,), extra=extra)}


def setup(issuer, server=None):
    repo = InMemoryRepository()
    plan = add_plan(repo)  # requested by "rita", approved by "ada"
    app = create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer)
    server = server or Tickets()
    app.state.ticket_http_client_factory = server.client
    c = TestClient(app)
    admin = signed_in(issuer, "ada", "g-admins", "ada@example.com")
    assert c.put("/api/v1/settings/ticket-system", headers=admin, json=SETUP).status_code == 200
    return repo, c, plan, server


def test_an_admin_sets_up_a_plugin_system_and_never_sees_its_secrets_again(issuer):
    repo, c, _plan, server = setup(issuer)
    admin, analyst = signed_in(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    assert c.get("/api/v1/settings/ticket-system", headers=analyst).status_code == 403
    assert c.put("/api/v1/settings/ticket-system", headers=analyst, json=SETUP).status_code == 403
    shown = c.get("/api/v1/settings/ticket-system", headers=admin)
    assert shown.headers["cache-control"] == "no-store"
    assert TOKEN not in shown.text and shown.json()["current"]["secrets_saved"] == ["token"]
    assert c.get("/api/v1/ticket-system", headers=analyst).json() == {"system": "fake", "label": "Fake tickets"}
    assert c.get("/api/v1/ticket-system", headers=bearer(issuer, "vic", "g-viewers")).status_code == 403
    checked = c.post("/api/v1/settings/ticket-system/check", headers=admin)
    assert checked.json() == {"ok": True, "code": None}
    server.fail["check"] = TicketError("FAKE_LOGIN_REFUSED")
    assert c.post("/api/v1/settings/ticket-system/check", headers=admin).json() == {"ok": False, "code": "FAKE_LOGIN_REFUSED"}
    audit = [(row["action"], row["note"]) for row in c.get("/api/v1/audit", headers=admin).json()
             if row["action"].startswith("TICKET_SYSTEM")]
    assert audit[::-1][1:] == [("TICKET_SYSTEM_CHECKED", "ok"), ("TICKET_SYSTEM_CHECKED", "failed=FAKE_LOGIN_REFUSED")]
    assert audit[-1][0] == "TICKET_SYSTEM_SAVED"  # newest first
    assert TOKEN not in json.dumps(audit)
    bad = c.put("/api/v1/settings/ticket-system", headers=admin, json={**SETUP, "values": {**SETUP["values"], "url": "nope"}})
    assert (bad.status_code, bad.json()["detail"]) == (422, "FAKE_URL_INVALID")
    kept = c.get("/api/v1/settings/ticket-system", headers=admin).json()["current"]
    assert kept["values"]["url"] == "https://tickets.acme.test" and repo.get_setting("ticket_system")


def test_a_remediator_asks_the_owner_in_a_ticket_and_the_worker_records_the_answer(issuer):
    repo, c, plan, server = setup(issuer)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval/ticket"
    rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com")
    assert c.post(path, headers=bearer(issuer, "ann", "g-analysts"), json={"to": "kim@example.com"}).status_code == 403
    # Every person on the security side must have signed in with an address before the owner is asked by address.
    unknown = c.post(path, headers=signed_in(issuer, "rob", "g-remediators", "rob@example.com"), json={"to": "kim@example.com"})
    assert (unknown.status_code, unknown.json()["detail"]) == (409, "OWNER_APPROVAL_ACTOR_EMAIL_UNKNOWN")
    c.get("/api/v1/ticket-system", headers=rita)  # rita requested the plan; ada approved it and set the system up
    for owner in ("rita@example.com", "ADA@example.com"):
        same = c.post(path, headers=rita, json={"to": owner})
        assert (same.status_code, same.json()["detail"]) == (403, "OWNER_APPROVAL_SAME_PERSON")
    assert not server.tickets and not events(repo, plan)
    bad = c.post(path, headers=rita, json={"to": "not an address"})
    assert (bad.status_code, bad.json()["detail"]) == (422, "OWNER_APPROVAL_RECIPIENT_INVALID")

    asked = c.post(path, headers=rita, json={"to": "Kim@Example.com", "locale": "en"})
    assert asked.status_code == 200, asked.text
    shown = asked.json()["owner_approval"]
    assert (shown["state"], shown["channel"], shown["recipient"]) == ("PENDING", "fake", "Kim@example.com")
    assert shown["ticket"]["ticket"] == "100" and shown["ticket"]["url"] == "https://tickets.acme.test/ticket/100"
    [ticket] = server.tickets.values()
    assert ticket.title.startswith("[CreMore] Approval asked for an AWS access key action")
    assert [kind for kind, _actor, _note in events(repo, plan)] == ["OWNER_APPROVAL_REQUESTED", "OWNER_APPROVAL_TICKET_OPENED"]
    server.answer("APPROVED", 42)
    assert ticket_sweep.sweep(repo, c.app.state.settings, server.client) == 1
    listed = c.get("/api/v1/action-plans", headers=rita).json()["items"][0]["owner_approval"]
    assert (listed["state"], listed["decided_by"], listed["evidence"]) == (
        "APPROVED", "fake:user:42", "fake ticket #100 approval #500")
    again = c.post(path, headers=rita, json={"to": "kim@example.com"})
    assert (again.status_code, again.json()["detail"]) == (409, "OWNER_APPROVAL_ALREADY_GRANTED")


def test_a_ticket_that_did_not_open_ends_its_request_and_says_why(issuer):
    repo, c, plan, server = setup(issuer, Tickets(users={}))
    rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com")
    c.get("/api/v1/ticket-system", headers=rita)
    missing = c.post(f"/api/v1/action-plans/{plan.id}/owner-approval/ticket", headers=rita, json={"to": "kim@example.com"})
    assert (missing.status_code, missing.json()["detail"]) == (409, "FAKE_USER_NOT_FOUND")
    assert not events(repo, plan) and not server.tickets  # found missing before anything was asked or recorded
    server.users = {"kim@example.com": ("42", ("kim@example.com",))}
    server.fail["approval"] = TicketError("FAKE_WRITE_REFUSED")
    half = c.post(f"/api/v1/action-plans/{plan.id}/owner-approval/ticket", headers=rita, json={"to": "kim@example.com"})
    assert (half.status_code, half.json()["detail"]) == (409, "FAKE_WRITE_REFUSED")
    assert [kind for kind, _actor, _note in events(repo, plan)] == ["OWNER_APPROVAL_REQUESTED", "OWNER_APPROVAL_NOT_SENT"]
    assert events(repo, plan)[-1][2] == "fake · FAKE_WRITE_REFUSED · ticket=100"  # a person closes it in the system
    assert c.get("/api/v1/action-plans", headers=rita).json()["items"][0]["owner_approval"]["state"] == "NOT_SENT"


def test_the_owner_is_told_apart_by_every_address_of_the_account_asked(issuer):
    # Kim's account also carries rita's address (an alias, a second address): it could be rita answering.
    repo, c, plan, server = setup(issuer, Tickets(users={"kim@example.com": ("42", ("kim@example.com", "rita@example.com"))}))
    rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com")
    path = f"/api/v1/action-plans/{plan.id}/owner-approval/ticket"
    same = c.post(path, headers=rita, json={"to": "kim@example.com"})
    assert (same.status_code, same.json()["detail"]) == (403, "OWNER_APPROVAL_SAME_PERSON")
    own = c.post(path, headers=rita, json={"to": "RITA@example.com"})  # refused before the system is asked
    assert (own.status_code, own.json()["detail"]) == (403, "OWNER_APPROVAL_SAME_PERSON")
    assert not server.tickets and not events(repo, plan)  # nothing asked, no request started
    # Each refusal is audited: an attempt to answer as one's own owner stays in view.
    refusals = [event.note for event in repo.finding_events.values() if event.event_type == "ACTION_PLAN_REFUSED"]
    assert refusals == [f"OWNER_TICKET OWNER_APPROVAL_SAME_PERSON to=kim@example.com plan_hash={plan.plan_hash}",
                        f"OWNER_TICKET OWNER_APPROVAL_SAME_PERSON to=RITA@example.com plan_hash={plan.plan_hash}"]


def test_an_unverified_address_is_no_address_and_an_adapters_own_text_never_leaves(issuer, monkeypatch):
    from cremore.ticketing import setup as ticket_setup

    repo, c, plan, _server = setup(issuer)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval/ticket"
    for flag in ("false", "0", False):  # rita's sign-in says its address is not verified: she has none
        rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com", email_verified=flag)
        refused = c.post(path, headers=rita, json={"to": "kim@example.com"})
        assert (refused.status_code, refused.json()["detail"]) == (409, "OWNER_APPROVAL_ACTOR_EMAIL_UNKNOWN")
    rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com")
    c.get("/api/v1/ticket-system", headers=rita)

    class Leaky:
        def find_approver(self, address):
            raise TicketError("upstream said: password=hunter2 <b>x</b>")

        def check(self):
            raise TicketError("upstream said: password=hunter2")

        def close(self):
            pass

    monkeypatch.setattr(ticket_setup, "open_system", lambda *args: ticket_setup.Ready(Leaky(), "fake", "b"))
    leaked = c.post(path, headers=rita, json={"to": "kim@example.com"})
    assert (leaked.status_code, leaked.json()["detail"]) == (409, "TICKET_SYSTEM_ERROR")
    checked = c.post("/api/v1/settings/ticket-system/check", headers=signed_in(issuer, "ada", "g-admins", "ada@example.com"))
    assert "hunter2" not in checked.text + json.dumps([event.note for event in repo.finding_events.values()])


def test_each_person_asks_a_bounded_number_of_owners_an_hour(issuer, monkeypatch):
    from cremore.governance import contact

    monkeypatch.setattr(contact, "HOURLY_RECIPIENTS", 1)
    _repo, c, plan, server = setup(issuer)
    rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com")
    c.get("/api/v1/ticket-system", headers=rita)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval/ticket"
    assert c.post(path, headers=rita, json={"to": "kim@example.com"}).status_code == 200
    again = c.post(path, headers=rita, json={"to": "kim@example.com"})
    assert (again.status_code, again.json()["detail"]) == (429, "CONTACT_RATE_LIMITED") and len(server.tickets) == 1


def test_the_local_operator_asks_in_a_ticket_too_and_nothing_is_asked_without_a_setup():
    repo = InMemoryRepository()
    plan = add_plan(repo)
    c = client(repo)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval/ticket"
    unset = c.post(path, headers=auth(), json={"to": "kim@example.com"})
    assert (unset.status_code, unset.json()["detail"]) == (409, "TICKET_SYSTEM_NOT_SET_UP")
    server = Tickets()
    c.app.state.ticket_http_client_factory = server.client
    assert c.put("/api/v1/settings/ticket-system", headers=auth(), json=SETUP).status_code == 200
    asked = c.post(path, headers=auth(), json={"to": "kim@example.com"})
    assert asked.status_code == 200 and asked.json()["owner_approval"]["state"] == "PENDING"


def test_nobody_is_asked_twice_at_once_and_an_unknown_system_asks_nobody(issuer):
    repo, c, plan, _server = setup(issuer)
    rita = signed_in(issuer, "rita", "g-remediators", "rita@example.com")
    c.get("/api/v1/ticket-system", headers=rita)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval/ticket"
    assert c.post(path, headers=rita, json={"to": "kim@example.com"}).status_code == 200
    assert c.post(path, headers=rita, json={"to": "kim@example.com"}).status_code == 200  # a new ticket replaces it
    rows = repo.list_settings("owner_approval_plan:")
    assert [row["value"]["ticket"]["ticket"] for row in rows] == ["101"]
    for system in ("servicenow", "glpi"):  # an adapter not installed, or the removed built-in one
        repo.put_setting("ticket_system", {"system": system, "values": {}}, "ada")
        assert c.get("/api/v1/ticket-system", headers=rita).json() == {"system": None, "label": None}
    asked = c.post(path, headers=rita, json={"to": "kim@example.com"})
    assert (asked.status_code, asked.json()["detail"]) == (409, "TICKET_SYSTEM_UNAVAILABLE")
