"""The company's domains over the API: analysts read which are verified, admins manage them (N4a)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.db.repository import InMemoryRepository
from cremore.domains_test import DNS


def signed_in(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def test_admins_manage_domains_and_analysts_read_which_are_verified(issuer):
    repo = InMemoryRepository()
    app = create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer)
    app.state.domain_dns_query = dns = DNS()
    c = TestClient(app)
    admin, analyst = signed_in(issuer, "ada", "g-admins"), signed_in(issuer, "ann", "g-analysts")
    viewer = signed_in(issuer, "vic", "g-viewers")
    assert c.post("/api/v1/settings/domains", headers=analyst, json={"name": "acme.com"}).status_code == 403
    added = c.post("/api/v1/settings/domains", headers=admin, json={"name": "Acme.com"})
    assert added.status_code == 200 and added.json()["record"]["name"] == "_cremore-challenge.acme.com"
    again = c.post("/api/v1/settings/domains", headers=admin, json={"name": "acme.com"})
    assert (again.status_code, again.json()["detail"]) == (409, "DOMAIN_EXISTS")
    address = c.post("/api/v1/settings/domains", headers=admin, json={"name": "10.0.0.1"})
    assert (address.status_code, address.json()["detail"]) == (422, "DOMAIN_INVALID")
    missing = c.post("/api/v1/settings/domains/acme.com/verify", headers=admin)
    assert (missing.json()["status"], missing.json()["result"]) == ("PENDING", "TXT_NOT_FOUND")
    dns.publish(added.json())
    assert c.post("/api/v1/settings/domains/acme.com/verify", headers=analyst).status_code == 403
    verified = c.post("/api/v1/settings/domains/acme.com/verify", headers=admin)
    assert verified.status_code == 200 and verified.json()["status"] == "VERIFIED"
    shown = c.get("/api/v1/settings/domains", headers=admin)
    assert shown.headers["cache-control"] == "no-store" and shown.json()["domains"][0]["record"]["type"] == "TXT"
    assert c.get("/api/v1/settings/domains", headers=analyst).status_code == 403
    # Analysts read which domains are verified, never the record; viewers read nothing.
    [listed] = c.get("/api/v1/domains", headers=analyst).json()["domains"]
    assert listed["name"] == "acme.com" and listed["status"] == "VERIFIED" and "record" not in listed
    assert c.get("/api/v1/domains", headers=viewer).status_code == 403
    internal = c.put("/api/v1/settings/domains/acme.com/internal", headers=admin, json={"allow_internal": True})
    assert internal.status_code == 200 and internal.json()["allow_internal"] is True
    wrong = c.put("/api/v1/settings/domains/acme.com/internal", headers=admin, json={"allow_internal": "on"})
    assert (wrong.status_code, wrong.json()["detail"]) == (422, "ALLOW_INTERNAL_INVALID")
    renewed = c.post("/api/v1/settings/domains/acme.com/challenge", headers=admin)
    assert renewed.json()["status"] == "PENDING"
    assert renewed.json()["record"]["value"] != added.json()["record"]["value"]
    assert c.delete("/api/v1/settings/domains/acme.com", headers=admin).status_code == 204
    gone = c.delete("/api/v1/settings/domains/acme.com", headers=admin)
    assert (gone.status_code, gone.json()["detail"]) == (404, "DOMAIN_NOT_FOUND")
    trail = [event.event_type for event in reversed(repo.list_events(50)) if event.target_type == "domain"]
    assert trail == ["DOMAIN_ADDED", "DOMAIN_VERIFICATION_FAILED", "DOMAIN_VERIFIED", "DOMAIN_INTERNAL_CHANGED",
                     "DOMAIN_CHALLENGE_RENEWED", "DOMAIN_REMOVED"]
    assert {event.actor for event in repo.list_events(50) if event.target_type == "domain"} == {"ada"}
