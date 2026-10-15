"""The service app key CreMore makes for Okta, against a synthetic org: only its public JWK is shown, and the
sealed private JWK signs client assertions Okta verifies with that public key and ``kid``."""

import base64
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import jwt
import pytest

from cremore.onboarding import catalog
from cremore_okta_provider import onboarding

ORIGIN = "https://acme.okta.com"
CLIENT = "0oa1serviceapp"


def test_the_key_is_made_in_cremore_and_only_its_public_half_is_shown():
    envelopes, made = onboarding.generate("okta", "made_key", {"client_id": f" {CLIENT} "}, {"organization": "acme.okta.com"})
    public, private = made["public_jwk"], json.loads(envelopes["credential"]["private_key"])
    assert envelopes["credential"]["client_id"] == CLIENT
    assert set(public) == {"kty", "e", "n", "kid", "alg", "use"} and public["use"] == "sig" and public["alg"] == "RS256"
    assert "d" in private and private["kid"] == public["kid"] == made["kid"]
    assert set(made) == {"public_jwk", "kid", "created_at"} and not {"d", "p", "q", "dp", "dq", "qi"} & set(public)
    # The kid is the key's RFC 7638 thumbprint: the same key always has the same kid.
    canonical = json.dumps({"e": public["e"], "kty": "RSA", "n": public["n"]}, separators=(",", ":"), sort_keys=True)
    assert made["kid"] == base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
    second = onboarding.generate("okta", "made_key", {"client_id": CLIENT}, {})[1]
    assert second["kid"] != made["kid"]
    with pytest.raises(ValueError, match="OKTA_CLIENT_ID_INVALID"):
        onboarding.generate("okta", "made_key", {"client_id": "bad id"}, {})


def test_okta_verifies_the_made_key_with_the_pasted_public_jwk():
    envelopes, made = onboarding.generate("okta", "made_key", {"client_id": CLIENT}, {})
    public = jwt.PyJWK(made["public_jwk"]).key
    seen = []

    def org(request):
        seen.append(request)
        if request.url.path == "/oauth2/v1/token":
            assertion = parse_qs(request.content.decode())["client_assertion"][0]
            assert jwt.get_unverified_header(assertion)["kid"] == made["kid"]
            claims = jwt.decode(assertion, public, algorithms=["RS256"], audience=ORIGIN + "/oauth2/v1/token")
            assert claims["iss"] == claims["sub"] == CLIENT
            return httpx.Response(200, json={"access_token": "t0k3n.plain", "token_type": "Bearer", "expires_in": 3600})
        assert request.url.path in ("/api/v1/users", "/api/v1/apps")
        return httpx.Response(200, json=[])

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(org)), memo={})
    connection = {"provider": "okta", "edition": "cloud", "auth_method": "made_key", "purposes": ["identity"],
                  "target": {"organization": "acme.okta.com", "auth": {"client_id": CLIENT}, "generated": made}}
    items = onboarding.check(connection, "identity", {"credential": dict(envelopes["credential"])}, context)
    assert items == [{"permission": "users_read", "status": "GRANTED"}, {"permission": "apps_read", "status": "GRANTED"}]
    assert [request.url.path for request in seen] == ["/oauth2/v1/token", "/api/v1/users", "/oauth2/v1/token",
                                                      "/api/v1/apps"]


def test_the_made_key_comes_first_and_takes_no_secret():
    methods = catalog.descriptor("okta")["auth_methods"]
    assert [method["id"] for method in methods] == ["made_key", "private_key_jwt"]
    made = methods[0]
    assert made["generated"] and made["reference"] is False
    assert [(field["name"], field.get("public")) for field in made["fields"]] == [("client_id", True)]
    # The records it makes are the same private_key_jwt collection, the made key in the same slots.
    child = onboarding.children({"target": {"organization": "acme.okta.com"}, "edition": "cloud"}, "identity", {})[0]
    assert child["spec"]["auth_type"] == "private_key_jwt"
    assert child["secret_slots"] == {"client_id": "credential", "private_key": "credential"}


def test_people_default_to_five_minutes_and_app_lists_keep_the_daily_limit():
    connection = {"target": {"organization": "acme.okta.com"}, "edition": "cloud"}
    [schedule] = [field for field in catalog.descriptor("okta")["purposes"]["identity"]["plan"]
                  if field["name"] == "schedule_minutes"]
    assert schedule["default"] == onboarding.spec(connection)["schedule_minutes"] == 5
    for plan, expected in (({"apps": True}, (5, 1440)), ({"apps": True, "schedule_minutes": 0}, (0, 0)),
                           ({"apps": True, "schedule_minutes": 60}, (60, 1440)),
                           ({"apps": True, "schedule_minutes": 10080}, (10080, 10080))):
        children = onboarding.children(connection, "identity", plan)
        assert tuple(child["spec"]["schedule_minutes"] for child in children) == expected


def test_cadence_change_updates_owned_collections_without_new_permission_check():
    from cremore.coverage.store import CoverageStore
    from cremore.db.repository import InMemoryRepository
    from cremore.onboarding import service
    from cremore.onboarding.onboarding_test import SETTINGS, activate, checked
    from cremore.onboarding.store import ProviderConnectionStore

    repo = InMemoryRepository()
    record = checked(repo, {"provider": "okta", "purposes": ["identity"], "auth_method": "made_key",
        "target": {"organization": "acme.okta.com"}, "credential": {"client_id": CLIENT}})
    activate(repo, record, {"identity": {"apps": True}})
    parents = ProviderConnectionStore(repo)
    parent = service.get(repo, record["id"])
    parent = parents.update(parent["id"], parent["revision"], "worker", checks={})
    previous = parent["revision"]
    plan = {**parent["plans"]["identity"], "schedule_minutes": 15}
    updated = service.update_plan(repo, SETTINGS, parent["id"], "identity",
                                  {"expected_revision": previous, "plan": plan}, "admin")
    assert updated["plans"]["identity"] == plan
    assert sorted(row["spec"]["schedule_minutes"] for row in CoverageStore(repo).list_connections()) == [15, 1440]
    with pytest.raises(service.OnboardingError, match="PROVIDER_CONNECTION_CHANGED"):
        service.update_plan(repo, SETTINGS, parent["id"], "identity",
                            {"expected_revision": previous, "plan": {**plan, "schedule_minutes": 0}}, "admin")
    service.update_plan(repo, SETTINGS, parent["id"], "identity",
                        {"expected_revision": updated["revision"], "plan": {**plan, "schedule_minutes": 0}}, "admin")
    assert {row["spec"]["schedule_minutes"] for row in CoverageStore(repo).list_connections()} == {0}


def test_a_key_made_again_names_the_earlier_one_to_remove_at_okta():
    from cremore.db.repository import InMemoryRepository
    from cremore.onboarding import service
    from cremore.onboarding.onboarding_test import SETTINGS

    repo = InMemoryRepository()
    body = {"provider": "okta", "purposes": ["identity"], "auth_method": "made_key",
            "target": {"organization": "acme.okta.com"}, "credential": {"client_id": CLIENT}}
    first = service.create(repo, SETTINGS, body, "admin")
    kid = first["target"]["generated"]["kid"]
    assert "previous" not in first["target"]["generated"]
    again = service.set_credential(repo, SETTINGS, first["id"], {"credential": {"client_id": CLIENT},
                                                                 "expected_revision": first["revision"]}, "admin")
    made = again["target"]["generated"]
    # Okta keeps the earlier key valid until an admin deactivates and deletes it: the wizard names it.
    assert made["kid"] != kid and made["previous"] == {"kid": kid}
    notes = [event.note for event in repo.finding_events.values()
             if event.event_type == "PROVIDER_CONNECTION_CREDENTIAL_CHANGED"]
    assert notes == [f"made_key {kid}->{made['kid']}"]
    assert not {"d", "p", "q", "dp", "dq", "qi"} & set(made["public_jwk"])


@pytest.mark.parametrize("issuer, organization", [
    ("https://acme.okta.com", "acme.okta.com"), ("https://acme.okta-emea.com", "acme.okta-emea.com"),
    ("https://acme.okta-gov.com", "acme.okta-gov.com"), ("https://acme.oktapreview.com", "acme.oktapreview.com"),
    ("https://acme.okta.mil", "acme.okta.mil"),  # the US military cell (login.okta.com) is no .com
    ("https://acme.okta-mil.com", None),  # a domain Okta does not use
])
def test_the_sign_in_org_is_an_okta_domain(issuer, organization):
    expected = {"organization": organization} if organization else None
    assert onboarding.sign_in_target("okta", issuer) == expected
