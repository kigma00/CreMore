"""On a team install the people directory is the sign-in IdP: what each issuer names, and what the wizard refuses."""

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import service, sign_in
from cremore.onboarding.store import ProviderConnectionStore

SOLO = Settings(FINGERPRINT_KEY="ab" * 32)
TENANT = "10000000-0000-4000-8000-000000000001"


def team(issuer):
    return Settings(FINGERPRINT_KEY="ab" * 32, AUTH_MODE="oidc", OIDC_ISSUER_URL=issuer, OIDC_AUDIENCE="cremore")


@pytest.mark.parametrize("issuer, provider, target", [
    ("https://acme.okta.com", "okta", {"organization": "acme.okta.com"}),
    ("https://acme.okta.com/oauth2/default", "okta", {"organization": "acme.okta.com"}),
    ("https://login.acme.example/oauth2/aus1a2b3c4d5e6f7g8h9", "okta", {"organization": "login.acme.example"}),
    (f"https://login.microsoftonline.com/{TENANT}/v2.0", "azure", {"tenant": TENANT}),
    (f"https://sts.windows.net/{TENANT.upper()}/", "azure", {"tenant": TENANT}),
    ("https://sso.acme.example/realms/staff", "keycloak",
     {"address": "https://sso.acme.example", "realm": "staff", "api_path": ""}),
    ("https://sso.acme.example:8443/auth/realms/staff/", "keycloak",
     {"address": "https://sso.acme.example:8443", "realm": "staff", "api_path": "/auth"}),
    ("https://accounts.google.com", "google_workspace", {}),
    # An Okta org authorization server on a custom domain looks like any IdP; so do others CreMore reads no people of.
    ("https://login.acme.example", None, None),
    ("https://acme.us.auth0.com/", None, None),
    (f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0", None, None),
    # Other products' issuers that look alike: WSO2, ForgeRock at the root and under /am.
    ("https://is.example.com/oauth2/token", None, None),
    ("https://am.example.com/oauth2/alpha", None, None),
    ("https://am.example.com/am/oauth2/realms/root/realms/alpha", None, None),
    # A Keycloak issuer as written in capitals, with the default port: the address as the collection keeps it.
    ("https://SSO.acme.example:443/realms/staff", "keycloak",
     {"address": "https://sso.acme.example", "realm": "staff", "api_path": ""}),
])
def test_each_sign_in_issuer_names_its_idp_and_target(issuer, provider, target):
    assert sign_in.idp(team(issuer)) == {"issuer": issuer.rstrip("/"), "provider": provider, "target": target,
                                         "exempt": ["github"]}


def test_a_single_operators_install_takes_any_people_directory():
    assert sign_in.idp(SOLO) is None
    assert sign_in.problem(SOLO, "keycloak", {"address": "https://sso.other", "realm": "x"}, ["identity"]) is None


def test_on_a_team_install_only_the_sign_in_idp_reads_people():
    okta = team("https://acme.okta.com/oauth2/default")
    assert sign_in.problem(okta, "okta", {"organization": "acme.okta.com"}, ["identity"]) is None
    assert sign_in.problem(okta, "okta", {"organization": "other.okta.com"}, ["identity"]) == "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP"
    for provider, target in (("keycloak", {"address": "https://sso.acme.example", "realm": "staff", "api_path": ""}),
                             ("google_workspace", {"domain": "acme.example"}), ("azure", {"tenant": TENANT}),
                             ("entra_id", {"tenant": TENANT})):
        assert sign_in.problem(okta, provider, target, ["identity"]) == "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", provider
    # What reads no people is not asked, and GitHub's identity link ties GitHub logins to the IdP's people.
    assert sign_in.problem(okta, "azure", {"tenant": TENANT}, ["inventory", "vault"]) is None
    assert sign_in.problem(okta, "github", {"org": "acme"}, ["identity"]) is None
    entra = team(f"https://login.microsoftonline.com/{TENANT}/v2.0")
    assert sign_in.problem(entra, "azure", {"tenant": TENANT}, ["inventory", "identity"]) is None
    assert sign_in.problem(entra, "entra_id", {"tenant": TENANT}, ["identity"]) is None  # the provider it replaced
    unknown = team("https://acme.us.auth0.com")
    assert sign_in.problem(unknown, "okta", {"organization": "acme.okta.com"}, ["identity"]) == \
        "PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN"
    assert sign_in.problem(unknown, "github", {"org": "acme"}, ["identity"]) is None


def refused(call, *args):
    with pytest.raises(service.OnboardingError) as raised:
        call(*args)
    return raised.value.code, raised.value.status


def test_the_wizard_refuses_another_directory_when_made_and_when_a_draft_starts_collecting():
    repo = InMemoryRepository()
    okta = team("https://acme.okta.com")
    keycloak = {"provider": "keycloak", "purposes": ["identity"], "auth_method": "oauth_client",
                "target": {"address": "https://sso.acme.example", "realm": "staff"},
                "credential": {"client_id": "cremore", "client_secret": "s" * 32}}
    assert refused(service.create, repo, okta, keycloak, "admin") == ("PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", 409)
    assert ProviderConnectionStore(repo).list() == []
    # A draft made while the install had no IdP sign-in meets the rule when it starts collecting people.
    draft = service.create(repo, SOLO, keycloak, "admin")
    store = ProviderConnectionStore(repo)
    store.update(draft["id"], store.get(draft["id"])["revision"], "worker", status="CHECKED")
    assert refused(service.activate, repo, okta, draft["id"], {"purposes": {"identity": {}}}, "admin") == (
        "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", 409)
    assert store.get(draft["id"])["status"] == "CHECKED" and store.get(draft["id"])["plans"] == {}
    made = service.create(repo, okta, {"provider": "okta", "purposes": ["identity"], "auth_method": "made_key",
                                       "target": {"organization": "https://ACME.okta.com/"},
                                       "credential": {"client_id": "0oa1serviceapp"}}, "admin")
    assert made["target"]["organization"] == "acme.okta.com"


def checked(repo, settings, body):
    from cremore.onboarding.fixtures_test import grant_access

    record = service.create(repo, settings, body, "admin")
    grant_access(repo, record["id"], {"identity": {}})
    return record


def test_a_directory_stopped_before_the_switch_is_not_turned_back_on_to_read_people():
    repo = InMemoryRepository()
    keycloak = {"provider": "keycloak", "purposes": ["identity"], "auth_method": "oauth_client",
                "target": {"address": "https://sso.acme.example", "realm": "staff"},
                "credential": {"client_id": "cremore", "client_secret": "s" * 32}}
    record = checked(repo, SOLO, keycloak)
    service.activate(repo, SOLO, record["id"], {"purposes": {"identity": {}}}, "admin")
    service.set_enabled(repo, record["id"], False, "admin")
    okta = team("https://acme.okta.com")
    assert refused(service.set_enabled, repo, record["id"], True, "admin", okta) == ("PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", 409)
    assert ProviderConnectionStore(repo).get(record["id"])["status"] == "DISABLED"
    assert service.set_enabled(repo, record["id"], True, "admin", SOLO)["status"] == "ACTIVE"


def test_google_sign_in_holds_people_to_the_workspace_already_connected():
    """Google's issuer names no domain: the Workspace people already sign in against is the one."""
    import json as _json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    key_file = _json.dumps({"type": "service_account", "private_key_id": "a" * 40, "private_key": pem,
                            "client_email": "cremore@acme-idp.iam.gserviceaccount.com", "client_id": "1" * 21})

    def workspace(domain):
        return {"provider": "google_workspace", "purposes": ["identity"], "auth_method": "service_account_delegation",
                "target": {"domain": domain}, "credential": {"username": f"admin@{domain}", "private_key": key_file}}

    repo = InMemoryRepository()
    google = team("https://accounts.google.com")
    service.create(repo, SOLO, workspace("acme.co"), "admin")  # a mistyped draft, never started, fixes nothing
    first = checked(repo, SOLO, workspace("acme.com"))  # made and started while one operator ran the install
    service.activate(repo, SOLO, first["id"], {"purposes": {"identity": {}}}, "admin")
    assert refused(service.create, repo, google, workspace("other.com"), "admin") == ("PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", 409)
    assert service.create(repo, google, workspace("acme.com"), "admin")["target"]["domain"] == "acme.com"
    assert sign_in.problem(google, "google_workspace", {"domain": "acme.com"}, ["identity"], repo=repo,
                           excluding=first["id"]) is None
    from cremore.onboarding.targets import target_id

    store = ProviderConnectionStore(repo)
    active = store.get(first["id"])
    target = {"domain": "acme.com"}
    versioned = {"version": 2, "roots": [{"id": target_id(target), "target": target, "purposes": ["identity"]}]}
    store.update(active["id"], active["revision"], "admin", target=versioned)
    assert sign_in.problem(google, "google_workspace", versioned, ["identity"], repo=repo) is None
    assert sign_in.problem(google, "google_workspace", {"domain": "other.com"}, ["identity"], repo=repo) == "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP"
    for record in ProviderConnectionStore(repo).list():  # with every one of them stopped, the next one starts afresh
        ProviderConnectionStore(repo).update(record["id"], record["revision"], "admin", status="DISABLED")
    assert service.create(repo, google, workspace("other.com"), "admin")["target"]["domain"] == "other.com"


def test_a_keycloak_address_is_kept_as_the_collection_keeps_it():
    repo = InMemoryRepository()
    signed_in = team("https://sso.acme.example/realms/staff")
    body = {"provider": "keycloak", "purposes": ["identity"], "auth_method": "oauth_client",
            "target": {"address": "https://SSO.Acme.example:443/", "realm": "staff"},
            "credential": {"client_id": "cremore", "client_secret": "s" * 32}}
    assert service.create(repo, signed_in, body, "admin")["target"]["address"] == "https://sso.acme.example"
    pathed = {**body, "target": {"address": "https://sso.acme.example/auth", "realm": "staff"}}
    assert refused(service.create, repo, SOLO, pathed, "admin") == ("KEYCLOAK_ADDRESS_INVALID", 422)
    other_realm = {**body, "target": {"address": "https://sso.acme.example", "realm": "Staff"}}  # realms are exact
    assert refused(service.create, repo, signed_in, other_realm, "admin") == ("PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", 409)
