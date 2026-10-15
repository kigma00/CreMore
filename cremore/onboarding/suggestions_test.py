"""Suggestions from the company IdP's app list: a Microsoft connection's stored Entra principals, synthetic only."""

import uuid

import pytest
from cremore_azure_provider.entra.normalization import entity_records

from cremore.coverage.metadata_models import (
    MetadataBatch,
    MetadataConnectionSpec,
    MetadataFinish,
    metadata_contract,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.onboarding.suggestions import suggestions

TENANTS = ("10000000-0000-0000-0000-000000000001", "10000000-0000-0000-0000-000000000002")


def principal(number, name, enabled=True):
    return {"id": f"20000000-0000-0000-0000-{number:012d}", "appId": f"30000000-0000-0000-0000-{number:012d}",
            "displayName": name, "accountEnabled": enabled, "passwordCredentials": [], "keyCredentials": []}


def seeded(tenants):
    """``tenants``: one list of (name, enabled) per tenant, each collected by its own Entra collection."""
    repo = InMemoryRepository()
    store = MetadataStore(repo)
    for tenant, names in zip(TENANTS, tenants, strict=False):
        spec = MetadataConnectionSpec.model_validate({
            "name": "Microsoft · apps", "provider": "azure_entra", "origin": "https://graph.microsoft.com", "tenant": tenant,
            "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": tenant}], "capabilities": ["inventory"],
            "auth_type": "workload_identity"})
        owner, _ = store.create(spec, "test")
        run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(spec).model_dump())
        items = [record for number, (name, enabled) in enumerate(names, 1)
                 for record in entity_records(spec, "service_principals", principal(number, name, enabled))[0]]
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items))
        store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status="COMPLETE"))
    return repo


def test_apps_the_idp_lists_suggest_the_services_not_connected_yet():
    repo = seeded([[("GitHub Enterprise Cloud - Organization", True), ("Slack", True), ("Atlassian Cloud", True),
                    ("Jira Service Management", True), ("AWS IAM Identity Center (successor to AWS Single Sign-On)", True),
                    ("Azure Key Vault", True), ("Microsoft Graph", True), ("Contoso HR", True)],
                   [("GitHub Enterprise Cloud - Organization", True), ("github_actions_deployer", True)]])
    found = {item["provider"]: item for item in suggestions(repo, [])}
    # Two tenants' collections name GitHub three times, twice alike: two names. A custom name counts too.
    assert found["github"] == {"provider": "github", "apps": ["GitHub Enterprise Cloud - Organization",
                                                             "github_actions_deployer"], "count": 2}
    # A service with a connection in any state -- collecting, being set up, stopped -- is not suggested again.
    # Microsoft's own apps and Azure Key Vault name no service CreMore connects.
    connections = [{"provider": "slack", "status": "ACTIVE"}, {"provider": "github", "status": "CHECKED"}]
    found = {item["provider"]: item for item in suggestions(repo, connections)}
    assert set(found) == {"atlassian", "aws"}
    assert found["atlassian"]["apps"] == ["Atlassian Cloud", "Jira Service Management"]
    assert found["aws"]["count"] == 1


def test_names_that_carry_the_word_but_not_the_service_suggest_nothing():
    repo = seeded([[("JIRA SAML SSO by Microsoft", True), ("Google Cloud / G Suite Connector by Microsoft", True),
                    ("HashiCorp Cloud Platform (HCP)", True), ("Amazon Business", True), ("Notion", False),
                    ("MyGitHubMirror", True), ("HashiCorp Vault", True), ("OpenBao secrets", True), ("GCP billing export", True)]])
    found = {item["provider"]: item["apps"] for item in suggestions(repo, [])}
    # The Jira Server plugin, the Workspace sign-in app, HCP and Amazon Business are not those services; Notion is
    # turned off in the tenant; a word inside another word is not the word.
    assert found == {"vault": ["HashiCorp Vault"], "openbao": ["OpenBao secrets"], "gcp": ["GCP billing export"]}


def idp_apps(repo, provider, body, apps):
    """An Okta or Keycloak app-list collection (cremore.identity.idp) that stored ``apps``: (id, label, key, state)."""
    import importlib

    from cremore.identity.idp import App, Collector

    spec = MetadataConnectionSpec.model_validate({"provider": provider, "tenant_confirmed": True,
                                                  "capabilities": ["identity_status"], "options": {"sources": ["apps"]},
                                                  **body})
    collector = Collector(importlib.import_module(f"cremore_{provider}_provider.identity"))
    source = {"okta": "apps", "keycloak": "clients"}[provider]
    items = [collector.app_record(spec, spec.scopes[0], source, App(id=ident, raw_state=state, state=state, name=label,
                                                                     key=key), "2026-10-02T00:00:00+00:00")
             for ident, label, key, state in apps]
    store = MetadataStore(repo)
    owner, _ = store.create(spec, "test")
    run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(spec).model_dump())
    # As the worker stores an identity collection's records: no machine may submit them.
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items), trusted_discovery=True)
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items), status="COMPLETE"))
    return owner


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def test_okta_and_keycloak_app_lists_suggest_too(repo):
    okta = idp_apps(repo, "okta", {"name": "Okta · apps", "origin": "https://acme.okta.com", "edition": "cloud",
                            "tenant": "acme.okta.com", "scopes": [{"kind": "organization", "id": "acme.okta.com"}],
                            "auth_type": "private_key_jwt",
                            "secret_refs": {"client_id": "vault://okta/id", "private_key": "vault://okta/key"}},
             [("0oaslack00001", "Slack", "slack", "ACTIVE"), ("0oaaws000001", "Prod console", "amazon_aws", "ACTIVE"),
              ("0oanotion0001", "Notion", "notion", "DISABLED")])
    idp_apps(repo, "keycloak", {"name": "Keycloak · apps", "origin": "https://sso.acme.test", "edition": "self_managed",
                                "tenant": "corp", "scopes": [{"kind": "realm", "id": "corp"}], "auth_type": "oauth_client",
                                "secret_refs": {"client_id": "vault://kc/id", "client_secret": "vault://kc/secret"}},
             [("66666666-6666-4666-8666-666666666666", "urn:amazon:webservices", "urn:amazon:webservices", "ACTIVE"),
              ("77777777-7777-4777-8777-777777777777", "Wiki", "https://acme.atlassian.net", "ACTIVE")])
    found = {item["provider"]: item["apps"] for item in suggestions(repo, [])}
    # A label of the company's own is matched by the catalog name or client ID it was made from (amazon_aws, the AWS
    # SAML audience, the Atlassian site); an app the IdP turned off suggests nothing.
    assert found == {"slack": ["Slack"], "aws": ["Prod console", "urn:amazon:webservices"], "atlassian": ["Wiki"]}
    # An app list switched off (its option turned off in the plan) suggests nothing more; the other IdP's still does.
    MetadataStore(repo).change(okta["id"], okta["revision"], "test", enabled=False)
    found = {item["provider"]: item["apps"] for item in suggestions(repo, [])}
    assert found == {"aws": ["urn:amazon:webservices"], "atlassian": ["Wiki"]}


def test_nothing_is_suggested_without_an_idp_inventory():
    assert suggestions(InMemoryRepository(), []) == []
