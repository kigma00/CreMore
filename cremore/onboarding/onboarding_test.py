"""The provider connection wizard end to end with synthetic providers (design 4.4, section 7).

Every provider registers through the same four steps; one credential serves every purpose;
checks store only statuses and codes; a credential change and a disable reach every record.
"""

import base64
import json
import os
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.config import Settings
from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable PostgreSQL
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.onboarding import catalog, check, service
from cremore.onboarding.fixtures_test import activate_with_access, grant_access, legacy_auth_method
from cremore.onboarding.store import ProviderConnectionConflict, ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)
ORG = "acme"


def app_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


PEM = app_key()


def github_app(**extra):
    return {"provider": "github", "edition": "cloud", "purposes": ["exposure", "inventory", "vault"],
            "auth_method": "github_app", "target": {"organization": ORG},
            "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}, **extra}


def github_server(permissions, account=ORG, asked=None, installation=678):
    """GitHub answering an App: the installation names what it holds, a token holds what it was asked for."""
    def handler(request):
        if request.url.path == f"/app/installations/{installation}/access_tokens":
            wanted = json.loads(request.content or b"{}").get("permissions") or permissions
            if asked is not None:
                asked.append(wanted)
            return httpx.Response(201, json={"token": "ghs_" + "x" * 36, "expires_at": "2099-01-01T00:00:00Z",
                                             "permissions": wanted})
        if request.url.path == f"/app/installations/{installation}":
            return httpx.Response(200, json={"id": installation, "app_id": 12345, "account": {"login": account},
                                             "permissions": permissions})
        return httpx.Response(404)

    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def worker(repo, http_client=None, **extra):
    return SimpleNamespace(**{"repo": repo, "settings": SETTINGS, "http_client_factory": http_client,
                              "metadata_secret_resolver": SecretResolver(sealing_key=SETTINGS.sealing_keys),
                              "aws_role_checker": None, "aws_sessions": None, **extra})


def run_check(repo, record, http_client):
    job = repo.get_job(uuid.UUID(service.view(repo, service.get(repo, record["id"]))["checks"]["job_id"]))
    check.run(worker(repo, http_client), job)
    return service.view(repo, service.get(repo, record["id"]))


def test_every_provider_has_a_valid_four_step_descriptor():
    providers = catalog.providers()
    assert set(providers) == {"github", "gitlab", "confluence", "bitbucket", "atlassian", "notion", "slack", "aws",
                              "gcp", "azure", "azure_devops", "entra_id", "vault", "openbao", "external_vault", "okta",
                              "keycloak", "google_workspace", "website"}
    for provider, descriptor in providers.items():
        for purpose in descriptor["purposes"]:
            # A purpose always has a recommended method: the first that serves it.
            assert catalog.methods_for(provider, [purpose]), (provider, purpose)
    assert [m["id"] for m in catalog.methods_for("bitbucket", ["exposure"], "data_center")] == ["http_token"]
    assert [m["id"] for m in catalog.methods_for("github", ["exposure", "identity"])] == ["github_app", "token"]
    # GitHub shows an App an organization's SAML identities only: not GHE.com's managed users, not a Server's SAML.
    for edition, methods in (("enterprise_cloud", ["github_app", "token"]), ("dedicated", ["token"]),
                             ("enterprise_server", ["token"])):
        assert [m["id"] for m in catalog.methods_for("github", ["identity"], edition)] == methods, edition
    assert [m["id"] for m in catalog.methods_for("github", ["exposure"], "dedicated")] == ["github_app", "token"]
    with pytest.raises(catalog.CatalogError):
        catalog.validate({**providers["github"], "auth_methods": [{**providers["github"]["auth_methods"][0],
                                                                   "purposes": ["exposure", "billing"]}]})
    app, *others = providers["github"]["auth_methods"]
    for narrowed in ({"billing": ["cloud"]}, {"identity": []}, {"identity": ["mainframe"]}, ["identity"]):
        with pytest.raises(catalog.CatalogError, match="purpose_editions"):
            catalog.validate({**providers["github"], "auth_methods": [{**app, "purpose_editions": narrowed}, *others]})


def test_steps_one_and_two_seal_one_credential_and_never_show_it():
    repo = InMemoryRepository()
    view = service.create(repo, SETTINGS, github_app(), "admin")
    record = ProviderConnectionStore(repo).get(view["id"])
    assert view["status"] == "DRAFT" and view["credential"] == {"roles": ["credential"], "reference": False, "shared_with": []}
    assert record["secret_refs"]["credential"].startswith("sealed:")
    assert "BEGIN PRIVATE KEY" not in json.dumps(view) and "sealed:" not in json.dumps(view)
    opened = SecretResolver(sealing_key=SETTINGS.sealing_keys).resolve(record["secret_refs"]["credential"])
    assert opened["GITHUB_APP_ID"] == "12345" and base64.b64decode(opened["GITHUB_APP_PRIVATE_KEY_BASE64"]).decode() == PEM.strip()


@pytest.mark.parametrize("change, code", [
    ({"provider": "billing"}, "PROVIDER_UNKNOWN"),
    ({"purposes": ["inventory"], "auth_method": "token", "credential": {"token": "ghp_" + "t" * 36}},
     "AUTH_METHOD_NOT_FOR_PURPOSES"),
    ({"purposes": []}, "PURPOSES_INVALID"),
    ({"target": {"organization": "acme/../x"}}, "FIELD_INVALID:organization"),
    ({"target": {"organization": ORG, "host": "https://ghes.example.com"}}, "TARGET_FIELD_UNKNOWN:host"),
    ({"credential": {"app_id": "12345", "installation_id": "678"}}, "CREDENTIAL_FIELD_REQUIRED:private_key"),
    ({"credential": {"app_id": "12345", "installation_id": "678", "private_key": "not a key"}},
     "GITHUB_APP_PRIVATE_KEY_INVALID"),
    ({"credential": {"vault_ref": "vault://ok/../escape"}}, "CREDENTIAL_REFERENCE_INVALID"),
])
def test_what_step_two_refuses(change, code):
    with pytest.raises(service.OnboardingError) as raised:
        service.create(InMemoryRepository(), SETTINGS, github_app(**change), "admin")
    assert raised.value.code == code


def test_a_vault_reference_stands_for_the_secret_fields_and_says_what_it_holds():
    repo = InMemoryRepository()
    body = {"provider": "bitbucket", "edition": "cloud", "purposes": ["inventory"], "auth_method": "api_token",
            "target": {"workspace": "acme"}}
    with_email = service.create(repo, SETTINGS, {**body, "credential": {
        "vault_ref": "vault://atlassian/bitbucket", "email": "ops@example.com"}}, "admin")
    stored = ProviderConnectionStore(repo).get(with_email["id"])
    assert stored["secret_refs"] == {"credential": "vault://atlassian/bitbucket"}
    assert stored["target"]["auth"] == {"email": "ops@example.com"}
    with pytest.raises(service.OnboardingError) as raised:  # a secret next to its reference is two answers
        service.create(repo, SETTINGS, {**body, "credential": {
            "vault_ref": "vault://atlassian/bitbucket", "token": "ATATT" + "x" * 30}}, "admin")
    assert raised.value.code == "CREDENTIAL_REFERENCE_INVALID"
    methods = {(item["provider"], method["id"]): method for item in catalog.public() for method in item["auth_methods"]}
    assert methods[("bitbucket", "api_token")]["reference_keys"] == ["username", "token"]
    assert methods[("gitlab", "token")]["reference_keys"] == ["token"]
    assert methods[("github", "github_app")]["reference_keys"][0] == "GITHUB_APP_ID"
    assert methods[("vault", "token")]["reference"] is False and "reference_keys" not in methods[("vault", "token")]
    # Nothing secret, nothing to reference: the worker's own identity reads.
    assert methods[("aws", "role")]["reference"] is False and methods[("gcp", "adc")]["reference"] is False


def test_gitlab_plans_add_audit_keys_values_and_the_whole_instance():
    repo = InMemoryRepository()
    group = {"provider": "gitlab", "purposes": ["inventory", "vault"], "auth_method": "token",
             "target": {"scope": "project", "id": "42"}, "credential": {"token": "glpat-" + "p" * 20}}
    record = service.create(repo, SETTINGS, group, "admin")
    store = ProviderConnectionStore(repo)
    store.update(record["id"], record["revision"], "worker", status="CHECKED")
    view = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {
        "inventory": {"audit_events": True, "deploy_keys": True},
        "vault": {"read_values": True}}}, "admin")
    specs = {row["purpose"]: CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"] for row in view["created"]}
    assert set(specs["inventory"]["capabilities"]) == {"inventory", "relations", "public_keys", "audit"}
    assert specs["inventory"]["options"]["sources"] == ["project_deploy_keys"]
    assert specs["inventory"]["options"]["include_audit_events"] is True
    assert "vault_value" in specs["vault"]["capabilities"] and specs["vault"]["options"]["include_values"] is True
    # Values stay unread unless step 4 asks for them.
    plain = service.create(repo, SETTINGS, {**group, "purposes": ["vault"], "target": {"scope": "group", "id": "7"}},
                           "admin")
    store.update(plain["id"], plain["revision"], "worker", status="CHECKED")
    [row] = activate_with_access(repo, SETTINGS, plain["id"], {"purposes": {"vault": {}}}, "admin")["created"]
    assert CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]["options"]["include_values"] is False

    instance = {"provider": "gitlab", "edition": "self_managed", "purposes": ["inventory"], "auth_method": "token",
                "target": {"host": "https://gitlab.example.com", "scope": "instance"},
                "credential": {"token": "glpat-" + "a" * 20}}
    with pytest.raises(service.OnboardingError) as raised:  # a group or project ID means nothing for it
        service.create(repo, SETTINGS, {**instance, "target": {**instance["target"], "id": "7"}}, "admin")
    assert raised.value.code == "TARGET_FIELD_UNKNOWN:id"
    with pytest.raises(service.OnboardingError) as raised:
        service.create(repo, SETTINGS, {**instance, "purposes": ["inventory", "exposure"]}, "admin")
    assert raised.value.code == "GITLAB_INSTANCE_SCOPE_IS_INVENTORY_ONLY"
    with pytest.raises(service.OnboardingError) as raised:
        service.create(repo, SETTINGS, {**instance, "edition": "cloud", "target": {"scope": "instance"}}, "admin")
    assert raised.value.code == "GITLAB_INSTANCE_SCOPE_NEEDS_SELF_MANAGED"
    whole = service.create(repo, SETTINGS, instance, "admin")
    assert {p["id"] for p in catalog.permissions_for("gitlab", "inventory", "token", whole["target"])} == {
        "read_api", "instance_admin", "self_rotate"}
    store.update(whole["id"], whole["revision"], "worker", status="CHECKED")
    [row] = activate_with_access(repo, SETTINGS, whole["id"], {"purposes": {"inventory": {
        "instance_sources": ["instance_pat", "instance_ssh_keys"]}}}, "admin")["created"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert spec["scopes"] == [{"kind": "organization", "id": "https://gitlab.example.com"}]
    assert spec["options"]["sources"] == ["instance_pat", "instance_ssh_keys"] and "public_keys" in spec["capabilities"]


def legacy_created(repo, settings, body, actor):
    with legacy_auth_method(body["provider"], body["auth_method"]):
        return service.create(repo, settings, body, actor)


def checked(repo, body, *, legacy=False):
    record = (legacy_created if legacy else service.create)(repo, SETTINGS, body, "admin")
    store = ProviderConnectionStore(repo)
    store.update(record["id"], store.get(record["id"])["revision"], "worker", status="CHECKED")
    return record


def activate(repo, record, plans):
    return activate_with_access(repo, SETTINGS, record["id"], {"purposes": plans}, "admin")


def refused(call, *args):
    with pytest.raises(service.OnboardingError) as raised:
        call(*args)
    return raised.value.code


def test_gcp_values_are_chosen_once_for_the_project_collection():
    repo = InMemoryRepository()
    body = {"provider": "gcp", "purposes": ["inventory", "vault"], "auth_method": "adc",
            "target": {"project": "acme-prod"}}
    # Asked together: one collection with what either purpose asks for.
    record = checked(repo, body)
    [row] = activate(repo, record, {"inventory": {}, "vault": {"read_values": True}})["created"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert {"issuer_value", "vault_value", "vault_metadata"} <= set(spec["capabilities"])
    assert spec["options"]["include_values"] and "store_values" not in spec["options"]
    for purpose in ("inventory", "vault"):
        assert "keep_values" not in {field["name"] for field in catalog.descriptor("gcp")["purposes"][purpose]["plan"]}
        assert refused(activate, repo, checked(repo, body), {purpose: {"read_values": True, "keep_values": True}}) == (
            "PLAN_FIELD_UNKNOWN:keep_values")
    # Asked one after the other: the later one may not ask for other value choices.
    later = checked(repo, body)
    [first] = activate(repo, later, {"inventory": {}})["created"]
    assert CoverageStore(repo).get(uuid.UUID(first["id"]))["spec"]["options"]["include_values"] is False
    assert refused(activate, repo, later, {"vault": {"read_values": True}}) == (
        "GCP_VALUE_CHOICES_SET_BY_THE_PROJECT_COLLECTION")
    assert activate(repo, later, {"vault": {}})["created"] == []
    assert "vault_metadata" in CoverageStore(repo).get(uuid.UUID(first["id"]))["spec"]["capabilities"]


@pytest.mark.parametrize("change", ["plan", "credential"])
def test_old_gcp_value_storage_choices_do_not_survive_collection_updates(change):
    from cremore.onboarding import children

    repo = InMemoryRepository()
    record = checked(repo, {"provider": "gcp", "purposes": ["inventory", "vault"], "auth_method": "adc",
                            "target": {"project": "acme-prod"}})
    parents = ProviderConnectionStore(repo)
    stored = parents.get(record["id"])
    # The completed OAuth flow's stored connection; synthetic references are never opened.
    parents.update(stored["id"], stored["revision"], "admin", auth_method="google_oauth",
                   secret_refs={"credential": "vault://onboarding/gcp-old"})
    [row] = activate(repo, record, {purpose: {"read_values": True} for purpose in ("inventory", "vault")})["created"]
    cid = uuid.UUID(row["id"])
    # An earlier installation's persisted rows, bypassing today's input validation.
    repo.coverage_memory["connections"][cid]["spec"]["options"]["store_values"] = True
    stored = parents.get(record["id"])
    old_plans = {purpose: {**plan, "keep_values": True} for purpose, plan in stored["plans"].items()}
    stored = parents.update(stored["id"], stored["revision"], "admin", plans=old_plans)
    for purpose, old_plan in old_plans.items():
        [described] = catalog.module("gcp").children({**stored, "plans": {}}, purpose, old_plan)
        assert "store_values" not in described["spec"]["options"]
    if change == "plan":
        service.update_plan(repo, SETTINGS, stored["id"], "inventory",
                            {"plan": {"read_values": True, "schedule_minutes": 60}}, "admin")
    else:
        stored = parents.update(stored["id"], stored["revision"], "admin",
                                 secret_refs={"credential": "vault://onboarding/gcp-new"})
        assert children.repoint(repo, stored, "admin") == []
    spec = CoverageStore(repo).get(cid)["spec"]
    assert spec["options"]["include_values"] and "store_values" not in spec["options"]
    assert {"issuer_value", "vault_value"} <= set(spec["capabilities"])
    assert spec["schedule_minutes"] == (60 if change == "plan" else 1440)
    assert set(spec["secret_refs"].values()) == {"vault://onboarding/gcp-old" if change == "plan"
                                               else "vault://onboarding/gcp-new"}


def test_gcp_discovery_and_the_customer_cli():
    repo = InMemoryRepository()
    org = {"provider": "gcp", "purposes": ["inventory"], "auth_method": "adc",
           "target": {"scope": "organization", "parent": "123456789012"}}
    assert refused(service.create, repo, SETTINGS, {**org, "target": {**org["target"], "project": "acme"}}, "admin") == (
        "TARGET_FIELD_UNKNOWN:project")
    assert refused(service.create, repo, SETTINGS, {**org, "purposes": ["inventory", "vault"]}, "admin") == (
        "GCP_DISCOVERY_IS_INVENTORY_ONLY")
    record = checked(repo, org)
    assert [p["id"] for p in catalog.permissions_for("gcp", "inventory", "adc", record["target"])] == [
        "resourcemanager.projects.list", "resourcemanager.folders.list"]
    [row] = activate(repo, record, {"inventory": {}})["created"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert spec["options"]["mode"] == "discovery" and spec["scopes"] == [{"kind": "organization", "id": "123456789012"}]
    # Secret Manager read where the customer runs the CLI: a collector token, nothing stored for CreMore.
    cli = checked(repo, {"provider": "gcp", "purposes": ["vault"], "auth_method": "customer_cli",
                         "target": {"project": "acme-prod"}}, legacy=True)
    [row] = activate(repo, cli, {"vault": {}})["created"]
    assert row["collector_token"] and CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]["provider"] == (
        "gcp_secret_manager")
    assert ProviderConnectionStore(repo).get(cli["id"])["secret_refs"] == {}


def test_aws_customer_cli_needs_no_scanner_and_reports_with_collector_tokens():
    repo = InMemoryRepository()
    body = {"provider": "aws", "purposes": ["inventory", "vault"], "auth_method": "customer_cli",
            "target": {"accounts": ["222222222222"]}}
    assert refused(service.create, repo, SETTINGS, {**body, "purposes": ["exposure"]}, "admin") == (
        "AUTH_METHOD_NOT_FOR_PURPOSES")
    record = checked(repo, body, legacy=True)  # no approved scanner identity is needed
    assert repo.list_aws_accounts() == []
    view = activate(repo, record, {"inventory": {}, "vault": {"regions": ["us-east-1"], "previous_versions": True}})
    specs = {row["id"]: CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"] for row in view["created"]}
    assert all(row["collector_token"] for row in view["created"])
    assert sorted(spec["provider"] for spec in specs.values()) == ["aws_iam", "aws_secrets_manager"]
    assert not any(spec["server_collection"] for spec in specs.values())
    assert [spec["include_previous_versions"] for spec in specs.values() if spec["provider"] == "aws_secrets_manager"] == [
        True]


def test_vault_plans_and_the_cluster_ca():
    repo = InMemoryRepository()
    body = {"provider": "vault", "purposes": ["vault"], "auth_method": "customer_cli",
            "target": {"address": "https://vault.example.com", "mounts": ["secret"]}}
    key = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    assert refused(legacy_created, repo, SETTINGS, {**body, "target": {**body["target"], "tls_ca_pem": key}},
                   "admin") == "VAULT_TLS_CA_MUST_BE_A_PEM_CERTIFICATE"
    record = checked(repo, body, legacy=True)
    [row] = activate(repo, record, {"vault": {"previous_versions": True, "max_versions": 3, "token_accessors": True,
                                              "lease_prefixes": ["database/creds/app"]}})["created"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert spec["include_previous_versions"] and spec["max_versions_per_secret"] == 3
    assert spec["include_token_accessors"] and spec["lease_prefixes"] == ["database/creds/app"]
    # KV v1 keeps no history, so the choice is not offered for it.
    kv1 = checked(repo, {**body, "target": {**body["target"], "kv_version": "1"}}, legacy=True)
    assert refused(activate, repo, kv1, {"vault": {"previous_versions": True}}) == "PLAN_FIELD_UNKNOWN:previous_versions"


def test_azure_and_github_choices_that_need_more_of_the_target():
    repo = InMemoryRepository()
    tenant = "11111111-2222-4333-8444-555555555555"
    azure = checked(repo, {"provider": "azure", "purposes": ["inventory", "vault"], "auth_method": "workload_identity",
                           "target": {"tenant": tenant, "key_vaults": ["acme-vault"]}})
    storage = f"/subscriptions/{tenant}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmedata"
    assert refused(activate, repo, azure, {"inventory": {"storage_key_accounts": [storage]}}) == (
        "AZURE_STORAGE_KEYS_NEED_THE_SUBSCRIPTION")
    view = activate(repo, azure, {"inventory": {"find_subscriptions": True}, "vault": {"read_values": True}})
    specs = [CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"] for row in view["created"]]
    assert {spec["provider"]: spec["options"]["mode"] for spec in specs} == {
        "azure_entra": "inventory", "azure_resource_manager": "discovery", "azure_key_vault": "inventory"}
    assert [spec["options"]["include_values"] for spec in specs if spec["provider"] == "azure_key_vault"] == [True]
    github = checked(repo, {**github_app(purposes=["inventory"]), "edition": "enterprise_cloud",
                            "target": {"organization": ORG, "enterprise": "acme-ent"}})
    assert refused(activate, repo, github, {"inventory": {"token_digests": True}}) == (
        "GITHUB_TOKEN_DIGESTS_NEED_THE_AUDIT_TOKEN")
    # Whose login is which person: the organization's SAML SSO, or the enterprise's -- one of them, never both.
    people = {"provider": "github", "edition": "enterprise_cloud", "purposes": ["identity"], "auth_method": "token",
              "target": {"organization": ORG, "enterprise": "acme-ent"}, "credential": {"token": GH_TOKEN}}

    def read(body, plan):
        [row] = activate(repo, checked(repo, body), {"identity": plan})["created"]
        spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
        return spec["tenant"], spec["scopes"]

    assert read(people, {}) == (ORG, [{"kind": "organization", "id": ORG}])  # as before the choice existed
    assert read(people, {"enterprise_identities": True}) == ("acme-ent", [{"kind": "enterprise", "id": "acme-ent"}])
    no_enterprise = checked(repo, {**people, "target": {"organization": ORG}})
    assert refused(activate, repo, no_enterprise, {"identity": {"enterprise_identities": True}}) == (
        "PLAN_FIELD_UNKNOWN:enterprise_identities")  # offered once the target names an enterprise
    ghe = {**people, "edition": "dedicated",
           "target": {"organization": ORG, "host": "https://acme.ghe.com", "enterprise": "acme"}}
    assert read(ghe, {}) == ("acme", [{"kind": "enterprise", "id": "acme"}])  # GHE.com has managed users only
    assert refused(activate, repo, checked(repo, ghe), {"identity": {"enterprise_identities": False}}) == (
        "GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE")
    assert refused(service.create, repo, SETTINGS, {**ghe, "target": {"organization": ORG, "host": "https://acme.ghe.com"}},
                   "admin") == "GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE"  # before anything is stored
    # Enterprise Server sets SAML on the instance: the option reads it as the enterprise's, as on Enterprise Cloud.
    ghes = {**people, "edition": "enterprise_server",
            "target": {"organization": ORG, "host": "https://ghes.acme.test", "enterprise": "acme"}}
    assert read(ghes, {"enterprise_identities": True}) == ("acme", [{"kind": "enterprise", "id": "acme"}])
    content = service.create(repo, SETTINGS, {**ghe, "purposes": ["exposure"],
                             "target": {"organization": ORG, "host": "https://acme.ghe.com"}}, "admin")
    assert content["purposes"] == ["exposure"] and "enterprise" not in content["target"]
    # A plan saved before the choice existed still describes the collection it made, so changing it works.
    saved = ProviderConnectionStore(repo).get(checked(repo, ghe)["id"])
    [child] = catalog.module("github").children(saved, "identity", {"schedule_minutes": 1440})
    assert child["spec"]["scopes"] == [{"kind": "organization", "id": ORG}]


def test_github_people_come_from_one_source_and_only_its_scope_counts():
    # The organization's permission counts unless the enterprise's identities are chosen, which GHE.com takes by
    # default; a binding to anything but a bool plan choice, or a malformed edition default, is refused.
    descriptor = catalog.descriptor("github")
    identity = descriptor["purposes"]["identity"]
    permissions = {p["id"]: p for p in identity["permissions"]}
    assert permissions["admin_org"]["unless"] == permissions["read_enterprise"]["option"] == "enterprise_identities"
    [field] = [f for f in identity["plan"] if f["name"] == "enterprise_identities"]
    assert field["default"] is False and field["edition_defaults"] == {"dedicated": True}

    def plan_with(**change):
        return [{**f, **change} if f["name"] == "enterprise_identities" else f for f in identity["plan"]]

    no_default = [{key: value for key, value in f.items() if key != "default"}
                  if f["name"] == "enterprise_identities" else f for f in plan_with(edition_defaults={})]
    for broken, fault in (({"permissions": [{**permissions["admin_org"], "unless": "schedule_minutes"}]},
                           "permission admin_org: unless"),
                          ({"plan": plan_with(edition_defaults={"elsewhere": True})}, "enterprise_identities: edition_defaults"),
                          ({"plan": plan_with(edition_defaults={"dedicated": "yes"})}, "enterprise_identities: edition_defaults"),
                          ({"plan": plan_with(edition_defaults=[True])}, "enterprise_identities: edition_defaults"),
                          ({"plan": plan_with(edition_defaults=[])}, "enterprise_identities: edition_defaults"),
                          ({"plan": no_default}, "enterprise_identities: edition_defaults")):
        with pytest.raises(catalog.CatalogError, match=fault):
            catalog.validate({**descriptor, "purposes": {**descriptor["purposes"], "identity": {**identity, **broken}}})


def test_a_github_app_reads_the_organization_s_people_and_never_the_enterprise_s():
    # GitHub shows an organization's SAML identities to an App installation with Members (read), an enterprise's only
    # to its owners' classic tokens: the App's people collection is the organization's, on the App's own credential.
    from cremore.onboarding.permissions import required

    repo = InMemoryRepository()
    body = {**github_app(purposes=["identity"]), "edition": "enterprise_cloud",
            "target": {"organization": ORG, "enterprise": "acme-ent"}}
    record = checked(repo, body)
    stored = ProviderConnectionStore(repo).get(record["id"])
    assert [p["id"] for p in required(stored, "identity", {})] == ["installation", "members"]
    assert [p["id"] for p in required(stored, "identity", {"enterprise_identities": True})] == [
        "read_enterprise", "installation"]
    [row] = activate(repo, record, {"identity": {}})["created"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    ref = stored["secret_refs"]["credential"]
    assert (spec["provider"], spec["auth_type"], spec["scopes"]) == (
        "github_identity", "github_app", [{"kind": "organization", "id": ORG}])
    assert spec["secret_refs"] == {"app_id": ref, "installation_id": ref, "private_key": ref}
    assert refused(activate, repo, checked(repo, body), {"identity": {"enterprise_identities": True}}) == (
        "GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN")
    ghe = {**body, "edition": "dedicated", "target": {"organization": ORG, "host": "https://acme.ghe.com",
                                                      "enterprise": "acme"}}
    # GHE.com has managed users only: the App is not offered for its people at all.
    with pytest.raises(service.OnboardingError, match="AUTH_METHOD_NOT_FOR_PURPOSES"):
        service.create(repo, SETTINGS, ghe, "admin")


def test_step_three_stores_only_statuses_and_a_rename_keeps_the_answer():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, github_app(), "admin")
    service.request_check(repo, record["id"], "admin")
    service.rename(repo, record["id"], {"name": "GitHub · acme (prod)"}, "admin")
    held = {"metadata": "read", "contents": "read", "organization_administration": "read",
            "administration": "read", "organization_secrets": "read", "secrets": "read"}
    view = run_check(repo, record, github_server(held))
    assert view["status"] == "CHECKED" and view["name"] == "GitHub · acme (prod)"
    exposure = view["checks"]["results"]["exposure"]
    assert exposure["status"] == "PASSED"
    assert {row["permission"]: row["status"] for row in view["checks"]["results"]["vault"]["items"]} == {
        "installation": "GRANTED", "organization_secrets": "GRANTED", "secrets": "GRANTED", "environments": "MISSING",
        "actions": "MISSING"}
    assert view["checks"]["results"]["inventory"]["status"] == "MISSING"
    assert "ghs_" not in json.dumps(view)


def test_a_check_for_a_credential_that_changed_since_is_discarded():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, github_app(), "admin")
    service.request_check(repo, record["id"], "admin")
    job = repo.get_job(uuid.UUID(service.view(repo, service.get(repo, record["id"]))["checks"]["job_id"]))
    service.set_credential(repo, SETTINGS, record["id"], {"credential": {
        "app_id": "12345", "installation_id": "678", "private_key": app_key()}}, "admin")
    check.run(worker(repo, github_server({"metadata": "read"})), job)
    assert service.view(repo, service.get(repo, record["id"]))["checks"]["results"] == {}


def test_an_app_installed_on_another_account_is_missing_there():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, github_app(purposes=["exposure"]), "admin")
    service.request_check(repo, record["id"], "admin")
    view = run_check(repo, record, github_server({"metadata": "read", "contents": "read"}, account="someone-else"))
    [installation] = [row for row in view["checks"]["results"]["exposure"]["items"] if row["permission"] == "installation"]
    assert installation == {"permission": "installation", "status": "MISSING", "detail": "INSTALLED_ON_ANOTHER_ACCOUNT",
                            "subject": "someone-else"}


def activated(repo, body, plans, http_client):
    record = service.create(repo, SETTINGS, body, "admin")
    service.request_check(repo, record["id"], "admin", {"plans": plans})
    run_check(repo, record, http_client)
    return record, activate_with_access(repo, SETTINGS, record["id"], {"purposes": plans}, "admin")


def test_step_four_creates_every_purpose_on_the_same_sealed_reference():
    repo = InMemoryRepository()
    held = {"metadata": "read", "contents": "read"}
    record, view = activated(repo, github_app(), {"exposure": {}, "inventory": {"schedule_minutes": 60}, "vault": {}},
                             github_server(held))
    assert view["status"] == "ACTIVE" and {row["purpose"] for row in view["created"]} == {"exposure", "inventory", "vault"}
    ref = ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    [content] = [row for row in view["created"] if row["kind"] == "content"]
    source = repo.get_connection(uuid.UUID(content["id"]))
    assert source.provider == "github" and source.config["org"] == ORG and source.secret_ref == ref
    # Its own credential check is queued, as when a credential is entered.
    assert any(job.kind == "credential-check" and job.connection_id == source.id for job in repo.jobs.values())
    metadata = [CoverageStore(repo).get(uuid.UUID(row["id"])) for row in view["created"] if row["kind"] == "metadata"]
    assert {row["spec"]["schedule_minutes"] for row in metadata} == {60, 1440}
    assert all(set(row["spec"]["secret_refs"].values()) == {ref} for row in metadata)
    with pytest.raises(service.OnboardingError) as raised:
        service.activate(repo, SETTINGS, record["id"], {"purposes": {"exposure": {}}}, "admin")
    assert raised.value.code == "PURPOSE_ALREADY_ACTIVE:exposure"


def test_activation_waits_for_a_check():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, github_app(), "admin")
    with pytest.raises(service.OnboardingError) as raised:
        service.activate(repo, SETTINGS, record["id"], {"purposes": {"exposure": {}}}, "admin")
    assert raised.value.code == "PROVIDER_CONNECTION_NOT_CHECKED"


def test_existing_connection_adds_features_after_a_fresh_check(sql_repo):
    repo = sql_repo
    record, original = activated(repo, github_app(purposes=["inventory"]),
                                 {"inventory": {"schedule_minutes": 60}}, github_server({}))
    store = ProviderConnectionStore(repo)
    secret_refs = store.get(record["id"])["secret_refs"]
    # A check still running for the old choice cannot approve the new feature.
    pending = service.request_check(repo, record["id"], "admin")
    old = service.get(repo, record["id"])
    expanded = service.update_purposes(repo, SETTINGS, record["id"], {
        "purposes": ["inventory", "exposure"], "expected_revision": pending["revision"]}, "admin")
    assert expanded["status"] == "ACTIVE" and expanded["checks"]["stale"]
    assert expanded["plans"] == original["plans"] and expanded["children"] == original["children"]
    assert store.get(record["id"])["secret_refs"] == secret_refs
    assert refused(service.activate, repo, SETTINGS, record["id"], {"purposes": {"exposure": {}}}, "admin") == (
        "PROVIDER_CONNECTION_NOT_CHECKED")
    check._store_results(repo, old, service.check_digest(old), {"inventory": {"status": "PASSED"}}, None)
    assert service.view(repo, service.get(repo, record["id"]))["checks"]["stale"]
    queued = service.request_check(repo, record["id"], "admin")
    assert queued["checks"]["job_id"] != pending["checks"]["job_id"]
    run_check(repo, queued, github_server({"contents": "read", "metadata": "read"}))
    done = service.activate(repo, SETTINGS, record["id"], {"purposes": {"exposure": {}}}, "admin")
    assert done["id"] == original["id"] and done["plans"]["inventory"] == original["plans"]["inventory"]
    assert len(done["children"]) == len(original["children"]) + 1
    assert len(store.list()) == 1
    source = repo.get_connection(uuid.UUID(done["created"][0]["id"]))
    assert source.secret_ref == secret_refs["credential"]
    # A no-op retry is idempotent, but a stale writer and removal of active work are refused.
    body = {"purposes": ["inventory", "exposure"], "expected_revision": done["revision"]}
    assert service.update_purposes(repo, SETTINGS, record["id"], body, "admin")["revision"] == done["revision"]
    assert refused(service.update_purposes, repo, SETTINGS, record["id"],
                   {**body, "expected_revision": 1}, "admin") == "PROVIDER_CONNECTION_CHANGED"
    assert refused(service.update_purposes, repo, SETTINGS, record["id"],
                   {"purposes": ["inventory"]}, "admin") == "ACTIVE_PURPOSE_CANNOT_BE_REMOVED"


def test_adding_features_keeps_authentication_and_provider_boundaries():
    repo = InMemoryRepository()
    cases = [
        ({**github_app(purposes=["identity"]), "auth_method": "token", "credential": {"token": GH_TOKEN}},
         ["identity", "inventory"], "AUTH_METHOD_NOT_FOR_PURPOSES"),
        (github_app(purposes=["inventory"]), ["inventory", "remediation"], "REMEDIATION_NEEDS_ITS_OWN_CONNECTION"),
        ({"provider": "gcp", "purposes": ["inventory"], "auth_method": "adc",
          "target": {"scope": "organization", "parent": "123456789012"}},
         ["inventory", "vault"], "GCP_DISCOVERY_IS_INVENTORY_ONLY"),
        ({"provider": "notion", "purposes": ["exposure"], "auth_method": "integration",
          "target": {"workspace": "11111111-2222-4333-8444-555555555555"}, "credential": {"token": "ntn_" + "x" * 40}},
         ["exposure", "inventory"], "AUTH_METHOD_NOT_FOR_PURPOSES"),
    ]
    for body, purposes, code in cases:
        record = service.create(repo, SETTINGS, body, "admin")
        assert refused(service.update_purposes, repo, SETTINGS, record["id"], {"purposes": purposes}, "admin") == code
        assert service.get(repo, record["id"])["purposes"] == body["purposes"]
    for invalid in ([], ["billing"], [{}], "inventory"):
        assert refused(service.update_purposes, repo, SETTINGS, record["id"], {"purposes": invalid}, "admin") == "PURPOSES_INVALID"
    service.set_enabled(repo, record["id"], False, "admin")
    assert refused(service.update_purposes, repo, SETTINGS, record["id"], {"purposes": ["exposure"]}, "admin") == (
        "PROVIDER_CONNECTION_DISABLED")


def test_adding_aws_exposure_reuses_accounts_and_external_ids():
    repo = InMemoryRepository()
    approve_aws(repo)
    record = checked(repo, {"provider": "aws", "purposes": ["inventory", "vault"], "auth_method": "role",
                            "target": {"accounts": ["222222222222"]}})
    original = activate(repo, record, {"inventory": {}, "vault": {"regions": ["us-east-1"], "schedule_minutes": 0}})
    accounts = [(a.id, a.external_id) for a in repo.list_aws_accounts()]
    added = service.update_purposes(repo, SETTINGS, record["id"], {"purposes": ["inventory", "vault", "exposure"]}, "admin")
    queued = service.request_check(repo, record["id"], "admin")
    run_check(repo, queued, None)  # An unavailable fake worker reports errors, never real AWS calls.
    done = activate(repo, added, {"exposure": {}})
    assert done["created"] == [] and done["children"] == original["children"]
    assert [(a.id, a.external_id) for a in repo.list_aws_accounts()] == accounts
    assert done["plans"]["inventory"] == original["plans"]["inventory"]


def test_adding_gcp_vault_updates_the_same_project_collection_only_on_activation():
    repo = InMemoryRepository()
    record = checked(repo, {"provider": "gcp", "purposes": ["inventory"], "auth_method": "adc",
                            "target": {"project": "acme-prod"}})
    original = activate(repo, record, {"inventory": {"schedule_minutes": 60}})
    cid = uuid.UUID(original["created"][0]["id"])
    store = CoverageStore(repo)
    before = store.get(cid)
    service.update_purposes(repo, SETTINGS, record["id"], {"purposes": ["inventory", "vault"]}, "admin")
    assert store.get(cid) == before  # Selecting a feature is not activation or scope approval.
    current = service.get(repo, record["id"])
    check._store_results(repo, current, service.check_digest(current), {}, None)
    done = activate(repo, record, {"vault": {}})
    assert done["created"] == [] and len(done["children"]) == 1
    after = store.get(cid)
    assert "vault_metadata" in after["spec"]["capabilities"]
    assert after["spec"]["schedule_minutes"] == 60 and after["enabled"] == before["enabled"]


def test_a_new_credential_reaches_every_record_and_asks_for_a_new_check():
    repo = InMemoryRepository()
    record, view = activated(repo, github_app(), {"exposure": {}, "inventory": {}}, github_server({}))
    source_id = next(uuid.UUID(row["id"]) for row in view["created"] if row["kind"] == "content")
    repo.update_connection(source_id, status="ACTIVE")
    changed = service.set_credential(repo, SETTINGS, record["id"], {"credential": {
        "app_id": "12345", "installation_id": "678", "private_key": app_key()}}, "admin")
    new_ref = ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    assert changed["not_updated"] == [] and changed["status"] == "ACTIVE"
    assert repo.get_connection(source_id).secret_ref == new_ref and repo.get_connection(source_id).status == "PENDING"
    metadata = next(uuid.UUID(row["id"]) for row in view["created"] if row["kind"] == "metadata")
    assert set(CoverageStore(repo).get(metadata)["spec"]["secret_refs"].values()) == {new_ref}
    assert changed["checks"]["job_id"] != view["checks"]["job_id"]


def test_disable_stops_every_record_and_a_used_connection_is_not_deleted():
    repo = InMemoryRepository()
    record, view = activated(repo, github_app(), {"exposure": {}, "inventory": {}}, github_server({}))
    service.set_enabled(repo, record["id"], False, "admin")
    source = next(uuid.UUID(row["id"]) for row in view["created"] if row["kind"] == "content")
    metadata = next(uuid.UUID(row["id"]) for row in view["created"] if row["kind"] == "metadata")
    assert repo.get_connection(source).status == "DISABLED" and CoverageStore(repo).get(metadata)["enabled"] is False
    restored = service.set_enabled(repo, record["id"], True, "admin")
    assert restored["status"] == "ACTIVE" and CoverageStore(repo).get(metadata)["enabled"] is True
    assert repo.get_connection(source).status == "PENDING"
    with pytest.raises(service.OnboardingError) as raised:
        service.delete(repo, record["id"], "admin")
    assert raised.value.code == "PROVIDER_CONNECTION_HAS_CHILDREN"
    draft = service.create(repo, SETTINGS, github_app(), "admin")
    service.delete(repo, draft["id"], "admin")
    with pytest.raises(service.OnboardingError):
        service.get(repo, draft["id"])


def test_every_step_is_audited_without_the_credential():
    repo = InMemoryRepository()
    activated(repo, github_app(), {"exposure": {}}, github_server({}))
    events = [event for event in repo.list_events(200) if event.target_type == "provider_connection"]
    assert {event.event_type for event in events} >= {"PROVIDER_CONNECTION_CREATED", "PROVIDER_CONNECTION_CHECK_REQUESTED",
                                                      "PROVIDER_CONNECTION_ACTIVATED"}
    assert "PRIVATE KEY" not in json.dumps([event.note for event in events])


def test_a_gcp_connection_reads_keys_and_secret_metadata_in_one_collection():
    repo = InMemoryRepository()
    body = {"provider": "gcp", "purposes": ["inventory", "vault"], "auth_method": "adc",
            "target": {"project": "acme-prod"}}
    record = service.create(repo, SETTINGS, body, "admin")
    ProviderConnectionStore(repo).update(record["id"], record["revision"], "admin", status="CHECKED")
    view = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {"inventory": {}, "vault": {}}}, "admin")
    [collection] = view["created"]
    spec = CoverageStore(repo).get(uuid.UUID(collection["id"]))["spec"]
    assert spec["provider"] == "gcp" and {"inventory", "vault_metadata"} <= set(spec["capabilities"])
    assert spec["secret_refs"] == {}


def test_a_vault_read_in_the_customer_environment_returns_its_collector_token_once():
    repo = InMemoryRepository()
    body = {"provider": "vault", "purposes": ["vault"], "auth_method": "customer_cli",
            "target": {"address": "https://vault.example.com", "mounts": ["secret"]}}
    record = legacy_created(repo, SETTINGS, body, "admin")
    service.request_check(repo, record["id"], "admin")
    checked = run_check(repo, record, None)
    assert {row["detail"] for row in checked["checks"]["results"]["vault"]["items"]} == {"CUSTOMER_CLI_REPORTS_ON_UPLOAD"}
    view = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {"vault": {}}}, "admin")
    [collection] = view["created"]
    assert collection["collector_token"]
    spec = CoverageStore(repo).get(uuid.UUID(collection["id"]))["spec"]
    assert spec["server_collection"] is False and spec["mounts"][0]["name"] == "secret"
    assert "collector_token" not in json.dumps(service.view(repo, service.get(repo, record["id"])))


def test_a_vault_token_login_is_sealed_and_shared_with_the_collection():
    repo = InMemoryRepository()
    body = {"provider": "openbao", "purposes": ["vault"], "auth_method": "token",
            "target": {"address": "https://bao.example.com", "mounts": ["kv"]},
            "credential": {"token": "hvs." + "t" * 24}}
    record = service.create(repo, SETTINGS, body, "admin")
    ProviderConnectionStore(repo).update(record["id"], record["revision"], "admin", status="CHECKED")
    [collection] = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {"vault": {}}}, "admin")["created"]
    spec = CoverageStore(repo).get(uuid.UUID(collection["id"]))["spec"]
    ref = ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    assert spec["server_collection"] is True and spec["server_auth"]["method"] == "token"
    assert spec["secret_refs"] == {"vault_token": ref}


def test_an_external_vault_is_declared_by_its_prefixes():
    repo = InMemoryRepository()
    body = {"provider": "external_vault", "purposes": ["vault"], "auth_method": "reader",
            "target": {"product": "Doppler", "prefixes": ["prod/"]}, "credential": {"reader": "doppler"}}
    record = service.create(repo, SETTINGS, body, "admin")
    assert service.view(repo, service.get(repo, record["id"]))["target"]["auth"] == {"reader": "doppler"}
    ProviderConnectionStore(repo).update(record["id"], record["revision"], "admin", status="CHECKED")
    [collection] = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {"vault": {}}}, "admin")["created"]
    spec = CoverageStore(repo).get(uuid.UUID(collection["id"]))["spec"]
    assert (spec["product"], spec["reader"], spec["prefixes"]) == ("Doppler", "doppler", ["prod"])


class _Denied(Exception):
    def __init__(self):
        super().__init__("denied")
        self.response = {"Error": {"Code": "AccessDeniedException"}}


class _AwsSessions:
    """The scanner session per account: S3, IAM and SSM answer, Secrets Manager refuses."""

    def __init__(self):
        self.opened = []

    def open(self, account_id, purpose):
        self.opened.append((account_id, purpose))

        class Client:
            def __init__(self, service):
                self.service = service

            def __getattr__(self, call):
                def answer(**_arguments):
                    if self.service == "secretsmanager":
                        raise _Denied()
                    return {}
                return answer

        return SimpleNamespace(client=lambda service, region=None: Client(service))


def approve_aws(repo):
    from cremore_aws_provider import aws_access

    aws_access.save_approval(repo, aws_access.SCANNER, {
        "kind": "IAM_ROLE", "partition": "aws", "account_id": "111111111111",
        "principal_arn": "arn:aws:iam::111111111111:role/cremore", "match_key": "iam-role:cremore",
        "credential_source": "iam-role",
        "trust": {"type": "IamRole", "principal_arn": "arn:aws:iam::111111111111:role/cremore"}}, "admin")


def test_aws_registers_its_accounts_before_the_check_and_proves_them_from_the_worker():
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    repo = InMemoryRepository()
    body = {"provider": "aws", "purposes": ["exposure", "inventory", "vault"], "auth_method": "role",
            "target": {"accounts": ["222222222222", "333333333333"]}}
    with pytest.raises(service.OnboardingError) as raised:
        service.create(repo, SETTINGS, body, "admin")
    assert raised.value.code == "AWS_SCANNER_IDENTITY_NOT_APPROVED"
    approve_aws(repo)
    view = service.create(repo, SETTINGS, body, "admin")
    accounts = {account.account_id: account for account in repo.list_aws_accounts()}
    assert set(accounts) == {"222222222222", "333333333333"} and all(a.external_id for a in accounts.values())
    assert {child["kind"] for child in view["children"]} == {"aws_account"}
    service.request_check(repo, view["id"], "admin", {"plans": {"exposure": {}, "inventory": {}, "vault": {"regions": ["us-east-1"]}}})
    job = repo.get_job(uuid.UUID(service.view(repo, service.get(repo, view["id"]))["checks"]["job_id"]))
    sessions, proved = _AwsSessions(), []

    def role_checker(account):
        proved.append(account.account_id)
        return RoleValidation("VALID", code="SCANNER_ROLE_ASSUMED")

    check.run(worker(repo, None, aws_role_checker=role_checker, aws_sessions=sessions), job)
    # One role check per account, however many purposes the connection serves.
    assert sorted(proved) == ["222222222222", "333333333333"]
    checked = service.view(repo, service.get(repo, view["id"]))
    vault = {(row["permission"], row.get("subject")): row["status"]
             for row in checked["checks"]["results"]["vault"]["items"]}
    assert vault[("scanner_access", "222222222222")] == "GRANTED"
    assert vault[("secrets_list", "222222222222")] == "MISSING" and vault[("ssm_list", "333333333333")] == "GRANTED"
    # The account screen shows the same proof: the worker recorded it under the job's lease.
    assert {account.validation_status for account in repo.list_aws_accounts()} == {"VALID"}
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        service.activate(repo, SETTINGS, view["id"], {"purposes": {"vault": {"regions": ["us-east-1"]}}}, "admin")
    activated_view = activate_with_access(repo, SETTINGS, view["id"], {"purposes": {
        "exposure": {}, "inventory": {},
        "vault": {"regions": ["ap-northeast-2"], "ssm_prefixes": ["/prod/"], "schedule_minutes": 60}}}, "admin")
    providers = sorted(CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]["provider"]
                       for row in activated_view["created"])
    assert providers == ["aws_iam", "aws_iam", "aws_secrets_manager", "aws_secrets_manager", "aws_ssm", "aws_ssm"]


def test_a_runtime_identity_connection_is_its_own_single_account():
    repo = InMemoryRepository()
    approve_aws(repo)
    body = {"provider": "aws", "purposes": ["exposure"], "auth_method": "runtime",
            "target": {"accounts": ["111111111111", "222222222222"]}}
    with pytest.raises(service.OnboardingError) as raised:
        service.create(repo, SETTINGS, body, "admin")
    assert raised.value.code == "RUNTIME_IDENTITY_IS_ONE_ACCOUNT"
    assert repo.list_aws_accounts() == []


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def sql_repo(request):
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def test_the_store_guards_revisions_and_owns_records_once_in_the_database(sql_repo):
    store = ProviderConnectionStore(sql_repo)
    record = store.create({"provider": "github", "edition": "cloud", "name": "GitHub · acme", "target": {"organization": ORG},
                           "auth_method": "github_app", "secret_refs": {}, "purposes": ["exposure"]}, "admin")
    updated = store.update(record["id"], 1, "admin", name="renamed")
    assert updated["revision"] == 2 and store.get(record["id"])["name"] == "renamed"
    with pytest.raises(ProviderConnectionConflict):
        store.update(record["id"], 1, "admin", name="stale")
    child = uuid.uuid4()
    store.link(record["id"], "exposure", "content", child, {"secret_ref": "credential"})
    assert store.parent_of("content", child) == record["id"]
    assert [row["secret_slots"] for row in store.children(record["id"])] == [{"secret_ref": "credential"}]
    with pytest.raises(ProviderConnectionConflict):
        store.delete(record["id"])
    assert [row["id"] for row in store.list()] == [record["id"]]


def test_the_whole_wizard_runs_on_the_database(sql_repo):
    held = {"metadata": "read", "contents": "read", "organization_administration": "read"}
    record, view = activated(sql_repo, github_app(), {"exposure": {}, "inventory": {}}, github_server(held))
    assert view["status"] == "ACTIVE" and len(view["created"]) == 2
    changed = service.set_credential(sql_repo, SETTINGS, record["id"], {"credential": {
        "app_id": "12345", "installation_id": "678", "private_key": app_key()}}, "admin")
    assert changed["not_updated"] == []
    service.set_enabled(sql_repo, record["id"], False, "admin")
    states = {child["kind"]: child["state"] for child in service.view(sql_repo, service.get(sql_repo, record["id"]))["children"]}
    assert states == {"content": "DISABLED", "metadata": "DISABLED"}


def a_failed_activation_leaves_nothing_and_can_be_retried(repo, monkeypatch):
    from cremore.onboarding import children

    record = service.create(repo, SETTINGS, github_app(purposes=["inventory", "exposure"]), "admin")
    service.request_check(repo, record["id"], "admin")
    run_check(repo, record, github_server({"metadata": "read", "contents": "read", "organization_administration": "read", "organization_personal_access_tokens": "read", "organization_personal_access_token_requests": "read", "administration": "read"}))
    jobs = len(repo.list_jobs(500))
    real = children.create

    def exposure_fails(repo_, settings, connection, purpose, child, actor):
        if purpose == "exposure":  # after the inventory collection was created
            raise children.ChildError("CONTENT_SOURCE_ALREADY_EXISTS", 409)
        return real(repo_, settings, connection, purpose, child, actor)

    monkeypatch.setattr(children, "create", exposure_fails)
    with pytest.raises(service.OnboardingError) as raised:
        service.activate(repo, SETTINGS, record["id"], {"purposes": {"inventory": {}, "exposure": {}}}, "admin")
    assert raised.value.status == 409
    stored = ProviderConnectionStore(repo).get(record["id"])
    assert stored["plans"] == {} and stored["status"] == "CHECKED" and stored["revision"] == record["revision"] + 2
    assert ProviderConnectionStore(repo).children(record["id"]) == []
    assert CoverageStore(repo).list_connections() == [] and repo.list_connections() == []
    assert len(repo.list_jobs(500)) == jobs
    assert "PROVIDER_CONNECTION_ACTIVATED" not in {event.event_type for event in repo.list_events(200)}
    # A retry meets none of the first attempt: exactly one inventory collection.
    monkeypatch.setattr(children, "create", real)
    view = service.activate(repo, SETTINGS, record["id"], {"purposes": {"inventory": {}}}, "admin")
    assert view["status"] == "ACTIVE" and [row["kind"] for row in view["created"]] == ["metadata"]
    assert len(CoverageStore(repo).list_connections()) == 1


def test_a_failed_activation_leaves_nothing_in_memory(monkeypatch):
    a_failed_activation_leaves_nothing_and_can_be_retried(InMemoryRepository(), monkeypatch)


def test_a_failed_activation_leaves_nothing_in_the_database(sql_repo, monkeypatch):
    a_failed_activation_leaves_nothing_and_can_be_retried(sql_repo, monkeypatch)


def change_plan(repo, record, purpose, plan, **extra):
    from cremore.onboarding import targets

    current = service.get(repo, record["id"])
    if current["status"] == "ACTIVE" and purpose in current["plans"]:
        normalized = targets.normalize_plan(current, purpose, plan)
        if normalized != current["plans"][purpose]:
            grant_access(repo, record["id"], {purpose: plan})
    return service.update_plan(repo, SETTINGS, record["id"], purpose, {"plan": plan, **extra}, "admin")


def a_changed_plan_reaches_the_collections(repo, monkeypatch):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.onboarding import children

    body = {"provider": "gitlab", "purposes": ["inventory", "vault"], "auth_method": "token",
            "target": {"scope": "project", "id": "42"}, "credential": {"token": "glpat-" + "p" * 20}}
    record = checked(repo, body)
    assert refused(change_plan, repo, record, "inventory", {}) == "PROVIDER_CONNECTION_NOT_ACTIVE"
    [row] = activate(repo, record, {"inventory": {"deploy_keys": True}})["created"]
    store, cid = CoverageStore(repo), uuid.UUID(row["id"])
    made = store.get(cid)
    # Set on the collection itself afterwards: neither plan names it, so it stays.
    store.change(cid, made["revision"], "admin",
                 spec=MetadataConnectionSpec.model_validate({**made["spec"], "schedule_minutes": 30}))
    view = change_plan(repo, record, "inventory", {"deploy_keys": True, "audit_events": True})
    spec = store.get(cid)["spec"]
    assert set(spec["capabilities"]) == {"inventory", "relations", "public_keys", "audit"}
    assert spec["options"] == {**made["spec"]["options"], "include_audit_events": True}
    assert spec["schedule_minutes"] == 30 and spec["secret_refs"] == made["spec"]["secret_refs"]
    assert view["plans"]["inventory"]["audit_events"] is True
    assert view["changed"] == [{"kind": "metadata", "id": row["id"], "purpose": "inventory", "name": spec["name"],
                                "enabled": True}]
    events = {event.event_type for event in repo.list_events(200)}
    assert {"PROVIDER_CONNECTION_PLAN_CHANGED", "COLLECTION_PLAN_CHANGED"} <= events
    # The same plan again changes nothing, not even the connection.
    revision, own = store.get(cid)["revision"], ProviderConnectionStore(repo).get(record["id"])["revision"]
    assert change_plan(repo, record, "inventory", {"deploy_keys": True, "audit_events": True})["changed"] == []
    assert store.get(cid)["revision"] == revision
    assert ProviderConnectionStore(repo).get(record["id"])["revision"] == own
    # Turned off by hand: a changed plan edits it and leaves it off.
    store.change(cid, revision, "admin", enabled=False)
    change_plan(repo, record, "inventory", {"schedule_minutes": 60})
    now = store.get(cid)
    assert not now["enabled"] and now["spec"]["schedule_minutes"] == 60
    assert set(now["spec"]["capabilities"]) == {"inventory", "relations"}
    assert now["spec"]["options"]["sources"] == [] and now["spec"]["options"]["include_audit_events"] is False
    # What the plan refuses, and a change made since it was read.
    assert refused(change_plan, repo, record, "vault", {}) == "PURPOSE_NOT_ACTIVE:vault"
    assert refused(change_plan, repo, record, "inventory", {"read_values": True}) == "PLAN_FIELD_UNKNOWN:read_values"
    current = ProviderConnectionStore(repo).get(record["id"])["revision"]
    assert refused(service.update_plan, repo, SETTINGS, record["id"], "inventory",
                   {"plan": {}, "expected_revision": current - 1}, "admin") == "PROVIDER_CONNECTION_CHANGED"
    # A collection that cannot take the change leaves the plan as it was.
    real = children.update

    def fails(*args):
        real(*args)
        raise children.ChildError("CONNECTION_REVISION_CONFLICT", 409)

    monkeypatch.setattr(children, "update", fails)
    assert refused(change_plan, repo, record, "inventory", {"audit_events": True}) == "CONNECTION_REVISION_CONFLICT"
    assert ProviderConnectionStore(repo).get(record["id"])["plans"]["inventory"]["audit_events"] is False
    assert "audit" not in store.get(cid)["spec"]["capabilities"]
    monkeypatch.setattr(children, "update", real)
    service.set_enabled(repo, record["id"], False, "admin")
    assert refused(change_plan, repo, record, "inventory", {}) == "PROVIDER_CONNECTION_NOT_ACTIVE"


def test_a_changed_plan_reaches_the_collections_in_memory(monkeypatch):
    a_changed_plan_reaches_the_collections(InMemoryRepository(), monkeypatch)


def test_a_changed_plan_reaches_the_collections_in_the_database(sql_repo, monkeypatch):
    a_changed_plan_reaches_the_collections(sql_repo, monkeypatch)


def test_a_plan_adds_turns_off_and_turns_back_on_its_own_collections():
    repo = InMemoryRepository()
    body = {"provider": "aws", "purposes": ["inventory", "vault"], "auth_method": "customer_cli",
            "target": {"accounts": ["222222222222"]}}
    record = checked(repo, body, legacy=True)
    created = activate(repo, record, {"inventory": {}, "vault": {"regions": ["us-east-1"]}})["created"]
    store = CoverageStore(repo)
    rows = {store.get(uuid.UUID(row["id"]))["spec"]["provider"]: store.get(uuid.UUID(row["id"])) for row in created}
    # Parameter Store paths: a new collection, with its collector token shown once.
    view = change_plan(repo, record, "vault", {"regions": ["us-east-1"], "ssm_prefixes": ["/prod/"]})
    [added] = view["changed"]
    assert added["collector_token"] and store.get(uuid.UUID(added["id"]))["spec"]["prefixes"] == ["prod"]
    # Without them it is turned off, never deleted, and comes back on with the new paths.
    [off] = change_plan(repo, record, "vault", {"regions": ["us-east-1"]})["changed"]
    assert off["id"] == added["id"] and off["enabled"] is False
    assert store.get(uuid.UUID(added["id"]))["enabled"] is False
    [back] = change_plan(repo, record, "vault", {"regions": ["us-east-1"], "ssm_prefixes": ["/prod/", "/stage/"]})[
        "changed"]
    assert back["id"] == added["id"] and back["enabled"] is True and "collector_token" not in back
    assert store.get(uuid.UUID(added["id"]))["spec"]["prefixes"] == ["prod", "stage"]
    # Earlier versions and regions reach Secrets Manager; the inventory's collection is not touched.
    change_plan(repo, record, "vault", {"regions": ["us-east-1", "eu-west-1"], "previous_versions": True,
                                        "ssm_prefixes": ["/prod/", "/stage/"]})
    secrets = store.get(rows["aws_secrets_manager"]["id"])["spec"]
    assert secrets["regions"] == ["us-east-1", "eu-west-1"] and secrets["include_previous_versions"] is True
    assert store.get(rows["aws_iam"]["id"])["revision"] == rows["aws_iam"]["revision"]
    assert len(store.list_connections()) == 3


def test_the_idp_app_list_option_adds_turns_off_and_turns_back_on_a_collection_of_its_own():
    repo = InMemoryRepository()
    body = {"provider": "okta", "purposes": ["identity"], "auth_method": "made_key",
            "target": {"organization": "acme.okta.com"}, "credential": {"client_id": "0oa1serviceapp"}}
    record = checked(repo, body)
    [people] = activate(repo, record, {"identity": {}})["created"]  # off unless chosen
    store = CoverageStore(repo)
    [apps] = change_plan(repo, record, "identity", {"apps": True})["changed"]
    made = store.get(uuid.UUID(apps["id"]))
    assert apps["id"] != people["id"] and made["enabled"] is True
    assert made["spec"]["options"]["sources"] == ["apps"] and made["spec"]["schedule_minutes"] == 1440
    [off] = change_plan(repo, record, "identity", {"apps": False})["changed"]
    assert off["id"] == apps["id"] and off["enabled"] is False
    # Back on, with people collected weekly: the app list is never collected more often than the people.
    changed = {row["id"]: row for row in change_plan(repo, record, "identity",
                                                     {"apps": True, "schedule_minutes": 10080})["changed"]}
    assert changed[apps["id"]]["enabled"] is True and changed[people["id"]]["enabled"] is True
    assert {store.get(uuid.UUID(cid))["spec"]["schedule_minutes"] for cid in changed} == {10080}
    assert len(store.list_connections()) == 2


@pytest.mark.parametrize("schedule", [None, 5])
def test_legacy_iam_policy_choice_reaches_the_existing_collection(schedule):
    from cremore.coverage.models import ConnectionSpec

    repo = InMemoryRepository()
    approve_aws(repo)
    aws = checked(repo, {"provider": "aws", "purposes": ["inventory"], "auth_method": "role",
                         "target": {"accounts": ["222222222222"]}})
    plan = {} if schedule is None else {"schedule_minutes": schedule}
    activate(repo, aws, {"inventory": plan})
    store = CoverageStore(repo)
    [iam] = store.list_connections()
    # Persisted pre-option owners and specs lack an explicit policy choice.
    owner = service.get(repo, aws["id"])
    legacy = {k: v for k, v in owner["plans"]["inventory"].items() if k != "iam_policy_metadata"}
    ProviderConnectionStore(repo).update(owner["id"], owner["revision"], "admin", plans={"inventory": legacy})
    store.change(iam["id"], iam["revision"], "admin", enabled=False,
                 spec=ConnectionSpec.model_validate({**iam["spec"], "iam_policy_metadata": None}))
    change_plan(repo, aws, "inventory", {**legacy, "iam_policy_metadata": True})
    [current] = store.list_connections()
    assert current["id"] == iam["id"] and not current["enabled"]
    assert current["spec"]["iam_policy_metadata"] is True
    assert current["spec"]["schedule_minutes"] == (schedule or 0)


def test_an_account_inventory_is_not_a_plan_and_a_shared_collection_takes_either_plan():
    repo = InMemoryRepository()
    approve_aws(repo)
    aws = checked(repo, {"provider": "aws", "purposes": ["inventory", "vault"], "auth_method": "role",
                         "target": {"accounts": ["222222222222"]}})
    activate(repo, aws, {"inventory": {}, "vault": {"regions": ["us-east-1"]}})
    before = {row["id"]: (row["enabled"], row["revision"]) for row in CoverageStore(repo).list_connections()}
    assert change_plan(repo, aws, "inventory", {})["changed"] == []
    assert {row["id"]: (row["enabled"], row["revision"]) for row in CoverageStore(repo).list_connections()} == before
    store = CoverageStore(repo)
    iam = next(r for r in store.list_connections() if r["spec"]["provider"] == "aws_iam")
    store.change(iam["id"], iam["revision"], "admin", enabled=False)
    change_plan(repo, aws, "inventory", {"schedule_minutes": 15})
    migrated = store.get(iam["id"])
    assert not migrated["enabled"] and migrated["spec"]["schedule_source"] == "connection"
    assert migrated["spec"]["schedule_minutes"] == 15
    assert len([r for r in store.list_connections() if r["spec"]["provider"] == "aws_iam"]) == 1
    # Policy reads have their own checked plan choice; preserve the same paused collection and schedule.
    change_plan(repo, aws, "inventory", {"schedule_minutes": 15, "iam_policy_metadata": False})
    assert store.get(iam["id"])["spec"]["iam_policy_metadata"] is False
    assert refused(service.update_plan, repo, SETTINGS, aws["id"], "inventory",
                   {"plan": {"schedule_minutes": 15, "iam_policy_metadata": True}}, "admin") == "PERMISSION_CHECK_REQUIRED"
    change_plan(repo, aws, "inventory", {"schedule_minutes": 15, "iam_policy_metadata": True})
    current = store.get(iam["id"])
    assert current["spec"]["iam_policy_metadata"] is True
    assert current["spec"]["schedule_minutes"] == 15 and not current["enabled"]
    assert len([r for r in store.list_connections() if r["spec"]["provider"] == "aws_iam"]) == 1
    # One GCP project collection serves both purposes: the purpose it is not linked to changes it too.
    gcp = checked(repo, {"provider": "gcp", "purposes": ["inventory", "vault"], "auth_method": "adc",
                         "target": {"project": "acme-prod"}})
    [row] = activate(repo, gcp, {"inventory": {}, "vault": {}})["created"]
    assert row["purpose"] == "inventory"
    [changed] = change_plan(repo, gcp, "vault", {"read_values": True})["changed"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert changed["id"] == row["id"] and spec["options"]["include_values"] is True
    assert {"issuer_value", "vault_value"} <= set(spec["capabilities"])
    change_plan(repo, gcp, "vault", {})
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert spec["options"]["include_values"] is False and "vault_value" not in spec["capabilities"]


def test_a_failed_prepare_leaves_no_connection_behind(monkeypatch):
    """AWS registers its accounts at step 2: the second failing (a race step 2's pre-check cannot see)
    takes the first and the connection with it, so the same accounts can be connected again."""
    from cremore.onboarding import children

    repo = InMemoryRepository()
    approve_aws(repo)
    body = {"provider": "aws", "purposes": ["exposure"], "auth_method": "role",
            "target": {"accounts": ["222222222222", "333333333333"]}}
    real, calls = children.create, []

    def second_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise children.ChildError("ACCOUNT_ALREADY_REGISTERED", 409)
        return real(*args, **kwargs)

    monkeypatch.setattr(children, "create", second_fails)
    with pytest.raises(service.OnboardingError) as raised:
        service.create(repo, SETTINGS, body, "admin")
    assert raised.value.code == "ACCOUNT_ALREADY_REGISTERED" and len(calls) == 2
    assert ProviderConnectionStore(repo).list() == [] and repo.list_aws_accounts() == []
    monkeypatch.setattr(children, "create", real)
    record = service.create(repo, SETTINGS, body, "admin")
    assert sorted(account.account_id for account in repo.list_aws_accounts()) == ["222222222222", "333333333333"]
    assert len(ProviderConnectionStore(repo).children(record["id"])) == 2


GH_TOKEN = "ghp_" + "t" * 36


def test_reconnecting_takes_the_source_over_from_the_disabled_connection():
    """Disable, then connect again (here with a token instead of the App): the same source,
    with its findings and scan history, now runs on the new connection's credential."""
    repo = InMemoryRepository()
    old, view = activated(repo, github_app(purposes=["exposure"]), {"exposure": {}}, github_server({}))
    source_id = uuid.UUID(view["created"][0]["id"])
    assert repo.get_connection(source_id).config["auth_kind"] == "GITHUB_APP"
    token = {"provider": "github", "purposes": ["exposure"], "auth_method": "token", "target": {"organization": ORG},
             "credential": {"token": GH_TOKEN}}
    # While the first connection runs, the second gets a source of its own.
    _, beside = activated(repo, token, {"exposure": {}}, github_server({}))
    assert beside["created"][0]["name"] == "GitHub · acme (2)" and beside["created"][0]["id"] != str(source_id)
    service.set_enabled(repo, beside["id"], False, "admin")

    service.set_enabled(repo, old["id"], False, "admin")
    new, again = activated(repo, token, {"exposure": {}}, github_server({}))
    assert again["created"][0]["id"] == str(source_id) and again["created"][0]["name"] == "GitHub · acme"
    source = repo.get_connection(source_id)
    assert source.status == "PENDING" and "auth_kind" not in source.config
    assert source.secret_ref == ProviderConnectionStore(repo).get(new["id"])["secret_refs"]["credential"]
    assert ProviderConnectionStore(repo).parent_of("content", source_id) == uuid.UUID(new["id"])
    moved = [event for event in repo.list_events(200) if event.event_type == "PROVIDER_CONNECTION_RECORD_TAKEN_OVER"]
    assert len(moved) == 1 and str(old["id"]) in moved[0].note
    # The old connection owns nothing now, so it can be deleted.
    service.delete(repo, old["id"], "admin")


def test_an_enabled_connection_keeps_its_aws_accounts_and_a_disabled_one_hands_them_over():
    repo = InMemoryRepository()
    approve_aws(repo)
    body = {"provider": "aws", "purposes": ["exposure"], "auth_method": "role",
            "target": {"accounts": ["222222222222", "333333333333"]}}
    first = service.create(repo, SETTINGS, body, "admin")
    external = {account.account_id: account.external_id for account in repo.list_aws_accounts()}
    with pytest.raises(service.OnboardingError) as raised:
        service.create(repo, SETTINGS, {**body, "target": {"accounts": ["333333333333", "444444444444"]}}, "admin")
    assert raised.value.code == "ACCOUNT_ALREADY_REGISTERED"
    assert sorted(external) == sorted(account.account_id for account in repo.list_aws_accounts())

    service.set_enabled(repo, first["id"], False, "admin")
    assert not any(account.enabled for account in repo.list_aws_accounts())
    with pytest.raises(service.OnboardingError) as raised:
        legacy_created(repo, SETTINGS, {**body, "auth_method": "sso"}, "admin")
    assert raised.value.code == "ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS"
    second = service.create(repo, SETTINGS, {**body, "target": {"accounts": ["333333333333", "444444444444"]}},
                            "admin")
    accounts = {account.account_id: account for account in repo.list_aws_accounts()}
    # The deployed stack keeps working: the account and its ExternalId are the same record.
    assert accounts["333333333333"].external_id == external["333333333333"] and accounts["333333333333"].enabled
    assert accounts["222222222222"].enabled is False and accounts["444444444444"].enabled
    owners = {link["child_id"] for link in ProviderConnectionStore(repo).children(second["id"])}
    assert owners == {str(accounts["333333333333"].id), str(accounts["444444444444"].id)}


def test_what_the_records_were_built_for_is_fixed_once_they_exist():
    repo = InMemoryRepository()
    body = {"provider": "github", "purposes": ["exposure"], "auth_method": "token", "target": {"organization": ORG},
            "credential": {"token": GH_TOKEN}}
    draft = service.create(repo, SETTINGS, body, "admin")
    # Before step 4 nothing was built on it, so the method may still change.
    changed = service.set_credential(repo, SETTINGS, draft["id"], {"auth_method": "github_app", "credential": {
        "app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    assert changed["auth_method"] == "github_app"
    record, _view = activated(repo, body, {"exposure": {}}, github_server({}))
    with pytest.raises(service.OnboardingError) as raised:
        service.set_credential(repo, SETTINGS, record["id"], {"auth_method": "github_app", "credential": {
            "app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    assert raised.value.code == "AUTH_SETTINGS_FIXED_WHILE_IN_USE" and raised.value.status == 409
    # A new value in the same method is what a credential change is for.
    renewed = service.set_credential(repo, SETTINGS, record["id"], {"credential": {"token": "ghp_" + "n" * 36}}, "admin")
    assert renewed["not_updated"] == []


def approve_identity_center(repo):
    from cremore_aws_provider import aws_access

    aws_access.save_approval(repo, aws_access.SCANNER, {
        "kind": "IDENTITY_CENTER", "partition": "aws", "account_id": "111111111111",
        "principal_arn": "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Audit_0",
        "match_key": "identity-center:aws:111111111111:Audit", "permission_set": "Audit",
        "sso_start_url": "https://d-1234567890.awsapps.com/start", "sso_region": "us-east-1",
        "trust": {"type": "IdentityCenter", "account_id": "111111111111", "principal_pattern": "arn:aws:iam::*"}},
        "admin")


def discovered(repo, account_id, source, **fields):
    from cremore_aws_provider import aws_access

    from cremore.domain.models import AwsAccount

    access = aws_access.SSO_PERMISSION_SET if source == "SSO" else aws_access.ROLE
    return repo.create_aws_account(AwsAccount(account_id=account_id, name=f"found {account_id}", access=access,
                                              source=source, **fields))


def test_accounts_discovery_registers_join_the_connection_that_takes_them_in():
    from cremore.onboarding.adoption import adopt

    repo = InMemoryRepository()
    approve_identity_center(repo)
    body = {"provider": "aws", "purposes": ["exposure", "inventory", "vault"], "auth_method": "sso",
            "target": {"accounts": ["222222222222"], "adopt_discovered": True},
            "credential": {"permission_set": "Audit"}}
    record = checked(repo, body, legacy=True)
    activate(repo, record, {"exposure": {}, "inventory": {},
                            "vault": {"regions": ["us-east-1"], "schedule_minutes": 60}})
    passive = checked(repo, {**body, "target": {"accounts": ["333333333333"]}}, legacy=True)  # does not take in
    activate(repo, passive, {"exposure": {}})
    found = discovered(repo, "444444444444", "SSO", sso_role_name="Audit")
    discovered(repo, "555555555555", "SSO", sso_role_name="Other")  # another permission set
    discovered(repo, "666666666666", "SSO", sso_role_name="Audit", enabled=False)  # an administrator stopped it
    discovered(repo, "777777777777", "ORGANIZATION", external_id="shared-external-id-0001")  # member-role mode
    taken = adopt(repo, SETTINGS)
    assert taken == [{"provider_connection_id": str(record["id"]), "kind": "aws_account", "id": str(found.id)}]
    store = ProviderConnectionStore(repo)
    assert store.parent_of("aws_account", found.id) == uuid.UUID(str(record["id"]))
    # The saved step 4 plans reach it: its IAM collection and its Secrets Manager read.
    owned = {link["child_id"] for link in store.children(record["id"]) if link["kind"] == "coverage"}
    specs = [CoverageStore(repo).get(uuid.UUID(child))["spec"] for child in owned]
    assert {(spec["provider"], spec["account_id"]) for spec in specs} >= {
        ("aws_iam", "444444444444"), ("aws_secrets_manager", "444444444444")}
    assert "PROVIDER_CONNECTION_RECORD_ADOPTED" in {event.event_type for event in repo.list_events(300)}
    # Taken once: a second call finds nothing new.
    assert adopt(repo, SETTINGS) == []
    # A member-role connection takes in what the Organizations sweep registered (its shared ExternalId).
    from cremore.onboarding.fixtures_test import legacy_aws_setup

    with legacy_aws_setup():
        role = checked(repo, {"provider": "aws", "purposes": ["exposure"], "auth_method": "role",
                              "target": {"accounts": ["888888888888"], "adopt_discovered": True}})
    activate(repo, role, {"exposure": {}})
    org = next(account for account in repo.list_aws_accounts() if account.account_id == "777777777777")
    assert [item["id"] for item in adopt(repo, SETTINGS)] == [str(org.id)]
    assert store.parent_of("aws_account", org.id) == uuid.UUID(str(role["id"]))


def test_the_worker_takes_discovered_accounts_in_on_its_poll():
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    approve_identity_center(repo)
    record = checked(repo, {"provider": "aws", "purposes": ["exposure"], "auth_method": "sso",
                            "target": {"accounts": ["222222222222"], "adopt_discovered": True},
                            "credential": {"permission_set": "Audit"}}, legacy=True)
    activate(repo, record, {"exposure": {}})
    found = discovered(repo, "444444444444", "SSO", sso_role_name="Audit")
    JobWorker(repo, settings=SETTINGS).poll_triggers()
    assert ProviderConnectionStore(repo).parent_of("aws_account", found.id) == uuid.UUID(str(record["id"]))


def test_the_worker_runs_the_check_job_it_is_given():
    """The poll loop swallows nothing here, but a missing dispatch would leave checks queued forever."""
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, github_app(purposes=["exposure"]), "admin")
    service.request_check(repo, record["id"], "admin")
    worker_ = JobWorker(repo, settings=SETTINGS, http_client_factory=github_server({"metadata": "read"}),
                        metadata_secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys))
    worker_._last_trigger_poll = float("inf")  # no trigger polling in this test
    for _ in range(4):
        worker_.process_next()
    view = service.view(repo, service.get(repo, record["id"]))
    assert view["status"] == "CHECKED" and view["checks"]["results"]["exposure"]["status"] == "MISSING"
    assert repo.get_job(uuid.UUID(view["checks"]["job_id"])).status == "SUCCEEDED"


@pytest.mark.parametrize("initial", [False, True])
def test_aws_cloudtrail_plan_creates_updates_and_disables_only_owned_collection(initial):
    repo = InMemoryRepository()
    record = checked(repo, {"provider": "aws", "purposes": ["inventory"], "auth_method": "customer_cli",
                            "target": {"accounts": ["123456789012"]}}, legacy=True)
    plan = {"cloudtrail": True, "cloudtrail_regions": ["us-east-1"], "cloudtrail_days": 90}
    activate(repo, record, {"inventory": plan if initial else {}})
    if not initial:
        change_plan(repo, record, "inventory", plan)
    store = CoverageStore(repo)
    rows = store.list_connections()
    assert len(rows) == 2
    trail = next(r for r in rows if r["spec"]["provider"] == "aws_cloudtrail")
    assert trail["spec"]["regions"] == ["us-east-1"] and trail["spec"]["window_days"] == 90
    assert str(ProviderConnectionStore(repo).parent_of("coverage", trail["id"])) == str(record["id"])
    change_plan(repo, record, "inventory", {**plan, "cloudtrail_days": 30})
    assert store.get(trail["id"])["spec"]["window_days"] == 30
    change_plan(repo, record, "inventory", {"cloudtrail": False})
    assert store.get(trail["id"])["enabled"] is False
    assert next(r for r in store.list_connections() if r["spec"]["provider"] == "aws_iam")["enabled"] is True
    change_plan(repo, record, "inventory", plan)
    assert store.get(trail["id"])["enabled"] is True and len(store.list_connections()) == 2


def test_aws_region_options_are_advisory_and_preserve_saved_or_future_regions():
    descriptor = catalog.descriptor("aws")
    inventory = descriptor["purposes"]["inventory"]
    field = next(f for f in inventory["plan"] if f["name"] == "cloudtrail_regions")
    regions = [option["id"] for option in field["options"]]
    assert field["kind"] == "list" and len(regions) == len(set(regions))
    assert {"us-east-1", "ap-northeast-2", "cn-north-1", "us-gov-west-1"} <= set(regions)
    assert next(f for f in descriptor["purposes"]["vault"]["plan"] if f["name"] == "regions")["options"] == field["options"]
    for options in ([], [{"id": "us-east-1"}]):
        broken = [{**f, "options": options} if f["name"] == field["name"] else f for f in inventory["plan"]]
        with pytest.raises(catalog.CatalogError):
            catalog.validate({**descriptor, "purposes": {**descriptor["purposes"], "inventory": {**inventory, "plan": broken}}})
    repo = InMemoryRepository()
    record = checked(repo, {"provider": "aws", "purposes": ["inventory"], "auth_method": "customer_cli",
                            "target": {"accounts": ["123456789012"]}}, legacy=True)
    activate(repo, record, {"inventory": {"cloudtrail": True, "cloudtrail_regions": ["ap-future-1"]}})
    trail = next(row for row in CoverageStore(repo).list_connections() if row["spec"]["provider"] == "aws_cloudtrail")
    assert trail["spec"]["regions"] == ["ap-future-1"]
