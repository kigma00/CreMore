"""Every provider's step 4 records pass the validation of the store that runs them.

A record the wizard would create but the collection refuses would only fail at
activation; this matrix builds each one from a synthetic connection instead.
"""

import itertools

import pytest

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.models import ConnectionSpec
from cremore.coverage.providers import validate_spec
from cremore.domain.connections import validate_connection
from cremore.domain.models import Connection
from cremore.onboarding import catalog
from cremore.sources.registry import BY_SOURCE

TENANT = "11111111-2222-4333-8444-555555555555"
STORAGE = (f"/subscriptions/{TENANT}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/acmedata")
# provider -> edition -> the target as step 2 stores it (target() normalises what the wizard sends).
TARGETS = {
    "github": {"cloud": {"organization": "acme"},
               # The organization's own SAML identities: the one edition the App reads people in besides GitHub.com.
               "enterprise_cloud": {"organization": "acme"},
               "enterprise_server": {"organization": "acme", "host": "ghes.example.com", "enterprise": "acme-ent"},
               "dedicated": {"organization": "acme", "host": "acme.ghe.com", "enterprise": "acme"}},
    "gitlab": {"cloud": {"scope": "group", "id": "123"},
               "self_managed": {"scope": "project", "id": "7", "host": "https://gitlab.example.com"}},
    "confluence": {"cloud": {"base_url": "https://acme.atlassian.net/wiki", "space": "12345"},
                   "data_center": {"base_url": "https://wiki.example.com", "space": "ENG"}},
    "bitbucket": {"cloud": {"workspace": "acme", "auth": {"email": "ops@example.com"}},
                  "data_center": {"base_url": "https://git.example.com", "project": "PAY"}},
    "atlassian": {"cloud": {"organization": TENANT}},
    "notion": {"cloud": {"workspace": TENANT}},
    "slack": {"cloud": {"organization": "E0ACME001"}},
    "gcp": {"cloud": {"scope": "project", "project": "acme-prod"}},
    "azure": {"cloud": {"tenant": TENANT, "subscription": TENANT, "storage_account": "acmedata",
                        "key_vaults": ["acme-vault"], "devops_organization": "acme", "devops_project": "Payments"}},
    "azure_devops": {"cloud": {"organization": "acme", "project": "Payments"},
                     "server": {"organization": "DefaultCollection", "project": "Payments",
                                "base_url": "https://devops.example.com/tfs"}},
    "entra_id": {"cloud": {"tenant": TENANT}},
    "vault": {"self_managed": {"address": "https://vault.example.com", "namespace": "", "mounts": ["secret"],
                               "kv_version": "2", "prefixes": [""],
                               "auth": {"role": "cremore", "token_file": "vault-pay", "mount": ""}}},
    "openbao": {"self_managed": {"address": "https://bao.example.com", "namespace": "", "mounts": ["kv"],
                                 "kv_version": "1", "prefixes": ["team"],
                                 "auth": {"role": "cremore", "token_file": "bao", "mount": "jwt"}}},
    "external_vault": {"self_managed": {"product": "Doppler", "prefixes": ["prod"], "auth": {"reader": "doppler"}}},
    "okta": {"cloud": {"organization": "acme.okta.com"}},
    "keycloak": {"self_managed": {"address": "https://sso.example.com", "realm": "staff", "api_path": "",
                                  "admin_events": True}},
    "google_workspace": {"cloud": {"domain": "acme.com"}},
    "website": {"web": {"domains": ["acme.com", "intranet.acme.test"],
                        "start_urls": "https://www.acme.com/app\nhttp://intranet.acme.test:8080/"}},
}
# Scopes that serve only some purposes (``ready`` refuses the others).
EXTRA_TARGETS = [
    ("slack", "cloud", {"organization": "T0ACME002"}, {"inventory"}),
    ("gitlab", "self_managed", {"scope": "instance", "host": "https://gitlab.example.com"}, {"inventory"}),
    ("gcp", "cloud", {"scope": "organization", "parent": "123456789012"}, {"inventory"}),
    ("gcp", "cloud", {"scope": "folder", "parent": "42"}, {"inventory"}),
]
PLANS = {"vault": {"regions": ["us-east-1"], "ssm_prefixes": ["/prod"], "schedule_minutes": 60}}
# Every step 4 choice turned on, where the target allows it: the records still pass.
OPTION_PLANS = {
    ("notion", "inventory"): {"personal_access_tokens": True, "mcp_connections": True},
    ("github", "inventory"): {"token_digests": True, "audit_events": True, "audit_days": 7,
                              "enterprise_inventory": True, "enterprise_audit": True,
                              "enterprise_schedule_minutes": 1440, "audit_schedule_minutes": 60},
    ("gitlab", "inventory"): {"audit_events": True, "deploy_keys": True, "enterprise_ssh_keys": True,
                              "instance_sources": ["instance_pat", "instance_deploy_tokens", "instance_ssh_keys",
                                                   "instance_deploy_keys"]},
    ("gitlab", "vault"): {"read_values": True},
    ("slack", "inventory"): {"audit_events": True},
    ("okta", "identity"): {"people_details": True, "apps": True},
    ("keycloak", "identity"): {"people_details": True, "apps": True, "admin_events": True},
    ("google_workspace", "identity"): {"people_details": True},
    ("entra_id", "identity"): {"people_details": True},
    ("github", "identity"): {"people_details": True, "enterprise_identities": True},
    ("gcp", "inventory"): {"read_values": True, "include_deleted": False, "audit_logs": True,
                            "api_metrics": True, "audit_days": 7, "service_account_iam": True, "effective_access": True},
    ("gcp", "vault"): {"read_values": True, "include_deleted": False, "audit_logs": True,
                        "api_metrics": True, "audit_days": 7, "service_account_iam": True, "effective_access": True,
                        "secret_iam": True, "locations": ["asia-northeast3"]},
    ("azure", "inventory"): {"find_subscriptions": True, "storage_key_accounts": [STORAGE],
                              "federated_credentials": True, "public_certificates": True,
                              "credential_sign_ins": True, "directory_audits": True, "audit_days": 7,
                              "app_permissions": True, "app_azure_roles": True},
    ("azure", "vault"): {"read_values": True, "versions": True, "deleted": True, "keys": True,
                          "certificates": True, "public_certificates": True},
    ("azure", "identity"): {"people_details": True},
    ("atlassian", "inventory"): {"oauth_clients": True},
    ("vault", "vault"): {"previous_versions": True, "max_versions": 5, "token_accessors": True,
                         "lease_prefixes": ["database/creds/app"]},
    # OpenBao's target here is KV v1, so the version choices do not apply to it (Vault's is KV v2).
    ("openbao", "vault"): {"previous_versions": True, "max_versions": 5, "token_accessors": True,
                           "lease_prefixes": ["database/creds/app"]},
}


def plan_for(provider, edition, purpose, target, options=False):
    """The plan as step 4 stores it: the given choices with the descriptor's defaults filled in."""
    from cremore.onboarding.service import _fields

    fields = catalog.descriptor(provider)["purposes"][purpose].get("plan") or []
    wanted = dict(PLANS.get(purpose, {}) if provider == "aws" else {})
    if options:
        applies = {field["name"] for field in fields if (not field.get("editions") or edition in field["editions"])
                   and catalog.applies(field, target)}
        wanted.update({key: value for key, value in OPTION_PLANS.get((provider, purpose), {}).items() if key in applies})
    return _fields(fields, wanted, edition, what="PLAN", target=target)


def cases():
    targets = [(provider, edition, target, None) for provider, editions in TARGETS.items()
               for edition, target in editions.items()] + EXTRA_TARGETS
    for provider, edition, target, only in targets:
        descriptor = catalog.descriptor(provider)
        for method in descriptor["auth_methods"]:
            if method.get("editions") and edition not in method["editions"]:
                continue
            for purpose in method["purposes"]:
                if edition not in method.get("purpose_editions", {}).get(purpose, [edition]):
                    continue  # the catalog never offers the method for it there (catalog.methods_for)
                if only is None or purpose in only:
                    for options in (False, True):
                        yield provider, edition, method["id"], purpose, target, options


@pytest.mark.parametrize("provider, edition, method, purpose, target, options", list(cases()),
                         ids=lambda value: value if isinstance(value, str) else "")
def test_each_record_a_purpose_creates_is_valid_where_it_runs(provider, edition, method, purpose, target, options):
    connection = {"id": "00000000-0000-0000-0000-000000000000", "provider": provider, "edition": edition,
                  "name": f"{provider} test", "target": target, "auth_method": method,
                  "purposes": [purpose], "plans": {},
                  "secret_refs": {"credential": "vault://onboarding/test", "audit_token": "vault://onboarding/audit"}}
    module = catalog.module(provider)
    plan = plan_for(provider, edition, purpose, target, options)
    if (provider, purpose, options) == ("github", "inventory", True) and not target.get("enterprise"):
        return  # digests come from an Enterprise audit log (refused without one: onboarding_test)
    for child in module.children({**connection, "activating": {purpose: plan}}, purpose, plan):
        refs = {slot: "vault://onboarding/test" for slot in child.get("secret_slots") or {}}
        if child["kind"] == "content":
            config = dict(child["config"])
            conn = Connection(provider=BY_SOURCE[child["source_type"]].PROVIDER, name=child["name"], config=config,
                              secret_ref=refs.get("secret_ref"))
            validate_connection(conn)
        elif child["kind"] == "metadata":
            validate_spec(MetadataConnectionSpec.model_validate({**child["spec"], "secret_refs": refs}))
        elif child["kind"] == "coverage":
            ConnectionSpec.model_validate({**child["spec"], "secret_refs": refs})
        else:
            pytest.fail(f"unexpected child kind {child['kind']}")


def test_the_matrix_covers_every_provider_purpose_and_every_choice():
    covered = {(provider, purpose) for provider, _edition, _method, purpose, _target, _options in cases()}
    expected = {(provider, purpose) for provider, descriptor in catalog.providers().items() if provider != "aws"
                for purpose in descriptor["purposes"]}
    assert covered == expected
    # Every step 4 field of every provider but AWS is turned on somewhere above.
    exercised = {(provider, purpose, name) for (provider, purpose), plan in OPTION_PLANS.items() for name in plan}
    for provider, descriptor in catalog.providers().items():
        for purpose, spec in descriptor["purposes"].items():
            for field in spec.get("plan") or []:
                if provider != "aws" and field["name"] != "schedule_minutes" and field["kind"] in ("bool", "choices",
                                                                                                   "list", "number"):
                    assert (provider, purpose, field["name"]) in exercised, (provider, purpose, field["name"])


@pytest.mark.parametrize("method", ["role", "customer_cli"])
def test_aws_records_are_valid_collections(method):
    from cremore_aws_provider import onboarding as aws

    connection = {"provider": "aws", "target": {"accounts": ["222222222222"]}, "auth_method": method,
                  "purposes": ["vault"], "plans": {}}
    for options in (False, True):
        plan = plan_for("aws", "cloud", "vault", connection["target"])
        if options:
            plan.update(previous_versions=True, max_versions=7)
        for child in aws.children(connection, "vault", plan):
            spec = ConnectionSpec.model_validate(child["spec"])
            assert spec.server_collection is (method != "customer_cli")
            assert bool(child.get("collector_token")) is (method == "customer_cli")
            if spec.provider == "aws_secrets_manager":
                assert spec.include_previous_versions is options
    inventory = aws.children(connection, "inventory", {})
    if method == "customer_cli":
        assert [ConnectionSpec.model_validate(child["spec"]).provider for child in inventory] == ["aws_iam"]
    else:
        assert [child["kind"] for child in inventory] == ["aws_inventory"]
    assert list(itertools.chain(aws.children(connection, "exposure", {}))) == []
    trails = aws.children(connection, "inventory", {"cloudtrail": True, "cloudtrail_regions": ["us-east-1"], "cloudtrail_days": 90})
    trail = next(child for child in trails if child.get("spec", {}).get("provider") == "aws_cloudtrail")
    assert ConnectionSpec.model_validate(trail["spec"]).window_days == 90
    assert trail["spec"]["regions"] == ["us-east-1"]
    assert bool(trail.get("collector_token")) is (method == "customer_cli")
    with pytest.raises(ValueError):
        aws.children(connection, "inventory", {"cloudtrail": True, "cloudtrail_regions": []})



# One listed item per declared inventory type, as each collector stores it.
LISTED = {
    ("github", "fine_grained_pat"): {"provider": "github", "object_id": "fgpat:acme:7", "facts": {}},
    ("github", "classic_pat"): {"provider": "github", "object_id": "sso:acme:9", "facts": {"credential_type": "personal access token"}},
    ("github", "oauth_app_token"): {"provider": "github", "object_id": "sso:acme:10", "facts": {"credential_type": "OAuth app token"}},
    ("github", "github_app_user_token"): {"provider": "github", "object_id": "inventory:github_app_user_token:id:4",
                                          "facts": {"credential_type": "github_app_user_token"}},
    ("github", "ssh_key"): {"provider": "github", "object_id": "inventory:ssh_key:fingerprint:SHA256:x",
                            "facts": {"credential_type": "ssh_key"}},
    ("github", "deploy_key"): {"provider": "github", "object_id": "deployKey:acme/app:3", "facts": {}},
    ("github", "app_installation"): {"provider": "github", "object_id": "installation:55", "facts": {}},
    ("github", "app_issuer"): {"provider": "github", "object_id": "inventory:export:github_app_installation:e:row:1",
                                 "facts": {"credential_type": "github_app_installation"}},
    ("github", "federated_jti"): {"provider": "github", "object_id": "inventory:export:federated_jti:e:row:2",
                                  "facts": {"credential_type": "federated_jti"}},
    ("gitlab", "personal_access_token"): {"provider": "gitlab", "object_id": "p", "facts": {"family": "personal_access_token"}},
    ("gitlab", "service_account_token"): {"provider": "gitlab", "object_id": "p",
                                          "facts": {"credential_types": ["group_service_account_pat"]}},
    ("gitlab", "group_access_token"): {"provider": "gitlab", "object_id": "p", "facts": {"family": "group_access_token"}},
    ("gitlab", "project_access_token"): {"provider": "gitlab", "object_id": "p", "facts": {"family": "project_access_token"}},
    ("gitlab", "deploy_token"): {"provider": "gitlab", "object_id": "deploy_token:4", "facts": {"family": "deploy_token"}},
    ("gitlab", "pipeline_trigger_token"): {"provider": "gitlab", "object_id": "p", "facts": {"family": "pipeline_trigger_token"}},
    ("gitlab", "error_tracking_client_key"): {"provider": "gitlab", "object_id": "p",
                                              "facts": {"family": "error_tracking_client_key"}},
    ("gitlab", "kubernetes_agent_token"): {"provider": "gitlab", "object_id": "p", "facts": {"family": "kubernetes_agent_token"}},
    ("gitlab", "ssh_key"): {"provider": "gitlab", "object_id": "ssh_key:8", "facts": {"family": "ssh_key"}},
    ("gitlab", "deploy_key"): {"provider": "gitlab", "object_id": "deploy_key:9", "facts": {"family": "deploy_key"}},
    ("bitbucket", "http_access_token"): {"provider": "bitbucket", "object_id": "dc:rest:project:PAY:123", "facts": {}},
    ("bitbucket", "ssh_key"): {"provider": "bitbucket", "object_id": "workspace/acme/user-ssh-key//str/%7Bk%7D", "facts": {}},
    ("bitbucket", "deploy_key"): {"provider": "bitbucket", "object_id": "workspace/acme/repository-deploy-key/app/int/4",
                                  "facts": {}},
    ("atlassian", "api_token"): {"provider": "atlassian", "object_id": "o", "facts": {"metadata": {"source": "user-api-tokens"}}},
    ("atlassian", "admin_api_key"): {"provider": "atlassian", "object_id": "o", "facts": {"context": {"operation": "admin-api-keys"}}},
    ("atlassian", "service_account_token"): {"provider": "atlassian", "object_id": "o",
                                             "facts": {"metadata": {"source": "service-account-api-tokens"}}},
    ("atlassian", "oauth_client"): {"provider": "atlassian", "object_id": "o", "facts": {"metadata": {"source": "org-oauth-clients"}}},
    ("notion", "personal_access_token"): {"provider": "notion", "object_id": "pat:ws:1", "facts": {}},
    ("notion", "mcp_connection"): {"provider": "notion", "object_id": "mcp:ws:ab", "facts": {}},
    ("slack", "bot_token"): {"provider": "slack", "object_id": "bot:E0ACME001:A0APP0001", "facts": {}},
    ("slack", "user_token"): {"provider": "slack", "object_id": "user:E0ACME001:A0APP0001", "facts": {}},
    ("slack", "incoming_webhook"): {"provider": "slack", "object_id": "hook:E0ACME001:A0APP0001", "facts": {}},
    ("aws", "access_key"): {"provider": "aws_iam", "object_id": "AKIA", "credential_type": "AWS_ACCESS_KEY"},
    ("aws", "service_credential"): {"provider": "aws_iam", "object_id": "ACCA", "credential_type": "AWS_SERVICE_CREDENTIAL"},
    ("gcp", "service_account_key"): {"provider": "gcp", "object_id": "serviceAccountKey:sa@p.iam.gserviceaccount.com:k1", "facts": {}},
    ("gcp", "api_key"): {"provider": "gcp", "object_id": "apiKey:k2", "facts": {}},
    ("azure", "client_secret"): {"provider": "azure_entra", "object_id": "application:a:passwordCredentials:b",
                                 "facts": {"credential_type": "AZURE_CLIENT_SECRET"}},
    ("azure", "certificate"): {"provider": "azure_entra", "object_id": "application:a:keyCredentials:b",
                               "facts": {"credential_type": "AZURE_CERTIFICATE"}},
    ("azure", "storage_account_key"): {"provider": "azure_resource_manager", "object_id": "k",
                                       "facts": {"credential_type": "AZURE_STORAGE_KEY"}},
    ("azure", "personal_access_token"): {"provider": "azure_devops", "object_id": "pat:acme:1", "facts": {}},
    ("azure_devops", "personal_access_token"): {"provider": "azure_devops", "object_id": "pat:acme:1", "facts": {}},
}


def test_each_declared_inventory_type_names_the_items_its_collector_lists():
    declared = {(p, t["id"]) for p, d in catalog.providers().items()
                for t in (d["purposes"].get("inventory") or {}).get("types") or []}
    assert declared == set(LISTED)
    for (provider, type_id), item in LISTED.items():
        assert catalog.inventory_type(provider, item)["id"] == type_id, (provider, type_id)
    # Context the collectors also store is not a credential type, and one provider's item never takes another's.
    assert catalog.inventory_type("github", {"provider": "github", "object_id": "repository:acme/app", "facts": {}}) is None
    assert catalog.inventory_type("gitlab", {"provider": "github", "object_id": "p", "facts": {"family": "deploy_key"}}) is None
    assert catalog.inventory_type("okta", {"provider": "okta", "object_id": "u"}) is None


@pytest.mark.parametrize("change,fault", [
    ({"support": "YYYY"}, "support"),
    ({"support": "YYPYYYYYY", "reasons": {}}, "reason for created"),
    ({"reasons": {"created": ["only one"]}, "support": "YYPYYYYYY"}, "reason for created"),
    ({"reasons": {"name": ["a", "b"]}}, "reason for name"),
    ({"permission": "not_declared"}, "permission"),
    ({"match": []}, "match"),
    ({"match": [{"fact": "family"}]}, "match rule"),
    ({"match": [{"elsewhere": "x"}]}, "match rule"),
    ({"when": {"scope": []}}, "when"),
    ({"plan": []}, "plan"),
    ({"plan": [{"field": "missing"}]}, "plan binding missing"),
    ({"plan": [{"field": "schedule_minutes"}]}, "bool or list"),
    ({"plan": [{"field": "sources", "option": "other"}]}, "plan binding sources:other"),
    ({"plan": [{"always": True, "field": "keys"}]}, "plan binding"),
    ({"plan": [{"always": True, "editions": ["server"]}]}, "plan binding"),
])
def test_a_type_declaration_is_refused_with_the_part_that_is_wrong(change, fault):
    good = {"id": "token", "label": "Token", "label_ko": "토큰", "permission": "read", "support": "YYYYYYYYY", "reasons": {},
            "match": [{"prefix": "t:"}]}
    descriptor = {"provider": "demo", "label": "Demo", "label_ko": "데모", "category": "saas",
                  "editions": [{"id": "cloud", "label": "Cloud", "label_ko": "클라우드"}],
                  "purposes": {"inventory": {"permissions": [{"id": "read", "label": "Read", "label_ko": "읽기"}],
                                             "types": [{**good, **change}], "plan": [
                                                 {"name": "schedule_minutes", "kind": "number", "label": "Every", "label_ko": "주기"},
                                                 {"name": "keys", "kind": "bool", "label": "Keys", "label_ko": "키"},
                                                 {"name": "sources", "kind": "choices", "label": "Sources", "label_ko": "목록",
                                                  "options": [{"id": "tokens", "label": "Tokens", "label_ko": "토큰"}]}]}},
                  "auth_methods": [{"id": "token", "label": "Token", "label_ko": "토큰", "renewal": "EXPIRES",
                                    "purposes": ["inventory"]}]}
    with pytest.raises(catalog.CatalogError, match=fault):
        catalog.validate(descriptor)
    descriptor["purposes"]["inventory"]["types"] = [good]
    assert catalog.validate(descriptor)
    bound = {**good, "when": {"scope": ["group"]}, "plan": [{"always": True, "editions": ["cloud"]}, {"field": "keys"},
                                                             {"field": "sources", "option": "tokens"}]}
    descriptor["purposes"]["inventory"]["types"] = [bound]
    assert catalog.validate(descriptor)


def test_what_an_exposure_scan_reads_is_declared_by_every_scanning_provider():
    for provider, d in catalog.providers().items():
        exposure = d["purposes"].get("exposure")
        if exposure is not None:
            assert exposure.get("scans"), provider
            assert all(item["label_ko"] and item["description_ko"] for item in exposure["scans"]), provider
    descriptor = {"provider": "demo", "label": "Demo", "label_ko": "데모", "category": "saas",
                  "editions": [{"id": "cloud", "label": "Cloud", "label_ko": "클라우드"}],
                  "purposes": {"inventory": {"scans": [{"id": "files", "label": "Files", "label_ko": "파일"}]}},
                  "auth_methods": [{"id": "token", "label": "Token", "label_ko": "토큰", "renewal": "EXPIRES",
                                    "purposes": ["inventory"]}]}
    with pytest.raises(catalog.CatalogError, match="scans belong to the exposure scan"):
        catalog.validate(descriptor)
    descriptor["purposes"] = {"exposure": {"scans": [{"id": "files", "label": "Files", "label_ko": "파일", "description": "x"}]}}
    descriptor["auth_methods"][0]["purposes"] = ["exposure"]
    with pytest.raises(catalog.CatalogError, match="scan files"):
        catalog.validate(descriptor)


def test_every_type_binding_names_a_plan_option_its_provider_honours():
    # A bound type is collected through the plan option it names; children() must read that option.
    for provider, d in catalog.providers().items():
        plan = {field["name"] for field in (d["purposes"].get("inventory") or {}).get("plan") or []}
        for item in (d["purposes"].get("inventory") or {}).get("types") or []:
            for binding in item.get("plan") or []:
                assert binding.get("always") or binding["field"] in plan, (provider, item["id"])
