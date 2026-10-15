"""List access never proves access to Key Vault values or storage account keys."""

from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from cremore.onboarding import catalog, check, permissions, service, targets
from cremore_azure_provider import onboarding

TENANT = "11111111-2222-4333-8444-555555555555"
SUBSCRIPTIONS = ["11111111-2222-4333-8444-555555555556", "11111111-2222-4333-8444-555555555557"]
ACCOUNTS = [f"/subscriptions/{s}/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/teststore{i}"
            for i, s in enumerate(SUBSCRIPTIONS)]


@pytest.mark.parametrize("purpose,plan,permission", [
    ("vault", {"read_values": True}, "key_vault_values"),
    ("inventory", {"storage_key_accounts": ACCOUNTS[:1]}, "storage_keys_read"),
])
def test_value_read_options_remain_unverified_without_reading_values(monkeypatch, purpose, plan, permission):
    monkeypatch.setattr(onboarding, "_bearer", lambda *_: {"Authorization": "Bearer synthetic"})
    record = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "secret_refs": {},
              "target": {"tenant": TENANT, "subscription": SUBSCRIPTIONS[0], "key_vaults": ["synthetic-vault"]},
              "purposes": [purpose], "plans": {}, "checks": {"requested_plans": {purpose: plan}}}

    def handler(request):
        assert request.method == "GET"
        assert request.url.path in {"/v1.0/applications", "/v1.0/organization", "/secrets", "/subscriptions/" + SUBSCRIPTIONS[0]}
        return httpx.Response(200, json={"value": []})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    record["checks"].update(results=check.evaluate(record, {}, context), checked_at=datetime.now(UTC).isoformat(),
                           digest=service.check_digest(record))
    blockers = permissions.blockers(record, {purpose: plan})
    assert blockers and {b["permission"] for b in blockers} == {permission}
    assert all(b["status"] == "NOT_REPORTED" and b["detail"] == "VALUE_READ_PERMISSION_NOT_CHECKED" for b in blockers)
    assert permission not in {p["id"] for p in permissions.required(record, purpose, {})}


def test_multiple_subscriptions_receive_only_their_own_selected_key_accounts():
    roots = [{"tenant": TENANT, "subscription": s} for s in SUBSCRIPTIONS]
    record = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "purposes": ["inventory"],
              "target": {"version": 2, "roots": [{"id": targets.target_id(r), "target": r} for r in roots]}}
    plan = {"storage_key_accounts": ACCOUNTS}
    for root, account in zip(targets.records_of(record), ACCOUNTS, strict=True):
        children = onboarding.children(root, "inventory", plan)
        arm = next(c["spec"] for c in children if c["spec"]["provider"] == "azure_resource_manager")
        assert arm["options"]["azure_storage_accounts"] == [account]
        assert onboarding.permission_plan(root, "inventory", plan)["storage_key_accounts"] == [account]
    assert "storage_keys_read" not in {p["id"] for p in permissions.required(
        targets.records_of(record)[1], "inventory", {"storage_key_accounts": ACCOUNTS[:1]})}


def test_selected_vault_resources_reach_the_collector_without_value_access():
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore_azure_provider.metadata.adapter import validate_spec

    record = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "secret_refs": {},
              "target": {"tenant": TENANT, "key_vaults": ["synthetic-vault"]}, "purposes": ["vault"]}
    plan = {"versions": True, "deleted": True, "keys": True, "public_certificates": True}
    [child] = onboarding.children(record, "vault", plan)
    model = MetadataConnectionSpec.model_validate(child["spec"])
    validate_spec(model)
    assert set(model.options.sources) == {"secrets", "versions", "deleted_secrets", "keys", "key_versions",
        "deleted_keys", "certificates", "certificate_versions", "deleted_certificates", "public_certificates"}
    assert not model.options.include_values and "vault_value" not in model.capabilities
    required = {p["id"] for p in permissions.required(record, "vault", plan)}
    assert {"key_vault_keys", "key_vault_certificates", "key_vault_deleted", "key_vault_public_certificates"} <= required
    assert "key_vault_values" not in required


def test_missing_key_permission_cannot_be_hidden_by_successful_secret_listing(monkeypatch):
    monkeypatch.setattr(onboarding, "_bearer", lambda *_: {"Authorization": "Bearer synthetic"})
    record = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "secret_refs": {},
              "target": {"tenant": TENANT, "key_vaults": ["synthetic-vault"]}, "purposes": ["vault"],
              "plans": {}, "checks": {"requested_plans": {"vault": {"keys": True}}}}
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(403 if request.url.path == "/keys" else 200, json={"value": []}))))
    record["checks"].update(results=check.evaluate(record, {}, context), checked_at=datetime.now(UTC).isoformat(),
                           digest=service.check_digest(record))
    assert {p["permission"] for p in permissions.blockers(record, record["checks"]["requested_plans"])} == {"key_vault_keys"}


@pytest.mark.parametrize("certificate_id,expected", [
    ("https://synthetic-vault.vault.azure.net/certificates/test", "MISSING"),
    ("https://other-vault.vault.azure.net/certificates/test", "NOT_REPORTED"),
    (None, "NOT_REPORTED"),
])
def test_public_certificate_preflight_uses_only_approved_vault(monkeypatch, certificate_id, expected):
    monkeypatch.setattr(onboarding, "_bearer", lambda *_: {"Authorization": "Bearer synthetic"})
    record = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity",
              "target": {"tenant": TENANT, "key_vaults": ["synthetic-vault"]},
              "purposes": ["vault"], "plans": {"vault": {"public_certificates": True}}}
    seen = []

    def handler(request):
        seen.append(request.url.path)
        assert request.url.host == "synthetic-vault.vault.azure.net"
        if request.url.path == "/certificates/test":
            return httpx.Response(403)
        return httpx.Response(200, json={"value": [{"id": certificate_id}] if certificate_id else []})

    ctx = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    rows = onboarding.check(record, "vault", {}, ctx)
    assert [r["status"] for r in rows if r["permission"] == "key_vault_public_certificates"] == [expected]
    assert ("/certificates/test" in seen) == (expected == "MISSING")


@pytest.mark.parametrize("edition,target,version", [
    ("server", {"base_url": "https://devops.example.test/tfs", "organization": "DefaultCollection", "project": "Web"},
     "5.0"),
    ("cloud", {"organization": "acme", "project": "Web"}, "7.1"),
])
def test_devops_code_read_check_uses_the_editions_api_version(edition, target, version):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        # A Server refuses an API version newer than it ships (Server 2019 answers 5.0 at most).
        if request.url.params.get("api-version") != version:
            return httpx.Response(400)
        return httpx.Response(200, json={"value": []})

    record = {"provider": "azure_devops", "edition": edition, "auth_method": "token", "target": target,
              "purposes": ["exposure"]}
    ctx = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    rows = onboarding.check(record, "exposure", {"credential": {"token": "synthetic-token-value-1234"}}, ctx)
    assert [(r["permission"], r["status"]) for r in rows] == [("code_read", "GRANTED")]
    assert seen and seen[0].startswith(target.get("base_url", "https://dev.azure.com"))


@pytest.mark.parametrize("project,valid", [("웹 서비스 (운영)", True), ("a" * 64, True), ("a/b", False), ("a" * 65, False)])
def test_microsoft_connection_accepts_the_devops_project_names_azure_devops_accepts(project, valid):
    from cremore_azure_provider.devops_content import valid_name

    values = {"tenant": TENANT, "devops_organization": "acme", "devops_project": project}
    assert valid_name(project) is valid
    if valid:
        assert onboarding.target("azure", "cloud", values)["devops_project"] == project
        assert onboarding.target("azure_devops", "cloud", {"organization": "acme", "project": project})["project"] == project
    else:
        with pytest.raises(onboarding.OnboardingValueError, match="AZURE_DEVOPS_PROJECT_INVALID"):
            onboarding.target("azure", "cloud", values)


@pytest.mark.parametrize("provider", ["azure", "entra_id"])
@pytest.mark.parametrize("status_code,status", [(200, "GRANTED"), (403, "MISSING")])
def test_people_permissions_declare_and_probe_organization_read(monkeypatch, provider, status_code, status):
    monkeypatch.setattr(onboarding, "_bearer", lambda *_: {"Authorization": "Bearer synthetic"})
    record = {"provider": provider, "edition": "cloud", "auth_method": "workload_identity",
              "target": {"tenant": TENANT}, "purposes": ["identity"]}
    declared = {p["id"]: p for p in catalog.permissions_for(provider, "identity", "workload_identity", {"tenant": TENANT})}
    permission = declared["organization_read"]
    # Needed only for a token whose tid cannot be read: shown by the check, never holding back activation.
    assert "organization_read" not in {p["id"] for p in permissions.required(record, "identity", {})}
    assert "Organization.Read.All" in permission["label"] and "Organization.Read.All" in permission["label_ko"]
    assert "tid" in permission["description"] and "tid" in permission["description_ko"]
    asked = []

    def handler(request):
        asked.append(request.url.path)
        if request.url.path == "/v1.0/organization":
            assert dict(request.url.params) == {"$select": "id"}
            return httpx.Response(status_code, json={"value": [{"id": TENANT}]})
        assert request.url.path == "/v1.0/users"
        return httpx.Response(200, json={"value": []})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    rows = {r["permission"]: r for r in onboarding.check(record, "identity", {}, context)}
    assert rows["organization_read"]["status"] == status
    assert rows["users_read"]["status"] == "GRANTED"
    assert asked.count("/v1.0/organization") == 1


@pytest.mark.parametrize("provider", ["azure", "entra_id"])
def test_missing_organization_permission_does_not_block_activation_or_readable_tid_collection(monkeypatch, provider):
    from cremore_azure_provider.entra_id import entra_id_test as directory

    token = directory.jwt({"tid": directory.TENANT})
    monkeypatch.setattr(onboarding, "_bearer", lambda *_: {"Authorization": "Bearer " + token})
    monkeypatch.setattr(directory.identity, "token_for_spec", lambda _spec: (lambda: token))
    record = {"provider": provider, "edition": "cloud", "auth_method": "workload_identity", "secret_refs": {},
              "target": {"tenant": directory.TENANT}, "purposes": ["identity"], "plans": {"identity": {}},
              "checks": {"requested_plans": {"identity": {}}}}
    asked = []

    def handler(request):
        asked.append(request.url.path)
        assert request.headers["Authorization"] == "Bearer " + token
        if request.url.path == "/v1.0/organization":
            return httpx.Response(403)
        if request.url.params.get("$top") == "1":
            return httpx.Response(200, json={"value": []})
        return directory.graph(httpx.Request(request.method, request.url, headers={"Authorization": "Bearer graph-token"}))

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    record["checks"].update(results=check.evaluate(record, {}, context), checked_at=datetime.now(UTC).isoformat(),
                            digest=service.check_digest(record))
    items = record["checks"]["results"]["identity"]["items"]
    assert next(item for item in items if item["permission"] == "organization_read")["status"] == "MISSING"
    assert permissions.blockers(record, {"identity": {}}) == []
    permissions.require(record, {"identity": {}})
    asked.clear()
    rows, final = directory.run(directory.spec(), handler)
    assert final.status == "COMPLETE"
    assert len([row for row in rows if row["record_type"] == "entity_observation"]) == 3
    assert asked and "/v1.0/organization" not in asked
