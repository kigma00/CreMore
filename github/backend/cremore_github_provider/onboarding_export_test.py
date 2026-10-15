"""Enterprise checks are read-only; separate cadences preserve old collections."""

from types import SimpleNamespace

import httpx
import pytest

from cremore.coverage.github_exports import applicable
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.onboarding import children, permissions, service
from cremore.onboarding.onboarding_test import PEM
from cremore_github_provider import onboarding
from cremore_github_provider.metadata.adapter import collect_pages, validate_spec
from cremore_github_provider.metadata.tests.fake import SECRETS, FakeBroker, enterprise_spec
from cremore_github_provider.metadata.tests.test_export_runtime import transport
from cremore_github_provider.onboarding_export import inventory_access


def connection(**extra):
    return {"provider": "github", "edition": "enterprise_cloud", "auth_method": "github_app",
            "target": {"organization": "acme", "enterprise": "acme-corp"},
            "secret_refs": {"credential": "vault://github/app", "audit_token": "vault://github/audit"}, **extra}


@pytest.mark.parametrize("patch,status,detail", [
    ({}, "GRANTED", "ENTERPRISE_INSTALLATION_PERMISSION_CONFIRMED"),
    ({"permissions": {}}, "MISSING", "GITHUB_ENTERPRISE_CREDENTIALS_READ_REQUIRED"),
    ({"suspended_at": "2026-10-05T00:00:00Z"}, "MISSING", "ENTERPRISE_INSTALLATION_SUSPENDED"),
    ({"app_id": 987}, "MISSING", "INSTALLATION_NOT_AUTHORIZED"),
    ({"account": {"slug": "another"}}, "MISSING", "INSTALLATION_NOT_AUTHORIZED"),
])
def test_preflight_verifies_enterprise_installation_and_permission_without_minting_or_creating(patch, status, detail):
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        assert request.method == "GET"
        if request.url.path == "/app":
            return httpx.Response(200, json={"id": 12345, "client_id": "Iv23liSYNTHETIC", "slug": "cremore",
                "owner": {"slug": "acme-corp", "type": "Enterprise"}, "permissions": {}})
        assert request.url.path == "/enterprises/acme-corp/installation"
        return httpx.Response(200, json={"id": 12, "app_id": 12345, "target_type": "Enterprise",
            "account": {"slug": "acme-corp"}, "permissions": {"enterprise_credentials": "read"}, **patch})

    context = SimpleNamespace(memo={}, http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    secret = onboarding.credential("github", "github_app", {"app_id": "12345", "installation_id": "12", "private_key": PEM})
    found = inventory_access(connection(), secret["credential"], context)
    assert (found["status"], found["detail"]) == (status, detail)
    assert inventory_access(connection(), secret["credential"], context) == found
    assert len(seen) == 2


def test_server_export_support_is_not_guessed_from_organization_access():
    def no_client():
        pytest.fail("An unsupported edition does not probe by creating an export")
    result = inventory_access(connection(edition="enterprise_server"), {}, SimpleNamespace(http_client=no_client))
    assert result["status"] == "NOT_REPORTED"
    assert result["detail"] == "GITHUB_ENTERPRISE_EXPORT_EDITION_UNSUPPORTED"


def test_server_lists_no_sso_authorized_types():
    """A Server has no organization SAML SSO credential authorizations (nor the Enterprise export) to list."""
    sso = {item["id"]: item for item in onboarding.INVENTORY_TYPES
           if any(rule.get("prefix") == "sso:" for rule in item["match"])}
    assert set(sso) == {"classic_pat", "oauth_app_token", "github_app_user_token", "ssh_key"}
    others = {edition["id"] for edition in onboarding.DESCRIPTORS[0]["editions"]} - {"enterprise_server"}
    assert all(set(item["editions"]) == others for item in sso.values())


def plan(**values):
    return service._fields(onboarding.DESCRIPTORS[0]["purposes"]["inventory"]["plan"], values,
        "enterprise_cloud", what="PLAN", target=connection()["target"])


def typed(child):
    spec = MetadataConnectionSpec.model_validate({**child["spec"],
        "secret_refs": {slot: "vault://github/" + slot for slot in child["secret_slots"]}})
    validate_spec(spec)
    return spec


def test_all_four_jobs_have_separate_scope_and_cadence_and_only_export_consumes_allowance():
    selected = plan(schedule_minutes=15, enterprise_schedule_minutes=1440, audit_schedule_minutes=5,
                    audit_events=True, enterprise_audit=True, token_digests=True)
    specs = [typed(child) for child in onboarding.children(connection(), "inventory", selected)]
    assert len(specs) == 4
    by_kind = {(s.options.mode, s.options.github_inventory): s for s in specs}
    assert by_kind["organization", True].schedule_minutes == 15
    assert by_kind["enterprise", True].schedule_minutes == 1440
    assert by_kind["enterprise", True].options.enterprise_only
    for mode in ("organization", "enterprise"):
        assert by_kind[mode, False].schedule_minutes == 5
        assert by_kind[mode, False].options.include_audit_events
        assert not by_kind[mode, True].options.include_audit_events
        assert not applicable(by_kind[mode, False])
    assert applicable(by_kind["enterprise", True])
    keys = [children._identity({"kind": "metadata", "spec": s.model_dump()}, "inventory") for s in specs]
    assert len(set(keys)) == 4


def test_disabling_enterprise_export_does_not_disable_enterprise_audit():
    specs = [typed(child) for child in onboarding.children(connection(), "inventory",
        plan(enterprise_inventory=False, enterprise_audit=True))]
    assert len(specs) == 2
    assert not any(applicable(s) for s in specs)
    assert any(s.options.mode == "enterprise" and s.options.include_audit_events for s in specs)


def test_legacy_mixed_jobs_keep_identity_and_split_edit_removes_only_their_inline_audit():
    legacy = {"schedule_minutes": 30, "audit_events": True, "audit_days": 7, "token_digests": True}
    # The common descriptor expansion supplies new defaults, but activating is
    # the saved plan that existed before the administrator made this edit.
    before = onboarding.children(connection(activating={"inventory": legacy}), "inventory", plan(**legacy))
    after = onboarding.children(connection(), "inventory", plan(**legacy, enterprise_audit=True))
    assert len(before) == 2 and all(typed(c).options.include_audit_events for c in before)
    assert len(after) == 4
    for old, new in zip(before, after, strict=False):
        assert children._identity(old, "inventory") == children._identity(new, "inventory")
        changed = children._apply_change(old["spec"], old["spec"], new["spec"])
        assert not changed["options"].get("include_audit_events", False)


def test_only_declared_schedule_changes_reuse_permission_evidence():
    record = connection()
    before = plan()
    after = {**before, "audit_schedule_minutes": 5, "enterprise_schedule_minutes": 2880}
    assert permissions.reductions_only(before, after, record=record, purpose="inventory")
    assert permissions.access_plan(before, record=record, purpose="inventory") == permissions.access_plan(after, record=record, purpose="inventory")
    assert not permissions.reductions_only(before, {**after, "enterprise_audit": True}, record=record, purpose="inventory")


def test_enterprise_audit_only_execution_never_requests_export_or_organization_inventory():
    seen = []
    spec = enterprise_spec(capabilities=["inventory", "audit"],
        secret_refs={**enterprise_spec().secret_refs, "audit_token": "vault://github/audit"},
        options={"enterprise_only": True, "github_inventory": False, "include_audit_events": True, "audit_scope": "enterprise"})

    def handler(request):
        seen.append((request.method, request.url.path))
        assert request.method == "GET" and request.url.path.endswith("/audit-log")
        return httpx.Response(200, json=[])

    pages = list(collect_pages(spec, secrets={**SECRETS, "audit_token": "ghp_" + "x" * 36}, checkpoint={},
        check=lambda: None, transport=transport(handler), broker=FakeBroker()))
    assert pages[-1].status == "COMPLETE"
    assert len(seen) == 1
