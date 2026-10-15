"""Permission evidence covers value reads without retrieving any secret value."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from cremore.onboarding import check, permissions, service
from cremore_gcp_provider import onboarding


@pytest.mark.parametrize("plans", [
    {"vault": {"read_values": True}},
    {"inventory": {"read_values": True}, "vault": {"read_values": False}},
    {"inventory": {"read_values": False}, "vault": {"read_values": True}},
])
def test_selected_or_shared_value_reads_require_their_own_permissions(monkeypatch, plans):
    monkeypatch.setattr(onboarding, "_token", lambda *_: "synthetic-token")
    record = {"provider": "gcp", "edition": "cloud", "auth_method": "adc", "secret_refs": {},
              "target": {"scope": "project", "project": "synthetic-project"}, "purposes": list(plans),
              "plans": {}, "checks": {"requested_plans": plans}}
    value_access, asked = False, []

    def handler(request):
        assert request.method == "POST" and request.url.path.endswith(":testIamPermissions")
        wanted = json.loads(request.content)["permissions"]
        asked.extend(wanted)
        return httpx.Response(200, json={"permissions": [p for p in wanted
            if value_access or p not in {"apikeys.keys.getKeyString", "secretmanager.versions.access"}]})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    for allowed in (False, True):
        value_access = allowed
        results = check.evaluate(record, {}, context)
        record["checks"].update(results=results, checked_at=datetime.now(UTC).isoformat(),
                               digest=service.check_digest(record))
        blockers = permissions.blockers(record, plans)
        assert bool(blockers) is not allowed
        if not allowed:
            assert {b["permission"] for b in blockers} == {"apikeys.keys.getKeyString", "secretmanager.versions.access"}
    assert {"apikeys.keys.getKeyString", "secretmanager.versions.access"} <= set(asked)


def test_inventory_only_value_check_does_not_require_secret_manager(monkeypatch):
    monkeypatch.setattr(onboarding, "_token", lambda *_: "synthetic-token")
    requested = []

    def handler(request):
        requested.extend(json.loads(request.content)["permissions"])
        return httpx.Response(200, json={"permissions": requested})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    record = {"auth_method": "adc", "target": {"project": "synthetic-project"}, "purposes": ["inventory"],
              "checks": {"requested_plans": {"inventory": {"read_values": True}}}}
    onboarding.check(record, "inventory", {}, context)
    assert "apikeys.keys.getKeyString" in requested
    assert not any(p.startswith("secretmanager.") for p in requested)


def test_project_alias_resolution_permission_is_visible_but_not_required_for_exact_ids():
    record = {"provider": "gcp", "edition": "cloud", "auth_method": "adc",
              "target": {"scope": "project", "project": "synthetic-project"}, "purposes": ["inventory", "vault"]}
    for purpose in ("inventory", "vault"):
        declared = next(p for p in onboarding._permissions(purpose) if p["id"] == "resourcemanager.projects.get")
        assert declared["required"] is False
        assert "resourcemanager.projects.get" not in {p["id"] for p in permissions.required(record, purpose, {})}


def test_inventory_audit_is_independent_of_vault_and_shared_plans_keep_approved_locations():
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore_gcp_provider.metadata.adapter import _enabled, validate_spec

    record = {"provider": "gcp", "edition": "cloud", "auth_method": "adc", "secret_refs": {},
              "target": {"scope": "project", "project": "synthetic-project"}, "purposes": ["inventory"]}
    plans = {"inventory": {"audit_logs": True, "audit_days": 7}}
    [(_, child)] = service._described(onboarding, record, plans)
    spec = MetadataConnectionSpec.model_validate(child["spec"])
    validate_spec(spec)
    assert "vault_metadata" not in spec.capabilities and not spec.options.include_values
    assert _enabled(spec, "relations_activity") and _enabled(spec, "relations_key_creation")
    assert not _enabled(spec, "relations_api_metrics") and not _enabled(spec, "relations_secret_iam")
    assert {"logging.logEntries.list", "logging.privateLogEntries.list", "apikeys.keys.list"} <= {
        p["id"] for p in permissions.required(record, "inventory", plans["inventory"])}
    record["purposes"].append("vault")
    plans["vault"] = {"locations": ["asia-northeast3"], "secret_iam": True, "audit_days": 1}
    [(_, child)] = service._described(onboarding, record, plans)
    spec = MetadataConnectionSpec.model_validate(child["spec"])
    validate_spec(spec)
    assert spec.options.locations == ["asia-northeast3"] and spec.options.audit_lookback_days == 7
    assert _enabled(spec, "relations_secret_iam") and _enabled(spec, "relations_secret_access")


def test_audit_permission_denial_blocks_activation_without_reading_logs(monkeypatch):
    monkeypatch.setattr(onboarding, "_token", lambda *_: "synthetic-token")
    record = {"provider": "gcp", "edition": "cloud", "auth_method": "adc", "secret_refs": {},
              "target": {"scope": "project", "project": "synthetic-project"}, "purposes": ["inventory"],
              "plans": {}, "checks": {"requested_plans": {"inventory": {"audit_logs": True}}}}

    def handler(request):
        assert request.url.path.endswith(":testIamPermissions")
        return httpx.Response(200, json={"permissions": [p for p in json.loads(request.content)["permissions"]
                                                        if p != "logging.privateLogEntries.list"]})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    record["checks"].update(results=check.evaluate(record, {}, context), checked_at=datetime.now(UTC).isoformat(),
                           digest=service.check_digest(record))
    assert {p["permission"] for p in permissions.blockers(record, record["checks"]["requested_plans"])} == {
        "logging.privateLogEntries.list"}
