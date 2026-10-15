"""Selected access is enforced by the service, including old API entry points."""

from datetime import UTC, datetime, timedelta

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import permissions, service
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.onboarding.store import ProviderConnectionStore


def draft():
    repo = InMemoryRepository()
    view = service.create(repo, SETTINGS, {"provider": "notion", "edition": "enterprise", "purposes": ["inventory"],
        "auth_method": "organization_bot", "target": {"workspace": "00000000-0000-0000-0000-000000000001"},
        "credential": {"token": "synthetic-credential-for-offline-test"}}, "admin")
    return repo, ProviderConnectionStore(repo).get(view["id"])


def answered(repo, record, plan, status="GRANTED", **extra):
    candidate = {**record, "checks": {"requested_plans": {"inventory": plan}}}
    checks = {**candidate["checks"], "digest": service.check_digest(candidate),
              "checked_at": datetime.now(UTC).isoformat(), "results": {"inventory": {"items": [
                  {"permission": "workspace_tokens", "status": status},
                  {"permission": "mcp_connections", "status": "MISSING"}]}}, **extra}
    return ProviderConnectionStore(repo).update(record["id"], record["revision"], "worker", status="CHECKED", checks=checks)


PLAN = {"schedule_minutes": 0, "personal_access_tokens": True, "mcp_connections": False}


@pytest.mark.parametrize("state", ["MISSING", "ERROR", "NOT_REPORTED"])
def test_finished_check_does_not_authorize_missing_required_access(state):
    repo, record = draft()
    record = answered(repo, record, PLAN, state)
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        service.activate(repo, SETTINGS, record["id"], {"purposes": {"inventory": PLAN}}, "admin")
    assert not ProviderConnectionStore(repo).children(record["id"])


def test_unselected_permissions_do_not_block_but_new_choices_require_a_check():
    repo, record = draft()
    record = answered(repo, record, PLAN)
    result = service.activate(repo, SETTINGS, record["id"], {"purposes": {"inventory": PLAN}}, "admin")
    assert result["status"] == "ACTIVE"
    with pytest.raises(service.OnboardingError, match="PERMISSION_CHECK_REQUIRED"):
        service.update_plan(repo, SETTINGS, record["id"], "inventory", {"plan": {**PLAN, "mcp_connections": True}}, "admin")


def test_stale_or_future_check_is_not_permission_and_reductions_remain_available():
    repo, record = draft()
    now = datetime.now(UTC)
    record = answered(repo, record, PLAN)
    assert permissions.blockers(record, {"inventory": PLAN}, now=now + timedelta(hours=1))
    assert permissions.blockers(record, {"inventory": PLAN}, now=now - timedelta(hours=1))
    assert permissions.reductions_only(PLAN, {**PLAN, "schedule_minutes": 60})
    assert not permissions.reductions_only({"cloudtrail_creation_only": True}, {"cloudtrail_creation_only": False})
    assert not permissions.reductions_only({"prefixes": ["private/"]}, {"prefixes": []})
    assert not permissions.reductions_only(PLAN, {**PLAN, "mcp_connections": True})
