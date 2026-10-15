"""Slack in the connection wizard against a synthetic Slack: the token it takes, the check and the collection."""

import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import catalog, service
from cremore.onboarding.onboarding_test import SETTINGS, activate, checked, refused, run_check
from cremore_slack_provider import onboarding

ORG = "E0SYNTH01"
# Built at run time: a literal in the source would read as a Slack token to secret scanners.
TOKEN = "xox" + "p-" + "synthetic-admin-fixture-" + "0" * 12
BODY = {"provider": "slack", "purposes": ["inventory"], "auth_method": "token", "target": {"organization": "e0synth01"},
        "credential": {"token": TOKEN}}


def slack(enterprise=ORG, *, auth="ok", apps="ok", audit="ok"):
    """A Slack that answers the three reads the check makes, each ok or refused with the given error."""
    seen = []

    def handler(request):
        seen.append(request)
        assert request.headers["authorization"] == "Bearer " + TOKEN and request.method == "GET"
        if request.url.path == "/api/auth.test":
            if auth != "ok":
                return httpx.Response(200, json={"ok": False, "error": auth})
            return httpx.Response(200, json={"ok": True, "url": "https://synthetic.enterprise.slack.com/",
                                             "team_id": enterprise, "user_id": "W0SYNTH01", "enterprise_id": enterprise})
        if request.url.path == "/api/admin.apps.approved.list":
            assert request.url.params["enterprise_id"] == ORG and request.url.params["limit"] == "1"
            if apps != "ok":
                return httpx.Response(200, json={"ok": False, "error": apps})
            return httpx.Response(200, json={"ok": True, "approved_apps": [], "response_metadata": {"next_cursor": ""}})
        if request.url.host == "api.slack.com" and request.url.path == "/audit/v1/logs":
            if audit != "ok":
                return httpx.Response(403, json={"ok": False, "error": audit})
            return httpx.Response(200, json={"entries": []})
        return httpx.Response(404)

    factory = lambda: httpx.Client(transport=httpx.MockTransport(handler))
    factory.seen = seen
    return factory


def results(view):
    return {row["permission"]: (row["status"], row.get("detail")) for row in view["checks"]["results"]["inventory"]["items"]}


def test_an_organization_admin_user_token_is_what_slack_takes():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, BODY, "admin")
    assert record["target"] == {"organization": ORG} and record["name"] == "Slack · E0SYNTH01"
    assert TOKEN not in str(record) and record["credential"]["roles"] == ["credential"]
    bot = "xox" + "b-" + "0" * 30
    assert refused(service.create, repo, SETTINGS, {**BODY, "credential": {"token": bot}}, "admin") == (
        "SLACK_ADMIN_USER_TOKEN_REQUIRED")
    assert refused(service.create, repo, SETTINGS, {**BODY, "credential": {"token": "xoxe." + TOKEN}}, "admin") == (
        "SLACK_ROTATING_TOKEN_NOT_SUPPORTED")
    assert refused(service.create, repo, SETTINGS, {**BODY, "target": {"organization": "acme.slack.com"}}, "admin") == (
        "SLACK_ORGANIZATION_ID_INVALID")
    # The wizard's card lists the three credentials an app's scopes imply.
    [descriptor] = [item for item in catalog.public() if item["provider"] == "slack"]
    assert [kind["id"] for kind in descriptor["purposes"]["inventory"]["types"]] == ["bot_token", "user_token",
                                                                                      "incoming_webhook"]
    assert catalog.inventory_type("slack", {"provider": "slack", "object_id": f"hook:{ORG}:A0SYNTH01", "facts": {},
                                            "object_kind": "credential"})["credential_type"] == "SLACK_WEBHOOK"


def test_the_check_reads_the_approved_list_and_asks_the_audit_log():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, BODY, "admin")
    service.request_check(repo, record["id"], "admin", {"plans": {"inventory": {"audit_events": True}}})
    answered = slack(audit="missing_scope")
    view = run_check(repo, record, answered)
    assert results(view) == {"admin_apps_read": ("GRANTED", None), "auditlogs_read": ("MISSING", "SLACK_SCOPE_MISSING")}
    assert [request.url.path for request in answered.seen] == ["/api/auth.test", "/api/admin.apps.approved.list",
                                                                "/audit/v1/logs"]
    # A token of another organization, a refused token and a non-admin are each named.
    for server, detail in ((slack("E0OTHER01"), "SLACK_ANOTHER_ORGANIZATION"),
                           (slack(auth="invalid_auth"), "SLACK_TOKEN_REJECTED")):
        service.request_check(repo, record["id"], "admin")
        assert set(results(run_check(repo, record, server)).values()) == {("MISSING", detail)}
    service.request_check(repo, record["id"], "admin")
    assert results(run_check(repo, record, slack(apps="not_an_admin")))["admin_apps_read"] == (
        "MISSING", "NOT_AN_ADMINISTRATOR")


def test_activation_makes_one_collection_whose_audit_log_follows_the_plan():
    repo = InMemoryRepository()
    record = checked(repo, BODY)
    [row] = activate(repo, record, {"inventory": {"audit_events": True, "schedule_minutes": 360}})["created"]
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert spec["provider"] == "slack" and spec["scopes"] == [{"kind": "enterprise", "id": ORG}]
    assert spec["capabilities"] == ["inventory", "audit"] and spec["schedule_minutes"] == 360
    assert spec["options"]["include_audit_events"] is True and spec["options"]["audit_lookback_days"] == 90
    assert spec["options"]["requests_per_second"] == 0.3
    # Turned off later, from the next run: the collection reads the approved list only.
    service.update_plan(repo, SETTINGS, record["id"], "inventory", {"plan": {"schedule_minutes": 360}}, "admin")
    spec = CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]
    assert spec["capabilities"] == ["inventory"] and spec["options"]["include_audit_events"] is False
    assert spec["options"]["audit_lookback_days"] is None
    # A workspace of the organization is its own scope.
    workspace = checked(repo, {**BODY, "target": {"organization": "T0SYNTH02"}})
    [row] = activate(repo, workspace, {"inventory": {}})["created"]
    assert CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]["scopes"] == [{"kind": "workspace", "id": "T0SYNTH02"}]


def test_the_audit_scope_counts_only_while_the_audit_log_option_is_on():
    # The check still answers it truthfully; the wizard and the row leave it out while the option is off.
    descriptor = catalog.descriptor("slack")
    permissions = {p["id"]: p for p in descriptor["purposes"]["inventory"]["permissions"]}
    assert permissions["auditlogs_read"]["option"] == "audit_events" and "option" not in permissions["admin_apps_read"]
    broken = {**descriptor, "purposes": {"inventory": {**descriptor["purposes"]["inventory"], "permissions": [
        {**permissions["auditlogs_read"], "option": "schedule_minutes"}]}}}
    with pytest.raises(catalog.CatalogError, match="permission auditlogs_read: option"):
        catalog.validate(broken)  # an option is a bool plan choice of the same purpose


def test_enterprise_workspace_discovery_and_selected_membership_use_the_same_pages():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert request.method == "GET" and request.url.host == "slack.com"
        if request.url.path == "/api/auth.test":
            return httpx.Response(200, json={"ok": True, "user_id": "U0SYNTH01", "enterprise_id": ORG,
                                             "team_id": "T0SYNTH01"})
        if request.url.path == "/api/admin.teams.list":
            assert "enterprise_id" not in request.url.params
            cursor = request.url.params.get("cursor")
            assert cursor in (None, "synthetic-page-2")
            return httpx.Response(200, json={"ok": True, "teams": [{"id": "T0SYNTH02" if cursor else "T0SYNTH01"}],
                "response_metadata": {"next_cursor": "" if cursor else "synthetic-page-2"}})
        assert request.url.path == "/api/admin.apps.approved.list"
        assert request.url.params["team_id"] == "T0SYNTH02"
        return httpx.Response(200, json={"ok": True, "approved_apps": []})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    secrets = {"credential": {"token": TOKEN}}
    first, completeness, cursor = onboarding.discover({}, secrets, context)
    assert [r["target"]["organization"] for r in first] == [ORG, "T0SYNTH01"]
    assert completeness == "PARTIAL" and cursor == {"next": "synthetic-page-2", "seen": ["synthetic-page-2"]}
    second, completeness, cursor = onboarding.discover({"discovery_cursor": cursor}, secrets, context)
    assert [r["target"]["organization"] for r in second] == ["T0SYNTH02"]
    assert completeness == "COMPLETE" and cursor is None
    results = onboarding.check({"target": {"organization": "T0SYNTH02"}}, "inventory", secrets, context)
    assert results == [{"permission": "admin_apps_read", "status": "GRANTED"},
                       {"permission": "auditlogs_read", "status": "NOT_REPORTED", "detail": "NOT_SELECTED"}]
    calls.clear()
    rejected = onboarding.check({"target": {"organization": "T0OTHER01"}}, "inventory", secrets, context)
    assert {r["detail"] for r in rejected} == {"SLACK_ANOTHER_ORGANIZATION"}
    assert "/api/admin.apps.approved.list" not in calls


def test_without_the_workspace_list_scope_the_organization_itself_is_offered():
    """The wizard's app asks only for admin.apps:read: the org-wide approved list needs no workspace list, so a missing
    admin.teams:read offers the organization alone instead of failing; a workspace target still needs it."""
    def handler(request):
        if request.url.path == "/api/auth.test":
            return httpx.Response(200, json={"ok": True, "user_id": "U0SYNTH01", "enterprise_id": ORG})
        if request.url.path == "/api/admin.teams.list":
            return httpx.Response(200, json={"ok": False, "error": "missing_scope", "needed": "admin.teams:read"})
        assert request.url.path == "/api/admin.apps.approved.list" and request.url.params["enterprise_id"] == ORG
        return httpx.Response(200, json={"ok": True, "approved_apps": []})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    secrets = {"credential": {"token": TOKEN}}
    assert onboarding.discover({}, secrets, context) == ([{"label": ORG, "target": {"organization": ORG}}], "COMPLETE")
    results = onboarding.check({"target": {"organization": ORG}}, "inventory", secrets, context)
    assert results[0] == {"permission": "admin_apps_read", "status": "GRANTED"}
    workspace = onboarding.check({"target": {"organization": "T0SYNTH02"}}, "inventory", secrets, context)
    assert {r["detail"] for r in workspace} == {"SLACK_TEAMS_READ_REQUIRED"}


@pytest.mark.parametrize("body,code", [
    ({"ok": False, "error": "not_an_admin"}, "NOT_AN_ADMINISTRATOR"),
    ({"ok": True, "teams": [{"id": "E0OTHER01"}]}, "SLACK_INVALID_RESPONSE"),
    ({"ok": True, "teams": [], "response_metadata": {"next_cursor": "https://untrusted.invalid/"}},
     "SLACK_INVALID_CURSOR"),
])
def test_workspace_list_refusal_and_unsafe_pages_never_become_empty_success(body, code):
    def handler(request):
        if request.url.path == "/api/auth.test":
            return httpx.Response(200, json={"ok": True, "user_id": "U0SYNTH01", "enterprise_id": ORG})
        assert request.url.path == "/api/admin.teams.list"
        return httpx.Response(200, json=body)

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(ValueError, match=code):
        onboarding.discover({}, {"credential": {"token": TOKEN}}, context)
    results = onboarding.check({"target": {"organization": "T0SYNTH02"}}, "inventory",
                               {"credential": {"token": TOKEN}}, context)
    assert all(r["status"] != "GRANTED" for r in results) and TOKEN not in str(results)


def test_workspace_discovery_refuses_cursor_cycle_across_more_requests():
    def handler(request):
        if request.url.path == "/api/auth.test":
            return httpx.Response(200, json={"ok": True, "user_id": "U0SYNTH01", "enterprise_id": ORG})
        return httpx.Response(200, json={"ok": True, "teams": [], "response_metadata": {"next_cursor": "page-a"}})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(onboarding.OnboardingValueError, match="SLACK_CURSOR_CYCLE"):
        onboarding.discover({"discovery_cursor": {"next": "page-b", "seen": ["page-a", "page-b"]}},
                            {"credential": {"token": TOKEN}}, context)
