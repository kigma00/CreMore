"""Synthetic Slack admin and audit log contracts; all HTTP is handled by httpx.MockTransport."""

from datetime import UTC, datetime

import httpx
import pytest
from cremore_slack_provider.metadata import API_ORIGIN, AUDIT_ACTIONS
from cremore_slack_provider.metadata.adapter import (
    _compare_runs,
    collect_pages,
    native_snapshots,
    validate_record,
    validate_spec,
)

from cremore.coverage.facts import unpack_facts
from cremore.coverage.metadata_models import MetadataConnectionSpec

ORG = "E0SYNTH01"
# Built at run time: a literal in the source would read as a Slack token to secret scanners.
BEARER = "xox" + "p-" + "synthetic-admin-fixture-" + "0" * 12
STAMP = datetime(2026, 9, 28, tzinfo=UTC)
DAY = 86400


def spec(*, audit=False, **patch):
    values = {"name": "Synthetic Slack", "provider": "slack", "origin": API_ORIGIN,
              "scopes": [{"kind": "enterprise", "id": ORG}], "capabilities": ["inventory"] + (["audit"] if audit else []),
              "auth_type": "bearer", "secret_refs": {"token": "vault://slack/admin"},
              "options": {"requests_per_second": 1.0, **({"include_audit_events": True} if audit else {})}}
    values.update(patch)
    return MetadataConnectionSpec.model_validate(values)


def approved(app_id, name, *, bot=(), user=(), updated=1788220800, **extra):
    scopes = [{"name": scope, "description": "synthetic", "is_sensitive": False, "token_type": "bot"} for scope in bot]
    scopes += [{"name": scope, "description": "synthetic", "is_sensitive": False, "token_type": "user"} for scope in user]
    return {"app": {"id": app_id, "name": name, "description": "synthetic app", "developer_type": "internal",
                    "is_internal": True, "icons": {"image_32": "https://example.test/32.png"}, **extra},
            "scopes": scopes, "date_updated": updated, "last_resolved_by": {"actor_id": "W0SYNTH01", "actor_type": "user"}}


def page(key, *items, cursor=""):
    return {"ok": True, key: list(items), "response_metadata": {"next_cursor": cursor}}


def entry(action, app_id, at, *, user="W0SYNTH02", name="Synthetic App", bot=None, scopes=None, workspace=None):
    app = {"id": app_id, "name": name, "is_distributed": False, "is_directory_approved": False, "is_workflow_app": False}
    if bot is not None:
        app["bot_scopes"] = bot
    if scopes is not None:
        app["scopes"] = scopes
    location = {"type": "workspace", "id": workspace} if workspace else {"type": "enterprise", "id": ORG}
    return {"id": "synthetic-" + action + app_id + str(at), "date_create": at, "action": action,
            "actor": {"type": "user", "user": {"id": user, "name": "Synthetic Admin", "email": "admin@example.test"}},
            "entity": {"type": "app", "app": app}, "context": {"location": location, "ua": "", "ip_address": ""}}


def client_for(responses, requests):
    def handle(request):
        requests.append(request)
        response = responses.pop(0)
        if isinstance(response, httpx.Response):
            return response
        return httpx.Response(200, json=response)

    return httpx.Client(transport=httpx.MockTransport(handle))


def run(responses, *, connection=None, checkpoint=None, prior=()):
    requests = []
    with client_for(list(responses), requests) as client:
        pages = list(collect_pages(connection or spec(), secrets={"token": BEARER}, checkpoint=checkpoint or {},
                                   check=lambda: None, read_records=lambda: iter(prior), client=client, now=STAMP,
                                   sleep=lambda seconds: None))
    return pages, requests


def records(pages):
    return [record for item in pages for record in item.records]


def facts(record):
    return unpack_facts([fact.model_dump() for fact in record.facts])


def test_an_approved_app_is_its_bot_token_the_user_tokens_and_its_webhook():
    first = approved("A0SYNTH01", "Deploy bot", bot=["chat:write", "incoming-webhook"], user=["search:read"])
    second = approved("A0SYNTH02", "Reader", bot=["channels:read"])
    pages, requests = run([page("approved_apps", first, cursor="c2"), page("approved_apps", second)])
    rows = {record.identity.object_id: record for record in records(pages) if record.record_type == "entity_observation"}
    assert set(rows) == {f"bot:{ORG}:A0SYNTH01", f"user:{ORG}:A0SYNTH01", f"hook:{ORG}:A0SYNTH01", f"bot:{ORG}:A0SYNTH02"}
    bot = facts(rows[f"bot:{ORG}:A0SYNTH01"])
    assert bot == {"app_id": "A0SYNTH01", "name": "Deploy bot", "token_type": "bot",
                   "scopes": ["chat:write", "incoming-webhook"], "developer_type": "internal", "is_internal": True,
                   "approved_at": "2026-09-01T00:00:00+00:00", "approved_by": {"id": "W0SYNTH01", "type": "user"}}
    assert facts(rows[f"user:{ORG}:A0SYNTH01"])["scopes"] == ["search:read"]
    assert "scopes" not in facts(rows[f"hook:{ORG}:A0SYNTH01"])
    # The approved list does not say an app is installed.
    assert {(row.provider_state, row.normalized_state, row.state_basis) for row in rows.values()} == {
        ("APPROVED", "UNKNOWN", "UNKNOWN")}
    reports = {record.provenance.operation: record for record in records(pages) if record.record_type == "operation_report"}
    assert reports["slack.approved_apps"].status == "COMPLETE" and reports["slack.approved_apps"].proves_completeness
    assert reports["slack.approved_apps"].received_records == 2 and reports["slack.approved_apps"].pages == 2
    assert reports["slack.audit_events"].status == reports["slack.installed_apps"].status == "NOT_REQUESTED"
    assert pages[-1].status == "COMPLETE"
    assert [request.url.path for request in requests] == ["/api/admin.apps.approved.list"] * 2
    assert requests[0].url.params["enterprise_id"] == ORG and "cursor" not in requests[0].url.params
    assert requests[1].url.params["cursor"] == "c2"
    assert requests[0].headers["authorization"] == "Bearer " + BEARER
    assert all(validate_record(spec(), record) for record in records(pages))
    assert BEARER not in str([record.model_dump() for record in records(pages)])


def test_the_audit_log_gives_installs_removals_and_apps_the_approved_list_does_not_name():
    now = int(STAMP.timestamp())
    audit = [
        entry("app_installed", "A0SYNTH01", now - 5 * DAY, bot=["chat:write", "incoming-webhook"]),
        entry("app_scopes_expanded", "A0SYNTH01", now - 2 * DAY),
        entry("app_installed", "A0SYNTH02", now - 9 * DAY),
        entry("app_uninstalled", "A0SYNTH02", now - 3 * DAY),
        entry("app_installed", "A0SYNTH03", now - 1 * DAY, name="Side door", bot=["files:read"], scopes=["im:history"]),
        # Another workspace's install, and an action this inventory does not read, are not taken.
        entry("user_login", "A0SYNTH03", now - DAY),
    ]
    approved_page = page("approved_apps", approved("A0SYNTH01", "Deploy bot", bot=["chat:write", "incoming-webhook"],
                                                   user=["search:read"]),
                         approved("A0SYNTH02", "Old bot", bot=["chat:write"]))
    pages, requests = run([{"entries": audit[:3], "response_metadata": {"next_cursor": "a2"}},
                           {"entries": audit[3:]}, approved_page], connection=spec(audit=True))
    rows = {record.identity.object_id: record for record in records(pages) if record.record_type == "entity_observation"}
    bot = rows[f"bot:{ORG}:A0SYNTH01"]
    assert (bot.provider_state, bot.normalized_state, bot.state_basis) == ("INSTALLED", "ACTIVE", "PROVIDER_REPORTED")
    values = facts(bot)
    assert values["created_at"] == "2026-09-23T00:00:00+00:00"
    assert values["added_by"] == {"id": "W0SYNTH02", "name": "Synthetic Admin"}
    assert values["last_change"] == "app_scopes_expanded" and values["last_change_at"] == "2026-09-26T00:00:00+00:00"
    # Each user grants their own token: the install says nothing of when or by whom.
    assert "created_at" not in facts(rows[f"user:{ORG}:A0SYNTH01"])
    assert rows[f"bot:{ORG}:A0SYNTH02"].provider_state == "UNINSTALLED"
    assert rows[f"bot:{ORG}:A0SYNTH02"].normalized_state == "REVOKED"
    side = rows[f"bot:{ORG}:A0SYNTH03"]
    assert side.provenance.operation == "slack.installed_apps" and side.provider_state == "INSTALLED"
    assert facts(side)["scopes"] == ["files:read"] and facts(rows[f"user:{ORG}:A0SYNTH03"])["scopes"] == ["im:history"]
    reports = {record.provenance.operation: record for record in records(pages) if record.record_type == "operation_report"}
    audit_report = reports["slack.audit_events"]
    assert audit_report.status == "COMPLETE" and not audit_report.proves_completeness
    assert audit_report.window_start == "2026-06-30T00:00:00+00:00" and audit_report.window_end == "2026-09-28T00:00:00+00:00"
    assert reports["slack.installed_apps"].status == "COMPLETE" and reports["slack.installed_apps"].saved_records == 1
    assert requests[0].url.host == "api.slack.com" and requests[0].url.path == "/audit/v1/logs"
    assert requests[0].url.params["action"] == ",".join(AUDIT_ACTIONS)
    assert int(requests[0].url.params["oldest"]) == int(STAMP.timestamp()) - 90 * DAY
    assert requests[1].url.params["cursor"] == "a2" and requests[1].url.params["oldest"] == requests[0].url.params["oldest"]
    assert "admin@example.test" not in str([record.model_dump() for record in records(pages)])
    assert all(validate_record(spec(audit=True), record) for record in records(pages))


def test_an_app_removed_from_one_workspace_stays_installed_in_the_others():
    now = int(STAMP.timestamp())
    audit = [
        entry("app_installed", "A0SYNTH07", now - 6 * DAY, workspace="T0SYNTH01", bot=["chat:write"]),
        entry("app_installed", "A0SYNTH07", now - 5 * DAY, workspace="T0SYNTH02"),
        entry("app_uninstalled", "A0SYNTH07", now - 2 * DAY, workspace="T0SYNTH02"),
        entry("app_installed", "A0SYNTH08", now - 6 * DAY, workspace="T0SYNTH01", bot=["chat:write"]),
        entry("app_uninstalled", "A0SYNTH08", now - 3 * DAY, workspace="T0SYNTH01"),
    ]
    # Arrival order does not matter: the newest entries come first, as the audit log gives them.
    pages, _ = run([{"entries": list(reversed(audit))}, page("approved_apps")], connection=spec(audit=True))
    rows = {record.identity.object_id: record for record in records(pages) if record.record_type == "entity_observation"}
    assert rows[f"bot:{ORG}:A0SYNTH07"].provider_state == "INSTALLED"
    assert facts(rows[f"bot:{ORG}:A0SYNTH07"])["created_at"] == "2026-09-23T00:00:00+00:00"
    # Removed from every workspace it was in: not an installed app outside the approved list.
    assert f"bot:{ORG}:A0SYNTH08" not in rows
    kept = pages[-1].checkpoint["audit"]["A0SYNTH07"]
    assert kept["s"] == "installed" and kept["w"] == (
        f"T0SYNTH01={now - 6 * DAY + 1};T0SYNTH02=-{now - 2 * DAY + 1}")


def test_a_workspace_takes_only_its_own_audit_events():
    workspace = "T0SYNTH09"
    connection = spec(audit=True, scopes=[{"kind": "workspace", "id": workspace}])
    now = int(STAMP.timestamp())
    pages, requests = run([{"entries": [entry("app_installed", "A0SYNTH05", now - DAY, workspace="T0OTHER01", bot=["chat:write"]),
                                        entry("app_installed", "A0SYNTH06", now - DAY, workspace=workspace, bot=["chat:write"])]},
                           page("approved_apps")], connection=connection)
    ids = {record.identity.object_id for record in records(pages) if record.record_type == "entity_observation"}
    assert ids == {f"bot:{workspace}:A0SYNTH06"}
    assert requests[1].url.params["team_id"] == workspace


def test_refusals_wait_or_end_the_listing_without_calling_it_empty():
    refused = httpx.Response(200, json={"ok": False, "error": "missing_scope", "needed": "admin.apps:read"})
    pages, _ = run([refused])
    [report] = [record for record in records(pages) if record.record_type == "operation_report"
                and record.provenance.operation == "slack.approved_apps"]
    assert report.status == "FAILED" and "SLACK_MISSING_SCOPE" in report.reasons and not report.proves_completeness
    assert pages[-1].status == "FAILED" and pages[-1].reasons == ["SLACK_MISSING_SCOPE"]
    # A rate limit is a wait the worker keeps, with Slack's Retry-After.
    pages, _ = run([httpx.Response(429, headers={"retry-after": "30"}, json={"ok": False, "error": "ratelimited"})])
    assert pages[-1].status == "WAITING" and pages[-1].reasons == ["SLACK_RATE_LIMITED"]
    assert pages[-1].retry_after_seconds == 30 and pages[-1].checkpoint["retries"] == 1
    # The audit log refused: the approved apps are still listed, and the run is partial.
    audit_refused = httpx.Response(403, json={"ok": False, "error": "feature_not_enabled"})
    pages, _ = run([audit_refused, page("approved_apps", approved("A0SYNTH01", "Deploy bot", bot=["chat:write"]))],
                   connection=spec(audit=True))
    reports = {record.provenance.operation: record for record in records(pages) if record.record_type == "operation_report"}
    assert reports["slack.audit_events"].status == "FAILED" and reports["slack.approved_apps"].status == "COMPLETE"
    assert reports["slack.installed_apps"].status == "PARTIAL"
    assert pages[-1].status == "PARTIAL" and pages[-1].reasons == ["SLACK_FEATURE_NOT_ENABLED"]


def test_a_resumed_run_keeps_its_cursor_and_saves_nothing_twice():
    first = approved("A0SYNTH01", "Deploy bot", bot=["chat:write"])
    second = approved("A0SYNTH02", "Reader", bot=["channels:read"])
    pages, _ = run([page("approved_apps", first, cursor="c2"), httpx.Response(503)])
    assert pages[-1].status == "WAITING"
    saved = records(pages)
    checkpoint = pages[-1].checkpoint
    assert checkpoint["cursor"] == "c2" and checkpoint["records"] == len(saved)
    pages, requests = run([page("approved_apps", second)], checkpoint=checkpoint,
                          prior=[record.model_dump() for record in saved])
    assert requests[0].url.params["cursor"] == "c2"
    ids = [record.identity.object_id for record in records(pages) if record.record_type == "entity_observation"]
    assert ids == [f"bot:{ORG}:A0SYNTH02"] and pages[-1].status == "COMPLETE"
    # A checkpoint whose saved records do not add up is refused.
    with pytest.raises(ValueError, match="SLACK_REPLAY_COUNT_MISMATCH"):
        run([], checkpoint=checkpoint, prior=[])


def test_what_the_contract_refuses():
    for patch in ({"origin": "https://example.test"}, {"scopes": [{"kind": "enterprise", "id": ORG},
                                                                  {"kind": "workspace", "id": "T0SYNTH02"}]},
                  {"scopes": [{"kind": "enterprise", "id": "T0SYNTH02"}]},
                  {"capabilities": ["inventory", "audit"]}, {"options": {"requests_per_second": 2.0}},
                  {"options": {"requests_per_second": 1.0, "include_values": True}},
                  {"options": {"requests_per_second": 1.0, "audit_lookback_days": 30}}):
        with pytest.raises(ValueError):
            validate_spec(spec(**patch))
    pages, _ = run([page("approved_apps", approved("A0SYNTH01", "Deploy bot", bot=["chat:write"]))])
    row = next(record for record in records(pages) if record.record_type == "entity_observation")
    forged = row.model_copy(update={"identity": row.identity.model_copy(update={"object_id": "bot:E0OTHER01:A0SYNTH01"})})
    assert not validate_record(spec(), forged)
    assert not validate_record(spec(), row.model_copy(update={"provider_state": "INSTALLED"}))
    assert not validate_record(spec(), row.model_copy(update={"state_basis": "PROVIDER_REPORTED"}))


def test_a_name_that_looks_like_a_secret_is_not_kept():
    leaked = "xox" + "b-" + "0" * 30
    pages, _ = run([page("approved_apps", approved("A0SYNTH01", leaked, bot=["chat:write"]),
                         approved("B0NOTAPP", "Broken", bot=["chat:write"]))])
    rows = [record for record in records(pages) if record.record_type == "entity_observation"]
    assert [facts(row)["name"] for row in rows] == ["A0SYNTH01"]
    assert rows[0].omissions[0].path == "app/name"
    assert leaked not in str([record.model_dump() for record in records(pages)])
    [report] = [record for record in records(pages) if record.record_type == "operation_report"
                and record.provenance.operation == "slack.approved_apps"]
    assert report.record_quality.invalid_records == 1 and report.status == "PARTIAL"


def test_runs_compare_and_export_from_the_kept_fields():
    before, _ = run([page("approved_apps", approved("A0SYNTH01", "Deploy bot", bot=["chat:write"]),
                          approved("A0SYNTH02", "Reader", bot=["channels:read"]))])
    after, _ = run([page("approved_apps", approved("A0SYNTH01", "Deploy bot", bot=["chat:write", "files:write"]))])
    old = [record.model_dump() for record in records(before)]
    new = [record.model_dump() for record in records(after)]
    diff = _compare_runs(old, new, spec=spec())
    assert diff["no_longer_listed"] == [f"bot:{ORG}:A0SYNTH02"]
    assert diff["changed"] == [{"object_id": f"bot:{ORG}:A0SYNTH01", "fields": ["scopes"]}]
    snapshot = next(item for item in native_snapshots(new) if item["source"] == "approved_apps")
    assert snapshot["records"][0]["object_id"] == f"bot:{ORG}:A0SYNTH01"
    assert snapshot["credential_match"] == "UNAVAILABLE"


def test_audit_same_timestamp_overflow_is_collected_and_pagination_continues():
    at = int(STAMP.timestamp()) - DAY
    connection = spec(audit=True, options={"requests_per_second": 1.0, "include_audit_events": True, "page_size": 1})
    pages, requests = run([
        page("entries", entry("app_installed", "A0SYNTH01", at, bot=["chat:write"]),
             entry("app_installed", "A0SYNTH02", at, bot=["chat:write"]), cursor="same-time"),
        page("entries"), page("approved_apps"),
    ], connection=connection)
    rows = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert {row.identity.object_id for row in rows} == {f"bot:{ORG}:A0SYNTH01", f"bot:{ORG}:A0SYNTH02"}
    assert pages[-1].status == "COMPLETE"
    assert requests[0].url.params["limit"] == "1" and requests[1].url.params["cursor"] == "same-time"


def test_audit_page_cap_and_approved_page_guard_remain_bounded():
    from cremore_slack_provider.metadata.transport import ReadError, Transport

    transport = Transport(None, spec(options={"page_size": 1}), BEARER, lambda: None)
    assert len(transport._page({"entries": [{}] * 9999}, "entries")[0]) == 9999
    with pytest.raises(ReadError, match="SLACK_PAGE_SIZE_EXCEEDED"):
        transport._page({"entries": [{}] * 10000}, "entries")
    with pytest.raises(ReadError, match="SLACK_PAGE_SIZE_EXCEEDED"):
        transport._page({"approved_apps": [{}, {}]}, "approved_apps")


def test_audit_overflow_keeps_response_and_request_budgets():
    from cremore_slack_provider.metadata.transport import ReadError, Transport

    connection = spec(options={"page_size": 1, "max_response_bytes": 1024})
    requests = []
    with client_for([page("entries", *([{"padding": "x" * 1024}] * 2))], requests) as client:
        transport = Transport(client, connection, BEARER, lambda: None)
        with pytest.raises(ReadError, match="SLACK_RESPONSE_LIMIT"):
            transport.audit(0, int(STAMP.timestamp()), None)
        transport.requests = connection.max_requests
        with pytest.raises(ReadError, match="REQUEST_BUDGET_EXCEEDED"):
            transport.audit(0, int(STAMP.timestamp()), None)
    assert len(requests) == 1


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(("kind", "scope_id", "workspace", "state"), [
    ("enterprise", ORG, "T0SYNTH02", "APPROVED"),
    ("enterprise", ORG, None, "UNINSTALLED"),
    ("workspace", "T0SYNTH02", "T0SYNTH02", "UNINSTALLED"),
    ("workspace", "T0SYNTH02", "T0OTHER01", "APPROVED"),
    ("workspace", "T0SYNTH02", None, "APPROVED"),
])
def test_removal_in_a_window_proves_only_the_declared_place(kind, scope_id, workspace, state, reverse):
    at = int(STAMP.timestamp()) - DAY
    audit = [entry("app_scopes_expanded", "A0SYNTH01", at - DAY, workspace=workspace),
             entry("app_uninstalled", "A0SYNTH01", at, workspace=workspace)]
    connection = spec(audit=True, scopes=[{"kind": kind, "id": scope_id}])
    pages, _ = run([page("entries", *(reversed(audit) if reverse else audit)),
                    page("approved_apps", approved("A0SYNTH01", "Bot", bot=["chat:write"]))], connection=connection)
    [row] = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert row.provider_state == state
    assert (row.normalized_state, row.state_basis) == (
        ("REVOKED", "PROVIDER_REPORTED") if state == "UNINSTALLED" else ("UNKNOWN", "UNKNOWN"))
    assert validate_record(connection, row)


def test_a_workspace_removal_with_unknown_location_is_not_organization_removal():
    event = entry("org_app_workspace_removed", "A0SYNTH01", int(STAMP.timestamp()) - DAY)
    event.pop("context")
    pages, _ = run([page("entries", event),
                    page("approved_apps", approved("A0SYNTH01", "Bot", bot=["chat:write"]))],
                   connection=spec(audit=True))
    [row] = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert (row.provider_state, row.normalized_state, row.state_basis) == ("APPROVED", "UNKNOWN", "UNKNOWN")


@pytest.mark.parametrize("actor", ["USLACKUSER", "USLACKSECURITY"])
def test_slack_placeholder_actors_are_not_installers(actor):
    at = int(STAMP.timestamp()) - DAY
    pages, _ = run([
        page("entries", entry("app_installed", "A0SYNTH01", at, user=actor, bot=["chat:write", "incoming-webhook"]),
             entry("app_installed", "A0SYNTH01", at - DAY)),
        page("approved_apps"),
    ], connection=spec(audit=True))
    rows = [row for row in records(pages) if row.record_type == "entity_observation"]
    assert {facts(row)["token_type"] for row in rows} == {"bot", "incoming_webhook"}
    assert all("added_by" not in facts(row) and "created_at" in facts(row) for row in rows)
    assert "iu" not in pages[-1].checkpoint["audit"]["A0SYNTH01"]
