"""Installation checks verify enterprise membership before App lookups; no network."""

import pytest

from cremore.coverage.errors import CoverageError
from cremore.coverage.providers import collector_for
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.endpoints import EndpointError
from cremore_github_provider.metadata.normalization import record_values
from cremore_github_provider.metadata.snapshot import installation_check_run, organization_roster

from .fake import (
    API,
    ENTERPRISE,
    ORG,
    OTHER_ORG,
    SECRETS,
    FakeBroker,
    FakeTransport,
    enterprise_responses,
    enterprise_spec,
    spec,
)
from .test_adapter import NOW, drive


def installation(login, iid, *, target="Organization", app_id=12345, permissions=None):
    return {"id": iid, "app_id": app_id, "target_type": target, "repository_selection": "all",
            "account": {"login": login, "id": iid + 1000, "type": target}, "suspended_at": None,
            "permissions": permissions or {"organization_administration": "read"}}


def collected():
    connection = enterprise_spec()
    responses = enterprise_responses(window=adapter._window(connection, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    return connection, drive(connection, responses, enterprise=ENTERPRISE)[2]


def check(connection, responses, plan, *, failures=None, enterprise=ENTERPRISE):
    if enterprise:
        responses = {f"/enterprises/{enterprise}/apps/installable_organizations?per_page=100":
                     [{"id": 9, "login": ORG}, {"id": 10, "login": OTHER_ORG}], **responses}
    transport, broker = FakeTransport(responses, failures=failures, enterprise=enterprise), FakeBroker()
    pages = list(adapter.collect_pages(connection, secrets=SECRETS, checkpoint={}, check=lambda: None,
                                       transport=transport, broker=broker, now=lambda: NOW,
                                       recollection_plan=plan))
    return transport, broker, [row.model_dump() for page in pages for row in page.records], pages[-1]


def health(connection, records, *checks):
    return {row["org"]: row["health"] for row in organization_roster(records, spec=connection, checks=checks)["items"]}


def reports(rows):
    return [row for row in rows if row["record_type"] == "operation_report"]


def test_installation_check_reads_one_organization_without_collecting_credentials():
    connection, base = collected()
    plan = adapter.plan_recollection(base, scope_id=ORG.lower(), operations=["installation_check"])
    assert plan == {"installation_check": {"orgs": [ORG], "listing": False}}
    transport, broker, rows, final = check(connection, {f"/orgs/{ORG}/installation": installation(ORG, 71)}, plan)
    assert transport.calls == [("GET", f"/enterprises/{ENTERPRISE}/apps/installable_organizations?per_page=100"),
                               ("GET", f"/orgs/{ORG}/installation")]
    assert transport.bearers[-1] == (f"/orgs/{ORG}/installation", "app-jwt")
    assert broker.issued == [("enterprise", ENTERPRISE.casefold())]
    assert final.status == "COMPLETE"
    assert {row["provenance"]["operation"] for row in rows} == {
        "github.app", "github.organizations", "github.installation_check"}
    assert installation_check_run(reports(rows)) and not installation_check_run(reports(base))
    state = health(connection, base, rows)
    assert (state[ORG]["basis"], state[ORG]["checked_at"] is not None) == ("installation_check", True)
    # Only organization administration is granted; the reads it ran also need repository administration.
    assert state[ORG]["status"] == "limited"
    assert (state[OTHER_ORG]["status"], state[OTHER_ORG]["reason"]) == ("unknown", "installation_not_checked")


def test_installation_check_refused_lookup_is_unknown_never_uninstalled():
    connection, base = collected()
    plan = {"installation_check": {"orgs": [ORG], "listing": False}}
    found = check(connection, {f"/orgs/{ORG}/installation": installation(ORG, 71)}, plan)[2]
    _t, _b, refused, final = check(connection, {}, plan)
    assert final.status == "PARTIAL"
    report = next(row for row in reports(refused) if row["provenance"]["operation"] == "github.installation_check")
    assert report["reasons"] == ["ORGANIZATION_INSTALLATION_GITHUB_HTTP_404"]
    # The newer refusal supersedes the older observation in this view, as unknown.
    state = health(connection, base, found, refused)[ORG]
    assert (state["status"], state["reason"]) == ("unknown", "ORGANIZATION_INSTALLATION_GITHUB_HTTP_404")
    assert health(connection, base, refused, found)[ORG]["status"] == "limited"


def test_installation_check_listing_proves_absence_only_when_complete():
    connection, base = collected()
    plan = adapter.plan_recollection(base, operations=["installation_check"])
    assert plan == {"installation_check": {"orgs": [ORG, OTHER_ORG], "listing": True}}
    listing = [installation(ORG, 71), installation("someone-else", 99),
               installation(ENTERPRISE, 70, target="Enterprise")]
    transport, broker, rows, final = check(connection, {"/app/installations?per_page=100": listing}, plan)
    assert final.status == "COMPLETE" and broker.issued == [("enterprise", ENTERPRISE.casefold())]
    assert transport.bearers[-1] == ("/app/installations?per_page=100", "app-jwt")
    recorded = {record_values(row).get("org") or record_values(row).get("enterprise") for row in rows
                if row["record_type"] == "entity_observation"
                and row["provenance"]["operation"] == "github.app_installations"}
    assert recorded == {ORG, ENTERPRISE}
    report = next(row for row in reports(rows) if row["provenance"]["operation"] == "github.app_installations")
    # Another account's installation is received and counted, never saved.
    assert (report["received_records"], report["saved_records"]) == (3, 2)
    state = health(connection, base, rows)
    assert (state[OTHER_ORG]["status"], state[OTHER_ORG]["reason"]) == (
        "not_installed", "absent_from_complete_app_installation_list")
    assert state[ORG]["basis"] == "app_installations" and state[ORG]["status"] != "not_installed"
    # A list that stopped early proves nothing about the organizations it did not reach.
    first = "/app/installations?per_page=100"
    paged = {first: ([installation(ORG, 71)], {"link": f'<{API}{first}&page=2>; rel="next"'})}
    _t, _b, partial, final = check(connection, paged, plan, failures={first + "&page=2": "github_http_403"})
    assert final.status == "PARTIAL"
    state = health(connection, base, partial)
    assert state[OTHER_ORG]["status"] == "unknown" and state[ORG]["basis"] == "app_installations"


def test_installation_check_plan_accepts_only_known_organizations_and_no_other_retry():
    _connection, base = collected()
    with pytest.raises(CoverageError, match="GITHUB_ORGANIZATION_NOT_OBSERVED_BY_THE_COLLECTION"):
        adapter.plan_recollection(base, scope_id="unknown-org", operations=["installation_check"])
    for operations in (None, ["org_sso"], ["installation_check", "org_sso"]):
        with pytest.raises(CoverageError, match="GITHUB_ONLY_AN_INSTALLATION_CHECK"):
            adapter.plan_recollection(base, operations=operations)
    assert collector_for("github").supports_recollection
    for bad in ({"installation_check": {"orgs": [ORG, OTHER_ORG], "listing": False}},
                {"installation_check": {"orgs": ["../x"], "listing": True}}, {"org_sso": []}):
        with pytest.raises(ValueError, match="GITHUB_INVALID_INSTALLATION_CHECK"):
            check(enterprise_spec(), {}, bad)
    # An organization connection checks only the organizations it was given.
    with pytest.raises(ValueError, match="GITHUB_INSTALLATION_CHECK_OUT_OF_SCOPE"):
        check(spec(), {}, {"installation_check": {"orgs": [OTHER_ORG], "listing": False}}, enterprise="")


def test_installation_check_tasks_never_run_in_a_collection_and_the_reverse():
    connection = enterprise_spec()
    collection = adapter._Run(connection, {}, "hash", lambda: NOW)
    checking = adapter._Run(connection, {}, "hash", lambda: NOW, {"orgs": [ORG], "listing": False})
    checking.authorized_orgs.add(ORG.casefold())
    probe = {"kind": "installation_check", "scope": ORG, "org": ORG, "enterprise": ENTERPRISE, "auth": "app",
             "path": f"/orgs/{ORG}/installation", "paginated": False, "next_path": f"/orgs/{ORG}/installation"}
    adapter._validate_pending_task(connection, checking, dict(probe))
    with pytest.raises(EndpointError, match="task_not_part_of_this_run"):
        adapter._validate_pending_task(connection, collection, dict(probe))
    sso = {**probe, "kind": "org_sso", "auth": "org", "path": f"/orgs/{ORG}/credential-authorizations",
           "paginated": True, "next_path": f"/orgs/{ORG}/credential-authorizations?per_page=100"}
    with pytest.raises(EndpointError, match="task_not_part_of_this_run"):
        adapter._validate_pending_task(connection, checking, sso)


def test_a_check_run_is_not_a_retry_base():
    connection, base = collected()
    plan = adapter.plan_recollection(base, scope_id=ORG, operations=["installation_check"])
    rows = check(connection, {f"/orgs/{ORG}/installation": installation(ORG, 71)}, plan)[2]
    with pytest.raises(CoverageError, match="GITHUB_INSTALLATION_CHECK_NEEDS_A_COLLECTION_BASE"):
        adapter.plan_recollection(rows, operations=["installation_check"])


def test_a_listing_marks_not_installed_only_its_planned_organizations():
    connection, base = collected()
    # As if planned from an older collection that knew only one organization.
    plan = {"installation_check": {"orgs": [ORG], "listing": True}}
    rows = check(connection, {"/app/installations?per_page=100": []}, plan)[2]
    report = next(row for row in reports(rows) if row["provenance"]["operation"] == "github.app_installations")
    assert report["status"] == "COMPLETE" and record_values(report)["organization"] == [ORG]
    state = health(connection, base, rows)
    assert (state[ORG]["status"], state[ORG]["reason"]) == ("not_installed", "absent_from_complete_app_installation_list")
    assert (state[OTHER_ORG]["status"], state[OTHER_ORG]["reason"]) == ("unknown", "installation_not_checked")


@pytest.mark.parametrize("listing", [False, True])
def test_stored_organization_cannot_authorize_check_without_current_membership(listing):
    connection, base = collected()
    plan = {"installation_check": {"orgs": [OTHER_ORG], "listing": listing}}
    membership = f"/enterprises/{ENTERPRISE}/apps/installable_organizations?per_page=100"
    transport, _broker, rows, final = check(connection, {
        membership: [{"id": 9, "login": ORG}],
        f"/orgs/{OTHER_ORG}/installation": installation(OTHER_ORG, 72),
        "/app/installations?per_page=100": [installation(OTHER_ORG, 72)],
    }, plan)
    assert final.status == "PARTIAL"
    assert transport.calls == [("GET", membership)]
    assert "TASK_ORGANIZATION_OUT_OF_SCOPE" in final.reasons
    assert health(connection, base, rows)[OTHER_ORG]["status"] == "unknown"


def test_failed_membership_read_never_turns_installation_absence_into_fact():
    connection, base = collected()
    membership = f"/enterprises/{ENTERPRISE}/apps/installable_organizations?per_page=100"
    transport, _broker, rows, final = check(connection, {},
        {"installation_check": {"orgs": [ORG], "listing": True}},
        failures={membership: "github_http_403"})
    assert final.status == "PARTIAL"
    assert transport.calls == [("GET", membership)]
    assert health(connection, base, rows)[ORG]["status"] == "unknown"


def test_installation_check_resume_uses_worker_checkpoint_membership():
    connection = enterprise_spec()
    plan = {"installation_check": {"orgs": [ORG], "listing": False}}
    membership = f"/enterprises/{ENTERPRISE}/apps/installable_organizations?per_page=100"
    transport, broker = FakeTransport({membership: [{"id": 9, "login": ORG}]}, enterprise=ENTERPRISE), FakeBroker()
    pages = adapter.collect_pages(connection, secrets=SECRETS, checkpoint={}, check=lambda: None,
        transport=transport, broker=broker, now=lambda: NOW, recollection_plan=plan)
    committed = []
    for page in pages:
        committed.extend(row.model_dump() for row in page.records)
        if page.checkpoint.get("verified_check_orgs"):
            state = page.checkpoint
            break
    pages.close()
    resumed = FakeTransport({f"/orgs/{ORG}/installation": installation(ORG, 71)}, enterprise=ENTERPRISE)
    output = list(adapter.collect_pages(connection, secrets=SECRETS, checkpoint=state, check=lambda: None,
        read_records=lambda: iter(committed), transport=resumed, broker=FakeBroker(), now=lambda: NOW,
        recollection_plan=plan))
    assert output[-1].status == "COMPLETE"
    assert resumed.calls == [("GET", f"/orgs/{ORG}/installation")]
