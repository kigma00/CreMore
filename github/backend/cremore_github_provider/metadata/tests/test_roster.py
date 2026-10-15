"""A discovered organization survives denied, pending and paginated reads."""

from copy import deepcopy

import pytest

from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.normalization import report
from cremore_github_provider.metadata.snapshot import native_snapshots, organization_roster

from .fake import ENTERPRISE, ORG, OTHER_ORG, enterprise_responses, enterprise_spec, spec
from .test_adapter import NOW, drive


def records():
    spec = enterprise_spec()
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    return drive(spec, responses, enterprise=ENTERPRISE)[2]


def test_discovery_alone_survives_in_the_native_snapshot_and_roster():
    discovered = [row for row in records() if row["provenance"]["operation"] == "github.organizations"]
    assert set(native_snapshots(discovered)["organizations"]) == {ORG, OTHER_ORG}
    result = organization_roster(iter(discovered))
    assert [row["org"] for row in result["items"]] == [ORG, OTHER_ORG]
    assert all(row["status"] == "NOT_COLLECTED" for row in result["items"])


def test_a_later_successful_repository_does_not_hide_a_failed_one():
    rows = records()
    report = next(row for row in rows if row["record_type"] == "operation_report"
                  and row["provenance"]["operation"] == "github.repo_deploy_keys")
    failed, succeeded = deepcopy(report), deepcopy(report)
    failed.update(status="FAILED", reasons=["GITHUB_HTTP_403"])
    succeeded.update(status="COMPLETE", reasons=[])
    result = organization_roster([failed, succeeded])
    assert result["items"][0]["status"] == "PARTIAL"
    assert result["items"][0]["sources"][0]["status"] == "PARTIAL"
    assert result["items"][0]["sources"][0]["reasons"] == ["GITHUB_HTTP_403"]


def test_discovery_failure_is_reported_separately_from_no_organizations():
    report = next(row for row in records() if row["record_type"] == "operation_report"
                  and row["provenance"]["operation"] == "github.organizations")
    report.update(status="FAILED", reasons=["GITHUB_HTTP_403"])
    result = organization_roster([report])
    assert result["items"] == []
    assert result["discovery"]["status"] == "FAILED"
    assert result["discovery"]["reasons"] == ["GITHUB_HTTP_403"]


def source_report(repo, status, *, reasons=(), pages=1, saved=0, warnings=()):
    connection = spec()
    path = f"/repos/{ORG}/{repo}/keys"
    return report(
        connection, connection.scopes[0], "github.repo_deploy_keys", status=status,
        reasons=reasons, pages=pages, received=saved, saved=saved, resource_id=path,
        facts={"kind": "repo_deploy_keys", "scope": ORG, "path": path,
               "warnings": list(warnings)},
    ).model_dump()


@pytest.mark.parametrize("statuses, expected", [
    (("FAILED", "COMPLETE"), "PARTIAL"),
    (("COMPLETE", "FAILED"), "PARTIAL"),
    (("FAILED", "FAILED"), "FAILED"),
    (("COMPLETE", "COMPLETE"), "COMPLETE"),
    (("PARTIAL", "COMPLETE"), "PARTIAL"),
    (("PARTIAL", "FAILED"), "PARTIAL"),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_native_source_summarizes_every_repository(statuses, expected, reverse):
    errors = ["GITHUB_HTTP_403", "GITHUB_HTTP_404"]
    rows = [source_report(
        f"repo-{index}", status, reasons=[errors[index]] if status != "COMPLETE" else [],
        pages=index + 2, saved=index + 4, warnings=["shared", f"warning-{index}"],
    ) for index, status in enumerate(statuses)]
    if reverse:
        rows.reverse()

    result = native_snapshots(rows)
    source = result["organizations"][ORG]["sources"]["repo_deploy_keys"]
    expected_errors = sorted(errors[index] for index, status in enumerate(statuses)
                             if status != "COMPLETE")
    assert source == {
        "source": "repository_deploy_keys", "kind": "repo_deploy_keys", "scope": ORG,
        "endpoint": None, "status": expected, "complete": expected == "COMPLETE",
        "pages_succeeded": 5, "records_collected": 9,
        "error": ", ".join(expected_errors) or None,
        "warnings": ["shared", "warning-0", "warning-1"],
    }
    # Aggregation must not overwrite the per-repository evidence in the export.
    assert result["enterprise"]["tasks"] == [
        native_snapshots([row])["enterprise"]["tasks"][0] for row in rows]
    assert source["status"] == organization_roster(rows)["items"][0]["sources"][0]["status"]


def test_an_org_audit_the_enterprise_audit_covered_leaves_the_organization_complete():
    connection = spec()
    covered = report(connection, connection.scopes[0], "github.org_audit", status="NOT_REQUESTED",
                     resource_id=f"/orgs/{ORG}/audit-log",
                     facts={"kind": "org_audit", "scope": ORG, "path": f"/orgs/{ORG}/audit-log"}).model_dump()
    item = organization_roster([source_report("repo-0", "COMPLETE"), covered])["items"][0]
    assert item["status"] == "COMPLETE"
    assert {row["kind"]: row["status"] for row in item["sources"]} == {
        "org_audit": "NOT_REQUESTED", "repo_deploy_keys": "COMPLETE"}
    failed = organization_roster([source_report("repo-0", "FAILED", reasons=["GITHUB_HTTP_403"]), covered])
    assert failed["items"][0]["status"] == "FAILED"


@pytest.mark.parametrize("status", [
    "COMPLETE", "FAILED", "PARTIAL", "NOT_REQUESTED", "UNSUPPORTED", "UNKNOWN",
])
def test_native_single_source_keeps_its_existing_fields(status):
    row = source_report("single", status, reasons=["FIRST_REASON", "SECOND_REASON"],
                        pages=2, saved=4, warnings=["second", "first"])
    result = native_snapshots([row])
    assert result["organizations"][ORG]["sources"]["repo_deploy_keys"] == {
        "source": "repository_deploy_keys", "kind": "repo_deploy_keys", "scope": ORG,
        "endpoint": f"/repos/{ORG}/single/keys", "status": status,
        "complete": status == "COMPLETE", "pages_succeeded": 2, "records_collected": 4,
        "error": "FIRST_REASON", "warnings": ["second", "first"],
    }


# -- installation permissions against the reads each organization ran ----------


def installation(org, *, permissions, suspended_at=None, iid=71):
    return {"id": iid, "target_type": "Organization", "account_login": org, "account_id": 9, "app_id": 12345,
            "suspended_at": suspended_at, "repository_selection": "selected", "permissions": permissions}


def org_run(broker, *orgs, **options):
    from .fake import SECRETS, FakeTransport, org_responses

    connection = spec(scopes=[{"kind": "organization", "id": org} for org in orgs], options=options)
    responses = {}
    for org in orgs:
        responses.update(org_responses(org))
    pages = adapter.collect_pages(connection, secrets=SECRETS, checkpoint={}, check=lambda: None,
                                  transport=FakeTransport(responses), broker=broker, now=lambda: NOW)
    return connection, [row.model_dump() for page in pages for row in page.records]


def by_org(result):
    return {row["org"]: row for row in result["items"]}


def test_health_compares_installation_permissions_with_the_reads_each_organization_ran():
    from .fake import FakeBroker

    granted = {"organization_administration": "read", "organization_personal_access_tokens": "read",
               "organization_personal_access_token_requests": "read", "metadata": "read"}
    broker = FakeBroker(installations={ORG: installation(ORG, permissions=granted),
                                       OTHER_ORG: installation(OTHER_ORG, iid=72,
                                                               permissions={**granted, "administration": "write"})})
    connection, rows = org_run(broker, ORG, OTHER_ORG)
    record = next(row for row in rows if row["provenance"]["operation"] == "github.installation"
                  and row["identity"]["object_id"] == "appInstallation:71")
    assert {grant["name"] for grant in record["permissions"] if grant["kind"] == "permission"} == set(granted)
    # Nothing is put in the row only to be dropped as an unapproved field.
    assert not record["omissions"]
    health = {name: row["health"] for name, row in by_org(organization_roster(rows, spec=connection)).items()}
    limited = health[ORG]
    assert (limited["status"], limited["reason"]) == ("limited", "required_installation_permissions_missing")
    sources = {row["kind"]: row for row in limited["sources"]}
    assert sources["repo_deploy_keys"]["missing"] == ["administration"]
    assert sources["repo_deploy_keys"]["status"] == "missing_permissions"
    assert sources["org_sso"] == {"kind": "org_sso", "required": {"organization_administration": "read"},
                                  "missing": [], "status": "permissions_present"}
    assert limited["api_access_verified"] is False and limited["repository_selection"] == "selected"
    # A write grant satisfies a read requirement.
    assert health[OTHER_ORG]["status"] == "permissions_present"
    assert all(not row["missing"] for row in health[OTHER_ORG]["sources"])


def test_the_apps_own_installation_lookup_is_not_a_second_observation_of_the_listed_installation():
    from .fake import SECRETS, FakeBroker, FakeTransport, org_responses

    # The organization's installation list includes this App's installation (701).
    ours = installation(ORG, permissions={"organization_administration": "read"}, iid=701)
    listed = {"id": 701, "app_id": 12345, "app_slug": "cremore-metadata", "target_id": 9,
              "target_type": "Organization", "repository_selection": "selected", "created_at": "2026-01-01T00:00:00Z",
              "permissions": ours["permissions"], "events": [], "account": {"login": ORG, "id": 9, "type": "Organization"}}
    responses = org_responses()
    responses[f"/orgs/{ORG}/installations?per_page=100"]["installations"].append(listed)
    pages = adapter.collect_pages(spec(), secrets=SECRETS, checkpoint={}, check=lambda: None,
                                  transport=FakeTransport(responses), broker=FakeBroker(installations={ORG: ours}),
                                  now=lambda: NOW)
    rows = [row.model_dump() for page in pages for row in page.records]
    entity = [row for row in rows if row.get("identity", {}).get("object_id") == "installation:701"]
    assert [row["provenance"]["operation"] for row in entity] == ["github.org_installations"]
    lookup = next(row for row in rows if row["provenance"]["operation"] == "github.installation")
    assert (lookup["identity"]["kind"], lookup["identity"]["object_id"]) == ("context", "appInstallation:701")
    # Organization health still reads the App's own lookup.
    health = by_org(organization_roster(rows, spec=spec()))[ORG]["health"]
    assert health["basis"] == "installation" and health["status"] in ("permissions_present", "limited")


def test_health_puts_suspension_first_and_a_refused_lookup_is_unknown_never_uninstalled():
    from .fake import FakeBroker

    broker = FakeBroker(refused=[("org", OTHER_ORG.lower())], installations={
        ORG: installation(ORG, permissions={"organization_administration": "read"}, suspended_at="2026-09-01T00:00:00Z")})
    connection, rows = org_run(broker, ORG, OTHER_ORG, sources=["org_sso"])
    assert ("org", ORG.lower()) not in broker.issued
    health = {name: row["health"] for name, row in by_org(organization_roster(rows, spec=connection)).items()}
    assert (health[ORG]["status"], health[ORG]["reason"]) == ("suspended", "installation_suspended")
    assert [row["status"] for row in health[ORG]["sources"]] == ["suspended"]
    assert (health[OTHER_ORG]["status"], health[OTHER_ORG]["reason"]) == (
        "unknown", "ORGANIZATION_INSTALLATION_GITHUB_HTTP_404")
    assert health[OTHER_ORG]["status"] != "not_installed"


def test_health_of_an_unread_organization_uses_the_planned_reads_it_would_make():
    discovered = [row for row in records() if row["provenance"]["operation"] == "github.organizations"]
    connection = enterprise_spec(options={"sources": ["org_fgpat"]})
    health = by_org(organization_roster(discovered, spec=connection))[ORG]["health"]
    assert (health["status"], health["reason"]) == ("unknown", "installation_not_checked")
    # Each grant is followed by a read of its repositories.
    assert [row["kind"] for row in health["sources"]] == ["org_fgpat", "org_fgpat_repositories"]


def test_planned_reads_match_the_tasks_a_collection_creates():
    from urllib.parse import quote

    from cremore_github_provider.metadata.actions import SECRET_SOURCES
    from cremore_github_provider.metadata.pages import ORG_SOURCES
    from cremore_github_provider.metadata.permissions import SOURCE_PERMISSIONS, planned_kinds

    from .fake import REPO, org_responses, repository

    connection = spec(capabilities=["inventory", "vault_metadata", "audit"], options={
        "sources": [*ORG_SOURCES, "repo_actions_runs", *SECRET_SOURCES], "include_actions": True,
        "include_audit_events": True, "audit_lookback_days": 7})
    window = adapter._window(connection, NOW.isoformat())
    runs = f"/repos/{ORG}/{REPO}/actions/runs"
    stamp = "2026-03-01T00:00:00Z"
    secret = {"name": "DEPLOY_TOKEN", "created_at": stamp, "updated_at": stamp}
    # Every read that leads to another returns a row, so every follow-up is created.
    responses = {**org_responses(),
                 f"{runs}?created={window[0][:10]}..{window[1][:10]}&per_page=100": {"workflow_runs": [
                     {"id": 7, "run_attempt": 1, "name": "build", "status": "completed", "created_at": stamp,
                      "repository": {"id": 501, "full_name": f"{ORG}/{REPO}"}}]},
                 f"{runs}/7/attempts/1/jobs?per_page=100": {"jobs": []},
                 f"/orgs/{ORG}/actions/secrets?per_page=100": {"total_count": 1, "secrets": [
                     {**secret, "visibility": "selected"}]},
                 f"/orgs/{ORG}/actions/secrets/DEPLOY_TOKEN/repositories?per_page=100": {
                     "total_count": 1, "repositories": [repository()]},
                 f"/repos/{ORG}/{REPO}/actions/secrets?per_page=100": {"total_count": 1, "secrets": [secret]},
                 f"/repos/{ORG}/{REPO}/environments?per_page=100": {"total_count": 1, "environments": [
                     {"id": 700, "name": "prod", "created_at": stamp, "updated_at": stamp}]},
                 f"/repos/{ORG}/{REPO}/environments/{quote('prod', safe='')}/secrets?per_page=100": {
                     "total_count": 1, "secrets": [secret]}}
    _t, _b, _records, state, _final = drive(connection, responses)
    created = {item["kind"] for item in state["tasks"].values()} & set(SOURCE_PERMISSIONS)
    assert created == planned_kinds(connection)
    assert {"repo_deploy_keys", "run_jobs", "org_secret_repositories", "environment_actions_secrets"} <= created


def test_planned_reads_leave_out_the_enterprise_fallback_organization_audit():
    from cremore_github_provider.metadata.permissions import planned_kinds

    audit = {"capabilities": ["inventory", "audit"]}
    assert "org_audit" not in planned_kinds(enterprise_spec(**audit, options={"include_audit_events": True}))
    assert "org_audit" in planned_kinds(enterprise_spec(**audit, options={"include_audit_events": True,
                                                                          "audit_scope": "organization"}))
    assert "org_audit" in planned_kinds(spec(**audit, options={"include_audit_events": True}))


def test_a_server_reads_and_plans_no_sso_authorizations():
    """A Server's API has no credential-authorizations: its default reads, and the health rows planned from them,
    leave them out; a source named explicitly is still asked for."""
    from types import SimpleNamespace

    from cremore_github_provider.metadata.permissions import planned_kinds

    server = {"edition": "enterprise_server", "origin": "https://ghes.example.com"}
    seeded = {item["kind"] for item in adapter._seed(spec(**server), SimpleNamespace(check=None, enterprise=""))}
    assert "org_sso" not in seeded and "org_fgpat" in seeded
    assert "org_sso" not in planned_kinds(spec(**server)) and "org_sso" in planned_kinds(spec())
    assert "org_sso" in planned_kinds(spec(**server, options={"mode": "organization", "sources": ["org_sso"]}))


def test_permission_map_names_every_organization_read_and_reaches_onboarding():
    from cremore.coverage.providers.catalog import descriptor
    from cremore_github_provider.metadata.actions import ACTION_TASKS
    from cremore_github_provider.metadata.pages import ORG_SOURCES
    from cremore_github_provider.metadata.permissions import SOURCE_PERMISSIONS, missing

    children = {"org_fgpat_repositories", "org_pat_request_repositories", "repo_deploy_keys",
                "repo_workflow_policy", "repo_actions_policy", "repo_fork_policy", "repo_actions_runs",
                "run_jobs", "org_audit"}
    assert set(SOURCE_PERMISSIONS) == set(ORG_SOURCES) | set(ACTION_TASKS) | children
    assert descriptor("github")["source_permissions"] == SOURCE_PERMISSIONS
    assert missing({"administration": "read"}, {"administration": "admin"}) == []
    assert missing({"administration": "write"}, {"administration": "read"}) == ["administration"]
    assert missing({"actions": "read"}, None) == ["actions"]
