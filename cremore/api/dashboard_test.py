"""Tests for the dashboard `/api/v1/*` contract the Next.js web/ calls."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from cremore import risk
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import create_app

TOKEN = "dash-token-" + "0" * 32
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


def client(repo=None, **overrides):
    validator = overrides.pop("_validator", None)
    # Tests never resolve the machine's real AWS credentials.
    probe = overrides.pop("_probe", lambda **_: {"state": "NO_CREDENTIALS", "error_code": "NoCredentialsError"})
    return TestClient(create_app(repo=repo or InMemoryRepository(),
                                 settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, **overrides),
                                 aws_role_validator=validator, aws_identity_probe=probe))


def switch_investigation_on(client_or_repo, *keys):
    """Turn a read-only AWS investigation on, as PUT /settings/aws-investigations does."""
    from cremore_aws_provider.investigation import investigation_switches

    repo = getattr(getattr(client_or_repo, "app", None), "state", None)
    repo = repo.repo if repo is not None else client_or_repo
    for key in keys or investigation_switches.KEYS:
        repo.put_setting(key, {"enabled": True}, "admin")
    return client_or_repo


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def source(c, source_type, profile_ref, display_name=None, credential_ref=None, headers=None):
    """A content source as a provider connection's step 4 leaves it, as the source list shows it."""
    from cremore.api.source_contract import SOURCE_TO_PROVIDER, config_from_scope
    from cremore.onboarding.fixtures_test import content_source

    provider = SOURCE_TO_PROVIDER[source_type]
    conn = content_source(c.app.state.repo, provider, config_from_scope(provider, profile_ref),
                          name=display_name or profile_ref, secret_ref=credential_ref)
    rows = c.get("/api/v1/source-connections", headers=headers or auth()).json()
    return next(row for row in rows if row["id"] == str(conn.id))


def connect_aws(c, *accounts, method="role", headers=None, **target):
    """Seed pre-server-policy connections for the existing AWS API contract tests."""
    from contextlib import nullcontext

    from cremore.onboarding.fixtures_test import legacy_aws_setup

    legacy = legacy_aws_setup(method) if method in {"role", "runtime", "sso", "customer_cli"} else nullcontext()
    with legacy:
        return c.post("/api/v1/provider-connections", headers=headers or auth(), json={
            "provider": "aws", "purposes": ["exposure"], "auth_method": method,
            "target": {"accounts": list(accounts), **target}})


def aws_row(c, account_id):
    return next(row for row in c.get("/api/v1/aws/accounts", headers=auth()).json() if row["account_id"] == account_id)


def registered(c, account_id, **fields):
    """An AWS account as an AWS connection registers it, for tests of what runs on it."""
    from cremore.onboarding.fixtures_test import aws_account

    aws_account(c.app.state.repo, c.app.state.settings, account_id, **fields)
    return aws_row(c, account_id)


def test_session_uses_the_dashboard_role_names():
    # The web gates every admin panel on PlatformRole ("Admin"), not "OWNER".
    body = client().get("/api/v1/session", headers=auth()).json()
    assert body["role"] == "Admin" and body["id"] and body["auth_mode"] == "local"
    assert body["email"] is None
    # Tickets name people by reference; the session says which reference is this person.
    from cremore.governance.tickets import actor_ref

    assert body["ref"] == str(actor_ref(body["id"]))


def test_session_maps_oidc_roles(issuer):
    c, _ = _oidc_client(issuer, InMemoryRepository())
    assert c.get("/api/v1/session", headers=_bearer(issuer, "v", "g-viewers")).json()["role"] == "Viewer"
    assert c.get("/api/v1/session", headers=_bearer(issuer, "r", "g-remediators")).json()["role"] == "Remediator"
    assert c.get("/api/v1/operations/status", headers=_bearer(issuer, "v", "g-viewers")).status_code == 403
    assert c.get("/api/v1/operations/status", headers=_bearer(issuer, "a", "g-admins")).status_code == 200


@pytest.mark.parametrize("claims,expected", [
    ({"name": "  홍길동  ", "email": "person@example.test"}, "홍길동"),
    ({"email": "person@example.test"}, "person@example.test"),
    ({"name": "  ", "email": "person@example.test"}, "person@example.test"),
    ({"name": {"unexpected": "value"}, "email": "person@example.test"}, "person@example.test"),
    ({"email": "unverified@example.test", "email_verified": False}, "oidc-user-1"),
    ({}, "oidc-user-1"),
    ({"name": "x" * 250}, "x" * 200),
])
def test_session_displays_verified_profile_without_changing_actor(issuer, claims, expected):
    from cremore.governance.tickets import actor_ref

    c, _ = _oidc_client(issuer, InMemoryRepository())
    token = issuer.mint(sub="oidc-user-1", groups=("g-analysts",), extra=claims)
    response = c.get("/api/v1/session", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == expected
    assert body["email"] == (claims.get("email") if claims.get("email_verified", True) else None)
    assert body["id"] == "oidc-user-1"
    assert body["ref"] == str(actor_ref("oidc-user-1"))
    assert body["role"] == "Analyst"
    assert body["auth_mode"] == "oidc"


def test_errors_carry_the_dashboard_error_key():
    c = client()
    r = c.get("/api/v1/findings/not-a-uuid", headers=auth())
    assert r.status_code == 422 and r.json()["error"]
    # A dashboard path this API does not implement is a 501 with a reason, not a 404.
    r = c.post("/api/v1/rules/learned-fp/00000000-0000-4000-8000-000000000000/train", headers=auth(), json={})
    assert r.status_code == 501 and "not supported" in r.json()["error"]
    # ...but still requires authentication.
    assert c.get("/api/v1/whatever").status_code == 401


def test_stopping_a_connection_is_readable_in_the_audit_trail():
    """Stopping a connection is an operator action on the installation. It used
    to leave the row in the list and nothing in the trail, so a reader could see
    that it happened but never who did it or when."""

    from cremore.domain.models import Connection

    repo = InMemoryRepository()
    c = client(repo)
    paused = repo.create_connection(Connection(provider="aws", name="Synthetic paused",
        config={"bucket": "synthetic-paused"}, status="DISABLED"))
    connection_id = source(c, "s3", "synthetic-bucket", "Synthetic S3")["id"]

    before = c.get("/api/v1/audit", headers=auth()).json()
    stopped = c.post(f"/api/v1/source-connections/{connection_id}/credential/revoke",
                     headers=auth(), json={"reason": "no longer in use"})
    assert stopped.status_code == 200, stopped.text

    trail = c.get("/api/v1/audit", headers=auth()).json()
    assert len(trail) == len(before) + 1
    entry = next(e for e in trail if e["target_type"] == "connection")
    assert entry["action"] == "CONNECTION_STOPPED"
    assert entry["target_id"] == connection_id
    assert entry["actor_id"] and entry["created_at"]
    assert entry["note"] == "no longer in use"
    assert entry["target_name"] == "Synthetic S3"
    # Stopped rows remain addressable as historical records. Pausing alone is
    # not revocation; only the stopped row leaves operational pages/counts.
    assert repo.get_connection(uuid.UUID(connection_id)).credential_evidence["revoked_at"]
    retained = c.get("/api/v1/source-connections", headers=auth()).json()
    assert any(row["id"] == connection_id and row["credential"]["revoked_at"] for row in retained)
    page = c.get("/api/v1/connections?limit=1", headers=auth()).json()
    assert page["total"] == page["returned"] == 1 and not page["has_more"]
    assert page["provider_counts"] == {"aws": 1}
    assert page["connections"][0]["profile"]["connection_id"] == str(paused.id)
    assert c.get("/api/v1/connections?q=Synthetic+S3", headers=auth()).json()["total"] == 0
    search = _group(c.get("/api/v1/search?q=Synthetic&limit=1", headers=auth()).json(), "connection")
    assert search["total"] == 1 and search["items"][0]["label"] == "Synthetic paused"
    # A finding's own events keep the prefix and the narrower target.
    assert all(e["target_type"] == "finding" for e in trail if e["action"].startswith("FINDING_"))


def test_legacy_stopped_connection_remains_visible_as_existing_evidence_in_audit():
    from cremore.domain.models import Connection, FindingEvent

    repo = InMemoryRepository()
    stopped = repo.create_connection(Connection(provider="github", name="Legacy connection", status="DISABLED",
        credential_evidence={"revoked_at": "2026-09-19T00:00:00Z", "revocation_reason": "old shutdown"}))
    c = client(repo)
    row = c.get("/api/v1/audit?limit=1", headers=auth()).json()[0]
    assert row["target_name"] == "Legacy connection" and row["target_id"] == str(stopped.id)
    assert row["recovered_from_connection"] is True and row["actor_id"] == "UNKNOWN"
    assert row["created_at"] == "2026-09-19T00:00:00Z" and row["note"] == "old shutdown"
    assert not repo.list_events(10)  # A read does not manufacture an audit event.
    repo.record_finding_event(FindingEvent(target_type="connection", target_id=stopped.id,
        actor="recorded-admin", event_type="CONNECTION_STOPPED", to_status="DISABLED"))
    rows = c.get("/api/v1/audit", headers=auth()).json()
    assert len(rows) == 1 and rows[0]["actor_id"] == "recorded-admin"
    assert not rows[0].get("recovered_from_connection")


def test_a_run_that_stopped_on_a_budget_is_not_listed_as_a_completed_scan():
    """A bounded stop read part of the scope. Calling it SUCCEEDED in the scan
    history is the difference between "your buckets are clean" and "we got this
    far", which is the whole point of the product."""

    from types import SimpleNamespace

    from cremore.scanning.scope import job_is_partial

    stopped = SimpleNamespace(status="SUCCEEDED", coverage={"stopped_reason": "BUDGET_REQUESTS"}, objects_failed=0)
    whole = SimpleNamespace(status="SUCCEEDED", coverage={"objects": 5}, objects_failed=0)
    assert job_is_partial(stopped) and not job_is_partial(whole)
    body = client().get("/api/v1/scan-runs", headers=auth()).json()
    assert isinstance(body, list)
    for run in body:
        if run.get("stopped_reason"):
            assert run["status"] != "SUCCEEDED", run


def test_detection_engine_is_backed_by_the_catalog():
    body = client().get("/api/v1/detection-engine", headers=auth()).json()
    assert body["mode"] == "INDEPENDENT"
    # The route must report the policy that scores, not a copy of its name.
    assert body["risk_policy"] == risk.POLICY_VERSION
    assert len(body["detectors"]) >= 800  # the real built-in catalog
    d0 = body["detectors"][0]
    assert {"id", "provider", "credential_type", "confidence", "source_url"} <= set(d0)


def test_credential_and_source_types():
    c = client()
    ctypes = c.get("/api/v1/credential-types", headers=auth()).json()
    assert any(t["credential_type"] == "GITHUB_TOKEN" for t in ctypes)
    # The source catalog is the object the dashboard's registration form reads.
    catalog = c.get("/api/v1/source-types", headers=auth()).json()
    assert catalog["dashboard_queue"] is True and catalog["engine"] == "cremore-native"
    assert {cap["id"] for cap in catalog["capabilities"]} == {"s3", "github", "notion", "gitlab", "gcp", "confluence", "bitbucket",
                                                              "azure_blob", "azure_devops", "website"}
    assert all(cap["profile_runnable"] for cap in catalog["capabilities"])


def test_credential_type_catalog_counts_current_detectors_and_omits_adapter_counts():
    c = client()
    cat = c.get("/api/v1/credential-type-catalog", headers=auth()).json()
    assert cat["mode"] == "SHADOW" and cat["coverage"] == "PARTIAL_SEMANTICS"
    # Reviewed lifecycle types come from the semantics file as written.
    assert cat["counts"]["reviewed_types"] == len(cat["types"]) >= 11
    assert any(t["type_id"] == "aws.iam.access_key" and t["expiration_model"] for t in cat["types"])
    # One mapping per *current* detector; counts partition them exactly, so a
    # retired detector id in the semantics file cannot inflate support.
    counts = cat["counts"]
    assert counts["detectors"] == len(cat["mappings"])
    assert counts["detectors"] == counts["reviewed_mappings"] + counts["ambiguous_mappings"] + counts["unclassified_mappings"]
    assert {m["classification_status"] for m in cat["mappings"]} <= {"REVIEWED", "AMBIGUOUS", "UNCLASSIFIED"}
    # Adapter and live-action-roundtrip counts have no measured source: omitted, not zeroed.
    assert set(counts) == {"detectors", "reviewed_mappings", "ambiguous_mappings", "unclassified_mappings", "reviewed_types"}


def _seed_connections(repo, sources=3, accounts=2):
    from cremore.domain.models import AwsAccount, Connection
    for i in range(sources):
        repo.create_connection(Connection(provider="github", name=f"gh-{i}", config={"org": f"org-{i}"}))
    for i in range(accounts):
        repo.create_aws_account(AwsAccount(account_id=f"{i}" * 12, name=f"acct-{i}",
                                           scanner_role_arn=f"arn:aws:iam::{i * 12}:role/R",
                                           external_id="external-id-0123456789"))
    return repo


def test_connections_page_searches_counts_and_pages_on_the_server():
    repo = _seed_connections(InMemoryRepository())
    c = client(repo)

    whole = c.get("/api/v1/connections", headers=auth()).json()
    assert whole["total"] == 5 and whole["returned"] == 5 and whole["has_more"] is False
    # Counts are real totals per provider, not a sum of loaded pages.
    assert whole["provider_counts"] == {"aws": 2, "github": 3}

    # Paging keeps a stable order, so page 2 continues rather than repeats.
    first = c.get("/api/v1/connections?limit=2", headers=auth()).json()
    second = c.get("/api/v1/connections?limit=2&offset=2", headers=auth()).json()
    assert first["returned"] == 2 and first["has_more"] is True and first["total"] == 5
    assert second["offset"] == 2 and second["returned"] == 2
    ident = lambda page: [i["profile"]["connection_id"] for i in page["connections"]]
    assert not set(ident(first)) & set(ident(second))

    # A page past the end is empty but still reports the real total, so the
    # client can tell it from "nothing matches".
    past = c.get("/api/v1/connections?offset=99", headers=auth()).json()
    assert past["connections"] == [] and past["total"] == 5 and past["has_more"] is False


def test_connections_page_filters_by_search_and_provider():
    c = client(_seed_connections(InMemoryRepository()))
    hit = c.get("/api/v1/connections?q=gh-1", headers=auth()).json()
    assert hit["total"] == 1 and hit["filtered"] is True
    miss = c.get("/api/v1/connections?q=no-such-connection", headers=auth()).json()
    assert miss["total"] == 0 and miss["connections"] == [] and miss["filtered"] is True

    facet = c.get("/api/v1/connections?provider=aws", headers=auth()).json()
    assert facet["total"] == 2
    # The facet narrows the page but the counts still show what it filters out.
    assert facet["provider_counts"] == {"aws": 2, "github": 3}
    assert c.get("/api/v1/connections?provider=bogus", headers=auth()).status_code == 422
    assert c.get("/api/v1/connections?limit=0", headers=auth()).status_code == 422
    assert c.get("/api/v1/connections?limit=500", headers=auth()).status_code == 422
    assert c.get("/api/v1/connections?offset=-1", headers=auth()).status_code == 422


def test_atlassian_parent_facet_pages_both_products_without_changing_source_identity():
    from cremore.domain.models import Connection

    repo = _seed_connections(InMemoryRepository(), sources=1, accounts=0)
    for provider, config in (("bitbucket", {"workspace": "team"}),
                             ("confluence", {"space": "42", "base_url": "https://team.atlassian.net/wiki"})):
        repo.create_connection(Connection(provider=provider, name=f"Team {provider}", config=config))
    c = client(repo)
    first = c.get("/api/v1/connections?provider=atlassian&limit=1", headers=auth())
    assert first.status_code == 200
    page = first.json()
    assert page["total"] == 2 and page["returned"] == 1 and page["has_more"]
    second = c.get("/api/v1/connections?provider=atlassian&limit=1&offset=1", headers=auth()).json()
    items = page["connections"] + second["connections"]
    assert {item["profile"]["source_type"] for item in items} == {"bitbucket", "confluence"}
    assert page["provider_counts"] == {"bitbucket": 1, "confluence": 1, "github": 1}
    child = c.get("/api/v1/connections?provider=bitbucket", headers=auth()).json()
    assert child["total"] == 1 and child["connections"][0]["profile"]["source_type"] == "bitbucket"
    searched = c.get("/api/v1/connections?provider=atlassian&q=confluence", headers=auth()).json()
    assert searched["total"] == 1
    assert c.get("/api/v1/connections?q=atlassian", headers=auth()).json()["total"] == 2


def _group(body, kind):
    return next(g for g in body["groups"] if g["kind"] == kind)


def test_unified_search_finds_connections_and_accounts_with_their_context():
    c = client(_seed_connections(InMemoryRepository()))
    body = c.get("/api/v1/search?q=gh-1", headers=auth()).json()

    conns = _group(body, "connection")
    assert conns["searched"] is True and conns["total"] == 1
    item = conns["items"][0]
    # A result says what kind of object it is, whose it is and where it lives.
    assert item["kind"] == "connection" and item["provider"] == "github"
    assert item["label"] == "gh-1" and item["context"] == "org-1"

    accounts = _group(body, "aws_account")
    assert accounts["searched"] is True and accounts["total"] == 0

    wide = c.get("/api/v1/search", headers=auth()).json()
    assert _group(wide, "connection")["total"] == 3
    assert _group(wide, "aws_account")["total"] == 2


def test_unified_search_covers_every_kind_it_reports():
    c = client(_seed_connections(InMemoryRepository()))
    body = c.get("/api/v1/search", headers=auth()).json()
    # Every kind is searched; none is reported without being looked at.
    for kind in ("connection", "aws_account", "finding", "asset", "managed_object"):
        group = _group(body, kind)
        assert group["searched"] is True and group["reason"] == ""


def test_asset_results_disclose_a_partial_catalog():
    # Absence in a partial catalog is not proof of absence, so the group says so.
    from cremore.api.dashboard import search_payload
    from cremore.domain.models import ScopeCatalog

    repo = InMemoryRepository()
    repo.save_catalog(ScopeCatalog(kind="source", connection_id=uuid.uuid4(),
                                   snapshot_id="snap", completeness="PARTIAL",
                                   items=[{"id": "repo-1", "display_name": "billing",
                                           "resource_type": "GITHUB_REPOSITORY"}]))
    assets = _group(search_payload(repo, "analyst", "billing", 10), "asset")
    assert assets["total"] == 1 and assets["partial"] is True
    assert assets["items"][0]["label"] == "billing"
    assert assets["items"][0]["connection_kind"] == "source"


def test_unified_search_answers_each_role_differently():
    # The gate is exercised per role, not asserted from a constant: assets need
    # Analyst on their own endpoint, so a Viewer must not learn they exist here.
    from cremore.api.dashboard import SEARCH_ROLES, search_payload

    repo = _seed_connections(InMemoryRepository())
    for role, asset_permitted in (("viewer", False), ("analyst", True), ("remediator", True), ("admin", True)):
        body = search_payload(repo, role, "", 10)
        assert body["role"] == role
        assets = _group(body, "asset")
        assert assets["permitted"] is asset_permitted
        assert assets["requires_role"] == "analyst"
        # A kind the caller cannot list reports neither items nor a count.
        if not asset_permitted:
            assert assets["total"] == 0 and assets["items"] == [] and assets["reason"] == "ROLE_REQUIRED"
        # Connections and accounts stay readable at every role.
        assert _group(body, "connection")["total"] == 3
        assert _group(body, "aws_account")["total"] == 2
        for group in body["groups"]:
            assert group["requires_role"] == SEARCH_ROLES[group["kind"]]


def test_searching_aws_finds_accounts_whose_name_is_only_a_number():
    # An account named after its own number, with no environment, is still an
    # AWS object and must answer to "aws".
    from cremore.api.dashboard import search_payload
    from cremore.domain.models import AwsAccount

    repo = InMemoryRepository()
    repo.create_aws_account(AwsAccount(account_id="111111111111", name="111111111111",
                                       scanner_role_arn="arn:aws:iam::111111111111:role/R",
                                       external_id="external-id-0123456789"))
    found = _group(search_payload(repo, "admin", "aws", 10), "aws_account")
    assert found["total"] == 1 and found["items"][0]["provider"] == "aws"


def test_unified_search_rejects_an_out_of_range_limit():
    c = client()
    assert c.get("/api/v1/search?limit=0", headers=auth()).status_code == 422
    assert c.get("/api/v1/search?limit=51", headers=auth()).status_code == 422
    assert c.get("/api/v1/search?limit=50", headers=auth()).status_code == 200


def test_enterprise_surfaces_empty_with_no_data():
    c = client()
    # With no data yet these return empty lists (real handlers, not stubs).
    for path in ("/api/v1/aws/accounts", "/api/v1/governance/reviews",
                 "/api/v1/management-actions", "/api/v1/rotation-automation/jobs",
                 "/api/v1/rules", "/api/v1/rules/learned-fp", "/api/v1/audit", "/api/v1/scans",
                 "/api/v1/source-scan-jobs", "/api/v1/source-connections"):
        r = c.get(path, headers=auth())
        assert r.status_code == 200 and r.json() == [], path
    empty = c.get("/api/v1/connections", headers=auth()).json()
    # "No connection exists" must be distinguishable from "this page is empty".
    assert empty["connections"] == [] and empty["total"] == 0 and empty["returned"] == 0
    assert empty["has_more"] is False and empty["filtered"] is False and empty["provider_counts"] == {}
    # Static capability surfaces are non-empty.
    assert c.get("/api/v1/rotation-automation/profiles", headers=auth()).json()
    onboarding = c.get("/api/v1/aws/accounts/onboarding", headers=auth()).json()
    # A code, never prose: the dashboard localises it (English text here would
    # reach a Korean dashboard untranslated).
    assert onboarding["configured"] is False and onboarding["configuration"] == "IDENTITY_NOT_APPROVED"


def test_aws_account_register_and_list():
    c = client()
    acct = registered(c, "123456789012", name="prod", environment="production")
    assert acct["scanner_role_arn"] == "arn:aws:iam::123456789012:role/CredentialExposureScannerRole"
    accts = c.get("/api/v1/aws/accounts", headers=auth()).json()
    assert len(accts) == 1 and accts[0]["name"] == "prod"
    # connecting AWS waits until an Admin approves the AWS identity CreMore runs as
    r = connect_aws(c, "210987654321")
    assert r.status_code == 409 and r.json()["error"] == "AWS_SCANNER_IDENTITY_NOT_APPROVED"
    assert c.get(f"/api/v1/aws/accounts/{accts[0]['id']}/onboarding", headers=auth()).status_code == 409

    # an account another connection holds is never registered twice; a bad id is rejected;
    # either refuses them all
    c = approved_client()
    assert connect_aws(c, "123456789012").status_code == 201
    again = connect_aws(c, "210987654321", "123456789012")
    assert again.status_code == 409 and again.json()["error"] == "ACCOUNT_ALREADY_REGISTERED"
    bad = connect_aws(c, "210987654321", "nope")
    assert bad.status_code == 422 and bad.json()["error"] == "AWS_ACCOUNT_IDS_INVALID"
    assert [row["account_id"] for row in c.get("/api/v1/aws/accounts", headers=auth()).json()] == ["123456789012"]
    assert len(c.get("/api/v1/provider-connections", headers=auth()).json()) == 1


SSO_ROLE = "AWSReservedSSO_SecurityAudit_0123456789abcdef"
SSO_PATTERN = ("arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/ap-northeast-2/"
               "AWSReservedSSO_SecurityAudit_" + "?" * 16)


def sso_identity(**_):
    return {"state": "READY", "kind": "IDENTITY_CENTER", "partition": "aws", "account_id": "111111111111",
            "caller_arn": f"arn:aws:sts::111111111111:assumed-role/{SSO_ROLE}/officer@example.com",
            "principal_arn": f"arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/ap-northeast-2/{SSO_ROLE}",
            "permission_set": "SecurityAudit", "sso_region": "ap-northeast-2", "requires": None,
            "sso_start_url": "https://d-1234567890.awsapps.com/start",
            "match_key": "identity-center:aws:111111111111:SecurityAudit",
            "trust": {"type": "IdentityCenter", "account_id": "111111111111", "principal_pattern": SSO_PATTERN}}


def report_worker(c, **identity):
    from cremore_aws_provider import aws_identity

    c.app.state.repo.put_setting(aws_identity.WORKER_IDENTITY_KEY, {**sso_identity(), **identity}, "worker")


def approved_client(**overrides):
    c = client(_probe=sso_identity, **overrides)
    report_worker(c)
    assert c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True}).status_code == 200
    return c


def test_scanner_identity_approval_requires_api_and_worker_to_match():
    c = client(_probe=sso_identity)
    body = c.get("/api/v1/aws/scanner-identity", headers=auth()).json()
    assert body["api"]["kind"] == "IDENTITY_CENTER" and body["worker"] is None and body["approved"] is None
    assert body["approvable"] is None and body["same_identity"] is False
    assert body["policy"]["Statement"][0]["Resource"] == "arn:aws:iam::*:role/CredentialExposureScannerRole"
    assert c.put("/api/v1/aws/scanner-identity", headers=auth(), json={}).status_code == 422

    r = c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
    assert r.status_code == 409 and "WORKER_IDENTITY_UNKNOWN" in r.json()["error"]
    report_worker(c, state="LOGIN_REQUIRED", match_key=None)
    assert "WORKER_LOGIN_REQUIRED" in c.put("/api/v1/aws/scanner-identity", headers=auth(),
                                            json={"confirm": True}).json()["error"]
    report_worker(c, match_key="identity-center:aws:111111111111:AdministratorAccess")
    assert "WORKER_IDENTITY_MISMATCH" in c.put("/api/v1/aws/scanner-identity", headers=auth(),
                                               json={"confirm": True}).json()["error"]

    report_worker(c)
    r = c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
    assert r.status_code == 200, r.json()
    assert r.json()["same_identity"] is True and r.json()["hold"] is None
    assert r.json()["approved"]["permission_set"] == "SecurityAudit" and r.json()["approved"]["source"] == "DASHBOARD"
    # the STS session (the person's sign-in) is never the stored trust
    stored = c.app.state.repo.get_setting("aws_scanner_identity")["value"]
    assert "officer@example.com" not in str(stored) and stored["trust"]["principal_pattern"] == SSO_PATTERN


def test_scanner_identity_refuses_root_and_passes_missing_details_to_the_probe():
    root = {"state": "READY", "kind": "ROOT", "account_id": "111111111111", "caller_arn": "arn:aws:iam::111111111111:root"}
    c = client(_probe=lambda **_: root)
    r = c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
    assert r.status_code == 409 and "ROOT_CREDENTIALS_REFUSED" in r.json()["error"]

    seen = []

    def probe(role_arn=None, sso_region=None):
        seen.append((role_arn, sso_region))
        return {"state": "READY", "kind": "IAM_ROLE", "requires": None if role_arn else "ROLE_ARN"}

    c = client(_probe=probe)
    assert c.get("/api/v1/aws/scanner-identity", headers=auth()).json()["approvable"] == "ROLE_ARN_REQUIRED"
    c.put("/api/v1/aws/scanner-identity", headers=auth(),
          json={"confirm": True, "role_arn": "arn:aws:iam::111111111111:role/ops/Scanner"})
    assert seen[-1] == ("arn:aws:iam::111111111111:role/ops/Scanner", None)


def test_aws_onboarding_returns_a_deployment_bound_to_the_approved_identity():
    c = approved_client()
    onboarding = c.get("/api/v1/aws/accounts/onboarding", headers=auth()).json()
    assert onboarding["configured"] is True and onboarding["quick_create"] is False
    r = connect_aws(c, "123456789012", environment="production")
    assert r.status_code == 201, r.text
    [child] = r.json()["children"]
    assert child["kind"] == "aws_account" and child["account_id"] == "123456789012"
    shown = c.get(f"/api/v1/aws/accounts/{child['id']}/onboarding", headers=auth()).json()
    assert shown["cloudformation_url"] is None  # no S3-hosted template configured
    deployment = shown["deployment"]
    params = deployment["parameters"]
    assert params["TargetAccountId"] == "123456789012" and params["TrustedPrincipalType"] == "IdentityCenter"
    assert params["IdentityCenterAccountId"] == "111111111111" and params["TrustedPrincipalPattern"] == SSO_PATTERN
    assert 16 <= len(params["ExternalId"]) <= 128
    assert f"'TrustedPrincipalPattern={SSO_PATTERN}'" in deployment["cli_command"]
    again = c.get(f"/api/v1/aws/accounts/{child['id']}/onboarding", headers=auth()).json()
    assert again["deployment"]["parameters"]["ExternalId"] == params["ExternalId"]
    assert "external_id" not in c.get("/api/v1/aws/accounts", headers=auth()).json()[0]
    assert params["ExternalId"] not in r.text  # the connection view names the account, never its ExternalId

    template = c.get(deployment["template_path"], headers=auth())
    assert template.status_code == 200 and "TrustedPrincipalType" in template.text
    assert "attachment" in template.headers["content-disposition"]


ONBOARDING = {"AWS_ONBOARDING_TEMPLATE_URL": "https://templates.example.com/member-account-role.yaml",
                  "AWS_SCANNER_PRINCIPAL_ARN": "arn:aws:iam::111111111111:role/platform/PlatformScannerExecutionRole",
                  "AWS_REGION": "eu-west-1"}


def test_aws_onboarding_quick_create_link_from_a_configured_server_principal():
    from urllib.parse import parse_qs, urlparse

    c = client(**ONBOARDING)
    assert c.get("/api/v1/aws/accounts/onboarding", headers=auth()).json()["configured"] is True
    r = connect_aws(c, "123456789012")
    assert r.status_code == 201, r.text
    account_id = r.json()["children"][0]["id"]
    url = urlparse(c.get(f"/api/v1/aws/accounts/{account_id}/onboarding", headers=auth()).json()["cloudformation_url"])
    assert url.scheme == "https" and url.hostname == "eu-west-1.console.aws.amazon.com"
    assert url.fragment.startswith("/stacks/create/review?")  # the quick-create form AWS documents
    params = parse_qs(url.fragment.split("?", 1)[1])
    assert params["templateURL"] == [ONBOARDING["AWS_ONBOARDING_TEMPLATE_URL"]]
    assert params["param_TargetAccountId"] == ["123456789012"]
    assert params["param_TrustedPrincipalType"] == ["IamRole"]
    assert params["param_TrustedPrincipalArn"] == [ONBOARDING["AWS_SCANNER_PRINCIPAL_ARN"]]
    assert params["param_MemberScannerRoleName"] == ["CredentialExposureScannerRole"]
    external_id = params["param_ExternalId"][0]
    again = c.get(f"/api/v1/aws/accounts/{account_id}/onboarding", headers=auth()).json()
    assert f"param_ExternalId={external_id}" in again["cloudformation_url"]


def test_one_aws_connection_registers_several_accounts_all_or_none():
    c = approved_client()
    assert connect_aws(c, "123456789012").status_code == 201
    assert connect_aws(c, "210987654321", "123456789012", "333333333333").status_code == 409
    assert connect_aws(c, "210987654321", "12").status_code == 422
    assert connect_aws(c).json()["error"] == "TARGET_FIELD_REQUIRED:accounts"
    # A repeated id is one account; the environment is set on each.
    r = connect_aws(c, "210987654321", "333333333333", "210987654321", environment="logs")
    assert r.status_code == 201, r.text
    assert sorted(child["account_id"] for child in r.json()["children"]) == ["210987654321", "333333333333"]
    accounts = {a["account_id"]: a for a in c.get("/api/v1/aws/accounts", headers=auth()).json()}
    assert set(accounts) == {"123456789012", "210987654321", "333333333333"}
    assert accounts["333333333333"]["environment"] == "logs"


def test_aws_role_validation_is_queued_to_the_worker():
    c = approved_client()
    acct = registered(c, "123456789012")
    r = c.post(f"/api/v1/aws/accounts/{acct['id']}/validate", headers=auth()).json()
    assert r["check"] == "QUEUED"
    # repeated clicks and validate-all reuse the pending check
    assert c.post("/api/v1/aws/accounts/validate", headers=auth()).json()["accounts"][0]["check_job_id"] == r["check_job_id"]
    jobs = [j for j in c.app.state.repo.list_jobs(50) if j.kind == "aws-role-check"]
    assert len(jobs) == 1 and jobs[0].payload == {"aws_account_id": acct["id"], "purpose": "scanner",
                                                  "access_revision": 1, "approval_revision": 1}
    # a role check is not a source scan
    assert c.get("/api/v1/source-scan-jobs", headers=auth()).json() == []


def test_trust_changes_and_new_approvals_make_results_stale_and_queue_revalidation():
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    c = client(_probe=sso_identity, _validator=lambda a: RoleValidation("VALID", "ok", "arn", code="SCANNER_ROLE_ASSUMED"))
    report_worker(c)
    assert c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True}).status_code == 200
    acct = registered(c, "123456789012")
    assert c.post(f"/api/v1/aws/accounts/{acct['id']}/validate", headers=auth()).json()["status"] == "VALID"

    # validation status is owned by the validator
    assert c.patch(f"/api/v1/aws/accounts/{acct['id']}", headers=auth(), json={"validation_status": "VALID"}).status_code == 422
    # renaming keeps the result; changing the trusted role does not
    assert c.patch(f"/api/v1/aws/accounts/{acct['id']}", headers=auth(), json={"name": "prod"}).json()["validation_status"] == "VALID"
    patched = c.patch(f"/api/v1/aws/accounts/{acct['id']}", headers=auth(),
                      json={"scanner_role_arn": "arn:aws:iam::123456789012:role/Other"}).json()
    assert (patched["validation_status"], patched["validation_detail"]) == ("PENDING", "REVALIDATION_REQUIRED")
    assert c.post(f"/api/v1/aws/accounts/{acct['id']}/validate", headers=auth()).json()["status"] == "VALID"

    # re-approving the identity turns every result stale and queues a check per account and revision
    assert c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True}).status_code == 200
    listed = c.get("/api/v1/aws/accounts", headers=auth()).json()[0]
    assert (listed["validation_status"], listed["validation_detail"]) == ("PENDING", "REVALIDATION_REQUIRED")
    jobs = [j.payload for j in c.app.state.repo.list_jobs(50) if j.kind == "aws-role-check"]
    assert jobs == [{"aws_account_id": acct["id"], "purpose": "scanner", "access_revision": 2, "approval_revision": 2}]


def test_a_validation_that_finishes_after_a_newer_approval_is_not_stored():
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    holder = {}

    def slow_validator(acct):
        # a new approval lands while this check is still running
        report_worker(holder["c"])
        holder["c"].put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
        return RoleValidation("VALID", "ok", "arn", code="SCANNER_ROLE_ASSUMED")

    c = holder["c"] = client(_probe=sso_identity, _validator=slow_validator)
    report_worker(c)
    c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
    acct = registered(c, "123456789012")
    r = c.post(f"/api/v1/aws/accounts/{acct['id']}/validate", headers=auth()).json()
    assert r["check"] == "SUPERSEDED" and r["status"] == "PENDING"
    assert c.app.state.repo.get_aws_account(uuid_of(acct["id"])).validation_key is None


def test_runtime_identity_account_is_only_the_approved_identitys_own_account():
    c = approved_client()
    other = connect_aws(c, "123456789012", method="runtime")
    assert other.status_code == 409 and other.json()["error"] == "RUNTIME_IDENTITY_ACCOUNT_MISMATCH"
    assert connect_aws(c, "111111111111", "123456789012", method="runtime").json()["error"] == (
        "RUNTIME_IDENTITY_IS_ONE_ACCOUNT")
    own = connect_aws(c, "111111111111", method="runtime")
    assert own.status_code == 201, own.text
    body = aws_row(c, "111111111111")
    assert body["access"] == "RUNTIME_IDENTITY" and body["scanner_role_arn"] is None
    assert body["validation_status"] == "PENDING" and body["remediation_validation_status"] == "PENDING"
    other = connect_aws(c, "210987654321", method="OTHER")
    assert other.status_code == 422 and other.json()["error"] == "AUTH_METHOD_NOT_FOR_PURPOSES"


def test_aws_role_validation_updates_status_from_an_injected_validator():
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    seen = []

    def validator(acct):
        seen.append((acct.account_id, acct.scanner_role_arn, bool(acct.external_id)))
        return RoleValidation("VALID", "ok", "arn:aws:sts::123456789012:assumed-role/x/y", code="SCANNER_ROLE_ASSUMED")

    c = client(_validator=validator, **ONBOARDING)
    assert connect_aws(c, "123456789012").status_code == 201
    acct = aws_row(c, "123456789012")
    r = c.post(f"/api/v1/aws/accounts/{acct['id']}/validate", headers=auth())
    assert r.status_code == 200 and r.json()["status"] == "VALID" and r.json()["check"] == "COMPLETED"
    assert seen == [("123456789012", "arn:aws:iam::123456789012:role/CredentialExposureScannerRole", True)]
    listed = c.get("/api/v1/aws/accounts", headers=auth()).json()[0]
    assert listed["validation_status"] == "VALID" and listed["validation_detail"] == "SCANNER_ROLE_ASSUMED"
    assert listed["validated_at"]
    assert c.post(f"/api/v1/aws/accounts/{acct['id']}/onboarding/validate", headers=auth()).json()["status"] == "VALID"
    assert c.post("/api/v1/aws/accounts/00000000-0000-4000-8000-000000000000/validate", headers=auth()).status_code == 404


def test_aws_hold_is_an_operations_alert():
    c = approved_client()
    assert c.get("/api/v1/aws/scanner-identity", headers=auth()).json()["hold"] is None
    report_worker(c, state="LOGIN_REQUIRED", match_key=None)
    alerts = c.get("/api/v1/operations/status", headers=auth()).json()["alerts"]
    assert {"code": "AWS_LOGIN_REQUIRED", "resource_type": "aws_identity", "resource_id": "worker"} in alerts
    report_worker(c, match_key="identity-center:aws:111111111111:AdministratorAccess")
    assert c.get("/api/v1/aws/scanner-identity", headers=auth()).json()["hold"] == "AWS_SCANNER_IDENTITY_CHANGED"


def test_dashboard_registers_scope_queues_scan_and_lists_jobs():
    c = client()
    conn = source(c, "github", "example-org/app", "App repo")
    assert conn["source_type"] == "github" and conn["profile_ref"] == "example-org/app"
    assert conn["credential_source"] == "NONE" and conn["enabled"] is True
    # a connection's scope and credential are refused before anything exists
    for body, code in (({"provider": "github", "purposes": ["exposure"], "auth_method": "token",
                         "target": {"organization": "a/b/c"}, "credential": {"token": GH}},
                        "FIELD_INVALID:organization"),
                       ({"provider": "unsupported"}, "PROVIDER_UNKNOWN"),
                       ({"provider": "notion", "purposes": ["exposure"], "auth_method": "integration",
                         "credential": {"vault_ref": "ghp_notavaultref"}}, "CREDENTIAL_REFERENCE_INVALID")):
        refused = c.post("/api/v1/provider-connections", headers=auth(), json=body)
        assert refused.status_code == 422 and refused.json()["error"] == code, refused.text
    s3 = source(c, "s3", "example-bucket/logs", "Logs")
    assert s3["profile_ref"] == "example-bucket/logs"
    assert c.get("/api/v1/provider-connections", headers=auth()).json() == []

    # "Select targets / review scan" queues the connection's job.
    job = c.post(f"/api/v1/source-connections/{conn['id']}/scans", headers=auth())
    assert job.status_code == 202 and job.json()["status"] == "QUEUED" and job.json()["job_kind"] == "SCAN"
    jobs = c.get("/api/v1/source-scan-jobs", headers=auth()).json()
    assert len(jobs) == 1 and jobs[0]["source_connection_id"] == conn["id"]
    assert jobs[0]["display_name"] == "App repo" and jobs[0]["source_type"] == "github"
    raw = c.get(f"/api/v1/scan-jobs/{jobs[0]['id']}", headers=auth()).json()
    assert raw["kind"] == "github" and "payload" not in raw
    stored = c.app.state.repo.get_job(uuid_of(jobs[0]["id"]))
    assert stored.payload == {"owner": "example-org", "repo": "app", "ref": "HEAD", "github_host": "", "base_url": "https://api.github.com"}

    # a queued job is withdrawn (idempotently) and frees the slot at once
    cancelled = c.post(f"/api/v1/source-scan-jobs/{jobs[0]['id']}/cancel", headers=auth())
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "CANCELLED"
    assert c.post(f"/api/v1/source-scan-jobs/{jobs[0]['id']}/cancel", headers=auth()).json()["status"] == "CANCELLED"
    second = c.post(f"/api/v1/source-connections/{conn['id']}/scans", headers=auth()).json()
    # New work is accepted durably, but a connection has only one executing run.
    queued = c.post(f"/api/v1/source-connections/{conn['id']}/scans", headers=auth())
    assert queued.status_code == 202 and queued.json()["status"] == "QUEUED"
    assert c.get("/api/v1/scan-activity", headers=auth()).json()["active"]["id"] == second["id"]
    assert c.app.state.repo.claim_next_job().id == uuid_of(second["id"])
    assert c.app.state.repo.claim_next_job() is None
    # a running scan is asked to stop; it keeps the slot until the worker has stopped
    stopping = c.post(f"/api/v1/source-scan-jobs/{second['id']}/cancel", headers=auth())
    assert stopping.status_code == 200 and stopping.json()["status"] == "CANCELLING"
    assert c.app.state.repo.claim_next_job() is None
    c.app.state.repo.finish_cancelled_job(uuid_of(second["id"]))
    assert c.app.state.repo.claim_next_job().id == uuid_of(queued.json()["id"])
    c.app.state.repo.complete_job(uuid_of(queued.json()["id"]), 0, 0)
    assert c.get("/api/v1/scan-activity", headers=auth()).json() == {"active": None}
    assert c.post(f"/api/v1/source-scan-jobs/{second['id']}/cancel", headers=auth()).status_code == 200
    assert c.post("/api/v1/source-scan-jobs/00000000-0000-4000-8000-000000000000/cancel", headers=auth()).status_code == 404


def test_dashboard_job_status_reflects_partial_and_failed_runs():
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    c = client(repo)
    partial = repo.enqueue_job(ScanJob(kind="s3", payload={"bucket": "b"}))
    repo.complete_job(partial.id, objects=4, findings=1, objects_failed=2)
    capped = repo.enqueue_job(ScanJob(kind="scope", payload={"source_type": "github"}))
    repo.complete_job(
        capped.id,
        objects=0,
        findings=0,
        coverage={
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "skipped": 0,
            "roots_failed": 0,
            "stopped_reason": "BUDGET_REQUESTS",
        },
    )
    pdfs = repo.enqueue_job(ScanJob(kind="github", payload={"owner": "o", "repo": "r"}))
    repo.complete_job(pdfs.id, objects=3, findings=0, objects_failed=2, coverage={"failed": 2, "skipped_unsupported": 2})
    failed = repo.enqueue_job(ScanJob(kind="github", payload={"owner": "o", "repo": "r"}))
    repo.fail_job(failed.id, "GITHUB_TREE_UNAVAILABLE: HTTP 404")
    jobs = {j["id"]: j for j in c.get("/api/v1/source-scan-jobs", headers=auth()).json()}
    p, cap, f = jobs[str(partial.id)], jobs[str(capped.id)], jobs[str(failed.id)]
    # `failed` also holds objects read but not fully scanned, so it is not called "unreadable".
    assert p["status"] == "PARTIAL" and p["safe_error_code"] == "OBJECTS_INCOMPLETE" and "2 listed" in p["safe_error_message"]
    # Recorded before format skips were separated: failures and skips are not told apart.
    pdf = jobs[str(pdfs.id)]
    assert pdf["status"] == "PARTIAL" and pdf["safe_error_code"] == "OBJECTS_NOT_SCANNED"
    assert "counted together" in pdf["safe_error_message"] and "format_skips" not in pdf
    assert cap["status"] == "PARTIAL" and cap["result_status"] is None
    assert cap["safe_error_code"] == "BUDGET_REQUESTS"
    assert f["status"] == "FAILED" and f["safe_error_code"] == "GITHUB_TREE_UNAVAILABLE"
    assert "could not be listed" in f["safe_error_message"] and "HTTP 404" not in f["safe_error_message"]
    runs = {r["id"]: r for r in c.get("/api/v1/scan-runs", headers=auth()).json()}
    assert runs[str(partial.id)]["resources_failed"] == 2


def test_format_skips_are_shown_apart_from_failures_and_old_counts_are_never_re_split():
    from cremore.domain.models import ScanJob
    from cremore.scanning.scope import FAILURE_BASIS

    repo = InMemoryRepository()
    c = client(repo)

    def done(coverage, objects_failed=0):
        job = repo.enqueue_job(ScanJob(kind="github-org", payload={"org": "o"}))
        repo.complete_job(job.id, objects=10, findings=0, objects_failed=objects_failed, coverage=coverage)
        return str(job.id)

    skips_only = done({"failed": 0, "skipped_unsupported": 2, "skipped_media": 5, "failure_basis": FAILURE_BASIS})
    mixed = done({"failed": 1, "skipped_unsupported": 2, "skipped_media": 0, "failure_basis": FAILURE_BASIS}, 1)
    # Old counting: 1 read failure + 2 PDFs in `failed`, and 50 images folded into
    # `skipped_unsupported`. Subtracting would hide the read failure.
    ambiguous = done({"failed": 3, "skipped_unsupported": 52}, 3)
    jobs = {j["id"]: j for j in c.get("/api/v1/source-scan-jobs", headers=auth()).json()}
    s, m, a = jobs[skips_only], jobs[mixed], jobs[ambiguous]
    assert s["status"] == "PARTIAL" and s["result_status"] is None and s["safe_error_code"] == "SCOPE_INCOMPLETE"
    assert s["format_skips"] == {"unsupported": 2, "media": 5}
    assert m["status"] == "PARTIAL" and m["safe_error_code"] == "OBJECTS_INCOMPLETE"
    assert m["safe_error_message"].startswith("1 listed") and m["format_skips"] == {"unsupported": 2, "media": 0}
    assert a["status"] == "PARTIAL" and a["safe_error_code"] == "OBJECTS_NOT_SCANNED"
    assert a["safe_error_message"].startswith("3 listed") and "format_skips" not in a
    runs = {r["id"]: r for r in c.get("/api/v1/scan-runs", headers=auth()).json()}
    assert runs[skips_only]["skipped_media"] == 5 and runs[skips_only]["failure_basis"] == FAILURE_BASIS
    assert runs[ambiguous]["failure_basis"] is None


def test_each_run_is_labelled_by_the_detection_policy_it_recorded():
    from cremore.domain.models import ScanJob
    from cremore.scanning.scope import FAILURE_BASIS

    repo = InMemoryRepository()
    c = client(repo)
    current = c.app.state.orchestrator.detection_policy_digest

    def done(**coverage):
        job = repo.enqueue_job(ScanJob(kind="github-org", payload={"org": "o"}))
        repo.complete_job(job.id, objects=1, findings=0, coverage={"failure_basis": FAILURE_BASIS, **coverage})
        return str(job.id)

    unrecorded = done()
    previous = done(detection_policy_digest="0" * 64, authoritative_listing=True)
    now = done(detection_policy_digest=current, authoritative_listing=True)
    queued = str(repo.enqueue_job(ScanJob(kind="github-org", payload={"org": "o"})).id)
    jobs = {j["id"]: j for j in c.get("/api/v1/source-scan-jobs", headers=auth()).json()}
    runs = {r["id"]: r for r in c.get("/api/v1/scan-runs", headers=auth()).json()}
    for view in (jobs, runs):
        assert view[unrecorded]["rule_basis"] == "UNRECORDED"
        assert view[previous]["rule_basis"] == "PREVIOUS"
        assert view[now]["rule_basis"] == "CURRENT"
        assert "rule_basis" not in view[queued]
    assert jobs[now]["connection_wide"] is True and jobs[now]["authoritative_listing"] is True
    assert jobs[unrecorded]["authoritative_listing"] is False


def test_scan_runs_carry_coverage_detail_duration_and_a_hold_reason():
    from cremore.api import create_app
    from cremore.config import Settings
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    import datetime as _dt
    start = _dt.datetime(2026, 9, 16, 7, 0, tzinfo=_dt.UTC)
    done = repo.enqueue_job(ScanJob(kind="scope", connection_id=None, payload={"mode": "DELTA"}))
    repo.jobs[done.id].status = "SUCCEEDED"
    repo.jobs[done.id].started_at = start
    repo.jobs[done.id].finished_at = start + _dt.timedelta(seconds=42)
    repo.jobs[done.id].objects = 1008
    repo.jobs[done.id].findings = 3
    repo.jobs[done.id].coverage = {"bytes": 543753, "requests": 1016, "reused": 4, "skipped_unsupported": 2,
                                   "timings": {"engine_seconds": 3.0, "listing_seconds": 0.5, "persistence_seconds": 1.0}, "stopped_reason": None}
    failed = repo.enqueue_job(ScanJob(kind="scope", connection_id=None, payload={"mode": "BASELINE"}))
    repo.jobs[failed.id].status = "FAILED"
    repo.jobs[failed.id].error = "CHILD_TASK_FAILED"
    running = repo.enqueue_job(ScanJob(kind="scope", connection_id=None, payload={"mode": "BASELINE"}))
    repo.jobs[running.id].status = "RUNNING"

    holds = {str(running.id): {"total": 5, "done": 2, "running": 1, "queued": 2, "held": [{"code": "AWS_LOGIN_REQUIRED"}],
                               "hold_code": "AWS_LOGIN_REQUIRED", "next_attempt_at": "2026-09-16T07:05:00+00:00", "failures": []},
             str(failed.id): {"total": 2, "done": 2, "running": 0, "queued": 0, "held": [], "hold_code": None,
                              "next_attempt_at": None, "failures": [{"root": "abcdef0123456789", "code": "GITHUB_TREE_UNAVAILABLE"}]}}
    token = "t" * 40
    c = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY="ab" * 32),
                              task_states=lambda rid: holds.get(str(rid))))
    runs = {r["id"]: r for r in c.get("/api/v1/scan-runs", headers={"Authorization": f"Bearer {token}"}).json()}
    d = runs[str(done.id)]
    # duration is the actual scan work (engine+listing+persistence = 4.5s), not the 42s wall clock
    assert d["mode"] == "DELTA" and d["duration_seconds"] == 4.5 and d["elapsed_seconds"] == 42.0 and d["bytes"] == 543753 and d["reused"] == 4
    assert d["skipped_unsupported"] == 2 and d["engine_seconds"] == 3.0 and "hold" not in d and "progress" not in d
    r = runs[str(running.id)]
    assert r["progress"] == {"done": 2, "total": 5, "running": 1, "queued": 2}
    assert r["hold"]["code"] == "AWS_LOGIN_REQUIRED" and r["hold"]["waiting_tasks"] == 1
    assert r["hold"]["next_attempt_at"] == "2026-09-16T07:05:00+00:00"
    # a failed run exposes the specific per-root failure codes for the toggle
    fr = runs[str(failed.id)]
    assert fr["error"] == "CHILD_TASK_FAILED" and fr["failures"] == [{"root": "abcdef012345", "code": "GITHUB_TREE_UNAVAILABLE"}]


def _seed_finding(c) -> str:
    c.post("/api/v1/scan", headers=auth(),
           json={"text": f"token = {GH}", "source_type": "github", "resource_name": "r",
                 "location": "a", "exposure": "public"})
    return c.get("/api/v1/findings", headers=auth()).json()[0]["id"]


def test_false_positive_and_ignore_are_audited_and_reopenable():
    c = client()
    fid = _seed_finding(c)
    r = c.post(f"/api/v1/findings/{fid}/false-positive", headers=auth(), json={"reason_code": "FALSE_POSITIVE_CONFIRMED"})
    assert r.status_code == 200 and r.json()["workflow_status"] == "FALSE_POSITIVE"
    assert c.get(f"/api/v1/findings/{fid}", headers=auth()).json()["workflow_status"] == "FALSE_POSITIVE"
    c.post(f"/api/v1/findings/{fid}/reopen", headers=auth(), json={"resolution": "second look"})
    assert c.post(f"/api/v1/findings/{fid}/ignore", headers=auth(), json={}).json()["workflow_status"] == "IGNORED"
    actions = [row["action"] for row in c.get("/api/v1/audit", headers=auth()).json()]
    assert actions == ["FINDING_IGNORED", "FINDING_REOPENED", "FINDING_FALSE_POSITIVE", "FINDING_ROLLUP_UPDATED"]


def test_ownership_review_bulk_update_with_revision_guard():
    c = client()
    fid = _seed_finding(c)
    initial = c.get(f"/api/v1/findings/{fid}/ownership-review", headers=auth()).json()
    assert initial["review"] == {"status": "OPEN", "revision": 0} and initial["context"]["status"] == "NOT_COLLECTED"
    body = {"items": [{"finding_id": fid, "revision": 0}], "status": "WAITING_OWNER",
            "assigned_team": "payments", "due_at": "2026-10-01T00:00:00Z", "closed_reason": ""}
    r = c.post("/api/v1/ownership-reviews/bulk", headers=auth(), json=body)
    assert r.status_code == 200, r.json()
    assert r.json()["updated"] == 1 and r.json()["items"][0]["review"]["revision"] == 1
    assert r.json()["items"][0]["review"]["assigned_team"] == "payments"
    # stale revision -> conflict, nothing written
    assert c.post("/api/v1/ownership-reviews/bulk", headers=auth(), json=body).status_code == 409
    # the review rides along on the finding list
    listed = c.get("/api/v1/findings", headers=auth()).json()[0]
    assert listed["owner_review"]["status"] == "WAITING_OWNER" and listed["owner_review"]["revision"] == 1
    # validation
    assert c.post("/api/v1/ownership-reviews/bulk", headers=auth(),
                  json={**body, "items": [{"finding_id": fid, "revision": 1}], "status": "CLOSED", "closed_reason": "?"}).status_code == 422
    assert c.post("/api/v1/ownership-reviews/bulk", headers=auth(),
                  json={**body, "items": [{"finding_id": fid, "revision": 1}], "status": "IN_PROGRESS", "assigned_team": ""}).status_code == 422
    closed = c.post("/api/v1/ownership-reviews/bulk", headers=auth(),
                    json={**body, "items": [{"finding_id": fid, "revision": 1}], "status": "CLOSED",
                          "closed_reason": "CREDENTIAL_RETIRED", "due_at": None}).json()
    assert closed["items"][0]["review"]["closed_reason"] == "CREDENTIAL_RETIRED"
    # Each saved change is one audit row with its team, due date and reason; refusals write none.
    reviews = [(row["from_status"], row["to_status"], row["note"]) for row in c.get("/api/v1/audit", headers=auth()).json()
               if row["action"] == "FINDING_OWNERSHIP_REVIEW_UPDATED"]
    assert reviews == [("WAITING_OWNER", "CLOSED", 'team="payments" due=- reason=CREDENTIAL_RETIRED'),
                       (None, "WAITING_OWNER", 'team="payments" due=2026-10-01T00:00:00+00:00')]
    # One line of plain text: no secret, no line or paragraph break, nothing that reorders or hides what follows.
    for team in (f"payments {GH}", "payments\nsecurity", "pay\u2028ments", "\u202epayments", "pay\u200bments", "pay\x85ments",
                 "\ud800", {"name": "payments"}, "팀" * 43):
        # JSON's \\ud800 escape carries a lone surrogate, which no UTF-8 body can.
        payload = json.dumps({**body, "items": [{"finding_id": fid, "revision": 2}], "assigned_team": team})
        refused = c.post("/api/v1/ownership-reviews/bulk", headers={**auth(), "Content-Type": "application/json"}, content=payload)
        assert refused.status_code == 422 and GH not in refused.text, team
    for team in (chr(0x3164), "pay" + chr(0x2800) + "ments"):  # letters that draw nothing: a team that reads as empty
        payload = json.dumps({**body, "items": [{"finding_id": fid, "revision": 2}], "assigned_team": team})
        refused = c.post("/api/v1/ownership-reviews/bulk", headers={**auth(), "Content-Type": "application/json"}, content=payload)
        assert refused.status_code == 422 and "TEXT_CONTROL_CHARACTERS" in refused.text, ascii(team)
    assert c.get(f"/api/v1/findings/{fid}/ownership-review", headers=auth()).json()["review"]["revision"] == 2


def test_custom_rules_crud_test_and_scanning():
    c = client()
    rule = {"name": "Internal marker", "pattern": r"(?P<secret>CREMORE_SYNTHETIC_[A-Z0-9]{8})", "keywords": ["cremore_synthetic"],
            "severity": "LOW", "rule_type": "regex", "enabled": True, "fixture_tests": [{"id": "SYNTHETIC_TOKEN", "expected": True}]}
    # unsafe patterns never get stored
    assert c.post("/api/v1/rules", headers=auth(), json={**rule, "pattern": "(?=a)b"}).status_code == 422
    assert c.post("/api/v1/rules", headers=auth(), json={**rule, "pattern": ".*"}).status_code == 422
    assert c.post("/api/v1/rules", headers=auth(), json={**rule, "category": "password"}).status_code == 422
    created = c.post("/api/v1/rules", headers=auth(), json={**rule, "category": "token", "updated_by": "someone-else"})
    assert created.status_code == 201, created.json()
    rid = created.json()["id"]
    assert created.json()["revision"] == 1 and created.json()["severity"] == "LOW"
    # the type is the operator's; who changed the rule and the type its matches report under come from the server
    assert created.json()["category"] == "token" and created.json()["updated_by"] not in (None, "someone-else")
    assert created.json()["credential_type"].startswith("CUSTOM_RULE_")
    assert c.post("/api/v1/rules", headers=auth(), json=rule).status_code == 409
    assert [r["id"] for r in c.get("/api/v1/rules", headers=auth()).json()] == [rid]

    # draft tests: a sample and the synthetic fixtures
    assert c.post("/api/v1/rules/new/test", headers=auth(), json={"rule": rule, "sample": "x = CREMORE_SYNTHETIC_AB12CD34"}).json() == {"matched": True}
    assert c.post(f"/api/v1/rules/{rid}/test", headers=auth(), json={"rule": rule, "sample": "nothing here"}).json() == {"matched": False}
    fx = c.post(f"/api/v1/rules/{rid}/test", headers=auth(), json={"rule": rule, "fixture_id": "NEUTRAL_TEXT"}).json()
    assert fx == {"id": "NEUTRAL_TEXT", "matched": False, "expected": False, "passed": True}
    fx = c.post(f"/api/v1/rules/{rid}/test", headers=auth(), json={"rule": rule, "fixture_id": "SYNTHETIC_ID_ONLY"}).json()
    assert fx["matched"] is True and fx["expected"] is False and fx["passed"] is False  # rule is broader than intended
    assert c.post(f"/api/v1/rules/{rid}/test", headers=auth(), json={"rule": rule, "fixture_id": "NOPE"}).status_code == 422

    # the rule scans live: inline scan reports it under the custom provider with its severity
    c.post("/api/v1/scan", headers=auth(), json={"text": "deploy = CREMORE_SYNTHETIC_AB12CD34\n", "source_type": "inline"})
    findings = c.get("/api/v1/findings", headers=auth()).json()
    assert len(findings) == 1 and findings[0]["provider"] == "custom" and findings[0]["severity"] == "LOW"
    assert findings[0]["credential_type"].startswith("CUSTOM_RULE_")

    # editing bumps the revision and the engine follows; disabling removes it
    updated = c.put(f"/api/v1/rules/{rid}", headers=auth(), json={**rule, "severity": "HIGH", "exclude_words": ["deploy"]})
    assert updated.status_code == 200 and updated.json()["revision"] == 2 and updated.json()["severity"] == "HIGH"
    assert updated.json()["category"] == "token" and updated.json()["updated_by"] == created.json()["updated_by"]
    c.post("/api/v1/scan", headers=auth(), json={"text": "deploy = CREMORE_SYNTHETIC_ZZ99YY88\n", "source_type": "inline"})
    assert len(c.get("/api/v1/findings", headers=auth()).json()) == 1  # excluded by context word
    assert c.put(f"/api/v1/rules/{rid}", headers=auth(), json={**rule, "pattern": "(a)\\1"}).status_code == 422
    assert c.delete(f"/api/v1/rules/{rid}", headers=auth()).status_code == 204
    assert c.delete(f"/api/v1/rules/{rid}", headers=auth()).status_code == 404
    c.post("/api/v1/scan", headers=auth(), json={"text": "x = CREMORE_SYNTHETIC_QQ11WW22\n", "source_type": "inline"})
    assert len(c.get("/api/v1/findings", headers=auth()).json()) == 1  # rule gone, nothing new


def test_credential_check_is_queued_and_reflected_on_the_connection():
    repo = InMemoryRepository()
    c = client(repo)
    conn = source(c, "github", "example-org/app", "App", "vault://github/app")
    assert conn["credential"]["checkable"] is True and conn["connection_auth"]["state"] == "AUTH_FRESHNESS_UNKNOWN"
    r = c.post(f"/api/v1/source-connections/{conn['id']}/credential/check", headers=auth())
    assert r.status_code == 202 and r.json()["job_kind"] == "CREDENTIAL_CHECK" and r.json()["source_type"] == "github"
    raw = c.get(f"/api/v1/scan-jobs/{r.json()['id']}", headers=auth()).json()
    assert raw["kind"] == "credential-check" and "payload" not in raw
    stored = repo.get_job(uuid_of(r.json()["id"]))
    assert stored.payload["secret_ref"] == "vault://github/app" and "token" not in stored.payload
    # the worker records evidence; the dashboard shape follows
    from cremore.collectors.credential_check import CredentialCheck
    from cremore.worker import JobWorker

    JobWorker(
        repo,
        credential_checker=lambda job: CredentialCheck(
            "ACTIVE",
            owner="ci-bot",
            scopes=("contents:read",),
            detail={
                "credential_mode": "GITHUB_APP",
                "refresh_supported": True,
                "expires_at": "2026-09-14T09:00:00+00:00",
                "ignored": "never persisted",
            },
        ),
    ).process_next()
    shown = c.get("/api/v1/source-connections", headers=auth()).json()[0]
    assert shown["credential"]["status"] == "ACTIVE" and shown["credential"]["owner"] == "ci-bot"
    assert shown["connection_auth"]["state"] == "READY" and shown["enabled"] is True
    assert shown["connection_auth"]["refresh_supported"] is True
    assert shown["connection_auth"]["expires_at"] == "2026-09-14T09:00:00+00:00"
    assert "ignored" not in str(repo.get_connection(uuid_of(conn["id"])).credential_evidence)
    jobs = c.get("/api/v1/source-scan-jobs", headers=auth()).json()
    assert jobs[0]["job_kind"] == "CREDENTIAL_CHECK" and jobs[0]["status"] == "COMPLETED"


def test_operations_status_reports_auth_worker_and_partial_jobs_without_raw_errors():
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    c = client(repo)
    conn = source(c, "github", "example/app", "App", "vault://github/app")
    partial = repo.enqueue_job(ScanJob(kind="github", payload={"token": "must-not-leak"}))
    repo.complete_job(partial.id, objects=2, findings=0, objects_failed=1)
    failed = repo.enqueue_job(ScanJob(kind="github", payload={"token": "must-not-leak"}))
    repo.fail_job(failed.id, "PROVIDER_ERROR: raw response must not leak")
    repo.enqueue_job(ScanJob(kind="github", payload={"token": "must-not-leak"}))

    response = c.get("/api/v1/operations/status", headers=auth())
    assert response.status_code == 200
    body = response.json()
    assert body["authentication"]["counts"]["AUTH_FRESHNESS_UNKNOWN"] == 1
    assert body["worker"]["activity"] == "QUEUE_WAITING"
    assert body["jobs"]["counts"] == {"QUEUED": 1, "RUNNING": 0, "FAILED": 1, "PARTIAL": 1}
    assert {alert["code"] for alert in body["alerts"]} == {
        "CONNECTION_AUTH_FRESHNESS_UNKNOWN", "JOB_PARTIAL", "JOB_FAILED"
    }
    rendered = str(body)
    assert conn["id"] in rendered and "raw response" not in rendered and "must-not-leak" not in rendered


def test_operations_status_does_not_raise_a_run_partial_only_for_the_upgrade_hold():
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    c = client(repo)
    held = {"root_coverage_complete": False, "policy_held": 1}
    runs = {}
    for name, coverage in (("held only", {**held, "policy_held_only": True}),  # the next full scan reads the rest
                           ("held and a gap", {**held, "inspection_gaps": 1}),
                           ("held and a failure", {**held, "failed": 1}),
                           ("not held", {"root_coverage_complete": False})):
        job = repo.enqueue_job(ScanJob(kind="scope", payload={"mode": "DELTA", "trigger": "SCHEDULE"}))
        repo.complete_job(job.id, objects=1, findings=0, coverage=coverage)
        runs[name] = str(job.id)
    body = c.get("/api/v1/operations/status", headers=auth()).json()
    raised = {alert["resource_id"] for alert in body["alerts"] if alert["code"] == "JOB_PARTIAL"}
    assert raised == {runs["held and a gap"], runs["held and a failure"], runs["not held"]}
    assert body["jobs"]["counts"]["PARTIAL"] == 3


class FakeSessions:
    """AccountSessions stand-in: opens only the accounts listed, records what was asked."""

    def __init__(self, *open_accounts, refusals=None):
        self.open_accounts, self.refusals, self.opened = set(open_accounts), refusals or {}, []

    def open(self, account_id, purpose):
        from cremore_aws_provider.aws_access import AccessBlocked
        from cremore_aws_provider.aws_sessions import AccountSession

        self.opened.append((account_id, purpose))
        if not account_id:
            raise AccessBlocked("ACCOUNT_OWNER_UNKNOWN")
        if account_id in self.refusals:
            raise AccessBlocked(self.refusals[account_id])
        if account_id not in self.open_accounts:
            raise AccessBlocked("ACCOUNT_NOT_CONNECTED")
        return AccountSession(account_id, purpose, "ROLE", {"AccessKeyId": "ASIA"}, lambda *a: object())


def _aws_key_credential(repo):
    from cremore.domain.models import Credential

    return repo.upsert_credential(Credential(
        fingerprint="fp-usage", credential_type="AWS_ACCESS_KEY", provider="aws",
        identifier="AKIAZ5X9K2" "MBV7QP3LN6", identifier_hint="AKIA••••••" "••••••3LN6",
        principal_arn="arn:aws:iam::123456789012:user/ci-deployer", credential_status="Active"))


def test_credential_usage_defaults_and_refresh_requires_configuration():
    repo = InMemoryRepository()
    cred = _aws_key_credential(repo)
    c = client(repo)
    usage = c.get(f"/api/v1/credentials/{cred.id}/usage", headers=auth()).json()
    assert usage["collection_status"] == "NOT_COLLECTED" and usage["credential_class"] == "LONG_LIVED"
    assert usage["potential_access"]["collection_status"] == "NOT_COLLECTED" and usage["events"] == []
    r = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert r.status_code == 501 and "USAGE_LOOKUP_OFF" in r.json()["error"]
    assert c.get("/api/v1/credentials/00000000-0000-4000-8000-000000000000/usage", headers=auth()).status_code == 404


def test_credential_usage_refresh_stores_snapshot_and_last_used():
    import datetime as dt

    from cremore_aws_provider.investigation.usage import LastUsed

    class FakeUsage:
        def collect(self, key_id, principal_arn=""):
            assert key_id == "AKIAZ5X9K2" "MBV7QP3LN6"
            return {"credential_class": "LONG_LIVED", "collection_status": "COMPLETE", "event_scope": "MANAGEMENT",
                    "regions_discovered": 1, "regions_complete": 1, "regions_failed": 0, "regions_capped": 0,
                    "events": [{"event_id": "e1", "event_time": "2026-09-13T00:00:00+00:00", "region": "us-east-1",
                                "evidence_source": "EVENT_HISTORY", "event_category": "MANAGEMENT",
                                "event_source": "s3.amazonaws.com", "event_name": "ListBuckets", "access_mode": "READ",
                                "outcome": "SUCCEEDED", "resources": []}],
                    "coverage": [], "scenarios": [],
                    "cloudtrail_lake": {"configured": False, "status": "NOT_CONFIGURED", "event_scope": "MANAGEMENT_AND_DATA",
                                        "evidence_source": "CLOUDTRAIL_LAKE", "events_collected": 0},
                    "potential_access": {"collection_status": "NOT_COLLECTED", "evidence_level": "POTENTIAL",
                                         "method": "IAM_SIMULATE_PRINCIPAL_POLICY",
                                         "scope": "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_RESOURCES", "limitations": [], "actions": []}}

        def last_used(self, key_id):
            return LastUsed(at=dt.datetime(2026, 9, 12, tzinfo=dt.UTC), service="s3", region="us-east-1")

    class FakePotential:
        def collect(self, arn, identity_policies=None):
            from cremore_aws_provider.investigation.potential_access import (
                ActionDecision,
                PotentialAccess,
            )

            return PotentialAccess(arn, "COMPLETE", actions=[ActionDecision("s3:GetObject", "ALLOWED", "READ")])

    repo = InMemoryRepository()
    switch_investigation_on(repo)  # the factory is wired; the Admin's switch must be on too
    cred = _aws_key_credential(repo)
    sessions = FakeSessions("123456789012")
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                     usage_service_factory=lambda session: FakeUsage(),
                     potential_access_factory=lambda session: FakePotential(), aws_sessions=sessions)
    c = TestClient(app)
    r = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert r.status_code == 200, r.json()
    assert r.json()["collection_status"] == "COMPLETE" and r.json()["events"][0]["event_name"] == "ListBuckets"
    # collected in the verified key owner's account, and recorded as such
    assert sessions.opened == [("123456789012", "scanner")]
    assert r.json()["collected_account_id"] == "123456789012" and r.json()["collected_via"] == "ROLE"
    assert r.json()["potential_access"]["collection_status"] == "COMPLETE"
    # identity policies are read through the owner-account scanner session (this fake client has no IAM)
    assert r.json()["identity_policies"]["principal_arn"] == cred.principal_arn
    assert r.json()["identity_policies"]["collection_status"] == "FAILED"
    assert r.json()["potential_access"]["actions"] == [{"action": "s3:GetObject", "service": "s3", "decision": "ALLOWED",
                                                          "risk": "READ", "missing_context_values": [], "resource_scope": "ALL"}]
    # persisted: the GET serves it, and the credential's last-used facts follow
    again = c.get(f"/api/v1/credentials/{cred.id}/usage", headers=auth()).json()
    assert again["collection_status"] == "COMPLETE" and again["account_verified"] is True
    # a snapshot recorded without its account is shown, never as complete evidence
    repo.update_credential(cred.id, usage_snapshot={**again, "collected_account_id": None})
    legacy = c.get(f"/api/v1/credentials/{cred.id}/usage", headers=auth()).json()
    assert legacy["collection_status"] == "ACCOUNT_UNVERIFIED" and legacy["recorded_collection_status"] == "COMPLETE"
    assert legacy["account_verified"] is False and legacy["events"]
    c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    stored = repo.get_credential(cred.id)
    assert stored.last_used_service == "s3" and stored.last_used_region == "us-east-1" and stored.last_used_at
    # not an AWS key -> 422
    c.post("/api/v1/scan", headers=auth(), json={"text": f"token = {GH}", "source_type": "github"})
    gh = c.get("/api/v1/credentials", headers=auth()).json()
    other = next(x for x in gh if x["credential_type"] == "GITHUB_TOKEN")
    assert c.post(f"/api/v1/credentials/{other['id']}/usage/refresh", headers=auth()).status_code == 422


def test_usage_is_never_collected_outside_the_verified_owner_account():
    class ExplodingUsage:
        def collect(self, *a, **k):
            raise AssertionError("must not collect")

    repo = InMemoryRepository()
    switch_investigation_on(repo)  # the factory is wired; the Admin's switch must be on too
    cred = _aws_key_credential(repo)
    sessions = FakeSessions(refusals={"123456789012": "REVALIDATION_REQUIRED"})
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                     usage_service_factory=lambda session: ExplodingUsage(), aws_sessions=sessions)
    c = TestClient(app)
    r = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert r.status_code == 409 and r.json()["error"].startswith("REVALIDATION_REQUIRED")
    assert repo.get_credential(cred.id).usage_snapshot is None  # nothing stored, no COMPLETE claim

    sessions.refusals = {}
    r = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert r.status_code == 409 and r.json()["error"].startswith("ACCOUNT_NOT_CONNECTED")
    # an unverified key has no owner account
    repo.update_credential(cred.id, principal_arn=None)
    r = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert r.status_code == 409 and r.json()["error"].startswith("ACCOUNT_OWNER_UNKNOWN")
    # without a session provider the API refuses rather than using its own identity
    bare = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                                 usage_service_factory=lambda session: ExplodingUsage()))
    repo.update_credential(cred.id, principal_arn="arn:aws:iam::123456789012:user/ci-deployer")
    assert bare.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth()).status_code == 503


@pytest.mark.parametrize("operation", [
    "describe_regions", "lookup_events", "simulate_principal_policy", "list_access_keys",
    "list_groups_for_user", "get_access_key_last_used", "client", "session",
])
def test_usage_session_expiry_keeps_saved_evidence_and_collection_time(operation):
    from copy import deepcopy

    from botocore.exceptions import ClientError
    from cremore_aws_provider.aws_access import AccessBlocked
    from cremore_aws_provider.aws_sessions import AccountSession
    from cremore_aws_provider.investigation.potential_access import PotentialAccessService
    from cremore_aws_provider.investigation.usage import CredentialUsageService

    repo = InMemoryRepository()
    switch_investigation_on(repo)
    cred = _aws_key_credential(repo)
    responses = {
        "describe_regions": {"Regions": [{"RegionName": "us-east-1"}]},
        # An expired-token event is evidence about the found key, not a scanner failure.
        "lookup_events": {"Events": [{"EventId": "historical-event", "EventTime": datetime(2026, 9, 19, tzinfo=UTC),
                                     "CloudTrailEvent": '{"errorCode":"ExpiredToken"}'}]},
        "get_access_key_last_used": {"AccessKeyLastUsed": {"LastUsedDate": datetime(2026, 9, 18, tzinfo=UTC)}},
        "simulate_principal_policy": {"EvaluationResults": []},
        "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": cred.identifier, "Status": "Active"}]},
        "get_user": {"User": {}}, "list_user_policies": {"PolicyNames": ["ReadOnly"]},
        "get_user_policy": {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}},
        "list_attached_user_policies": {"AttachedPolicies": []}, "list_groups_for_user": {"Groups": []},
    }

    class Provider:
        failed = None
        code = "ExpiredToken"

        def check(self, name):
            if name == self.failed:
                raise ClientError({"Error": {"Code": self.code, "Message": "provider text must not leak"}}, name)

        def __getattr__(self, name):
            def call(**kwargs):
                self.check(name)
                return deepcopy(responses[name])
            return call

        def client(self, *args):
            self.check("client")
            return self

    provider = Provider()

    class Sessions:
        def open(self, account_id, purpose):
            if provider.failed == "session":
                raise AccessBlocked("AWS_LOGIN_REQUIRED")
            return AccountSession(account_id, purpose, "SSO_PERMISSION_SET", None, provider.client)

    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                     aws_sessions=Sessions(),
                     usage_service_factory=lambda session: CredentialUsageService(
                         lambda region: session.client("cloudtrail", region), session.client("ec2"), session.client("iam")),
                     potential_access_factory=lambda session: PotentialAccessService(session.client("iam")))
    c = TestClient(app)
    path = f"/api/v1/credentials/{cred.id}/usage"
    assert c.post(f"{path}/refresh", headers=auth()).status_code == 200
    saved = deepcopy(repo.get_credential(cred.id).usage_snapshot)
    assert saved["identity_policies"]["policies"] and saved["access_key"]["status"] == "Active"
    provider.failed = operation
    response = c.post(f"{path}/refresh", headers=auth())
    assert response.status_code == 409, response.json()
    assert response.json()["error"].startswith("AWS_LOGIN_REQUIRED")
    assert "provider text" not in response.text
    assert repo.get_credential(cred.id).usage_snapshot == saved
    # The read adds the technique labels; the saved evidence itself is untouched.
    served = c.get(path, headers=auth()).json()
    assert {key: value for key, value in served.items() if key != "techniques"} == {**saved, "account_verified": True}
    provider.failed = None
    assert c.post(f"{path}/refresh", headers=auth()).status_code == 200
    # A genuine IAM denial stays partial policy evidence; it is never called login expiry.
    provider.failed, provider.code = "list_groups_for_user", "AccessDenied"
    denied = c.post(f"{path}/refresh", headers=auth()).json()["identity_policies"]
    assert denied["collection_status"] == "PARTIAL" and denied["policies"]
    assert denied["errors"] == [{"step": "ListGroupsForUser", "error_code": "AccessDenied"}]


def test_an_identifier_without_its_secret_is_resolved_through_the_owner_account():
    """A saved exact IAM owner avoids probing all connected accounts."""
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.aws_sessions import AccountSession
    from cremore_aws_provider.investigation.usage import CredentialUsageService

    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
    from cremore.coverage.store import CoverageStore
    from cremore.domain.models import AwsAccount, Credential

    repo = InMemoryRepository()
    switch_investigation_on(repo)
    key_id = "AKIAZ5X9K2" "MBV7QP3LN6"
    cred = repo.upsert_credential(Credential(
        fingerprint="fp-identifier-only", credential_type="AWS_ACCESS_KEY_ID", provider="aws",
        identifier=key_id, identifier_hint="AKIA••••••" "••••••3LN6"))
    for account in ("111111111111", "222222222222"):
        repo.create_aws_account(AwsAccount(account_id=account, name=account,
            access="RUNTIME_IDENTITY", validation_status="VALID", validation_key="1:1"))
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1}, "admin")
    store = CoverageStore(repo)
    row, _ = store.create(ConnectionSpec(name="Synthetic IAM", provider="aws_iam", account_id="222222222222"), "admin")
    run = store.start(row["id"], row["revision"], str(uuid.uuid4()), Contract(engine_digest="a" * 64).model_dump())
    arn = "arn:aws:iam::222222222222:user/ops/ci-deployer"
    store.append(row["id"], run["id"], Batch(index=0, items=[Observation(
        reference=arn, principal_arn=arn, account_id="222222222222", evidence="ISSUED",
        credential_type="AWS_ACCESS_KEY", identifier=key_id, state="Active")]))
    store.finish(row["id"], run["id"], Finish(batch_count=1, item_count=1, status="COMPLETE"))

    class Provider:
        def __init__(self, account_id):
            self.account_id = account_id

        def get_access_key_last_used(self, AccessKeyId):
            assert self.account_id == "222222222222" and AccessKeyId == key_id
            return {"UserName": "ci-deployer", "AccessKeyLastUsed": {
                "LastUsedDate": datetime(2026, 9, 18, tzinfo=UTC), "ServiceName": "s3", "Region": "us-east-1"}}

        def get_user(self, UserName):
            return {"User": {"Arn": "arn:aws:iam::222222222222:user/ops/ci-deployer"}}

        def list_access_keys(self, UserName):
            return {"AccessKeyMetadata": [{"AccessKeyId": key_id, "Status": "Active",
                                           "CreateDate": datetime(2026, 1, 2, tzinfo=UTC)}]}

        def describe_regions(self, **kwargs):
            return {"Regions": [{"RegionName": "us-east-1"}]}

        def lookup_events(self, **kwargs):
            return {"Events": []}

        def list_user_policies(self, **kwargs):
            return {"PolicyNames": []}

        def list_attached_user_policies(self, **kwargs):
            return {"AttachedPolicies": []}

        def list_groups_for_user(self, **kwargs):
            return {"Groups": []}

        def client(self, service, region=None):
            return self

    opened = []

    class Sessions:
        def open(self, account_id, purpose):
            opened.append(account_id)
            assert account_id == "222222222222"
            provider = Provider(account_id)
            return AccountSession(account_id, purpose, "ROLE", None, lambda *a, **k: provider)

    c = TestClient(create_app(
        repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
        aws_sessions=Sessions(),
        usage_service_factory=lambda session: CredentialUsageService(
            lambda region: session.client("cloudtrail", region), session.client("ec2"), session.client("iam"))))
    response = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert response.status_code == 200, response.json()
    snapshot = response.json()

    # Only the saved owner account was opened; there was no ownership sweep.
    assert snapshot["collected_account_id"] == "222222222222"
    assert opened == ["222222222222"]
    assert snapshot["owner_lookup"]["source"] == "IAM_INVENTORY"
    assert snapshot["owner_lookup"]["run_id"] == str(run["id"])
    assert snapshot["access_key"] == {"collection_status": "COMPLETE", "status": "Active",
                                      "created_at": "2026-01-02T00:00:00+00:00"}

    from cremore.api.credential_governance import credential_governance

    saved = repo.get_credential(cred.id)
    assert saved.principal_arn == "arn:aws:iam::222222222222:user/ops/ci-deployer"
    # The owner came from IAM, not from verifying the key; the projection says so.
    assert saved.principal_arn_source == "IAM_INVENTORY"
    assert saved.credential_status == "Active" and saved.last_used_service == "s3"
    facts = {f["key"]: f for f in credential_governance(saved, [], None)["metadata"]}
    assert facts["provider_owner"]["source"] == "IAM_INVENTORY"
    assert facts["provider_owner"]["observed_at"] == snapshot["owner_lookup"]["observed_at"]
    assert facts["verification"]["value"] == "NOT_SUPPORTED"  # still no secret to verify with

    # An owner established this way can be acted on: a key is disabled by its id.
    capability = credential_governance(saved, [], None)["type_capability"]
    assert capability["supports_rotation"]["documented_support"] == "CONDITIONAL"
    assert capability["supports_verification"]["documented_support"] == "NOT_SUPPORTED"

    # A second refresh checks the saved inventory evidence, without a sweep.
    opened.clear()
    assert c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth()).status_code == 200
    assert opened == ["222222222222"]
    assert repo.get_credential(cred.id).usage_snapshot["owner_lookup"] == snapshot["owner_lookup"]
    store.change(row["id"], row["revision"], "admin", enabled=False)
    opened.clear()
    assert c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth()).status_code == 409
    assert not opened  # a stale inventory-derived principal is not reused


@pytest.mark.parametrize("background", [False, True])
def test_an_identifier_no_connected_account_claims_is_refused_not_guessed(background):
    from cremore.domain.models import AwsAccount, Credential

    repo = InMemoryRepository()
    switch_investigation_on(repo)
    cred = repo.upsert_credential(Credential(
        fingerprint="fp-orphan", credential_type="AWS_ACCESS_KEY_ID", provider="aws",
        identifier="AKIAN6P3Q7" "VBM2K9X5ZL"))
    repo.create_aws_account(AwsAccount(account_id="111111111111", name="a",
                                       scanner_role_arn="arn:aws:iam::111111111111:role/R",
                                       external_id="external-id-0123456789"))

    class Sessions:
        def open(self, account_id, purpose):
            pytest.fail("an unowned identifier must not open any provider account")

    c = TestClient(create_app(
        repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
        aws_sessions=Sessions(), usage_service_factory=lambda session: None))
    response = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", params={"background": background}, headers=auth())
    assert response.status_code == 409 and response.json()["error"].startswith("ACCOUNT_OWNER_UNKNOWN")
    assert "does not establish a unique owner" in response.json()["error"]
    # Missing inventory is not evidence that the key is absent.
    assert repo.get_credential(cred.id).principal_arn is None


def _review(now):
    import datetime as dt

    u = lambda n: f"00000000-0000-4000-8000-{n:012d}"
    return {"mode": "PLANNED", "scope_evidence_id": u(1), "recovery_evidence_id": u(2), "scope_complete": True,
            "unknown_consumers": False, "business_impact": "LIMITED", "impact_accepted": True,
            "stop_criteria_reviewed": True, "replacement_reviewed": True,
            "window_start": (now - dt.timedelta(hours=1)).isoformat(), "window_end": (now + dt.timedelta(hours=4)).isoformat(),
            "consumers": [{"consumer_id": u(3), "owner_id": u(4), "evidence_id": u(5), "environment": "PRODUCTION",
                           "transition": "SUCCEEDED", "authentication_basis": "NEW_CREDENTIAL", "workload_succeeded": True,
                           "scheduled_cycle_checked": True, "confirmed_at": (now - dt.timedelta(hours=2)).isoformat(),
                           "valid_until": (now + dt.timedelta(hours=6)).isoformat()}]}


def test_action_plans_local_single_operator_self_approves_after_reconfirming():
    import datetime as dt
    import uuid as _uuid

    repo = InMemoryRepository()
    cred = _aws_key_credential(repo)
    c = client(repo)
    listing = c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth()).json()
    assert listing["plans"] == [] and listing["policy"]["can_plan"] is True and listing["policy"]["auth_mode"] == "local"
    assert listing["policy"]["execution_enabled"] is False and listing["policy"]["single_operator"] is True
    body = {"action_type": "DISABLE_ACCESS_KEY", "reason_code": "EXPOSURE_CONTAINMENT", "idempotency_key": str(_uuid.uuid4()),
            "operational_review": _review(dt.datetime.now(dt.UTC))}
    created = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth(), json=body)
    assert created.status_code == 201, created.json()
    plan = created.json()
    assert plan["status"] == "PENDING_APPROVAL" and plan["readiness"]["execution_gate_passed"] is True
    assert plan["user_name"] == "ci-deployer" and plan["account_id"] == "123456789012" and "key_id" not in plan
    assert c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth()).json()["policy"]["block_reason"] == "ACTION_PLAN_TARGET_LOCKED"
    # the single local operator is the requester: approval needs an explicit re-confirmation
    r = c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=auth(), json={"plan_hash": plan["plan_hash"]})
    assert r.status_code == 409 and "SELF_APPROVAL_CONFIRMATION_REQUIRED" in r.json()["error"]
    r = c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=auth(),
               json={"plan_hash": plan["plan_hash"], "self_approval_confirmed": True})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED" and r.json()["self_approved"] is True
    # execution still follows installation policy
    r = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=auth(), json={"plan_hash": plan["plan_hash"]})
    assert r.status_code == 409 and "EXECUTION_DISABLED" in r.json()["error"]
    cancelled = c.post(f"/api/v1/action-plans/{plan['id']}/cancel", headers=auth(), json={})
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "CANCELLED"
    # a malformed review is rejected before anything is stored
    bad = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth(),
                 json={**body, "idempotency_key": str(_uuid.uuid4()), "operational_review": {"mode": "PLANNED"}})
    assert bad.status_code == 422 and "CHANGE_REVIEW_INVALID" in bad.json()["error"]
    assert len(c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth()).json()["plans"]) == 1


def test_the_approvals_queue_lists_every_plan_newest_first_with_its_target():
    import datetime as dt
    import uuid as _uuid

    repo = InMemoryRepository()
    cred = _aws_key_credential(repo)
    c = client(repo)
    body = {"action_type": "DISABLE_ACCESS_KEY", "reason_code": "EXPOSURE_CONTAINMENT",
            "operational_review": _review(dt.datetime.now(dt.UTC))}
    first = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth(),
                   json={**body, "idempotency_key": str(_uuid.uuid4())}).json()
    c.post(f"/api/v1/action-plans/{first['id']}/cancel", headers=auth(), json={})
    second = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=auth(),
                    json={**body, "idempotency_key": str(_uuid.uuid4())}).json()
    queue = c.get("/api/v1/action-plans", headers=auth()).json()
    assert [item["id"] for item in queue["items"]] == [second["id"], first["id"]]
    assert queue["items"][0]["target"] == {"kind": "credential", "credential_type": cred.credential_type, "provider": cred.provider}
    assert queue["policy"]["single_operator"] is True and "can_plan" not in queue["policy"]
    waiting = c.get("/api/v1/action-plans?status=PENDING_APPROVAL", headers=auth()).json()["items"]
    assert [item["id"] for item in waiting] == [second["id"]]


def test_action_plan_two_party_execution_over_oidc(issuer):
    import datetime as dt
    import uuid as _uuid

    from cremore.api.conftest import oidc_settings
    from cremore.remediation.action_plans import KeyActionAdapter

    class Adapter(KeyActionAdapter):
        def __init__(self):
            self.status, self.writes = "Active", []

        def key_status(self, user_name, key_id):
            return self.status

        def disable_key(self, user_name, key_id):
            self.writes.append((user_name, key_id))
            self.status = "Inactive"

        def delete_key(self, user_name, key_id):
            raise AssertionError("not requested")

    adapter = Adapter()
    repo = InMemoryRepository()
    cred = _aws_key_credential(repo)
    sessions = FakeSessions("123456789012")
    app = create_app(repo=repo, settings=oidc_settings(ACTION_EXECUTION_ENABLED="true"), oidc_http_client=issuer,
                     key_action_adapter_factory=lambda session: adapter, aws_sessions=sessions)
    c = TestClient(app)
    remediator = _bearer(issuer, "rita", "g-remediators")
    admin = _bearer(issuer, "adam", "g-admins")
    analyst = _bearer(issuer, "ann", "g-analysts")
    body = {"action_type": "DISABLE_ACCESS_KEY", "reason_code": "SECURITY_INCIDENT", "idempotency_key": str(_uuid.uuid4()),
            "operational_review": _review(dt.datetime.now(dt.UTC))}
    assert c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=analyst, json=body).status_code == 403
    plan = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=remediator, json=body).json()
    # the requester (even as admin-capable) may not approve; a different admin may
    assert c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=remediator, json={"plan_hash": plan["plan_hash"]}).status_code == 403
    approved = c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=admin, json={"plan_hash": plan["plan_hash"]}).json()
    assert approved["status"] == "APPROVED" and approved["approved_by"] == "adam"
    # execution is bound to the hash and read back from the provider
    wrong = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=remediator, json={"plan_hash": "0" * 64})
    assert wrong.status_code == 409 and adapter.writes == []
    # The key's owner has not approved: execution waits, until an Admin turns that wait off (audited).
    waiting = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=remediator, json={"plan_hash": plan["plan_hash"]})
    assert waiting.status_code == 409 and "OWNER_APPROVAL_REQUIRED" in waiting.json()["error"]
    assert sessions.opened == []  # a request failing its gates never opens an AWS session
    assert c.put("/api/v1/settings/owner-approval", headers=remediator, json={"required": False}).status_code == 403
    policy = c.put("/api/v1/settings/owner-approval", headers=admin, json={"required": False}).json()
    assert policy["required"] is False and policy["updated_by"] == "adam"
    assert [(e.actor, e.note) for e in repo.finding_events.values() if e.event_type == "OWNER_APPROVAL_POLICY_CHANGED"] == [
        ("adam", "required=off")]
    done = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=remediator, json={"plan_hash": plan["plan_hash"]}).json()
    assert done["status"] == "VERIFIED" and done["verified_at"] and done["provider_write_started_at"]
    assert sessions.opened == [("123456789012", "remediation")]
    assert adapter.writes == [("ci-deployer", ("AKIAZ5X9K2" "MBV7QP3LN6"))]
    listing = c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=analyst).json()
    assert listing["plans"][0]["status"] == "VERIFIED" and listing["policy"]["can_plan"] is True


def test_an_admin_contains_a_publicly_exposed_key_at_once_and_the_owner_is_told_after(issuer):
    import datetime as dt
    import uuid as _uuid

    from cremore.api.conftest import oidc_settings
    from cremore.domain.models import Exposure
    from cremore.governance.contact_test import MAIL, Relay
    from cremore.remediation.action_plans import KeyActionAdapter

    class Adapter(KeyActionAdapter):
        def __init__(self):
            self.status, self.writes = "Active", []

        def key_status(self, user_name, key_id):
            return self.status

        def disable_key(self, user_name, key_id):
            self.writes.append((user_name, key_id))
            self.status = "Inactive"

        def delete_key(self, user_name, key_id):
            raise AssertionError("not requested")

    adapter, relay = Adapter(), Relay()
    repo = InMemoryRepository()
    cred = _aws_key_credential(repo)
    app = create_app(repo=repo, settings=oidc_settings(ACTION_EXECUTION_ENABLED="true"), oidc_http_client=issuer,
                     key_action_adapter_factory=lambda session: adapter, aws_sessions=FakeSessions("123456789012"))
    app.state.contact_transports = {"smtp": relay, "smtp_ssl": relay}
    c = TestClient(app)
    remediator, admin = _bearer(issuer, "rita", "g-remediators"), _bearer(issuer, "adam", "g-admins")
    body = {"action_type": "DISABLE_ACCESS_KEY", "reason_code": "SECURITY_INCIDENT", "idempotency_key": str(_uuid.uuid4()),
            "operational_review": _review(dt.datetime.now(dt.UTC))}
    plan = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=remediator, json=body).json()
    c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=admin, json={"plan_hash": plan["plan_hash"]})
    path = f"/api/v1/action-plans/{plan['id']}/emergency-execute"
    urgent = {"plan_hash": plan["plan_hash"], "reason": "공개 저장소에 노출되어 사용 기록이 있음"}
    # Not publicly exposed: the owner's approval stands in the way.
    refused = c.post(path, headers=admin, json=urgent)
    assert refused.status_code == 409 and "EMERGENCY_NOT_PUBLIC" in refused.json()["error"]
    # A public label someone pasted with text is not evidence; a connection's own scan is.
    pasted = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="inline", resource_name="pasted",
                                           location="-", metadata={"exposure": "public"}))
    repo.upsert_finding(cred.id, pasted.id, "HIGH")
    assert c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=remediator).json()["plans"][0]["emergency_eligible"] is False
    repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="acme/app", location="deploy.yml",
                                  metadata={"exposure": "public"}, source_connection_id=_uuid.uuid4()))
    assert c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=remediator).json()["plans"][0]["emergency_eligible"] is True
    # An Admin's decision, with a reason.
    assert c.post(path, headers=remediator, json=urgent).status_code == 403
    short = c.post(path, headers=admin, json={**urgent, "reason": "급함"})
    assert (short.status_code, short.json()["detail"]) == (422, "EMERGENCY_REASON_REQUIRED")
    assert any(e.event_type == "ACTION_PLAN_REFUSED" and e.note.startswith("EMERGENCY EMERGENCY_REASON_REQUIRED")
               for e in repo.finding_events.values())
    done = c.post(path, headers=admin, json=urgent).json()
    assert done["status"] == "VERIFIED" and adapter.writes and done["owner_emergency"]["notice_pending"] is True
    kinds = [e.event_type for e in repo.finding_events.values() if e.target_id == uuid_of(plan["id"])]
    assert kinds.index("ACTION_PLAN_EMERGENCY") < kinds.index("ACTION_PLAN_EXECUTION_STARTED")  # declared before any write
    # The owner is told afterwards, in CreMore's own words and without a link; a message that does not go out
    # leaves the notice pending, with why.
    c.put("/api/v1/settings/contact-delivery", headers=admin, json={"mail": MAIL, "allowed_domains": ["example.com"]})
    notice = f"/api/v1/action-plans/{plan['id']}/owner-notice"
    app.state.contact_transports = {"smtp": Relay(fail="connect"), "smtp_ssl": Relay(fail="connect")}
    lost = c.post(notice, headers=remediator, json={"channel": "mail", "to": "kim@example.com"})
    assert lost.status_code == 502 and c.get(f"/api/v1/credentials/{cred.id}/action-plans", headers=remediator).json()[
        "plans"][0]["owner_emergency"]["notice_pending"] is True
    assert [e.note.split(" · ")[0] for e in repo.finding_events.values() if e.event_type == "OWNER_NOTICE_NOT_SENT"] == ["mail"]
    app.state.contact_transports = {"smtp": relay, "smtp_ssl": relay}
    told = c.post(notice, headers=remediator, json={"channel": "mail", "to": "kim@example.com"})
    assert told.status_code == 200 and told.json()["owner_emergency"]["notice_pending"] is False
    [message] = relay.sent
    text = message.get_content()
    assert "공개 저장소에 노출되어 사용 기록이 있음" in text and "http" not in text and message["To"] == "kim@example.com"
    again = c.post(notice, headers=remediator, json={"channel": "record", "to": "kim", "evidence": "phone"})
    assert (again.status_code, again.json()["detail"]) == (409, "OWNER_NOTICE_NOT_PENDING")
    told_rows = [(e.actor, e.note) for e in repo.finding_events.values() if e.event_type == "OWNER_NOTIFIED_AFTER"]
    assert len(told_rows) == 2 and all(actor == "rita" and note.startswith("mail · to=kim@example.com · text=")
                                       for actor, note in told_rows)  # claimed before each send, released once


def test_key_actions_and_rechecks_write_nothing_outside_a_verified_plan_account_session(issuer):
    import datetime as dt
    import uuid as _uuid

    from cremore.api.conftest import oidc_settings
    from cremore.remediation.action_plans import KeyActionAdapter

    class Adapter(KeyActionAdapter):
        def __init__(self):
            self.writes, self.reads = [], 0

        def key_status(self, user_name, key_id):
            self.reads += 1
            return "Active" if self.reads == 1 else "ABSENT"

        def disable_key(self, user_name, key_id):
            self.writes.append("disable")
            raise TimeoutError("unknown outcome")

        def delete_key(self, user_name, key_id):
            raise AssertionError("not requested")

    adapter = Adapter()
    repo = InMemoryRepository()
    cred = _aws_key_credential(repo)
    sessions = FakeSessions(refusals={"123456789012": "REVALIDATION_REQUIRED"})
    c = TestClient(create_app(repo=repo, settings=oidc_settings(ACTION_EXECUTION_ENABLED="true"), oidc_http_client=issuer,
                              key_action_adapter_factory=lambda session: adapter, aws_sessions=sessions))
    remediator, admin = _bearer(issuer, "rita", "g-remediators"), _bearer(issuer, "adam", "g-admins")
    c.put("/api/v1/settings/owner-approval", headers=admin, json={"required": False})  # this test is about sessions
    body = {"action_type": "DISABLE_ACCESS_KEY", "reason_code": "SECURITY_INCIDENT", "idempotency_key": str(_uuid.uuid4()),
            "operational_review": _review(dt.datetime.now(dt.UTC))}
    plan = c.post(f"/api/v1/credentials/{cred.id}/action-plans", headers=remediator, json=body).json()
    c.post(f"/api/v1/action-plans/{plan['id']}/approve", headers=admin, json={"plan_hash": plan["plan_hash"]})

    blocked = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=remediator, json={"plan_hash": plan["plan_hash"]})
    assert blocked.status_code == 409 and "REVALIDATION_REQUIRED" in blocked.json()["error"]
    assert adapter.writes == [] and adapter.reads == 0

    sessions.refusals, sessions.open_accounts = {}, {"123456789012"}
    unknown = c.post(f"/api/v1/action-plans/{plan['id']}/execute", headers=remediator, json={"plan_hash": plan["plan_hash"]}).json()
    assert unknown["status"] == "OUTCOME_UNKNOWN"
    # the account becomes unusable: a recheck may not "confirm" anything from elsewhere
    sessions.refusals = {"123456789012": "AWS_IDENTITY_CHANGED"}
    r = c.post(f"/api/v1/action-plans/{plan['id']}/recheck", headers=remediator, json={"plan_hash": plan["plan_hash"]})
    assert r.status_code == 409 and repo.get_action_plan(uuid_of(plan["id"])).status == "OUTCOME_UNKNOWN"
    assert adapter.reads == 1  # only the execute preflight; the refused recheck read nothing
    # Both refusals came from the account session, after the plan's own gate: each is audited with its code.
    refusals = sorted(e.note.split(" plan_hash=")[0] for e in repo.finding_events.values() if e.event_type == "ACTION_PLAN_REFUSED")
    assert refusals == ["EXECUTE REVALIDATION_REQUIRED", "RECHECK AWS_IDENTITY_CHANGED"]
    # The SIEM sees the plan's own statuses, not UNKNOWN.
    approvals = [e["audit"] for e in repo.siem_events.values()
                 if e["event_type"] == "audit.action" and e["audit"]["action"] == "ACTION_PLAN_APPROVED"]
    assert [(a["from_status"], a["to_status"], a["target_type"]) for a in approvals] == [("PENDING_APPROVAL", "APPROVED", "action_plan")]


def test_connection_check_ledger_revoke_and_blast_radius():
    from cremore.collectors.credential_check import CredentialCheck
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    c = client(repo)
    conn = source(c, "github", "example-org/app", "App", "vault://github/app")
    # a scan through the connection records reach; then a check runs
    c.post("/api/v1/scan", headers=auth(), json={"text": f"token = {GH}", "source_type": "github",
                                                   "resource_name": "example-org/app", "location": "app.py"})
    finding = c.get("/api/v1/findings", headers=auth()).json()[0]
    # tie the exposure to the connection the way a worker run would
    for e in repo.exposures.values():
        e.source_connection_id = uuid_of(conn["id"])
    c.post(f"/api/v1/source-connections/{conn['id']}/credential/check", headers=auth())
    JobWorker(repo, credential_checker=lambda job: CredentialCheck("ACTIVE", owner="ci-bot")).process_next()
    history = c.get(f"/api/v1/source-connections/{conn['id']}/verification-history?limit=20", headers=auth()).json()
    assert history["scope"] == "CONNECTION_AUTHENTICATION" and history["coverage"] == "RECORDED_EVENTS_ONLY"
    stages = [(e["stage"], e["job_status"], e["outcome"], e["reason_code"]) for e in history["items"]]
    assert stages == [("TERMINAL", "COMPLETED", "ACTIVE", "CHECK_RESULT"), ("CLAIMED_FOR_CHECK", "RUNNING", "NOT_APPLICABLE", "NONE"),
                      ("REQUESTED", "QUEUED", "NOT_APPLICABLE", "NONE")]
    assert all(e["provenance"] == "JOB_LIFECYCLE" and len(e["requested_by"]) == 36 for e in history["items"])
    assert "next_cursor" not in history
    # paging: limit 1 walks the ledger by cursor and expires an unknown cursor
    first = c.get(f"/api/v1/source-connections/{conn['id']}/verification-history?limit=1", headers=auth()).json()
    assert first["next_cursor"] == first["items"][0]["id"]
    second = c.get(f"/api/v1/source-connections/{conn['id']}/verification-history?limit=1&cursor={first['next_cursor']}", headers=auth()).json()
    assert second["items"][0]["stage"] == "CLAIMED_FOR_CHECK"
    assert c.get(f"/api/v1/source-connections/{conn['id']}/verification-history?cursor=00000000-0000-4000-8000-000000000000", headers=auth()).status_code == 410

    radius = c.get(f"/api/v1/source-connections/{conn['id']}/blast-radius", headers=auth()).json()
    assert radius["resources_reached"] == 1 and radius["resources"][0]["resource"] == "example-org/app"
    assert radius["findings_found"] == 1 and radius["severity_counts"] == {finding["severity"]: 1}
    assert radius["provider_revocable"] is True and radius["revocation_url"].startswith("https://github.com/")

    # stop using the connection: disabled, queued work withdrawn, provider guidance returned
    c.post(f"/api/v1/source-connections/{conn['id']}/credential/check", headers=auth())  # queued, never claimed
    r = c.post(f"/api/v1/source-connections/{conn['id']}/credential/revoke", headers=auth(), json={"reason": "rotated"})
    assert r.status_code == 200 and r.json()["jobs_cancelled"] == 1 and "github.com/settings/tokens" in r.json()["self_service_url"]
    shown = c.get("/api/v1/source-connections", headers=auth()).json()[0]
    assert shown["enabled"] is False and shown["credential"]["status"] == "REVOKED"
    assert shown["credential"]["revoked_at"] and shown["credential"]["revocation_reason"] == "rotated" and shown["credential"]["checkable"] is False
    cancelled = c.get(f"/api/v1/source-connections/{conn['id']}/verification-history", headers=auth()).json()["items"][0]
    assert cancelled["stage"] == "TERMINAL" and cancelled["job_status"] == "CANCELLED" and cancelled["outcome"] == "NOT_DISPATCHED"
    assert c.post(f"/api/v1/source-connections/{conn['id']}/credential/check", headers=auth()).status_code == 409


def uuid_of(value: str):
    import uuid as _uuid

    return _uuid.UUID(value)


def test_scan_scope_catalog_profile_plan_run_and_exact_rescan():
    from cremore.collectors.base import CollectorError
    from cremore.collectors.bytes_source import BytesCollector
    from cremore.scanning import scope
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    c = client(repo)
    conn = source(c, "github", "example-org", "Org", "vault://github/org")
    cid = conn["id"]
    base = f"/api/v1/connections/source/{cid}"
    # nothing collected yet: an empty catalog is labelled, never a clean empty listing
    r = c.get(f"{base}/resources", headers=auth()).json()
    assert r["catalog_snapshot_id"] == "" and r["reason_code"] == "NOT_COLLECTED" and r["items"] == [] and r["kind"] == "source"
    # a refresh queues one metadata-only job (an INVENTORY job in the sources tab); a second request does not duplicate it
    r = c.post(f"{base}/resources/refresh", headers=auth()).json()
    assert r["reason_code"] == "REFRESH_QUEUED"
    c.post(f"{base}/resources/refresh", headers=auth())
    jobs = c.get("/api/v1/source-scan-jobs", headers=auth()).json()
    assert len(jobs) == 1 and jobs[0]["job_kind"] == "INVENTORY" and jobs[0]["source_type"] == "github"
    listed = [scope.resource("source", uuid_of(cid), "GITHUB_REPOSITORY", f"example-org/{n}", f"example-org/{n}",
                             f"https://github.com/example-org/{n}", "github.com", default_branch="main") for n in ("app", "infra")]

    def lister(job):
        assert job.payload["secret_ref"] == "vault://github/org" and "token" not in job.payload
        return listed, "COMPLETE"

    assert JobWorker(repo, catalog_lister=lister).process_next()
    cat = c.get(f"{base}/resources?q=app&page_size=50", headers=auth()).json()
    assert cat["catalog_snapshot_id"] and cat["known_count"] == 1 and "reason_code" not in cat and cat["catalog_completeness"] == "COMPLETE"
    snap, app_id = cat["catalog_snapshot_id"], cat["items"][0]["id"]
    # a later failed refresh is reported as a reason code; the last good catalog stays
    c.post(f"{base}/resources/refresh", headers=auth())

    def broken(job):
        raise CollectorError("GITHUB_ORG_LIST_FAILED", "HTTP 401")

    JobWorker(repo, catalog_lister=broken).process_next()
    cat2 = c.get(f"{base}/resources", headers=auth()).json()
    assert cat2["reason_code"] == "GITHUB_ORG_LIST_FAILED" and cat2["catalog_snapshot_id"] == snap and cat2["known_count"] == 2
    # selection drafts freeze every current match of a query
    page = c.get(f"{base}/scan-scope-profiles", headers=auth()).json()
    assert page["state"] == "NO_TARGETS_SELECTED" and page["profiles"] == [] and page["runs"] == []
    d = c.post(f"{base}/selection-drafts", headers=auth(), json={"q": "", "sort": "name_asc", "page_size": 50}).json()
    assert d["resolution_status"] == "READY" and d["known_count"] == 2 and d["processed_count"] == d["total_count"] == 2
    assert c.get(f"/api/v1/selection-drafts/{d['id']}", headers=auth()).json()["resource_ids"] == d["resource_ids"]
    cancelled = c.post(f"/api/v1/selection-drafts/{d['id']}/cancel", headers=auth(), json={}).json()
    assert cancelled["resolution_status"] == "CANCELLED" and cancelled["resource_ids"] == [] and cancelled["resources"] == []
    # an approved profile pins the catalog snapshot it was reviewed against
    root = {"resource_id": app_id, "all_current_objects": False, "prefixes": [], "excluded_prefixes": [], "ref": "refs/heads/main",
            "paths": ["src/"], "excluded_paths": [], "descendant_ids": [], "include_future_descendants": False}
    body = {"expected_version": 0, "name": "app only", "selected_roots": [root], "excluded_ids": [],
            "budgets": {"bytes": 104857600, "requests": 1000, "seconds": 600}, "schedule_minutes": 0, "event_mode": "DISABLED",
            "change_reason": "baseline", "catalog_snapshot_id": "stale"}
    assert c.post(f"{base}/scan-scope-profiles", headers=auth(), json=body).status_code == 409
    r = c.post(f"{base}/scan-scope-profiles", headers=auth(), json={**body, "catalog_snapshot_id": snap})
    assert r.status_code == 201, r.json()
    p = r.json()
    assert p["version"] == 1 and p["state"] == "READY" and p["auth_revision"] == cat["auth_revision"] and p["approved_by"]
    assert c.patch(f"/api/v1/scan-scope-profiles/{p['id']}", headers=auth(),
                   json={**body, "catalog_snapshot_id": snap, "expected_version": 5}).status_code == 409
    # preview: a fixed, expiring, executable plan echoing the profile
    plan = c.post(f"/api/v1/scan-scope-profiles/{p['id']}/preview", headers=auth(), json={}).json()
    assert plan["executable"] and plan["known_count"] == 1 and plan["profile"]["id"] == p["id"] and plan["warnings"] == []
    assert plan["catalog_snapshot_id"] == snap and plan["auth_revision"] == p["auth_revision"] and len(plan["policy_digest"]) == 64
    # A plan persisted by an older release must not bypass the unresolved-root
    # invariant even if its executable flag was stored as true.
    plan_id = uuid_of(plan["plan_id"])
    repo.update_plan(plan_id, executable=True, unresolved_count=1)
    before = len(repo.list_jobs())
    blocked = c.post(
        "/api/v1/scan-runs",
        headers=auth(),
        json={"plan_id": plan["plan_id"], "profile_version": 1},
    )
    assert blocked.status_code == 409 and len(repo.list_jobs()) == before
    repo.update_plan(plan_id, unresolved_count=0)
    # run: queued from the plan; the same submission again returns the same run
    r = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan["plan_id"], "profile_version": 1})
    assert r.status_code == 202, r.json()
    run = r.json()
    assert run["status"] == "QUEUED" and run["scope_snapshot_id"] == plan["plan_id"] and run["trigger"] == "BASELINE"
    assert c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan["plan_id"], "profile_version": 1}).json()["id"] == run["id"]
    assert c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan["plan_id"], "profile_version": 2}).json()["id"] == run["id"]
    job = repo.get_job(uuid_of(run["id"]))
    assert job.kind == "scope" and job.payload["roots"][0]["paths"] == ["src/"] and job.payload["secret_ref"] == "vault://github/org"
    assert "token" not in job.payload and job.payload["budgets"]["bytes"] == 104857600

    def factory(job):
        assert job.payload["roots"][0]["provider_resource_id"] == "example-org/app"
        return BytesCollector.one(f"key = {GH}".encode(), source_type="github", resource="example-org/app", location="src/config.py")

    worker = JobWorker(repo, collector_factory=factory)
    assert worker.process_next()  # durable root planning
    assert worker.process_next()  # leased root and parent completion
    cov = c.get(f"/api/v1/scan-runs/{run['id']}/coverage", headers=auth()).json()
    assert cov["status"] == "COMPLETED" and cov["succeeded"] == 1 and cov["result_status"] == "SCANNED" and cov["engine_name"]
    page = c.get(f"{base}/scan-scope-profiles", headers=auth()).json()
    assert page["state"] == "READY" and page["runs"][0]["id"] == run["id"] and page["profiles"][0]["id"] == p["id"]
    # exact rescan: only the exposure's current location, only inside the approved profile
    finding = c.get("/api/v1/findings", headers=auth()).json()[0]
    exposure = repo.exposures_for_credential(uuid_of(finding["credential_id"]))[0]
    assert str(exposure.source_connection_id) == cid
    profiles = c.get(f"/api/v1/findings/{finding['id']}/rescan-profiles?exposure_id={exposure.id}", headers=auth()).json()
    assert profiles["connection_id"] == cid and [x["id"] for x in profiles["profiles"]] == [p["id"]]
    prev = c.post(f"/api/v1/findings/{finding['id']}/rescan-preview", headers=auth(),
                  json={"exposure_id": str(exposure.id), "profile_id": p["id"], "verify": False}).json()
    target = prev["rescan_target"]
    assert prev["known_count"] == 1 and prev["executable"] and target["path"] == "src/config.py" and target["ref"] == "refs/heads/main"
    assert target["finding_id"] == finding["id"] and target["exposure_id"] == str(exposure.id) and len(target["evidence_digest"]) == 64
    exposure.location = "docs/notes.md"  # outside the approved paths
    r = c.post(f"/api/v1/findings/{finding['id']}/rescan-preview", headers=auth(),
               json={"exposure_id": str(exposure.id), "profile_id": p["id"], "verify": False})
    assert r.status_code == 422 and r.json()["error"].startswith("RESCAN_OUT_OF_SCOPE")
    assert c.post(f"/api/v1/findings/{finding['id']}/rescan", headers=auth(),
                  json={"plan_id": prev["plan_id"], "profile_version": 1, "confirm": False}).status_code == 422
    # A scheduled full scan of this scope waiting in the queue answers no rescan: the rescan reads its exact path.
    from cremore.domain.models import ScanJob
    scheduled = repo.enqueue_job(ScanJob(kind="scope", connection_id=uuid_of(cid), payload={
        "profile_id": p["id"], "profile_version": 1, "mode": "RECONCILE", "requested_by": "schedule",
        "auth_revision": p["auth_revision"]}))
    rr = c.post(f"/api/v1/findings/{finding['id']}/rescan", headers=auth(),
                json={"plan_id": prev["plan_id"], "profile_version": 1, "confirm": True})
    assert rr.status_code == 202, rr.json()
    assert rr.json()["trigger"] == "RESCAN" and rr.json()["scope_snapshot_id"] == prev["plan_id"]
    rescan = repo.get_job(uuid_of(rr.json()["id"]))
    assert rescan.payload["roots"][0]["exact_paths"] == ["src/config.py"] and rescan.payload["verify"] is False
    assert c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": prev["plan_id"], "profile_version": 1}).status_code == 422
    # Nor does the rescan, which reads one path, answer a full scan asked for meanwhile.
    repo.request_job_cancel(scheduled.id)
    full = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": c.post(
        f"/api/v1/scan-scope-profiles/{p['id']}/preview", headers=auth()).json()["plan_id"], "profile_version": 1,
        "mode": "BASELINE"})
    assert full.status_code == 202 and full.json()["id"] != rr.json()["id"]
    assert "exact_paths" not in repo.get_job(uuid_of(full.json()["id"])).payload["roots"][0]
    repo.request_job_cancel(uuid_of(full.json()["id"]))
    # a queued run can be withdrawn; a revoked connection pauses its scope
    assert c.post(f"/api/v1/scan-runs/{rr.json()['id']}/cancel", headers=auth(), json={}).json()["status"] == "CANCELLED"
    c.post(f"/api/v1/source-connections/{cid}/credential/revoke", headers=auth(), json={"reason": "rotated"})
    assert c.get(f"{base}/scan-scope-profiles", headers=auth()).json()["state"] == "PAUSED"
    assert c.post(f"{base}/resources/refresh", headers=auth()).status_code == 409


def test_learned_fp_profiles_learn_from_decisions_and_auto_triage(issuer):
    repo = InMemoryRepository()
    # The tuning values still pin from configuration; the on/off switch is an
    # Admin's, so it is set the way the dashboard sets it.
    c, _ = _oidc_client(issuer, repo, LEARNED_FP_MIN_SAMPLES="2",
                        LEARNED_FP_THRESHOLD="0.6", LEARNED_FP_MAX_CONFIDENCE="high")
    from cremore.scanning import learned_fp_settings

    repo.put_setting(learned_fp_settings.KEY, {"enabled": True}, "admin")
    admin, alice, bob = _bearer(issuer, "root", "g-admins"), _bearer(issuer, "alice", "g-analysts"), _bearer(issuer, "bob", "g-analysts")
    conn = source(c, "github", "example-org/app", "App", "vault://github/app", headers=admin)
    # off-by-default elsewhere; here two analysts confirm the same fixture context
    assert c.get("/api/v1/rules/learned-fp", headers=admin).json() == []
    for i, who in enumerate((alice, bob)):
        token = GH[:-2] + f"{i:02d}"  # a distinct credential per case
        c.post("/api/v1/scan", headers=admin, json={"text": f"token = {token}", "source_type": "github",
                                                     "resource_name": "example-org/app", "location": f"tests/fixtures/case{i}/sample.py"})
        for e in repo.exposures.values():
            e.source_connection_id = uuid_of(conn["id"])
        fid = next(f["id"] for f in c.get("/api/v1/findings", headers=admin).json() if f["workflow_status"] == "OPEN")
        r = c.post(f"/api/v1/findings/{fid}/false-positive", headers=who, json={"reason_code": "TEST_FIXTURE"})
        assert r.json()["learned_fp_samples"] == 1
    profiles = c.get("/api/v1/rules/learned-fp", headers=admin).json()
    assert len(profiles) == 1
    p = profiles[0]
    assert p["active"] and p["sample_count"] == 2 and p["min_samples"] == 2 and p["model_type"] == "CONTEXT_SIMILARITY"
    assert p["account_id"] == conn["id"] and p["account_name"] == "App" and p["source_type"] == "github" and p["threshold"] == 0.6
    assert c.get("/api/v1/rules/learned-fp", headers=alice).status_code == 403
    # the profile is inspectable and controllable by an Admin
    off = c.post(f"/api/v1/rules/learned-fp/{p['id']}/deactivate", headers=admin).json()
    assert off["active"] is False and off["contradictions"] == 1
    reset = c.post(f"/api/v1/rules/learned-fp/{p['id']}/reset", headers=admin).json()
    assert reset["sample_count"] == 0 and reset["contradictions"] == 0 and reset["active"] is False
    # Both are an Admin's hand on auto-triage, so both are in the audit trail with the profile they touched.
    rows = [row for row in c.get("/api/v1/audit", headers=admin).json() if row["target_type"] == "learned_fp_profile"]
    assert sorted(row["action"] for row in rows) == ["LEARNED_FP_PROFILE_RESET", "LEARNED_FP_PROFILE_STOPPED"]
    assert {row["target_id"] for row in rows} == {p["id"]} and all(row["note"].startswith(p["credential_type"]) for row in rows)
    # The note keeps what the profile held before the change, not what the reset left.
    assert all(row["note"].endswith("samples=2") for row in rows)


def test_internal_tickets_are_operator_declarations_with_independent_approval(issuer):
    repo = InMemoryRepository()
    c, _ = _oidc_client(issuer, repo)
    analyst, admin, viewer = _bearer(issuer, "alice", "g-analysts"), _bearer(issuer, "bob", "g-admins"), _bearer(issuer, "carol", "g-viewers")
    c.post("/api/v1/scan", headers=admin, json={"text": f"token = {GH}", "source_type": "github",
                                                 "resource_name": "example-org/app", "location": "app.py"})
    fid = c.get("/api/v1/findings", headers=admin).json()[0]["id"]
    cred_id = c.get("/api/v1/findings", headers=admin).json()[0]["credential_id"]

    catalog = c.get("/api/v1/governance/playbooks", headers=viewer).json()
    assert catalog["provider_execution"] == "NOT_EXECUTED_BY_WORKFLOW" and len(catalog["data"]["templates"]) == 6
    empty = c.get(f"/api/v1/tickets?offset=0&credential_id={cred_id}", headers=viewer).json()["data"]
    assert empty == {"items": [], "next_offset": None}

    # viewers cannot create; analysts can. CUSTOM freezes the playbook.
    body = {"finding_id": fid, "template_id": "CUSTOM", "custom_steps": ["CONFIRM_OWNER_AND_TARGET", "REVIEW_CONTAINMENT"],
            "customization": {"conditions": [{"field": "PROVIDER", "equals": "github"}], "approval_rule": "INDEPENDENT_ADMIN"},
            "priority": "HIGH", "service_impact": "LIMITED", "responsible_team": "payments",
            "review_due_at": "2026-10-01T09:00:00Z", "evidence": [{"kind": "FINDING", "id": fid}]}
    assert c.post("/api/v1/tickets", headers=viewer, json=body).status_code == 403
    r = c.post("/api/v1/tickets", headers=analyst, json=body)
    assert r.status_code == 201, r.json()
    t = r.json()["data"]
    assert t["provider"] == "github" and t["playbook"]["config"]["conditions"] == [{"field": "PROVIDER", "equals": "github"}]
    assert t["credential_id"] == cred_id and t["status"] == "OPEN" and len(t["review_digest"]) == 64
    listed = c.get(f"/api/v1/tickets?offset=0&credential_id={cred_id}", headers=viewer).json()["data"]
    assert [x["id"] for x in listed["items"]] == [t["id"]]

    # errors carry the dashboard's reason codes
    r = c.post("/api/v1/tickets", headers=analyst, json={**body, "customization": {"conditions": [{"field": "PROVIDER", "equals": "aws"}]}})
    assert r.status_code == 422 and r.json()["error"].startswith("WORKFLOW_PLAYBOOK_NOT_APPLICABLE")
    r = c.put(f"/api/v1/tickets/{t['id']}", headers=analyst, json={**body, "expected_version": 9})
    assert r.status_code == 409 and r.json()["error"].startswith("WORKFLOW_VERSION_CONFLICT")

    steps = [{"code": s["code"], "status": "REVIEWED"} for s in t["steps"]]
    owner = c.get("/api/v1/session", headers=analyst).json()["id"]
    update = {**body, "expected_version": 1, "status": "IN_PROGRESS", "steps": steps, "owner_id": t["created_by"]}
    t2 = c.put(f"/api/v1/tickets/{t['id']}", headers=analyst, json=update).json()["data"]
    assert t2["version"] == 2 and t2["steps"][0]["reviewed_by"] == t["created_by"] and owner  # owner is the OIDC subject
    # resolving before the independent approval is refused
    r = c.put(f"/api/v1/tickets/{t['id']}", headers=analyst, json={**update, "expected_version": 2, "status": "RESOLVED"})
    assert r.status_code == 409 and r.json()["error"].startswith("WORKFLOW_APPROVAL_REQUIRED")
    # the approver must be an Admin other than the creator/editor, on the exact digest
    approve = {"expected_version": 2, "content_digest": t2["review_digest"], "confirm": True}
    assert c.post(f"/api/v1/tickets/{t['id']}/approve", headers=analyst, json=approve).status_code == 403
    a = c.post(f"/api/v1/tickets/{t['id']}/approve", headers=admin, json=approve)
    assert a.status_code == 200 and a.json()["data"]["internal_approval"]["source_version"] == 2
    done = c.put(f"/api/v1/tickets/{t['id']}", headers=analyst, json={**update, "expected_version": 3, "status": "RESOLVED"}).json()["data"]
    assert done["status"] == "RESOLVED" and done["resolution_basis"] == "MANUAL_WORKFLOW_REVIEW_COMPLETED"
    trail = c.get("/api/v1/audit", headers=admin).json()
    actions = [row["action"] for row in trail if row["action"].startswith("FINDING_TICKET_")]
    assert actions[:3] == ["FINDING_TICKET_UPDATED", "FINDING_TICKET_APPROVED", "FINDING_TICKET_UPDATED"]
    assert any(row["action"] == "API_REQUEST_DENIED" and row["actor_id"] == "carol" for row in trail)


def test_secret_manager_mapping_is_a_declaration_with_metadata_reads():
    ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db-AbCdEf"
    repo = InMemoryRepository()
    switch_investigation_on(repo)  # the factory is wired; the Admin's switch must be on too
    cred = _aws_key_credential(repo)
    # no allowlist: no manager connected, nothing to map
    c = client(repo)
    assert c.get("/api/v1/secret-managers", headers=auth()).json() == {"mode": "REAL", "scope": "THIS_INSTALLATION_CONFIGURATION", "items": []}
    m = c.get(f"/api/v1/credentials/{cred.id}/management", headers=auth()).json()
    assert m["status"] == "NO_MANAGER_CONNECTED" and m["revision"] == 0 and m["secret_value_returned"] is False
    assert c.put(f"/api/v1/credentials/{cred.id}/management", headers=auth(), json={"reference": ARN, "revision": 0}).status_code == 422

    class FakeMetadata:
        def describe(self, arn):
            assert arn == ARN
            return {"arn": arn, "region": "us-east-1", "account_id": "123456789012", "current_version_id": "1" * 32,
                    "rotation_enabled": False, "versions": [], "field_status": {"tags": "OMITTED_BY_SECURITY_POLICY"}}

    opened_regions = []
    sessions = FakeSessions("123456789012")
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, SECRET_MANAGER_ALLOWED_REFERENCES=ARN),
                     secret_metadata_factory=lambda session, region: opened_regions.append(region) or FakeMetadata(),
                     aws_sessions=sessions)
    c = TestClient(app)
    config = c.get("/api/v1/secret-managers", headers=auth()).json()
    assert config["items"][0]["allowed_references"] == [ARN] and config["items"][0]["mode"] == "METADATA_ONLY"
    assert c.get(f"/api/v1/credentials/{cred.id}/management", headers=auth()).json()["reason"] == "NO_ADMIN_DECLARATION"
    saved = c.put(f"/api/v1/credentials/{cred.id}/management", headers=auth(), json={"reference": ARN, "revision": 0}).json()
    assert saved["status"] == "MANAGED_MATCHED" and saved["match_status"] == "POSSIBLE_MATCH" and saved["revision"] == 1
    assert saved["reference"] == ARN and saved["can_read_metadata"] is True
    # stale revision -> 409; unknown ARN -> 422
    assert c.put(f"/api/v1/credentials/{cred.id}/management", headers=auth(), json={"reference": ARN, "revision": 0}).status_code == 409
    assert c.put(f"/api/v1/credentials/{cred.id}/management", headers=auth(), json={"reference": ARN.replace("db", "x"), "revision": 1}).status_code == 422
    meta = c.get(f"/api/v1/credentials/{cred.id}/management/metadata", headers=auth()).json()
    assert meta["reference_revision"] == 1 and meta["match_basis"] == "ADMIN_CONFIGURED" and meta["secret_value_returned"] is False
    assert meta["metadata"]["region"] == "us-east-1" and meta["last_access_semantics"] == "SECRET_STORAGE_ACCESS_NOT_CREDENTIAL_USE"
    # read in the secret ARN's own account and region
    assert sessions.opened[-1] == ("123456789012", "scanner") and opened_regions[-1] == "us-east-1"
    assert meta["collected_account_id"] == "123456789012"
    cleared = c.request("DELETE", f"/api/v1/credentials/{cred.id}/management", headers=auth(), json={"revision": 1}).json()
    assert cleared["revision"] == 2 and "reference" not in cleared and cleared["status"] == "UNKNOWN"
    assert c.get(f"/api/v1/credentials/{cred.id}/management/metadata", headers=auth()).status_code == 422


def test_audit_trail_lists_finding_events():
    c = client()
    c.post("/api/v1/scan", headers=auth(),
           json={"text": f"token = {GH}", "source_type": "github", "resource_name": "r",
                 "location": "a", "exposure": "public"})
    fid = c.get("/api/v1/findings", headers=auth()).json()[0]["id"]
    c.post(f"/api/v1/findings/{fid}/acknowledge", headers=auth())
    c.post(f"/api/v1/findings/{fid}/assign", headers=auth(), json={"assignee": "alice"})
    audit = c.get("/api/v1/audit", headers=auth()).json()
    assert [row["action"] for row in audit] == ["FINDING_ASSIGNED", "FINDING_ACKNOWLEDGED", "FINDING_ROLLUP_UPDATED"]  # newest first
    assert audit[0]["target_id"] == fid and audit[0]["target_type"] == "finding" and audit[0]["actor_id"]
    listed = c.get("/api/v1/findings", headers=auth()).json()[0]
    assert audit[0]["target_name"] == f"GITHUB_TOKEN · {listed['identifier_hint']}"
    assert audit[1]["from_status"] == "OPEN" and audit[1]["to_status"] == "ACKNOWLEDGED"
    assert GH not in str(audit)


def test_connection_governance_page_and_declaration():
    c = client(**ONBOARDING)
    conn = source(c, "github", "example-org", "App repo")
    assert connect_aws(c, "123456789012").status_code == 201
    acct = aws_row(c, "123456789012")
    page = c.get("/api/v1/connections", headers=auth()).json()
    kinds = {(i["profile"]["kind"], i["profile"]["connection_id"]) for i in page["connections"]}
    assert kinds == {("source", conn["id"]), ("aws", acct["id"])}
    src = next(i for i in page["connections"] if i["profile"]["kind"] == "source")
    assert src["profile"]["declaration_status"] == "NOT_DECLARED" and src["snapshot"]["mode"] == "REAL"
    assert src["snapshot"]["scope"] == {"connection_id": conn["id"], "connection_kind": "source"}
    assert src["config"] == {"org": "example-org"} and src["provider"] == "github"  # plain fields too
    assert all(not cap["supported"] and cap["availability"] == "NOT_PROBED"
               for cap in src["snapshot"]["capabilities"].values())  # nothing is inferred

    # The administrator's declaration is recorded (never observed evidence).
    declared = c.post(f"/api/v1/connections/source/{conn['id']}/profile", headers=auth(),
                      json={"product_type": "GITHUB_DOT_COM", "auth_type": "PERSONAL_ACCESS_TOKEN",
                            "base_url": "", "purposes": ["DISCOVERY"],
                            "environment": {"deployment_type": "GITHUB_COM", "regions": [], "plan": "TEAM"}})
    assert declared.status_code == 200, declared.json()
    assert declared.json()["profile"]["declaration_status"] == "DECLARED_NOT_VERIFIED"
    assert declared.json()["profile"]["declared"]["environment"]["plan"] == "TEAM"
    assert declared.json()["profile"]["auth_type"] == "PERSONAL_ACCESS_TOKEN"
    # and is reflected in the capabilities read and the page
    single = c.get(f"/api/v1/connections/source/{conn['id']}/capabilities", headers=auth()).json()
    assert single["profile"]["declared"]["purposes"] == ["DISCOVERY"]
    assert c.get("/api/v1/scan-jobs", headers=auth()).status_code == 200  # declaration never queued work
    # invalid declarations are refused
    assert c.post(f"/api/v1/connections/source/{conn['id']}/profile", headers=auth(),
                  json={"purposes": ["HACK"]}).status_code == 422
    assert c.post(f"/api/v1/connections/source/{conn['id']}/profile", headers=auth(),
                  json={"base_url": "http://plain.example"}).status_code == 422
    # AWS accounts take declarations too
    aws = c.post(f"/api/v1/connections/aws/{acct['id']}/profile", headers=auth(),
                 json={"product_type": "SINGLE_ACCOUNT", "auth_type": "ASSUME_ROLE"}).json()
    assert aws["profile"]["kind"] == "aws" and aws["profile"]["account_id"] == "123456789012"
    # no persistent investigation exists: null (not started), and starting one is unsupported
    assert c.get(f"/api/v1/connections/source/{conn['id']}/inspection", headers=auth()).json() is None
    assert c.post(f"/api/v1/connections/source/{conn['id']}/inspection", headers=auth(), json={}).status_code == 501
    assert c.get("/api/v1/connections/source/00000000-0000-4000-8000-000000000000/capabilities", headers=auth()).status_code == 404


def test_governance_review_lifecycle():
    c = client()
    c.post("/api/v1/scan", headers=auth(),
           json={"text": f"token = {GH}", "source_type": "github", "resource_name": "r",
                 "location": "a", "exposure": "public"})
    fid = c.get("/api/v1/findings", headers=auth()).json()[0]["id"]
    created = c.post("/api/v1/governance/reviews", headers=auth(),
                     json={"finding_id": fid, "question": "who owns this?"})
    assert created.status_code == 201
    rid = created.json()["id"]
    assert len(c.get("/api/v1/governance/reviews", headers=auth()).json()) == 1
    resolved = c.post(f"/api/v1/governance/reviews/{rid}/resolve", headers=auth(),
                      json={"response": "team payments"}).json()
    assert resolved["status"] == "RESOLVED" and resolved["response"] == "team payments"


SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/key-AbCdEf"


def _aws_credential(repo):
    """A verified-looking AWS credential whose principal resolves to an IAM user."""

    from cremore.domain.models import Credential

    return repo.upsert_credential(Credential(
        fingerprint="fp-rot", credential_type="AWS_ACCESS_KEY", provider="aws",
        identifier="AKIAZ5X9K2" "MBV7QP3LN6",
        principal_arn="arn:aws:iam::123456789012:user/ci-deployer", credential_status="Active"))


def test_legacy_rotation_apply_requires_the_explicit_action_plan_workflow():
    repo = InMemoryRepository()
    cred = _aws_credential(repo)
    c = client(repo)
    response = c.post("/api/v1/rotation-automation/apply", headers=auth(),
                      json={"credential_id": str(cred.id), "secret_arn": SECRET_ARN})
    assert response.status_code == 409
    assert response.json()["error"] == "LEGACY_ROTATION_REQUIRES_ACTION_PLAN"
    assert response.json()["migration"]["action_plan_path"].endswith("/action-plans")
    assert repo.list_rotation_jobs() == []
    preview = c.post("/api/v1/rotation-automation/preview", headers=auth(),
                     json={"credential_id": str(cred.id)}).json()
    assert preview["execution_enabled"] is False
    assert preview["action_plan_path"] == f"/api/v1/credentials/{cred.id}/action-plans"


class FakeRotationService:
    """Records the phases it was asked to run and fills the plan like the real one."""

    def __init__(self):
        self.phases: list[str] = []
        self.sessions: list[tuple] = []

    def bind(self, session, region):
        self.sessions.append((session.account_id, session.purpose, region))
        return self

    def prepare(self, plan):
        assert plan.approved_by and plan.approved_by != plan.requested_by
        self.phases.append("PREPARE")
        plan.new_key_id, plan.pending_version, plan.access_pin = ("AKIANEWKEY" "0000000001"), "v-pending", "1:1"

    def publish(self, plan):
        assert plan.pending_version == "v-pending" and plan.access_pin == "1:1"
        self.phases.append("PUBLISH")


def _oidc_client(issuer, repo, **settings_overrides):
    from cremore.api.conftest import oidc_settings

    service = FakeRotationService()
    sessions = FakeSessions("123456789012")
    app = create_app(repo=repo, settings=oidc_settings(**settings_overrides), oidc_http_client=issuer,
                     rotation_service_factory=lambda session, region: service.bind(session, region), aws_sessions=sessions)
    return TestClient(app), service


def _bearer(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def test_an_assignee_and_a_tag_are_one_line_without_secrets():
    c = client()
    fid = _seed_finding(c)
    for name in (f"alice {GH}", "alice\nbob", "ali\\u202ece", "a" * 201):
        refused = c.post(f"/api/v1/findings/{fid}/assign", headers={**auth(), "Content-Type": "application/json"},
                         content='{"assignee": "' + name.replace("\n", "\\n") + '"}')
        assert refused.status_code == 422 and GH not in refused.text, name
    assert c.post(f"/api/v1/findings/{fid}/assign", headers=auth(), json={"assignee": "박보안"}).json()["assigned_to"] == "박보안"
    revision = c.get(f"/api/v1/findings/{fid}/annotations", headers=auth()).json()["revision"]
    tagged = c.put(f"/api/v1/findings/{fid}/tags", headers={**auth(), "Content-Type": "application/json"},
                   content='{"revision": ' + str(revision) + ', "tags": ["pay\\u2028ments"]}')
    assert tagged.status_code == 422


def test_a_second_operator_confirms_a_management_action_once(issuer, monkeypatch):
    repo = InMemoryRepository()
    c, _ = _oidc_client(issuer, repo)
    analyst, remediator = _bearer(issuer, "ann", "g-analysts"), _bearer(issuer, "rita", "g-remediators")
    c.post("/api/v1/scan", headers=analyst, json={"text": f"token = {GH}", "source_type": "github", "resource_name": "r",
                                                 "location": "a", "exposure": "public"})
    fid = c.get("/api/v1/findings", headers=analyst).json()[0]["id"]
    action = c.post("/api/v1/management-actions", headers=remediator, json={"finding_id": fid, "note": "owner is on call"}).json()
    # With single sign-on there are two operators: re-confirming one's own request is not enough.
    own = c.post(f"/api/v1/management-actions/{action['id']}/confirm", headers=remediator, json={"self_approval_confirmed": True})
    assert own.status_code == 409 and "SECOND_OPERATOR_REQUIRED" in own.text
    rob = _bearer(issuer, "rob", "g-remediators")
    stale = repo.get_management_action(uuid.UUID(action["id"])).model_copy(deep=True)
    confirmed = c.post(f"/api/v1/management-actions/{action['id']}/confirm", headers=rob)
    assert confirmed.status_code == 200 and confirmed.json()["status"] == "CONFIRMED"
    again = c.post(f"/api/v1/management-actions/{action['id']}/confirm", headers=rob)
    assert again.status_code == 409 and "MANAGEMENT_ACTION_NOT_PENDING" in again.text
    # One that read the request before the first confirmation landed: the state is checked again as it changes.
    monkeypatch.setattr(repo, "get_management_action", lambda _id: stale)
    raced = c.post(f"/api/v1/management-actions/{action['id']}/confirm", headers=_bearer(issuer, "ria", "g-remediators"))
    assert raced.status_code == 409 and "MANAGEMENT_ACTION_NOT_PENDING" in raced.text
    actions = [row["action"] for row in c.get("/api/v1/audit", headers=analyst).json()]
    assert actions.count("FINDING_MANAGEMENT_ACTION_CONFIRMED") == 1 and "FINDING_MANAGEMENT_ACTION_REQUESTED" in actions
    assert actions.count("FINDING_MANAGEMENT_ACTION_REFUSED") == 3  # own, again, raced


@pytest.mark.parametrize("status", ["REQUESTED", "PREPARED", "FAILED", "PUBLISHED"])
def test_legacy_rotation_history_is_read_only_and_never_resumes_writes(issuer, status):
    from cremore.domain.models import RotationJob

    repo = InMemoryRepository()
    cred = _aws_credential(repo)
    job = repo.create_rotation_job(RotationJob(credential_id=cred.id, status=status,
        requested_by="alice", account_id="123456789012", user_name="ci-deployer",
        old_key_id=cred.identifier, secret_arn=SECRET_ARN, expected_current_version="A" * 32))
    before = job.model_dump()
    c, service = _oidc_client(issuer, repo, ACTION_ROTATION_ENABLED="true")
    remediator = _bearer(issuer, "bob", "g-remediators")
    for phase in ("approve", "publish"):
        response = c.post(f"/api/v1/rotation-automation/jobs/{job.id}/{phase}", headers=remediator)
        assert response.status_code == 409
        assert response.json()["migration"]["legacy_job_id"] == str(job.id)
        assert response.json()["migration"]["reconciliation_required"] == (status != "PUBLISHED")
    assert service.phases == service.sessions == []
    assert repo.get_rotation_job(job.id).model_dump() == before
    [history] = c.get("/api/v1/rotation-automation/jobs", headers=remediator).json()
    assert history["status"] == status and history["read_only"] and history["migration_required"]
    assert history["action_plan_path"] == f"/api/v1/credentials/{cred.id}/action-plans"
    assert len([event for event in repo.finding_events.values()
                if event.event_type == "ROTATION_LEGACY_WRITE_REFUSED"]) == 2


def test_rotation_action_plans_require_allowlist_admin_hash_and_separate_phase_approval(issuer):
    repo = InMemoryRepository()
    cred = _aws_credential(repo)
    c, service = _oidc_client(issuer, repo, ACTION_ROTATION_ENABLED="true", ACTION_EXECUTION_ENABLED="true",
                              ROTATION_SECRET_ARNS=SECRET_ARN)
    remediator = _bearer(issuer, "rita", "g-remediators")
    admin = _bearer(issuer, "adam", "g-admins")
    c.put("/api/v1/settings/owner-approval", headers=admin, json={"required": False})
    binding = {"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}
    body = {"action_type": "PREPARE_ACCESS_KEY_ROTATION", "reason_code": "OWNER_REQUEST",
            "idempotency_key": str(uuid.uuid4()), "operational_review": _review(datetime.now(UTC)),
            "rotation": binding}
    path = f"/api/v1/credentials/{cred.id}/action-plans"
    bad = c.post(path, headers=remediator, json={**body, "rotation": {**binding, "secret_arn": SECRET_ARN + "other"}})
    assert bad.status_code == 422 and "ROTATION_SECRET_NOT_ALLOWLISTED" in bad.text
    prepared_id = None
    for phase in ("PREPARE_ACCESS_KEY_ROTATION", "PUBLISH_ACCESS_KEY_ROTATION"):
        body.update(action_type=phase, idempotency_key=str(uuid.uuid4()))
        if prepared_id:
            body["rotation"] = {**binding, "preparation_plan_id": prepared_id}
        created = c.post(path, headers=remediator, json=body)
        assert created.status_code == 201, created.text
        plan = created.json()
        route = f"/api/v1/action-plans/{plan['id']}"
        assert c.post(route + "/approve", headers=remediator, json={"plan_hash": plan["plan_hash"]}).status_code == 403
        assert c.post(route + "/approve", headers=admin, json={"plan_hash": plan["plan_hash"]}).status_code == 200
        assert c.post(route + "/execute", headers=remediator, json={"plan_hash": "0" * 64}).status_code == 409
        done = c.post(route + "/execute", headers=remediator, json={"plan_hash": plan["plan_hash"]})
        assert done.status_code == 200 and done.json()["status"] == "VERIFIED", done.text
        assert c.post(route + "/execute", headers=remediator, json={"plan_hash": plan["plan_hash"]}).status_code == 409
        prepared_id = plan["id"]
    assert service.phases == ["PREPARE", "PUBLISH"]
    assert len(service.sessions) == 2 and repo.list_rotation_jobs() == []


def test_oidc_role_gating_on_mutations(issuer):
    c, _ = _oidc_client(issuer, InMemoryRepository())
    viewer = _bearer(issuer, "v", "g-viewers")
    analyst = _bearer(issuer, "a", "g-analysts")
    admin = _bearer(issuer, "ad", "g-admins")
    # everyone authenticated can read
    assert c.get("/api/v1/findings", headers=viewer).status_code == 200
    assert c.get("/api/v1/session", headers=viewer).json()["id"] == "v"
    # scans need analyst; connecting a provider needs admin
    assert c.post("/api/v1/scan", headers=viewer, json={"text": "x"}).status_code == 403
    assert c.post("/api/v1/scan", headers=analyst, json={"text": "x"}).status_code == 202
    body = {"provider": "notion", "purposes": ["exposure"], "auth_method": "integration",
            "credential": {"token": "ntn_" + "s" * 46}}
    assert c.post("/api/v1/provider-connections", headers=analyst, json=body).status_code == 403
    assert c.post("/api/v1/provider-connections", headers=admin, json=body).status_code == 201
    # reading them is every signed-in role's; the credential is never in them
    listed = c.get("/api/v1/provider-connections", headers=viewer)
    assert listed.status_code == 200 and len(listed.json()) == 1 and "ntn_" not in listed.text
    # and an unsigned / foreign token is rejected outright
    assert c.get("/api/v1/findings", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_management_action_two_party_confirm():
    c = client()
    c.post("/api/v1/scan", headers=auth(),
           json={"text": f"token = {GH}", "source_type": "github", "resource_name": "r",
                 "location": "a", "exposure": "public"})
    fid = c.get("/api/v1/findings", headers=auth()).json()[0]["id"]
    action = c.post("/api/v1/management-actions", headers=auth(),
                    json={"finding_id": fid, "action_type": "ACKNOWLEDGE_OWNER"}).json()
    # A shared-token installation has one operator: they confirm their own request only by re-confirming it.
    conflict = c.post(f"/api/v1/management-actions/{action['id']}/confirm", headers=auth())
    assert conflict.status_code == 409 and "SELF_APPROVAL_CONFIRMATION_REQUIRED" in conflict.text
    targets = c.get("/api/v1/management-actions/targets", headers=auth()).json()
    assert len(targets) == 1 and "ACKNOWLEDGE_OWNER" in targets[0]["available_actions"]
    # Only what the credential offers, and a note without control characters or secrets.
    for wrong in ({"action_type": "ROTATE"}, {"action_type": "DELETE_EVERYTHING"}, {"note": "x" * 501},
                  {"note": "a\x07b"}, {"note": f"pasted {GH}"}):
        refused = c.post("/api/v1/management-actions", headers=auth(), json={"finding_id": fid, **wrong})
        assert refused.status_code == 422 and GH not in refused.text, wrong
    confirmed = c.post(f"/api/v1/management-actions/{action['id']}/confirm", headers=auth(), json={"self_approval_confirmed": True})
    assert confirmed.status_code == 200 and confirmed.json()["status"] == "CONFIRMED"
    audited = sorted((row["action"], row["note"]) for row in c.get("/api/v1/audit", headers=auth()).json()
                     if row["action"].startswith("FINDING_MANAGEMENT_ACTION"))
    named = f"action={action['id']} type=ACKNOWLEDGE_OWNER"
    assert audited == [("FINDING_MANAGEMENT_ACTION_CONFIRMED", f"{named} self_approval=confirmed"),
                       ("FINDING_MANAGEMENT_ACTION_REFUSED", f"{named} code=SELF_APPROVAL_CONFIRMATION_REQUIRED"),
                       ("FINDING_MANAGEMENT_ACTION_REQUESTED", named)]


def test_findings_list_has_dashboard_shape():
    c = client()
    c.post("/api/v1/scan", headers=auth(),
           json={"text": f"token = {GH}", "source_type": "github", "resource_name": "org/repo",
                 "location": "app.py", "exposure": "public"})
    findings = c.get("/api/v1/findings", headers=auth()).json()
    assert len(findings) == 1
    f = findings[0]
    # Fields the web Finding type requires beyond the old summary.
    for key in ("providers", "scope_id", "scope_type", "source_type", "resource_name",
                "location", "exposure_count", "first_seen_at", "last_seen_at"):
        assert key in f, key
    assert f["source_type"] == "github" and f["resource_name"] == "org/repo"
    assert f["exposure_count"] == 1


def test_source_connections_shape():
    c = client()
    source(c, "github", "a/b", "acme", "vault://x")
    conns = c.get("/api/v1/source-connections", headers=auth()).json()
    assert len(conns) == 1
    assert conns[0]["source_type"] == "github"
    assert conns[0]["display_name"] == "acme" and conns[0]["profile_ref"] == "a/b"
    assert "credential" in conns[0] and "status" in conns[0]["credential"]
    # a vault:// pointer shows as operator-managed supply; the pointer itself is not echoed
    assert conns[0]["credential_source"] == "OPERATOR_MOUNTED_ENV" and conns[0]["credential_ref"] == ""
    assert conns[0]["connection_auth"]["state"] == "AUTH_FRESHNESS_UNKNOWN"


def test_scan_runs_reflect_jobs():
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    c = client(repo)
    repo.enqueue_job(ScanJob(kind="inline", payload={"text": f"k={GH}"}))
    runs = c.get("/api/v1/scan-runs", headers=auth()).json()
    assert len(runs) == 1 and runs[0]["status"] == "QUEUED"


def test_log_safe_escapes_line_breaks_and_control_characters():
    from cremore.api.dashboard import _log_safe

    nl, cr, tab = chr(10), chr(13), chr(9)
    forged = _log_safe('rotated' + nl + '2026-09-14 INFO scope: approved by admin')
    assert nl not in forged and forged.startswith('rotated' + chr(92) + 'n')
    assert _log_safe('a' + cr + nl + 'b') == 'a' + chr(92) + 'r' + chr(92) + 'n' + 'b'
    assert _log_safe('x' + tab + 'y') == 'x' + chr(92) + 'x09y'
    assert _log_safe('한국어 사유') == '한국어 사유'


def test_provider_verification_is_on_by_default_and_admin_switches_it_from_the_dashboard():
    repo = InMemoryRepository()
    c = client(repo, CREDENTIAL_VERIFICATION_MODE="enabled")
    view = c.get("/api/v1/settings/credential-verification", headers=auth()).json()
    assert view["enabled"] is True and view["installation_allows"] is True and view["updated_by"] is None
    assert c.get("/api/v1/source-types", headers=auth()).json()["network_verification"] is True

    off = c.put("/api/v1/settings/credential-verification", headers=auth(), json={"enabled": False})
    assert off.status_code == 200 and off.json()["enabled"] is False and off.json()["updated_by"] == "local operator"
    assert c.get("/api/v1/detection-engine", headers=auth()).json()["network_verification"] is False
    # The next scan reads the switch: inline scans pass verify=False while it is off.
    seen = []
    original = c.app.state.orchestrator.scan_resource
    c.app.state.orchestrator.scan_resource = lambda data, resource, verify=None, verify_config=None: seen.append(verify) or original(data, resource, verify=verify, verify_config=verify_config)
    assert c.post("/api/v1/scan", headers=auth(), json={"text": "nothing here", "source_type": "github"}).status_code == 202
    assert c.put("/api/v1/settings/credential-verification", headers=auth(), json={"enabled": True}).json()["enabled"] is True
    assert c.post("/api/v1/scan", headers=auth(), json={"text": "nothing here", "source_type": "github"}).status_code == 202
    assert seen == [False, None]
    assert c.put("/api/v1/settings/credential-verification", headers=auth(), json={"enabled": "yes"}).status_code == 422


def test_a_github_app_can_be_stored_without_a_secret_store_and_reaches_the_worker():
    """The short-lived path, for an installation that runs no Vault.

    A GitHub App is three values that only mean anything together, and sealing
    could only hold one. So an installation with no secret store had to use a
    personal access token -- long-lived, and the thing this is all for avoiding.
    """
    import base64

    from cremore.secretstore.resolver import SecretResolver, inject_secret

    pem = base64.b64encode("-----BEGIN RSA PRIVATE KEY-----|synthetic|-----END RSA PRIVATE KEY-----|".replace("|", chr(10)).encode()).decode()
    from cremore.onboarding.fixtures_test import wizard

    app = {"GITHUB_APP_ID": "123456", "GITHUB_APP_INSTALLATION_ID": "789012",
           "GITHUB_APP_PRIVATE_KEY_BASE64": pem}
    fields = {"app_id": "123456", "installation_id": "789012", "private_key": pem}
    body = {"provider": "github", "purposes": ["exposure"], "auth_method": "github_app",
            "target": {"organization": "example"}}
    c = client()
    created = c.post("/api/v1/provider-connections", headers=auth(), json={**body, "credential": fields})
    assert created.status_code == 201, created.text
    # Nothing of the App comes back, and the stored reference names the key.
    assert pem not in created.text and "123456" not in created.text
    view = wizard(c, auth(), {**body, "credential": fields}, plans={"exposure": {}})
    # The list says which supply method it was registered with. Without that, a
    # credential that expires in an hour reads as an indefinite stored token,
    # and telling them apart would mean opening the credential.
    listed = c.get("/api/v1/source-connections", headers=auth()).json()
    assert [row["credential_source"] for row in listed] == ["GITHUB_APP"]
    stored = c.app.state.repo.get_connection(uuid.UUID(view["created"][0]["id"])).secret_ref
    assert stored.startswith("sealed:v2:")

    # The worker opens it and mints an installation token from it -- the same
    # path a vault:// reference takes, with nothing stored outside this install.
    resolver = SecretResolver(sealing_key=c.app.state.settings.sealing_keys)
    assert resolver.resolve(stored) == app
    issued = []
    injected = inject_secret("github", {"secret_ref": stored, "org": "example"},
                             resolver, github_client_factory=lambda: issued.append(1) or object())
    assert callable(injected["token"]), "an App yields a token source, not a stored token"

    for bad, code in (({**fields, "app_id": "0"}, "GITHUB_APP_ID_INVALID"),
                      ({**fields, "private_key": "not base64!"}, "GITHUB_APP_PRIVATE_KEY_INVALID"),
                      ({**fields, "extra": "x"}, "CREDENTIAL_FIELD_UNKNOWN")):
        refused = c.post("/api/v1/provider-connections", headers=auth(), json={**body, "credential": bad})
        assert refused.status_code == 422 and refused.json()["error"] == code, refused.text

    # It is a GitHub App; no other provider pretends to have one.
    other = c.post("/api/v1/provider-connections", headers=auth(), json={
        "provider": "notion", "purposes": ["exposure"], "auth_method": "github_app", "credential": fields})
    assert other.status_code == 422 and other.json()["error"] == "AUTH_METHOD_NOT_FOR_PURPOSES"
    # And it is one credential or another, never two.
    both = c.post("/api/v1/provider-connections", headers=auth(), json={
        **body, "credential": {**fields, "token": GH}})
    assert both.status_code == 422 and both.json()["error"] == "CREDENTIAL_FIELD_UNKNOWN"


def test_no_route_is_unreachable_behind_an_earlier_parameterised_one():
    """A literal path registered after a matching {placeholder} never runs.

    FastAPI matches in registration order, so /aws/accounts/discoverable placed after
    /aws/accounts/{account_id} is answered by the latter with account_id="discoverable"
    -- a 404 or a confusing 422, and no test of that route would notice
    unless it went through the whole app. Splitting the registrar into per-area
    modules changes that order, which is exactly when this can happen.
    """
    import re

    routes = [(r.path, set(getattr(r, "methods", []) or [])) for r in client().app.routes]
    placeholder = re.compile(r"\{[^}]+\}")
    for index, (path, methods) in enumerate(routes):
        if not placeholder.search(path):
            continue
        literal = re.escape(path).replace(r"\{", "{").replace(r"\}", "}")
        pattern = re.compile("^" + placeholder.sub(r"[^/]+", literal) + "$")
        for later, later_methods in routes[index + 1:]:
            if placeholder.search(later) or not methods & later_methods:
                continue
            assert not pattern.match(later), f"{later} is unreachable behind {path}"


def test_the_local_credential_view_reports_the_real_root_and_leaks_no_value():
    # Setting SEALING_KMS_KEY_ID and having the master in KMS are not the same
    # sentence, and the difference only shows when somebody copies the .env.
    c = client()
    view = c.get("/api/v1/settings/local-credentials", headers=auth()).json()
    assert view["sealing"]["root"] == "FINGERPRINT_KEY"
    assert "SEALING_MASTER_CANNOT_ROTATE" in view["reasons"]
    assert {item["name"] for item in view["items"]} >= {"sealing master", "FINGERPRINT_KEY", "API_TOKEN"}
    body = c.get("/api/v1/settings/local-credentials", headers=auth()).text
    for secret in ("ab" * 32, TOKEN):
        assert secret not in body

    separated = client(SEALING_KEY="cd" * 32).get("/api/v1/settings/local-credentials", headers=auth()).json()
    assert separated["sealing"]["root"] == "ENVIRONMENT"
    assert "SEALING_MASTER_HELD_HERE" in separated["reasons"]
    assert "cd" * 32 not in str(separated)


def test_the_local_credential_view_is_an_admin_read(issuer):
    # It describes how this installation is configured, which is an Admin's
    # business; a Viewer learning the deployment shape is not part of the job.
    c, _ = _oidc_client(issuer, InMemoryRepository())
    assert c.get("/api/v1/settings/local-credentials", headers=_bearer(issuer, "v", "g-viewers")).status_code == 403
    assert c.get("/api/v1/settings/local-credentials", headers=_bearer(issuer, "a", "g-admins")).status_code == 200


def test_capability_probe_and_cross_host_are_dashboard_switches_off_by_default():

    repo = InMemoryRepository()
    c = client(repo, CREDENTIAL_VERIFICATION_MODE="enabled", CREDENTIAL_CAPABILITY_PROBE_MODE="enabled",
               CREDENTIAL_CROSS_HOST_VERIFICATION="enabled", GITHUB_ENTERPRISE_HOSTS="ghe.example.com")
    for path in ("capability-probe", "cross-host-verification"):
        view = c.get(f"/api/v1/settings/{path}", headers=auth()).json()
        assert view["installation_allows"] is True and view["switch"] is False and view["enabled"] is False
    # the scan reads the switches: verify_config carries them off, then on
    seen = []
    original = c.app.state.orchestrator.scan_resource
    c.app.state.orchestrator.scan_resource = lambda data, resource, verify=None, verify_config=None: (
        seen.append((verify_config.probe_capabilities, verify_config.cross_host, verify_config.known_github_hosts)) or
        original(data, resource, verify=verify, verify_config=verify_config))
    c.post("/api/v1/scan", headers=auth(), json={"text": "x", "source_type": "github"})
    assert c.put("/api/v1/settings/capability-probe", headers=auth(), json={"enabled": True}).json()["enabled"] is True
    assert c.put("/api/v1/settings/cross-host-verification", headers=auth(), json={"enabled": True}).json()["enabled"] is True
    c.post("/api/v1/scan", headers=auth(), json={"text": "x", "source_type": "github"})
    assert seen[0] == (False, False, ("ghe.example.com",)) and seen[1] == (True, True, ("ghe.example.com",))


def test_scan_toggles_are_locked_off_when_the_installation_disallows_them():
    c = client(InMemoryRepository(), CREDENTIAL_VERIFICATION_MODE="enabled", CREDENTIAL_CAPABILITY_PROBE_MODE="disabled")
    view = c.get("/api/v1/settings/capability-probe", headers=auth()).json()
    assert view["installation_allows"] is False and view["enabled"] is False
    assert c.put("/api/v1/settings/capability-probe", headers=auth(), json={"enabled": True}).status_code == 409
    assert c.put("/api/v1/settings/capability-probe", headers=auth(), json={"enabled": False}).status_code == 200


def test_installation_lock_keeps_verification_off_whatever_the_dashboard_says():
    c = client(InMemoryRepository(), CREDENTIAL_VERIFICATION_MODE="disabled")
    view = c.get("/api/v1/settings/credential-verification", headers=auth()).json()
    assert view["enabled"] is False and view["switch"] is True and view["installation_allows"] is False
    r = c.put("/api/v1/settings/credential-verification", headers=auth(), json={"enabled": True})
    assert r.status_code == 409 and "CREDENTIAL_VERIFICATION_MODE=disabled" in r.json()["detail"]
    assert c.put("/api/v1/settings/credential-verification", headers=auth(), json={"enabled": False}).status_code == 200


def test_an_admin_reads_how_people_sign_in(issuer):
    from cremore.api.conftest import AUDIENCE, GROUPS, ISSUER

    local = client().get("/api/v1/settings/sign-in", headers=auth()).json()
    assert local == {"mode": "local", "issuer": None, "audience": None, "groups_claim": None, "groups": None,
                     "role_groups": None}
    c, _ = _oidc_client(issuer, InMemoryRepository(), OIDC_VIEWER_GROUP="")
    view = c.get("/api/v1/settings/sign-in", headers=_bearer(issuer, "bob", GROUPS["admin"])).json()
    assert (view["mode"], view["issuer"], view["audience"], view["groups_claim"]) == ("oidc", ISSUER, AUDIENCE, "groups")
    assert view["groups"] == {"viewer": None, "analyst": GROUPS["analyst"], "remediator": GROUPS["remediator"],
                              "admin": GROUPS["admin"]}
    assert view["role_groups"] is None  # the IdP's tokens carry the groups
    assert c.get("/api/v1/settings/sign-in", headers=_bearer(issuer, "alice", GROUPS["analyst"])).status_code == 403


def test_viewer_cannot_switch_verification(issuer):
    from cremore.api.conftest import oidc_settings

    app = create_app(repo=InMemoryRepository(), settings=oidc_settings(CREDENTIAL_VERIFICATION_MODE="enabled"),
                     oidc_http_client=issuer)
    c = TestClient(app)
    viewer = {"Authorization": "Bearer " + issuer.mint(sub="viewer-1", groups=("g-viewers",))}
    assert c.get("/api/v1/settings/credential-verification", headers=viewer).status_code == 200
    assert c.put("/api/v1/settings/credential-verification", headers=viewer, json={"enabled": False}).status_code == 403


def test_remediation_identity_is_approved_and_validated_separately_in_the_api():
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    remediation_key = "identity-center:aws:111111111111:CreMoreRemediation"
    pattern = SSO_PATTERN.replace("SecurityAudit", "CreMoreRemediation")
    state = {"remediation": {**sso_identity(), "permission_set": "CreMoreRemediation", "match_key": remediation_key,
                             "trust": {"type": "IdentityCenter", "account_id": "111111111111", "principal_pattern": pattern}}}
    validated = []

    def probe(role_arn=None, sso_region=None, purpose="scanner"):
        return state["remediation"] if purpose == "remediation" else sso_identity()

    def remediation_validator(acct):
        validated.append(acct.account_id)
        return RoleValidation("VALID", "ok", "arn", code="SCANNER_ROLE_ASSUMED")

    repo = InMemoryRepository()
    c = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                              aws_identity_probe=probe, aws_remediation_validator=remediation_validator))
    report_worker(c)
    c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
    acct = registered(c, "123456789012")

    # the deployment has no remediation role until one is set for the account and an identity approved
    params = c.get(f"/api/v1/aws/accounts/{acct['id']}/onboarding", headers=auth()).json()["deployment"]["parameters"]
    assert "EnableRemediation" not in params and params["MemberScannerRoleName"] == "CredentialExposureScannerRole"
    custom = registered(c, "210987654321", scanner_role_arn="arn:aws:iam::210987654321:role/TeamScanner")
    custom_params = c.get(f"/api/v1/aws/accounts/{custom['id']}/onboarding", headers=auth()).json()["deployment"]["parameters"]
    assert custom_params["MemberScannerRoleName"] == "TeamScanner"  # the command creates the role the record assumes
    c.patch(f"/api/v1/aws/accounts/{acct['id']}", headers=auth(),
            json={"remediation_role_arn": "arn:aws:iam::123456789012:role/CredentialExposureRemediationRole"})
    body = c.get("/api/v1/aws/remediation-identity", headers=auth()).json()
    assert body["approved"] is None and body["api"]["permission_set"] == "CreMoreRemediation"
    assert body["policy"]["Statement"][0]["Resource"] == "arn:aws:iam::*:role/CredentialExposureRemediationRole"
    r = c.post(f"/api/v1/aws/accounts/{acct['id']}/validate?purpose=remediation", headers=auth())
    assert r.status_code == 409 and "IDENTITY_NOT_APPROVED" in r.json()["error"]

    approved = c.put("/api/v1/aws/remediation-identity", headers=auth(), json={"confirm": True}).json()
    assert approved["approved"]["permission_set"] == "CreMoreRemediation" and approved["same_as_scanner"] is False
    params = c.get(f"/api/v1/aws/accounts/{acct['id']}/onboarding", headers=auth()).json()["deployment"]["parameters"]
    assert params["EnableRemediation"] == "true" and params["RemediationTrustedPrincipalPattern"] == pattern
    assert params["TrustedPrincipalPattern"] == SSO_PATTERN  # scanner trust unchanged

    done = c.post(f"/api/v1/aws/accounts/{acct['id']}/validate?purpose=remediation", headers=auth()).json()
    assert done["purpose"] == "remediation" and done["status"] == "VALID" and validated == ["123456789012"]
    listed = c.get("/api/v1/aws/accounts", headers=auth()).json()[0]
    assert listed["remediation_validation_status"] == "VALID" and listed["validation_status"] == "PENDING"

    # the API refuses to validate under a remediation identity other than the approved one
    state["remediation"] = {**state["remediation"], "match_key": "identity-center:aws:111111111111:Other"}
    r = c.post(f"/api/v1/aws/accounts/{acct['id']}/validate?purpose=remediation", headers=auth())
    assert r.status_code == 409 and "AWS_IDENTITY_CHANGED" in r.json()["error"] and validated == ["123456789012"]
    assert c.post(f"/api/v1/aws/accounts/{acct['id']}/validate?purpose=other", headers=auth()).status_code == 422


# --- Identity Center onboarding route ----------------------------------------

START_URL = "https://d-1234567890.awsapps.com/start"


def no_start_url(**_):
    """A READY Identity Center identity whose directory could not be resolved."""
    return {**sso_identity(), "sso_start_url": None}


def discovery_probe(sso=None, org=None):
    """Stands in for the live, read-only probe of each discovery source."""

    def probe(source, _approved):
        if source == "sso":
            return sso if sso is not None else {"available": False, "reason": "AWS_LOGIN_REQUIRED", "accounts": []}
        return org if org is not None else {"available": False, "reason": "AccessDeniedException", "accounts": []}

    return probe


def sso_listing(accounts, permission_set="CreMoreScanner"):
    return {"available": True, "reason": None, "permission_set": permission_set, "start_url": START_URL,
            "region": "ap-northeast-2", "accounts": accounts}


def discovery_sweep(sso=None, org=None):
    """Registers from the same fake listings the probe returns, via the real reconcile."""

    def sweep(source, _approved, queue_validation):
        from cremore_aws_provider.aws_org_settings import config as org_config
        from cremore_aws_provider.aws_sso_discovery import reconcile_sso_accounts

        listing = (sso if source == "sso" else org) or {}
        repo = sweep.repo
        if source == "sso":
            return reconcile_sso_accounts(repo, sweep.settings, _FakeSsoListing(listing.get("accounts") or []),
                                          "tok", listing.get("permission_set"), queue_validation=queue_validation)
        from cremore_aws_provider.aws_org_discovery import reconcile_org_accounts

        return reconcile_org_accounts(repo, sweep.settings, _FakeOrgListing(listing.get("accounts") or []),
                                      org_config(sweep.settings, repo), queue_validation=queue_validation)

    return sweep


class _FakeSsoListing:
    def __init__(self, accounts):
        self.accounts = accounts

    def get_paginator(self, operation):
        return self

    def paginate(self, **kwargs):
        if "accountId" in kwargs:
            roles = next((a["roles"] for a in self.accounts if a["account_id"] == kwargs["accountId"]), [])
            return iter([{"roleList": [{"roleName": r} for r in roles]}])
        return iter([{"accountList": [{"accountId": a["account_id"], "accountName": a["name"]}
                                      for a in self.accounts]}])


class _FakeOrgListing:
    def __init__(self, accounts):
        self.accounts = accounts

    def get_paginator(self, _operation):
        return self

    def paginate(self, **_kwargs):
        return iter([{"Accounts": [{"Id": a.get("id") or a.get("account_id"), "Name": a["name"],
                                    "State": a.get("state")} for a in self.accounts]}])


def sso_route_client(repo=None, sso=None, org=None, probe=sso_identity, permission_set="CreMoreScanner",
                     **overrides):
    """An approved Identity Center install, with discovery probing stubbed out.

    The permission set is chosen through the dashboard, which is how an operator
    who cannot edit the deployment's environment has to do it.
    """
    repo = repo if repo is not None else InMemoryRepository()
    app_settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, **overrides)
    sweep = discovery_sweep(sso=sso, org=org)
    sweep.repo, sweep.settings = repo, app_settings
    c = TestClient(create_app(
        repo=repo, settings=app_settings, aws_identity_probe=probe,
        aws_discovery_probe=discovery_probe(sso=sso, org=org), aws_discovery_sweep=sweep))
    c.app.state.repo.put_setting(_worker_identity_key(), probe(), "worker")
    assert c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True}).status_code == 200
    if permission_set:
        assert c.put("/api/v1/settings/aws-identity-center", headers=auth(),
                     json={"permission_set": permission_set}).status_code == 200
    return c


def _worker_identity_key():
    from cremore_aws_provider import aws_identity

    return aws_identity.WORKER_IDENTITY_KEY


def _role_check_jobs(c):
    from cremore_aws_provider import aws_identity

    return [j for j in c.app.state.repo.list_jobs(50) if j.kind == aws_identity.ROLE_CHECK_JOB]


def test_onboarding_lists_the_routes_from_local_state_only():
    """The dashboard polls this on every refresh, so it must never call AWS."""

    def explode(_source, _approved):
        raise AssertionError("onboarding must not probe a discovery source")

    repo = InMemoryRepository()
    c = TestClient(create_app(
        repo=repo,
        settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
        aws_identity_probe=sso_identity, aws_discovery_probe=explode))
    repo.put_setting(_worker_identity_key(), sso_identity(), "worker")
    c.put("/api/v1/aws/scanner-identity", headers=auth(), json={"confirm": True})
    c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"permission_set": "CreMoreScanner"})

    body = c.get("/api/v1/aws/accounts/onboarding", headers=auth()).json()
    assert body["configured"] is True
    assert body["sources"]["sso"] == {"supported": True, "permission_set": "CreMoreScanner", "auto_discovery": False}
    assert body["sources"]["org"]["supported"] is True and body["sources"]["org"]["external_id_configured"] is False
    assert body["sources"]["manual"] == {"supported": True}


def test_the_sso_route_is_not_offered_without_an_identity_center_identity():
    def iam_user(**_):
        arn = "arn:aws:iam::111111111111:user/scanner"
        return {"state": "READY", "kind": "IAM_USER", "partition": "aws", "account_id": "111111111111",
                "caller_arn": arn, "principal_arn": arn, "match_key": f"user:{arn}", "requires": None,
                "trust": {"type": "IamUser", "principal_arn": arn}}

    body = sso_route_client(probe=iam_user).get("/api/v1/aws/accounts/onboarding", headers=auth()).json()
    assert body["sources"]["sso"]["supported"] is False
    assert body["sources"]["manual"]["supported"] is True

    # READY Identity Center, but the directory could not be read from the profile.
    body = sso_route_client(probe=no_start_url).get("/api/v1/aws/accounts/onboarding", headers=auth()).json()
    assert body["sources"]["sso"]["supported"] is False


def test_discoverable_selects_only_accounts_carrying_the_configured_permission_set():
    listed = [{"account_id": "1" * 12, "name": "alpha", "roles": ["CreMoreScanner", "AdministratorAccess"]},
              {"account_id": "2" * 12, "name": "beta", "roles": ["AdministratorAccess"]},
              {"account_id": "3" * 12, "name": "gamma", "roles": ["CreMoreScanner"]}]
    c = sso_route_client(sso=sso_listing(listed))
    body = c.get("/api/v1/aws/accounts/discoverable?source=sso", headers=auth()).json()
    assert body["available"] is True and body["total"] == 3 and body["truncated"] is False
    picked = {a["account_id"]: a for a in body["accounts"]}
    assert picked["1" * 12]["selectable"] is True and picked["3" * 12]["selectable"] is True
    # Assigned to the account, but not with the permission set CreMore is set to use.
    assert picked["2" * 12]["selectable"] is False
    assert picked["1" * 12]["roles"] == ["CreMoreScanner", "AdministratorAccess"]

    # Already registered accounts are shown, never offered again.
    assert connect_aws(c, "1" * 12, method="sso").status_code == 201
    again = {a["account_id"]: a for a in
             c.get("/api/v1/aws/accounts/discoverable?source=sso", headers=auth()).json()["accounts"]}
    assert again["1" * 12] == {**again["1" * 12], "registered": True, "selectable": False,
                               "registered_access": "SSO_PERMISSION_SET"}


def test_discoverable_offers_only_active_organization_accounts():
    org = {"available": True, "reason": None,
           "accounts": [{"id": "1" * 12, "name": "alpha", "state": "ACTIVE"},
                        {"id": "2" * 12, "name": "closing", "state": "SUSPENDED"},
                        {"id": "3" * 12, "name": "unknown", "state": None}]}
    body = sso_route_client(org=org).get("/api/v1/aws/accounts/discoverable?source=org", headers=auth()).json()
    picked = {a["account_id"]: a["selectable"] for a in body["accounts"]}
    assert picked == {"1" * 12: True, "2" * 12: False, "3" * 12: False}


def test_discoverable_reports_a_safe_reason_and_never_raises():
    def boom(_source, _approved):
        raise RuntimeError("AccessDeniedException")

    repo = InMemoryRepository()
    c = TestClient(create_app(repo=repo,
                              settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                              aws_identity_probe=sso_identity, aws_discovery_probe=boom))
    body = c.get("/api/v1/aws/accounts/discoverable?source=org", headers=auth()).json()
    assert body["available"] is False and body["reason"] == "RuntimeError" and body["accounts"] == []
    assert c.get("/api/v1/aws/accounts/discoverable?source=nope", headers=auth()).status_code == 422

    # A refusal carries its reason code through unchanged.
    refused = sso_route_client().get("/api/v1/aws/accounts/discoverable?source=sso", headers=auth()).json()
    assert refused["available"] is False and refused["reason"] == "AWS_LOGIN_REQUIRED"


def test_registering_an_identity_center_account_needs_no_role_and_no_external_id():
    c = sso_route_client()
    r = connect_aws(c, "5" * 12, method="sso")
    assert r.status_code == 201, r.json()
    body = aws_row(c, "5" * 12)
    assert body["access"] == "SSO_PERMISSION_SET" and body["sso_role_name"] == "CreMoreScanner"
    assert body["scanner_role_arn"] is None and body["source"] == "SSO"
    # No stack exists for this mode, so there is no deployment command to show.
    r = c.get(f"/api/v1/aws/accounts/{body['id']}/onboarding", headers=auth())
    assert r.status_code == 409 and "IDENTITY_CENTER_ACCESS" in r.json()["error"]


@pytest.mark.parametrize("method", ["sso", "customer_cli", "role", "runtime"])
def test_new_aws_connections_cannot_depend_on_a_personal_login(method):
    c = sso_route_client()
    response = c.post("/api/v1/provider-connections", headers=auth(), json={
        "provider": "aws", "purposes": ["inventory"], "auth_method": method,
        "target": {"accounts": ["111111111111"]}})
    assert response.status_code == 409
    assert response.json()["error"] == ("AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS"
        if method in {"sso", "customer_cli"} else "AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED")
    assert not c.app.state.repo.list_aws_accounts()


def test_identity_center_access_is_refused_when_the_directory_was_never_recorded():
    c = sso_route_client(probe=no_start_url)
    r = connect_aws(c, "5" * 12, method="sso")
    # Without the approved directory nothing pins the account and every session
    # would be refused; say so now rather than creating a dead record.
    assert r.status_code == 409 and r.json()["error"] == "IDENTITY_CENTER_START_URL_REQUIRED"
    assert c.get("/api/v1/aws/accounts", headers=auth()).json() == []


def test_a_permission_set_name_is_validated_and_an_unknown_access_mode_is_refused():
    from cremore.onboarding.fixtures_test import legacy_aws_setup

    c = sso_route_client()
    with legacy_aws_setup("sso"):
        r = c.post("/api/v1/provider-connections", headers=auth(), json={
            "provider": "aws", "purposes": ["exposure"], "auth_method": "sso",
            "target": {"accounts": ["5" * 12]}, "credential": {"permission_set": "has space"}})
    assert r.status_code == 422 and r.json()["error"] == "AWS_PERMISSION_SET_INVALID"
    r = connect_aws(c, "5" * 12, method="MAGIC")
    assert r.status_code == 422 and r.json()["error"] == "AUTH_METHOD_NOT_FOR_PURPOSES"
    # A permission set named here is the one each account is reached with.
    with legacy_aws_setup("sso"):
        named = c.post("/api/v1/provider-connections", headers=auth(), json={
            "provider": "aws", "purposes": ["exposure"], "auth_method": "sso",
            "target": {"accounts": ["5" * 12]}, "credential": {"permission_set": "TeamAudit"}})
    assert named.status_code == 201 and named.json()["target"]["auth"] == {"permission_set": "TeamAudit"}
    assert aws_row(c, "5" * 12)["sso_role_name"] == "TeamAudit"


def test_importing_several_accounts_proves_each_one_at_once():
    c = sso_route_client()
    assert connect_aws(c, "5" * 12, "6" * 12, "nope", method="sso").status_code == 422
    assert c.get("/api/v1/aws/accounts", headers=auth()).json() == []
    r = connect_aws(c, "5" * 12, "6" * 12, method="sso")
    assert r.status_code == 201, r.text
    assert {child["access"] for child in r.json()["children"]} == {"SSO_PERMISSION_SET"}
    # Nothing to wait for, so each new account's check is queued straight away.
    assert len(_role_check_jobs(c)) == 2


def test_member_role_imports_are_not_auto_validated():
    """A ROLE account has a stack to deploy first; checking now would only record
    a failure the operator has not had a chance to prevent."""
    c = sso_route_client()
    assert connect_aws(c, "5" * 12, "6" * 12).status_code == 201
    assert _role_check_jobs(c) == []


def test_one_access_mode_per_connection_and_a_refused_one_leaves_the_other_untouched():
    """Accounts reached in two ways are two connections; one refused never blocks the other."""
    c = sso_route_client(probe=no_start_url)
    refused = connect_aws(c, "5" * 12, method="sso")
    assert refused.status_code == 409 and refused.json()["error"] == "IDENTITY_CENTER_START_URL_REQUIRED"
    # The ordinary member-role account still goes in.
    assert connect_aws(c, "6" * 12).status_code == 201
    assert [row["account_id"] for row in c.get("/api/v1/aws/accounts", headers=auth()).json()] == ["6" * 12]


def test_promotion_keeps_the_record_and_blocks_scanning_until_the_role_is_proved():
    from cremore_aws_provider import aws_access

    c = sso_route_client()
    assert connect_aws(c, "5" * 12, method="sso").status_code == 201
    created = aws_row(c, "5" * 12)
    repo = c.app.state.repo
    account = repo.list_aws_accounts()[0]
    aws_access.record_validation(repo, account, aws_access.SCANNER, access_revision=account.access_revision,
                                 approval_revision=1, current_approval_revision=1, status="VALID", detail="OK")
    assert c.get("/api/v1/aws/accounts", headers=auth()).json()[0]["validation_status"] == "VALID"

    r = c.post(f"/api/v1/aws/accounts/{created['id']}/promote", headers=auth())
    assert r.status_code == 200, r.json()
    body = r.json()
    assert body["access"] == "ROLE" and body["sso_role_name"] is None
    assert body["scanner_role_arn"].endswith(":role/CredentialExposureScannerRole")
    # The assignment sweep must stop owning a record that no longer depends on it.
    assert body["source"] == "MANUAL"
    # The same record, and its stored VALID no longer counts.
    assert body["id"] == created["id"] and body["validation_status"] == "PENDING"
    assert body["validation_detail"] == "REVALIDATION_REQUIRED"
    # Promotion hands back the deployment command straight away.
    assert "cli_command" in body["deployment"] and body["deployment"]["parameters"]["ExternalId"]
    # Only Identity Center access is promoted this way.
    assert c.post(f"/api/v1/aws/accounts/{created['id']}/promote", headers=auth()).status_code == 409


def test_the_permission_set_is_chosen_in_the_dashboard_not_the_deployment_env():
    """An operator who runs CreMore often cannot edit its environment, so the
    Identity Center route must be usable without a config change or a restart."""
    listed = [{"account_id": "1" * 12, "name": "alpha", "roles": ["CreMoreScanner", "AdministratorAccess"]},
              {"account_id": "2" * 12, "name": "beta", "roles": ["CreMoreScanner"]}]
    c = sso_route_client(sso=sso_listing(listed), permission_set=None)

    view = c.get("/api/v1/settings/aws-identity-center", headers=auth()).json()
    assert view["permission_set"] is None and view["locked"] is False
    assert view["discovery"] == {**view["discovery"], "enabled": False, "switch": False,
                                 "installation_allows": True}

    # Nothing can be selected or registered until someone chooses.
    body = c.get("/api/v1/aws/accounts/discoverable?source=sso", headers=auth()).json()
    assert [a["selectable"] for a in body["accounts"]] == [False, False]
    # The dialog offers what Identity Center actually reports, commonest first,
    # including AdministratorAccess: only a person should decide against it.
    assert body["available_permission_sets"] == [{"name": "CreMoreScanner", "accounts": 2},
                                                 {"name": "AdministratorAccess", "accounts": 1}]
    refused = connect_aws(c, "1" * 12, method="sso")
    assert refused.status_code == 409 and refused.json()["error"] == "PERMISSION_SET_NOT_CHOSEN"

    r = c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"permission_set": "CreMoreScanner"})
    assert r.status_code == 200 and r.json()["permission_set"] == "CreMoreScanner"
    assert r.json()["source"] == "DASHBOARD" and r.json()["permission_set_updated_by"] == "local operator"

    after = c.get("/api/v1/aws/accounts/discoverable?source=sso", headers=auth()).json()
    assert [a["selectable"] for a in after["accounts"]] == [True, True]
    assert connect_aws(c, "1" * 12, method="sso").status_code == 201


def test_a_configured_pin_still_wins_and_refuses_to_be_overridden():
    c = sso_route_client(permission_set=None, AWS_SSO_DISCOVERY_PERMISSION_SET="PinnedSet")
    view = c.get("/api/v1/settings/aws-identity-center", headers=auth()).json()
    assert view["permission_set"] == "PinnedSet" and view["locked"] is True and view["source"] == "SETTING"
    r = c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"permission_set": "Other"})
    assert r.status_code == 409 and "PERMISSION_SET_LOCKED" in r.json()["error"]
    # Registration uses the pin, not the rejected value.
    assert connect_aws(c, "1" * 12, method="sso").status_code == 201
    assert aws_row(c, "1" * 12)["sso_role_name"] == "PinnedSet"


def test_the_sweep_switch_needs_a_permission_set_and_obeys_the_configuration_lock():
    c = sso_route_client(permission_set=None)
    blocked = c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"discovery_enabled": True})
    assert blocked.status_code == 409 and "PERMISSION_SET_NOT_CHOSEN" in blocked.json()["error"]

    c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"permission_set": "CreMoreScanner"})
    on = c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"discovery_enabled": True}).json()
    assert on["discovery"]["enabled"] is True and on["discovery"]["switch"] is True
    # The onboarding view reports the live sweep state without calling AWS.
    assert c.get("/api/v1/aws/accounts/onboarding", headers=auth()).json()["sources"]["sso"] == {
        "supported": True, "permission_set": "CreMoreScanner", "auto_discovery": True}

    off = c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"discovery_enabled": False}).json()
    assert off["discovery"]["enabled"] is False

    locked = sso_route_client(AWS_SSO_DISCOVERY_MODE="disabled")
    r = locked.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"discovery_enabled": True})
    assert r.status_code == 409 and "AWS_SSO_DISCOVERY_MODE" in r.json()["error"]
    assert locked.get("/api/v1/settings/aws-identity-center",
                      headers=auth()).json()["discovery"]["installation_allows"] is False


def test_the_chosen_permission_set_is_validated_and_can_be_cleared():
    c = sso_route_client()
    assert c.put("/api/v1/settings/aws-identity-center", headers=auth(),
                 json={"permission_set": "has space"}).status_code == 422
    assert c.put("/api/v1/settings/aws-identity-center", headers=auth(),
                 json={"permission_set": "x" * 33}).status_code == 422
    cleared = c.put("/api/v1/settings/aws-identity-center", headers=auth(), json={"permission_set": ""}).json()
    assert cleared["permission_set"] is None and cleared["discovery"]["enabled"] is False


def test_choosing_the_permission_set_needs_admin():
    c = sso_route_client()
    assert c.get("/api/v1/settings/aws-identity-center", headers=auth()).status_code == 200
    # Role gating is the same as every other installation setting.
    assert c.put("/api/v1/settings/aws-identity-center", json={"permission_set": "X"}).status_code in (401, 403)


# --- why there is no AWS sign-in ----------------------------------------------


def test_the_dashboard_can_say_why_there_is_no_aws_sign_in(monkeypatch):
    """NO_CREDENTIALS alone is what the operator already saw and could not act on.

    The three causes need different fixes, so the API names which one it is from
    a local, no-network look at the AWS CLI configuration this process can see.
    """
    from cremore_aws_provider import aws_identity

    seen = {}

    def sources(profile=""):
        seen["profile"] = profile
        return {"config_present": False, "credentials_present": False, "profiles": [],
                "requested_profile": profile or None, "sso_cache_entries": 0,
                "reason": "AWS_CONFIG_NOT_MOUNTED"}

    monkeypatch.setattr(aws_identity, "local_credential_sources", sources)
    monkeypatch.setenv("AWS_PROFILE", "cremore-scanner")
    c = client()  # the default probe reports NO_CREDENTIALS
    body = c.get("/api/v1/aws/scanner-identity", headers=auth()).json()
    assert body["api"]["state"] == "NO_CREDENTIALS"
    assert body["sign_in"]["reason"] == "AWS_CONFIG_NOT_MOUNTED"
    assert body["sign_in"]["state"] == "NO_CREDENTIALS"
    # The profile actually requested is what gets diagnosed.
    assert seen["profile"] == "cremore-scanner"


def test_a_usable_identity_has_nothing_to_prescribe():
    c = approved_client()
    body = c.get("/api/v1/aws/scanner-identity", headers=auth()).json()
    assert body["api"]["state"] == "READY" and body["sign_in"] is None


def test_an_expired_session_is_told_apart_from_a_missing_configuration(monkeypatch):
    from cremore_aws_provider import aws_identity

    monkeypatch.setattr(aws_identity, "local_credential_sources",
                        lambda profile="": {"config_present": True, "credentials_present": False,
                                            "profiles": ["cremore-scanner"], "requested_profile": None,
                                            "sso_cache_entries": 2, "reason": None})

    def expired(**_):
        return {"state": "LOGIN_REQUIRED", "error_code": "UnauthorizedSSOTokenError"}

    body = client(_probe=expired).get("/api/v1/aws/scanner-identity", headers=auth()).json()
    # The configuration is fine; only the sign-in ran out.
    assert body["sign_in"]["reason"] == "SIGN_IN_EXPIRED"


# --- Organizations discovery, configured in the dashboard ---------------------

EXT = "ext-shared-0123456789"
OU = "ou-abcd-11111111"


def test_organization_discovery_is_configured_without_touching_the_environment():
    c = sso_route_client()
    view = c.get("/api/v1/settings/aws-organizations", headers=auth()).json()
    assert view["enabled"] is False and view["external_id"] is None and view["effective"] is False
    assert view["installation_allows"] is True

    # The switch alone is refused: a role deployed with a different ExternalId
    # could never be assumed, so the sweep would register broken records.
    blocked = c.put("/api/v1/settings/aws-organizations", headers=auth(), json={"enabled": True})
    assert blocked.status_code == 409 and "EXTERNAL_ID_NOT_SET" in blocked.json()["error"]

    r = c.put("/api/v1/settings/aws-organizations", headers=auth(),
              json={"external_id": EXT, "ou_ids": [OU], "excludes": ["111111111111"],
                    "auto_validate": True, "enabled": True})
    assert r.status_code == 200, r.json()
    body = r.json()
    assert body["external_id"] == EXT and body["ou_ids"] == [OU] and body["excludes"] == ["111111111111"]
    assert body["auto_validate"] is True and body["enabled"] is True and body["effective"] is True
    assert body["updated_by"] == "local operator"

    # The connect dialog reflects it without calling AWS.
    org = c.get("/api/v1/aws/accounts/onboarding", headers=auth()).json()["sources"]["org"]
    assert org["auto_discovery"] is True and org["external_id_configured"] is True and org["ou_ids"] == [OU]


def test_organization_values_are_validated_before_they_reach_aws():
    c = sso_route_client()
    for body in ({"external_id": "x"}, {"ou_ids": ["not-an-ou"]}, {"excludes": ["nope"]},
                 {"ou_ids": "not-a-list"}, {"enabled": "yes"}, {"auto_validate": 1}):
        assert c.put("/api/v1/settings/aws-organizations", headers=auth(), json=body).status_code == 422, body


def test_a_pinned_organization_value_refuses_to_be_overridden():
    c = sso_route_client(AWS_ORG_DISCOVERY_EXTERNAL_ID=EXT, AWS_ORG_DISCOVERY_OU_IDS=OU)
    view = c.get("/api/v1/settings/aws-organizations", headers=auth()).json()
    assert view["external_id"] == EXT and view["external_id_locked"] is True
    assert view["ou_ids"] == [OU] and view["ou_ids_locked"] is True
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(),
                 json={"external_id": "other-value-01234"}).status_code == 409
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(),
                 json={"ou_ids": ["ou-abcd-22222222"]}).status_code == 409
    # Excludes were not pinned, so that one still works.
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(),
                 json={"excludes": ["222222222222"]}).status_code == 200
    # A pinned ExternalId satisfies the switch's requirement on its own.
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(),
                 json={"enabled": True}).json()["effective"] is True


def test_the_organization_stackset_trusts_only_the_approved_identity_scoped_by_org_and_external_id():
    """The org-wide role is one account's stack in Organization mode: the approved identity's trust, narrowed by the
    organization and the StackSet's shared ExternalId; the parameters go in a file (an ExternalId may hold a comma)."""
    path = "/api/v1/aws/onboarding/organization"
    unapproved = client().get(path, headers=auth(), params={"organization_id": "o-abcd123456"})
    assert unapproved.status_code == 409 and "AWS_SCANNER_IDENTITY_NOT_APPROVED" in unapproved.json()["error"]
    c = sso_route_client()
    missing = c.get(path, headers=auth(), params={"organization_id": "o-abcd123456"})
    assert missing.status_code == 409 and "EXTERNAL_ID_NOT_SET" in missing.json()["error"]
    # The sweep takes a short ExternalId; the member role template does not (16 to 128 characters).
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(), json={"external_id": "short-ext-id"}).status_code == 200
    short = c.get(path, headers=auth(), params={"organization_id": "o-abcd123456"})
    assert short.status_code == 409 and "EXTERNAL_ID_TEMPLATE_LENGTH" in short.json()["error"]
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(), json={"external_id": EXT, "ou_ids": [OU]}).status_code == 200
    for bad in ("", "o-short", "O-ABCD123456", "ou-abcd-11111111"):
        refused = c.get(path, headers=auth(), params={"organization_id": bad})
        assert refused.status_code == 422 and "AWS_ORGANIZATION_ID_INVALID" in refused.json()["error"], bad
    body = c.get(path, headers=auth(), params={"organization_id": "o-abcd123456"}).json()
    params = {item["ParameterKey"]: item["ParameterValue"] for item in body["parameters"]}
    assert params == {"DeploymentMode": "Organization", "OrganizationId": "o-abcd123456", "TargetAccountId": "",
                      "MemberScannerRoleName": "CredentialExposureScannerRole", "ExternalId": EXT,
                      "TrustedPrincipalType": "IdentityCenter", "IdentityCenterAccountId": "111111111111",
                      "TrustedPrincipalPattern": SSO_PATTERN}
    create, instances = body["commands"]
    for part in ("create-stack-set", "--permission-model SERVICE_MANAGED", "--capabilities CAPABILITY_NAMED_IAM",
                 "--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false",
                 f"--parameters file://{body['parameters_file']}", f"--template-body file://{body['template_file']}"):
        assert part in create, part
    assert f"--deployment-targets OrganizationalUnitIds={OU} " in instances and body["targets"] == [OU]
    assert EXT not in create + instances  # the ExternalId travels in the parameters file only
    # An account the sweep excludes gets no role either.
    assert c.put("/api/v1/settings/aws-organizations", headers=auth(), json={"excludes": ["222222222222"]}).status_code == 200
    body = c.get(path, headers=auth(), params={"organization_id": "o-abcd123456"}).json()
    assert body["excludes"] == ["222222222222"]
    assert (f"--deployment-targets OrganizationalUnitIds={OU},Accounts=222222222222,AccountFilterType=DIFFERENCE "
            in body["commands"][1])
    # The Region goes into the commands as typed in the configuration, so only a Region name does.
    odd = sso_route_client(AWS_REGION="us-east-1 --debug").get(path, headers=auth(), params={"organization_id": "o-abcd123456"})
    assert odd.status_code == 409 and "AWS_REGION_INVALID" in odd.json()["error"]


def test_configuration_can_still_hard_lock_organization_discovery_off():
    c = sso_route_client(AWS_ORG_DISCOVERY_MODE="disabled")
    assert c.get("/api/v1/settings/aws-organizations", headers=auth()).json()["installation_allows"] is False
    c.put("/api/v1/settings/aws-organizations", headers=auth(), json={"external_id": EXT})
    r = c.put("/api/v1/settings/aws-organizations", headers=auth(), json={"enabled": True})
    assert r.status_code == 409 and "AWS_ORG_DISCOVERY_MODE" in r.json()["error"]


# --- running a sweep now ------------------------------------------------------


def test_a_sweep_can_be_run_at_once_instead_of_waiting_for_the_worker():
    """Turning a switch on in the dashboard has to do something visible; the
    worker's poll is up to an hour away."""
    listed = [{"account_id": "5" * 12, "name": "alpha", "roles": ["CreMoreScanner"]},
              {"account_id": "6" * 12, "name": "beta", "roles": ["AdministratorAccess"]}]
    c = sso_route_client(sso=sso_listing(listed))
    r = c.post("/api/v1/aws/accounts/discover?source=sso", headers=auth())
    assert r.status_code == 200, r.json()
    # No connection takes discovered accounts in here, so none was adopted.
    assert r.json() == {"source": "sso", "registered": ["5" * 12], "changed": [], "skipped": 1, "error": None,
                        "adopted": 0}
    registered = c.get("/api/v1/aws/accounts", headers=auth()).json()
    assert [a["account_id"] for a in registered] == ["5" * 12]
    assert registered[0]["access"] == "SSO_PERMISSION_SET" and registered[0]["source"] == "SSO"
    # Nothing to wait for, so each new account's check is already queued.
    assert len(_role_check_jobs(c)) == 1


def test_a_sweep_hands_what_it_registers_to_the_connection_that_takes_it_in():
    from cremore.onboarding.fixtures_test import legacy_aws_setup, wizard

    listed = [{"account_id": "5" * 12, "name": "alpha", "roles": ["CreMoreScanner"]}]
    c = sso_route_client(sso=sso_listing(listed))
    with legacy_aws_setup("sso"):
        view = wizard(c, auth(), {"provider": "aws", "purposes": ["exposure", "inventory"], "auth_method": "sso",
                                  "target": {"accounts": ["6" * 12], "adopt_discovered": True}},
                      plans={"exposure": {}, "inventory": {}})
    r = c.post("/api/v1/aws/accounts/discover?source=sso", headers=auth())
    assert r.status_code == 200 and r.json()["registered"] == ["5" * 12] and r.json()["adopted"] == 1
    shown = c.get(f"/api/v1/provider-connections/{view['id']}", headers=auth()).json()
    accounts = {child["account_id"] for child in shown["children"] if child["kind"] == "aws_account"}
    assert accounts == {"5" * 12, "6" * 12}


def test_a_sweep_refuses_clearly_rather_than_failing_silently():
    c = sso_route_client()
    assert c.post("/api/v1/aws/accounts/discover?source=nope", headers=auth()).status_code == 422
    # Organizations without the shared ExternalId cannot register anything.
    r = c.post("/api/v1/aws/accounts/discover?source=org", headers=auth())
    assert r.status_code == 409 and "EXTERNAL_ID_NOT_SET" in r.json()["error"]

    # And nothing runs at all before the identity is approved.
    fresh = TestClient(create_app(repo=InMemoryRepository(),
                                  settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                                  aws_identity_probe=sso_identity))
    r = fresh.post("/api/v1/aws/accounts/discover?source=sso", headers=auth())
    assert r.status_code == 409 and "IDENTITY_NOT_APPROVED" in r.json()["error"]


def test_learned_false_positive_policy_is_set_and_audited_in_the_dashboard():
    """It decides which findings close without anyone reading them, so the
    policy has to be visible and the change has to say who made it."""
    c = client()
    view = c.get("/api/v1/settings/learned-false-positives", headers=auth()).json()
    assert view["enabled"] is False and view["switch"] is False
    assert (view["threshold"], view["min_samples"], view["max_confidence"]) == (0.85, 3, "medium")
    assert view["installation_allows"] is True and view["min_sample_floor"] == 2

    r = c.put("/api/v1/settings/learned-false-positives", headers=auth(),
              json={"enabled": True, "threshold": 0.93, "min_samples": 4, "max_confidence": "low"})
    assert r.status_code == 200, r.json()
    body = r.json()
    assert body["enabled"] is True and body["threshold"] == 0.93
    assert body["min_samples"] == 4 and body["max_confidence"] == "low"
    assert body["updated_by"] == "local operator" and body["updated_at"]


def test_a_policy_that_would_suppress_too_eagerly_is_refused():
    c = client()
    for body in ({"threshold": 0}, {"threshold": 1.5}, {"threshold": "high"},
                 {"min_samples": 1}, {"min_samples": "many"},
                 {"max_confidence": "certain"}, {"enabled": "yes"}):
        assert c.put("/api/v1/settings/learned-false-positives",
                     headers=auth(), json=body).status_code == 422, body


def test_configuration_can_pin_or_lock_the_auto_triage_policy():
    pinned = client(LEARNED_FP_THRESHOLD="0.7")
    view = pinned.get("/api/v1/settings/learned-false-positives", headers=auth()).json()
    assert view["threshold"] == 0.7 and view["threshold_locked"] is True
    r = pinned.put("/api/v1/settings/learned-false-positives", headers=auth(), json={"threshold": 0.9})
    assert r.status_code == 409 and "THRESHOLD_LOCKED" in r.json()["error"]
    # Not pinned, so this one still moves.
    assert pinned.put("/api/v1/settings/learned-false-positives",
                      headers=auth(), json={"min_samples": 6}).json()["min_samples"] == 6

    locked = client(LEARNED_FP_MODE="disabled")
    assert locked.get("/api/v1/settings/learned-false-positives",
                      headers=auth()).json()["installation_allows"] is False
    r = locked.put("/api/v1/settings/learned-false-positives", headers=auth(), json={"enabled": True})
    assert r.status_code == 409 and "LEARNED_FP_MODE" in r.json()["error"]


SQS_QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/cremore-only"


def _approved_scope_profile(repo):
    """The kind of profile a trigger may be bound to: approved, with a schedule."""
    from cremore.domain.models import Connection, ScopeProfile
    from cremore.scanning import scope

    target = repo.create_connection(Connection(provider="aws", name="S3", config={"bucket": "approved-bucket"}))
    item = scope.resource("source", target.id, "S3_BUCKET", "approved-bucket", "approved-bucket", "approved-bucket", "aws")
    return repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=target.id, name="approved", state="READY", schedule_minutes=60,
        event_mode="ENABLED",
        selected_roots=[{"resource_id": item["id"], "all_current_objects": True}],
        auth_revision=scope.auth_revision("source", target), catalog_snapshot_id="s",
        approved_by="admin", approved_at=datetime.now(UTC)))


def test_schedules_and_change_feeds_run_until_an_admin_switches_them_off_and_a_queue_waits_to_be_bound():
    """Nobody has to sign in for approved scopes to be scanned: schedules (a daily full scan from 02:00 KST)
    and change feeds are on until an Admin says otherwise; a queue reads nothing until it is bound."""
    repo = InMemoryRepository()
    c = client(repo)
    view = c.get("/api/v1/settings/scan-triggers", headers=auth()).json()
    for name in ("schedules", "change_feeds"):
        assert view[name]["enabled"] is True and view[name]["switch"] is True and view[name]["installation_allows"] is True
    assert view["sqs"]["enabled"] is False and view["sqs"]["switch"] is False
    assert (view["schedules"]["full_scan_default_minutes"], view["schedules"]["full_scan_start_minute"]) == (1440, 1020)
    assert view["change_feeds"]["minutes"]["bitbucket"] == 15 and view["change_feeds"]["minutes"]["notion"] == 5
    assert view["updated_by"] is None

    body = c.put("/api/v1/settings/scan-triggers", headers=auth(), json={"schedules_enabled": False}).json()
    assert body["schedules"]["enabled"] is False and body["updated_by"] == "local operator"
    # One switch is one trigger.
    assert body["change_feeds"]["enabled"] is True and body["sqs"]["enabled"] is False


def test_an_admin_sets_how_often_and_from_when_scopes_without_their_own_cadence_are_scanned_in_full():
    repo = InMemoryRepository()
    c = client(repo)
    body = c.put("/api/v1/settings/scan-triggers", headers=auth(),
                 json={"full_scan_default_minutes": 720, "full_scan_start_minute": 0}).json()
    assert (body["schedules"]["full_scan_default_minutes"], body["schedules"]["full_scan_start_minute"]) == (720, 0)
    for bad in ({"full_scan_default_minutes": 90}, {"full_scan_default_minutes": "1440"}, {"full_scan_default_minutes": None},
                {"full_scan_start_minute": 1440}, {"full_scan_start_minute": -1}, {"full_scan_start_minute": True}):
        assert c.put("/api/v1/settings/scan-triggers", headers=auth(), json=bad).status_code == 422, bad
    assert c.put("/api/v1/settings/scan-triggers", headers=auth(), json={"full_scan_default_minutes": 0}).json()[
        "schedules"]["full_scan_default_minutes"] == 0
    notes = [row["note"] for row in c.get("/api/v1/audit", headers=auth()).json()
             if row["action"] == "INSTALLATION_SETTING_CHANGED"]
    assert sorted(notes) == ["scan_triggers full_scan_default_minutes=0",
                             "scan_triggers full_scan_default_minutes=720 full_scan_start_minute=0"]


def test_a_viewer_reads_the_scan_cadence_and_only_an_admin_changes_it(issuer):
    from cremore.api.conftest import oidc_settings

    c = TestClient(create_app(repo=InMemoryRepository(), settings=oidc_settings(), oidc_http_client=issuer))
    viewer = {"Authorization": "Bearer " + issuer.mint(sub="viewer-1", groups=("g-viewers",))}
    assert c.get("/api/v1/settings/scan-triggers", headers=viewer).json()["schedules"]["full_scan_default_minutes"] == 1440
    for change in ({"full_scan_default_minutes": 0}, {"full_scan_start_minute": 0}, {"change_feed_minutes": {"notion": 30}}):
        assert c.put("/api/v1/settings/scan-triggers", headers=viewer, json=change).status_code == 403, change


def test_a_trigger_binds_to_an_approved_profile_without_a_redeploy():
    repo = InMemoryRepository()
    profile = _approved_scope_profile(repo)
    c = client(repo)
    c.put("/api/v1/settings/scan-triggers", headers=auth(), json={"schedules_enabled": True})
    body = c.put("/api/v1/settings/scan-triggers", headers=auth(),
                 json={"sqs_enabled": True, "sqs_profile_id": str(profile.id),
                       "sqs_queue_url": SQS_QUEUE, "sqs_dedicated_acknowledged": True}).json()
    assert body["sqs"]["enabled"] is True and body["sqs"]["queue_url"] == SQS_QUEUE
    assert body["sqs"]["profile_id"] == str(profile.id)
    # The earlier switch is untouched.
    assert body["schedules"]["enabled"] is True


def test_a_settings_change_reads_in_the_audit_trail_without_its_values():
    """Who switched verification off, bound a queue or set the StackSet's ExternalId is in the audit trail; the
    queue's address and the ExternalId themselves never are."""
    repo = InMemoryRepository()
    profile = _approved_scope_profile(repo)
    c = sso_route_client(repo)
    for path, body in (("credential-verification", {"enabled": False}),
                       ("scan-triggers", {"sqs_enabled": True, "sqs_profile_id": str(profile.id), "sqs_queue_url": SQS_QUEUE,
                                          "sqs_dedicated_acknowledged": True, "change_feed_minutes": {"github": 15}}),
                       ("learned-false-positives", {"threshold": 0.9, "max_confidence": "low"}),
                       ("aws-organizations", {"external_id": EXT, "ou_ids": [OU]})):
        assert c.put(f"/api/v1/settings/{path}", headers=auth(), json=body).status_code == 200, path
    rows = c.get("/api/v1/audit", headers=auth()).json()
    changed = [row for row in rows if row["action"] == "INSTALLATION_SETTING_CHANGED"]
    assert {row["target_type"] for row in changed} == {"installation_setting"}
    assert sorted(row["note"] for row in changed) == [
        "aws_identity_center permission_set=set",  # sso_route_client chooses it through the dashboard
        "aws_org_discovery external_id=set ou_ids=1",
        "credential_verification enabled=off",
        "learned_false_positives threshold=0.9 max_confidence=low",
        ("scan_triggers sqs_enabled=on sqs_profile_id=set sqs_queue_url=set sqs_dedicated_acknowledged=on "
         "change_feed_minutes=github:15")]
    assert not any(value in (row["note"] or "") for row in rows for value in (SQS_QUEUE, EXT, OU, str(profile.id)))


MANIFEST_POINTER = {"manifest_bucket": "existing-reports", "manifest_key": "reports/manifest.json"}


def test_an_inventory_binding_is_set_in_the_dashboard_not_in_a_json_env_var():
    """Which report belongs to which bucket is known by whoever runs the scans."""
    from cremore.domain.models import Connection

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="aws", name="S3", config={"bucket": "b"}))
    identity = f"{conn.id}/approved-bucket"
    c = client(repo)
    assert c.get("/api/v1/settings/inventory-manifests", headers=auth()).json() == {
        "bindings": {}, "locked": False, "updated_by": None, "updated_at": None}

    body = c.put("/api/v1/settings/inventory-manifests", headers=auth(),
                 json={"bindings": {identity: MANIFEST_POINTER}}).json()
    assert body["bindings"] == {identity: MANIFEST_POINTER}
    assert body["locked"] is False and body["updated_by"] == "local operator"


def test_an_inventory_binding_may_name_the_aws_account_a_bucket_is_reached_through():
    """An AWS integration reaches its buckets through the AWS account, whose id a scan's job carries."""
    from cremore.domain.models import AwsAccount

    repo = InMemoryRepository()
    account = repo.create_aws_account(AwsAccount(account_id="111111111111", name="Synthetic"))
    identity = f"{account.id}/approved-bucket"
    body = client(repo).put("/api/v1/settings/inventory-manifests", headers=auth(),
                            json={"bindings": {identity: MANIFEST_POINTER}}).json()
    assert body["bindings"] == {identity: MANIFEST_POINTER}


def test_an_inventory_binding_names_a_registered_connection_and_an_exact_report():
    repo = InMemoryRepository()
    c = client(repo)
    unknown = c.put("/api/v1/settings/inventory-manifests", headers=auth(),
                    json={"bindings": {f"{uuid.uuid4()}/bucket": MANIFEST_POINTER}})
    assert unknown.status_code == 409 and "MANIFEST_CONNECTION_UNKNOWN" in unknown.json()["error"]
    for bad in ({"bindings": {"x/y": MANIFEST_POINTER}},
                {"bindings": {f"{uuid.uuid4()}/b": {**MANIFEST_POINTER, "url": "https://untrusted.invalid"}}},
                {"bindings": []}, {}):
        assert c.put("/api/v1/settings/inventory-manifests", headers=auth(),
                     json=bad).status_code == 422, bad


def test_pinned_inventory_bindings_are_refused_rather_than_silently_overridden():
    import json

    identity = f"{uuid.uuid4()}/approved-bucket"
    locked = client(SCAN_INVENTORY_MANIFESTS=json.dumps({identity: MANIFEST_POINTER}))
    view = locked.get("/api/v1/settings/inventory-manifests", headers=auth()).json()
    assert view["locked"] is True and view["bindings"] == {identity: MANIFEST_POINTER}
    r = locked.put("/api/v1/settings/inventory-manifests", headers=auth(), json={"bindings": {}})
    assert r.status_code == 409 and "SCAN_INVENTORY_MANIFESTS" in r.json()["error"]


def test_a_trigger_binding_is_chosen_from_a_list_not_typed_as_a_uuid():
    """Otherwise binding a trigger means finding and copying a UUID out of a
    per-connection page, which is how an Admin binds the wrong scope."""
    repo = InMemoryRepository()
    profile = _approved_scope_profile(repo)
    c = client(repo)
    rows = c.get("/api/v1/settings/scan-triggers/bindable-profiles", headers=auth()).json()
    assert [row["id"] for row in rows] == [str(profile.id)]
    assert rows[0]["name"] == "approved" and rows[0]["schedule_minutes"] == 60
    # The connection is named, because a profile name alone does not say where.
    assert rows[0]["connection"] == "S3"
    # The list is exactly what a PUT accepts.
    body = c.put("/api/v1/settings/scan-triggers", headers=auth(),
                 json={"sqs_profile_id": rows[0]["id"]}).json()
    assert body["sqs"]["profile_id"] == str(profile.id)


def test_a_profile_no_trigger_may_bind_is_not_offered():
    from cremore.domain.models import Connection, ScopeProfile
    from cremore.scanning import scope

    repo = InMemoryRepository()
    target = repo.create_connection(Connection(provider="aws", name="S3", config={"bucket": "b"}))
    common = {"kind": "source", "connection_id": target.id, "state": "READY",
              "auth_revision": scope.auth_revision("source", target), "catalog_snapshot_id": "s"}
    # Never approved, and approved but not asking for events.
    repo.create_scope_profile(ScopeProfile(name="unapproved", event_mode="ENABLED", **common))
    repo.create_scope_profile(ScopeProfile(name="no-events", event_mode="DISABLED",
                                           approved_by="admin", approved_at=datetime.now(UTC), **common))
    c = client(repo)
    assert c.get("/api/v1/settings/scan-triggers/bindable-profiles", headers=auth()).json() == []


def test_a_trigger_cannot_be_bound_to_a_profile_nobody_approved():
    repo = InMemoryRepository()
    c = client(repo)
    r = c.put("/api/v1/settings/scan-triggers", headers=auth(),
              json={"sqs_profile_id": "8a1a2b3c-4d5e-4f60-8123-456789abcdef"})
    assert r.status_code == 409 and "TRIGGER_PROFILE_NOT_APPROVED" in r.json()["error"]


def test_trigger_settings_are_validated():
    c = client()
    for body in ({"schedules_enabled": "yes"}, {"sqs_queue_url": "https://untrusted.invalid/q"},
                 {"sqs_profile_id": "not-a-uuid"}, {"scan_everything": True}):
        assert c.put("/api/v1/settings/scan-triggers", headers=auth(), json=body).status_code == 422, body


def test_trigger_configuration_can_hard_lock_or_pin():
    locked = client(SCAN_SQS_MODE="disabled", SCAN_SQS_QUEUE_URL=SQS_QUEUE)
    view = locked.get("/api/v1/settings/scan-triggers", headers=auth()).json()
    assert view["sqs"]["installation_allows"] is False
    assert view["schedules"]["installation_allows"] is True
    assert view["sqs"]["queue_url"] == SQS_QUEUE and view["sqs"]["queue_url_locked"] is True
    r = locked.put("/api/v1/settings/scan-triggers", headers=auth(), json={"sqs_enabled": True})
    assert r.status_code == 409 and "SCAN_SQS_MODE" in r.json()["error"]
    # A pinned field is refused rather than accepted and silently overridden.
    r = locked.put("/api/v1/settings/scan-triggers", headers=auth(), json={"sqs_queue_url": SQS_QUEUE})
    assert r.status_code == 409 and "SCAN_SQS_QUEUE_URL" in r.json()["error"]


def test_a_pubsub_subscription_and_a_service_bus_queue_bind_like_sqs():
    repo = InMemoryRepository()
    profile = _approved_scope_profile(repo)
    c = client(repo)
    subscription = "projects/acme-scans/subscriptions/cremore-only"
    bus = "https://acme-events.servicebus.windows.net/cremore-only"
    body = c.put("/api/v1/settings/scan-triggers", headers=auth(), json={
        "pubsub_enabled": True, "pubsub_profile_id": str(profile.id), "pubsub_subscription": subscription,
        "pubsub_dedicated_acknowledged": True, "servicebus_enabled": True, "servicebus_profile_id": str(profile.id),
        "servicebus_queue": bus, "change_feeds_enabled": True, "change_feed_minutes": {"github": 15}}).json()
    assert body["pubsub"]["enabled"] is True and body["pubsub"]["subscription"] == subscription
    # Not yet acknowledged as the customer's own: read as off, and the view says why.
    assert body["servicebus"]["enabled"] is False and body["servicebus"]["blocked_by"] == "SERVICEBUS_NOT_ACKNOWLEDGED"
    assert body["change_feeds"]["enabled"] is True and body["change_feeds"]["minutes"]["github"] == 15
    for bad in ({"pubsub_subscription": "projects/acme-scans/topics/cremore"},
                {"servicebus_queue": "https://attacker.test/cremore-only"},
                {"change_feed_minutes": {"github": 0}}, {"change_feed_minutes": {"website": 5}}):
        assert c.put("/api/v1/settings/scan-triggers", headers=auth(), json=bad).status_code == 422, bad
    r = c.put("/api/v1/settings/scan-triggers", headers=auth(),
              json={"servicebus_profile_id": "8a1a2b3c-4d5e-4f60-8123-456789abcdef"})
    assert r.status_code == 409 and "TRIGGER_PROFILE_NOT_APPROVED" in r.json()["error"]


@pytest.mark.parametrize("mode, field", [("SCAN_PUBSUB_MODE", "pubsub_enabled"),
                                         ("SCAN_SERVICEBUS_MODE", "servicebus_enabled"),
                                         ("SCAN_CHANGE_FEEDS_MODE", "change_feeds_enabled")])
def test_each_new_trigger_can_be_hard_locked_by_the_installation(mode, field):
    locked = client(**{mode: "disabled"})
    r = locked.put("/api/v1/settings/scan-triggers", headers=auth(), json={field: True})
    assert r.status_code == 409 and mode in r.json()["error"]


def test_each_investigation_obeys_its_own_switch_not_a_neighbour_s():
    """Observed use being on is not permission to simulate what a key could
    reach: potential access is a separate AWS call with a separate switch."""
    import datetime as dt

    from cremore_aws_provider.investigation.usage import LastUsed

    class FakeUsage:
        def collect(self, key_id, principal_arn=""):
            return {"collection_status": "COMPLETE", "events": [], "coverage": [], "scenarios": []}

        def last_used(self, _key_id):
            return LastUsed(at=dt.datetime(2026, 9, 12, tzinfo=dt.UTC), service="s3", region="us-east-1")

    simulated = []

    class FakePotential:
        def collect(self, arn, identity_policies=None):
            from cremore_aws_provider.investigation.potential_access import PotentialAccess

            simulated.append(arn)
            return PotentialAccess(arn, "COMPLETE", actions=[])

    repo = InMemoryRepository()
    from cremore_aws_provider.investigation import investigation_switches

    switch_investigation_on(repo, investigation_switches.USAGE_LOOKUP)
    cred = _aws_key_credential(repo)
    c = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                              usage_service_factory=lambda session: FakeUsage(),
                              potential_access_factory=lambda session: FakePotential(),
                              aws_sessions=FakeSessions("123456789012")))
    body = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth()).json()
    assert body["collection_status"] == "COMPLETE"
    assert not simulated, "SimulatePrincipalPolicy ran with its own switch off"
    assert "potential_access" not in body or body["potential_access"].get("collection_status") != "COMPLETE"

    switch_investigation_on(repo, investigation_switches.POTENTIAL_ACCESS)
    body = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth()).json()
    assert simulated == [cred.principal_arn]
    assert body["potential_access"]["collection_status"] == "COMPLETE"


def test_read_only_investigations_are_switched_on_in_the_dashboard():
    """An analyst wants one of these during an investigation, which is exactly
    when filing a deployment change is useless."""
    c = client()
    view = c.get("/api/v1/settings/aws-investigations", headers=auth()).json()
    assert sorted(view) == ["potential_access", "secrets_inventory", "usage_lookup"]
    for one in view.values():
        # Nothing new calls AWS until somebody asks for it.
        assert one["enabled"] is False and one["switch"] is False and one["installation_allows"] is True

    body = c.put("/api/v1/settings/aws-investigations", headers=auth(),
                 json={"usage_lookup": True, "secrets_inventory": True}).json()
    assert body["usage_lookup"]["enabled"] is True and body["usage_lookup"]["updated_by"] == "local operator"
    assert body["secrets_inventory"]["enabled"] is True
    # Untouched keys keep their own state.
    assert body["potential_access"]["enabled"] is False

    off = c.put("/api/v1/settings/aws-investigations", headers=auth(), json={"usage_lookup": False}).json()
    assert off["usage_lookup"]["enabled"] is False and off["secrets_inventory"]["enabled"] is True


def test_an_investigation_configuration_can_hard_lock_one_off():
    locked = client(AWS_USAGE_LOOKUP_MODE="disabled")
    view = locked.get("/api/v1/settings/aws-investigations", headers=auth()).json()
    assert view["usage_lookup"]["installation_allows"] is False
    # The others are untouched by one lock.
    assert view["secrets_inventory"]["installation_allows"] is True
    r = locked.put("/api/v1/settings/aws-investigations", headers=auth(), json={"usage_lookup": True})
    assert r.status_code == 409 and "AWS_USAGE_LOOKUP_MODE" in r.json()["error"]


def test_investigation_switches_are_validated():
    c = client()
    for body in ({"usage_lookup": "yes"}, {"secrets_inventory": 1}, {"nonsense": True}):
        assert c.put("/api/v1/settings/aws-investigations", headers=auth(), json=body).status_code == 422, body


def test_switching_usage_lookup_off_again_stops_the_endpoint():
    """The switch is read per request, so turning it off takes effect at once."""
    from cremore_aws_provider.investigation.usage import LastUsed

    class Usage:
        def collect(self, key_id, principal_arn=""):
            return {"collection_status": "COMPLETE", "events": [], "coverage": [], "scenarios": []}

        def last_used(self, _key_id):
            return LastUsed(at=None, status="NOT_REQUESTED")

    repo = InMemoryRepository()
    switch_investigation_on(repo)
    cred = _aws_key_credential(repo)
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                     usage_service_factory=lambda session: Usage(),
                     aws_sessions=FakeSessions("123456789012"))
    c = TestClient(app)
    assert c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth()).status_code == 200
    c.put("/api/v1/settings/aws-investigations", headers=auth(), json={"usage_lookup": False})
    r = c.post(f"/api/v1/credentials/{cred.id}/usage/refresh", headers=auth())
    assert r.status_code == 501 and "USAGE_LOOKUP_OFF" in r.json()["error"]


def test_exposure_surface_gathers_one_identity_across_the_places_it_was_found():
    c = client()
    key = ("aws_access_key_id = A" "KIAZ5X9K2MBV7QP3LN6\n"
           "aws_secret_access_key = aB3dE5fG" "7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f")
    for source, resource in (("s3", "bucket-a"), ("github", "org/app")):
        c.post("/api/v1/scan", headers=auth(),
               json={"text": key, "source_type": source, "resource_name": resource,
                     "location": "conf.yml", "exposure": "public"})
    assert c.get("/api/v1/exposure-surface").status_code == 401
    body = c.get("/api/v1/exposure-surface", headers=auth()).json()
    # The same key found twice is one credential in two places, not two problems.
    assert body["totals"]["locations"] == 2 >= body["totals"]["credentials"]
    assert body["revision"] and sorted(body["unattributed"]) == ["credentials", "locations"]
    # Nothing verified this key, so no identity was established and nothing is grouped
    # under a name the product cannot support.
    assert body["principals"] == [] and body["bases"] == []
    assert body["unattributed"]["locations"] == 2


def test_secret_scanning_is_a_github_read_and_is_never_empty_before_it_runs():
    c = client()
    github = source(c, "github", "example-org/app", "App repo")["id"]
    s3 = source(c, "s3", "synthetic-bucket", "Bucket")["id"]

    # Nothing has been read, which the response says rather than reporting no alerts.
    before = c.get(f"/api/v1/source-connections/{github}/secret-scanning", headers=auth()).json()
    assert before["collection_status"] == "NOT_COLLECTED" and before["alerts"] == [] and before["limitations"]

    queued = c.post(f"/api/v1/source-connections/{github}/secret-scanning", headers=auth())
    assert queued.status_code == 202 and queued.json()["id"]
    # It is a provider read about the connection, not a content scan, and the job
    # list says which so it is never counted or drawn as scan coverage.
    listed = next(job for job in c.get("/api/v1/source-scan-jobs", headers=auth()).json()
                  if job["id"] == queued.json()["id"])
    assert listed["job_kind"] == "SECRET_SCANNING" and listed["result_status"] is None

    # Only GitHub has this API, and an unauthenticated caller gets nothing.
    for path in (f"/api/v1/source-connections/{s3}/secret-scanning",):
        assert c.get(path, headers=auth()).status_code == 422
        assert c.post(path, headers=auth()).status_code == 422
    assert c.post(f"/api/v1/source-connections/{github}/secret-scanning").status_code == 401
    assert c.get(f"/api/v1/source-connections/{uuid.uuid4()}/secret-scanning", headers=auth()).status_code == 404


def test_a_secret_scanning_summary_rides_the_connection_row_without_the_alerts():
    repo = InMemoryRepository()
    c = client(repo)
    conn_id = source(c, "github", "example-org/app", "App repo")["id"]
    stored = {"collection_status": "COMPLETE", "reason_code": "", "scope": "REPOSITORY",
              "target": "example-org/app", "truncated": False, "collected_at": "2026-09-21T00:00:00+00:00",
              "counts": {"alerts": 2, "open": 1, "publicly_leaked": 1},
              "alerts": [{"number": 1, "secret_type": "github_personal_access_token"}]}
    repo.update_connection(uuid.UUID(conn_id), secret_scanning=stored)

    row = next(row for row in c.get("/api/v1/source-connections", headers=auth()).json() if row["id"] == conn_id)
    # The row carries the counts; the alerts are read one connection at a time.
    assert row["secret_scanning"]["counts"]["publicly_leaked"] == 1
    assert "alerts" not in row["secret_scanning"]
    full = c.get(f"/api/v1/source-connections/{conn_id}/secret-scanning", headers=auth()).json()
    assert full["alerts"][0]["secret_type"] == "github_personal_access_token"


def test_search_reaches_the_managed_inventory_and_opens_one_exact_object():
    from cremore.api.dashboard import search_payload
    from cremore.api.metadata_coverage_test import GCP, PROJECT, observation

    repo = InMemoryRepository()
    store = _collected_entity(repo, observation("apiKey:billing-exporter", operation="gcp.api_keys"))
    body = search_payload(repo, "viewer", "billing", 10)
    managed = _group(body, "managed_object")
    assert managed["searched"] is True and managed["permitted"] is True and managed["total"] == 1
    hit = managed["items"][0]
    # The id is the object's own entity id, so the screen opens that object
    # rather than a filtered list the operator would have to search again.
    assert hit["kind"] == "managed_object" and hit["label"] == "apiKey:billing-exporter"
    assert hit["provider"] == "gcp" and hit["detail"] == "credential"
    assert store.entity_detail(uuid.UUID(hit["id"]))["entity"]["object_id"] == "apiKey:billing-exporter"
    # Tenancy the provider did not confirm is not shown as tenancy.
    assert hit["context"] == GCP["origin"]
    assert _group(search_payload(repo, "viewer", "nothing-like-this", 10), "managed_object")["total"] == 0
    assert PROJECT


def _collected_entity(repo, *items):
    """One finished schema 2 run holding these observations."""
    import uuid as _uuid

    from cremore.api.metadata_coverage_test import GCP, record
    from cremore.coverage.metadata_models import (
        MetadataBatch,
        MetadataConnectionSpec,
        MetadataFinish,
        metadata_contract,
    )
    from cremore.coverage.metadata_store import MetadataStore

    store = MetadataStore(repo)
    spec = MetadataConnectionSpec.model_validate(GCP)
    row, token = store.create(spec, "synthetic-admin")
    run = store.start(row["id"], row["revision"], str(_uuid.uuid4()),
                      metadata_contract(spec).model_dump(), token=token)
    store.append(row["id"], run["id"],
                 MetadataBatch.model_validate({"schema_version": 2, "index": 0,
                                               "items": [record(), *items]}), token=token)
    store.finish(row["id"], run["id"],
                 MetadataFinish(schema_version=2, batch_count=1, item_count=1 + len(items),
                                status="COMPLETE", reasons=[]), token=token)
    return store
