"""API tests using FastAPI's TestClient over the in-memory repository."""

from __future__ import annotations

import uuid

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import create_app

TOKEN = "test-token-" + "0" * 32
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


def client(repo=None, **overrides):
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, **overrides)
    return TestClient(create_app(repo=repo or InMemoryRepository(), settings=settings))


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def test_healthz_open():
    assert client().get("/healthz").json()["status"] == "ok"


def test_findings_requires_auth():
    assert client().get("/api/v1/findings").status_code == 401
    assert (
        client().get("/api/v1/findings", headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )


def test_scan_then_list_and_detail():
    c = client()
    r = c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": f"token = {GH}",
            "source_type": "github",
            "resource_name": "org/repo",
            "location": "app.py",
            "exposure": "public",
        },
    )
    assert r.status_code == 202
    assert r.json()["detections"] == 1

    listing = c.get("/api/v1/findings", headers=auth()).json()
    assert len(listing) == 1
    assert listing[0]["credential_type"] == "GITHUB_TOKEN"
    assert listing[0]["severity"] == "MEDIUM"
    assert "•" in listing[0]["identifier_hint"]

    fid = listing[0]["id"]
    detail = c.get(f"/api/v1/findings/{fid}", headers=auth()).json()
    assert detail["credential"]["credential_type"] == "GITHUB_TOKEN"
    # the dashboard's FindingDetail contract names
    assert (
        detail["credential"]["type"] == "GITHUB_TOKEN"
        and detail["credential"]["secret_stored"] is False
    )
    assert (
        detail["credential"]["observed_providers"] == ["github"] and detail["credential"]["status"]
    )
    assert detail["source_scope"]["type"] and detail["aws_account"] is None
    assert detail["exposures"][0]["provider"] == "github" and detail["exposures"][0]["scope_name"]
    assert "identifier" not in detail["credential"]  # raw identifier never served
    assert "fingerprint" not in detail["credential"]
    assert len(detail["exposures"]) == 1
    assert detail["exposures"][0]["location"] == "app.py"


def test_scan_enforces_utf8_input_byte_limit():
    c = client(MAX_INPUT_BYTES=4)
    assert c.post("/api/v1/scan", headers=auth(), json={"text": "éé"}).status_code == 202
    over = c.post("/api/v1/scan", headers=auth(), json={"text": "ééx"})
    assert over.status_code == 413
    assert "MAX_INPUT_BYTES" in over.json()["detail"]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/connections"),
        ("PATCH", "/api/v1/connections/00000000-0000-4000-8000-000000000000"),
        ("PUT", "/api/v1/rules/00000000-0000-4000-8000-000000000000"),
        ("DELETE", "/api/v1/rules/00000000-0000-4000-8000-000000000000"),
    ],
)
def test_all_mutating_api_bodies_have_a_raw_byte_limit(method, path):
    c = client(MAX_INPUT_BYTES=1)
    response = c.request(
        method,
        path,
        headers={**auth(), "Content-Type": "application/json"},
        content=b"x" * ((64 << 10) + 2),
    )
    assert response.status_code == 413


def test_findings_sorted_most_severe_first():
    c = client()
    c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": f"k = {GH}",
            "source_type": "github",
            "resource_name": "r",
            "location": "a",
            "exposure": "internal",
        },
    )
    c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": "aws_access_key_id = A"
            "KIAZ5X9K2MBV7QP3LN6\n"
            "aws_secret_access_key = aB3dE5fG"
            "7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f",
            "source_type": "s3",
            "resource_name": "bucket",
            "location": "creds",
            "exposure": "public",
        },
    )
    listing = c.get("/api/v1/findings", headers=auth()).json()
    ranks = [f["severity"] for f in listing]
    assert ranks == sorted(
        ranks, key={"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get, reverse=True
    )


def test_missing_finding_404():
    r = client().get(f"/api/v1/findings/{uuid.uuid4()}", headers=auth())
    assert r.status_code == 404


def test_generic_job_submission_is_closed_and_stored_payload_is_never_returned():
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    c = client(repo)
    blocked = c.post(
        "/api/v1/scan-jobs",
        headers=auth(),
        json={
            "kind": "credential-check",
            "payload": {"token": GH},
        },
    )
    assert blocked.status_code == 501
    assert repo.list_jobs() == []

    job = repo.enqueue_job(ScanJob(kind="inline", payload={"text": f"k={GH}"}))
    got = c.get(f"/api/v1/scan-jobs/{job.id}", headers=auth()).json()
    assert got["kind"] == "inline"
    assert got["status"] == "QUEUED"
    assert "payload" not in got and GH not in str(got)


def _seed_two(c):
    c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": f"k = {GH}",
            "source_type": "github",
            "resource_name": "r",
            "location": "a",
            "exposure": "internal",
        },
    )  # LOW github
    c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": "aws_access_key_id = A"
            "KIAZ5X9K2MBV7QP3LN6\n"
            "aws_secret_access_key = aB3dE5fG"
            "7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f",
            "source_type": "s3",
            "resource_name": "bucket",
            "location": "creds",
            "exposure": "public",
        },
    )  # AWS


def test_findings_filter_by_provider_and_severity():
    c = client()
    _seed_two(c)
    gh_only = c.get("/api/v1/findings", headers=auth(), params={"provider": "github"}).json()
    assert len(gh_only) == 1 and gh_only[0]["provider"] == "github"

    low_only = c.get("/api/v1/findings", headers=auth(), params={"severity": "low"}).json()
    assert all(f["severity"] == "LOW" for f in low_only)

    open_only = c.get("/api/v1/findings", headers=auth(), params={"workflow_status": "open"}).json()
    assert len(open_only) == 2  # nothing resolved yet


def test_findings_use_bounded_pages_even_when_filters_hide_every_row():
    repo = InMemoryRepository()
    c = client(repo)
    _seed_two(c)
    first = c.get("/api/v1/findings", headers=auth(), params={"limit": 1, "provider": "absent"})
    assert first.status_code == 200 and first.json() == []
    assert first.headers["x-page-limit"] == "1"
    cursor = first.headers["x-next-cursor"]
    second = c.get("/api/v1/findings", headers=auth(), params={"limit": 1, "cursor": cursor})
    assert len(second.json()) == 1 and second.json()[0]["id"] != cursor
    assert "x-next-cursor" not in second.headers
    assert c.get("/api/v1/findings", headers=auth(), params={"limit": 501}).status_code == 422
    assert c.get("/api/v1/findings", headers=auth(), params={"cursor": "invalid"}).status_code == 422


def test_findings_refuse_oversized_related_rows_and_response(monkeypatch):
    repo = InMemoryRepository()
    c = client(repo)
    _seed_two(c)
    original = repo.findings_with_exposures

    # Keep the input small; the repeated fake rows only exercise the output boundary.
    def too_many(ids, *, exposure_limit):
        assert exposure_limit == 10_001
        finding, credential, exposures = original(ids[:1])[0]
        return [(finding, credential, exposures * 10_001)]

    monkeypatch.setattr(repo, "findings_with_exposures", too_many)
    assert c.get("/api/v1/findings", headers=auth()).status_code == 413
    monkeypatch.setattr(repo, "findings_with_exposures", original)
    import cremore.api.finding_presenters as presenters
    project = presenters.present_finding

    def oversized(*args, **kwargs):
        return {**project(*args, **kwargs), "synthetic": "x" * (8 * 1024 * 1024)}

    monkeypatch.setattr(presenters, "present_finding", oversized)
    assert c.get("/api/v1/findings", headers=auth()).status_code == 413


def test_stats_summary():
    c = client()
    _seed_two(c)
    stats = c.get("/api/v1/stats", headers=auth()).json()
    assert stats["total"] == 2
    assert stats["open"] == 2
    assert sum(stats["by_severity"].values()) == 2
    assert stats["by_provider"].get("github") == 1
    assert stats["by_provider"].get("aws") == 1


def test_list_scan_jobs():
    from cremore.domain.models import ScanJob

    repo = InMemoryRepository()
    c = client(repo)
    # One content scan plus checks: only one content scan can be queued at a time.
    repo.enqueue_job(ScanJob(kind="inline", payload={"text": f"k={GH}"}))
    for _ in range(2):
        repo.enqueue_job(ScanJob(kind="credential-check", payload={"provider": "github"}))
    jobs = c.get("/api/v1/scan-jobs", headers=auth()).json()
    assert len(jobs) == 3
    assert all(j["status"] == "QUEUED" for j in jobs)
    assert all("payload" not in j for j in jobs)


def test_connection_crud_and_scan():
    from cremore.onboarding.fixtures_test import content_source

    c = client()
    # a source as a provider connection's step 4 leaves it
    cid = str(content_source(c.app.state.repo, "github", {"owner": "acme", "repo": "app"}, name="acme",
                             secret_ref="vault://github/acme").id)
    conn = c.get(f"/api/v1/connections/{cid}", headers=auth()).json()
    assert conn["status"] == "PENDING" and conn["provider"] == "github"
    # sources are created by a provider connection only
    assert c.post("/api/v1/connections", headers=auth(),
                  json={"provider": "github", "name": "x", "config": {}}).status_code in (404, 405, 501)

    # list + get
    page = c.get("/api/v1/connections", headers=auth()).json()
    assert len(page["connections"]) == 1 and page["connections"][0]["name"] == "acme"
    assert c.get(f"/api/v1/connections/{cid}", headers=auth()).json()["name"] == "acme"

    # activate
    patched = c.patch(
        f"/api/v1/connections/{cid}", headers=auth(), json={"status": "ACTIVE"}
    ).json()
    assert patched["status"] == "ACTIVE"

    # launch a scan -> enqueues a github job bound to the connection
    scan = c.post(f"/api/v1/connections/{cid}/scan", headers=auth())
    assert scan.status_code == 202
    job = c.get(f"/api/v1/scan-jobs/{scan.json()['id']}", headers=auth()).json()
    assert job["kind"] == "github"
    assert job["connection_id"] == cid
    assert "payload" not in job
    stored = c.app.state.repo.get_job(uuid.UUID(scan.json()["id"]))
    assert stored.payload["owner"] == "acme"
    assert stored.payload["secret_ref"] == "vault://github/acme"


def test_connection_token_is_sealed_at_rest_never_served_and_reaches_the_worker():
    from cremore.onboarding.fixtures_test import wizard
    from cremore.secretstore.resolver import SecretResolver, inject_secret

    c = client()
    view = wizard(c, auth(), {"provider": "github", "purposes": ["exposure"], "auth_method": "token",
                              "target": {"organization": "acme"}, "credential": {"token": GH}},
                  plans={"exposure": {}})
    assert GH not in str(view)
    cid = view["created"][0]["id"]
    r = c.get(f"/api/v1/connections/{cid}", headers=auth())
    # The served marker carries the version, so a reader is not told v1 about a
    # v2 credential; the ciphertext itself is never served.
    assert r.json()["secret_ref"] == "sealed:v2" and GH not in r.text
    sealed = c.app.state.repo.get_connection(uuid.UUID(cid)).secret_ref
    assert sealed.startswith("sealed:v2:") and GH not in sealed
    for path in (f"/api/v1/connections/{cid}", "/api/v1/connections", "/api/v1/source-connections"):
        page = c.get(path, headers=auth())
        assert page.status_code == 200 and sealed not in page.text and GH not in page.text

    job_id = c.post(f"/api/v1/connections/{cid}/scan", headers=auth()).json()["id"]
    payload = c.app.state.repo.get_job(uuid.UUID(job_id)).payload
    resolver = SecretResolver(sealing_key=bytes.fromhex("ab" * 32))
    assert inject_secret("github", payload, resolver)["token"] == GH

    # The token is replaced on the provider connection; the source can never be handed one.
    for bad in ({"token": "replacement-token"}, {"secret_ref": sealed}, {"secret_ref": "vault://gh/acme"}):
        refused = c.patch(f"/api/v1/connections/{cid}", headers=auth(), json=bad)
        assert refused.status_code == 409 and refused.json()["error"].startswith(
            "CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION"), refused.text
    assert c.app.state.repo.get_connection(uuid.UUID(cid)).secret_ref == sealed
    replacement = "ghp_" + "R" * 36
    replaced = c.put(f"/api/v1/provider-connections/{view['id']}/credential", headers=auth(),
                     json={"credential": {"token": replacement}})
    assert replaced.status_code == 200 and replacement not in replaced.text
    assert c.app.state.repo.get_connection(uuid.UUID(cid)).secret_ref not in (sealed, None)


def test_dashboard_registration_seals_credential_token():
    """The wizard seals the token on arrival; the source it creates shows only that it is CreMore's own."""
    from cremore.onboarding.fixtures_test import wizard

    c = client()
    view = wizard(c, auth(), {"provider": "notion", "purposes": ["exposure"], "auth_method": "integration",
                              "credential": {"token": "synthetic-notion-integration-token"}},
                  plans={"exposure": {}})
    assert "synthetic-notion" not in str(view)
    [source] = [row for row in c.get("/api/v1/source-connections", headers=auth()).json()
                if row["id"] == view["created"][0]["id"]]
    assert source["credential_source"] == "CREMORE_ENCRYPTED"


def test_connection_rejects_secret_in_config():
    from cremore.onboarding.fixtures_test import content_source

    c = client()
    cid = content_source(c.app.state.repo, "github", {"owner": "o", "repo": "r"}, name="x").id
    r = c.patch(f"/api/v1/connections/{cid}", headers=auth(),
                json={"config": {"owner": "o", "repo": "r", "token": "ghp_should_not_be_here"}})
    assert r.status_code == 422
    assert "secret" in r.json()["detail"].lower()
    assert "token" not in c.app.state.repo.get_connection(cid).config


def test_connection_duplicate_conflict():
    """Source names stay unique: a second connection to a scanned source gets a numbered one of its own."""
    from cremore.onboarding.fixtures_test import wizard

    c = client()
    body = {"provider": "github", "purposes": ["exposure"], "auth_method": "token",
            "target": {"organization": "acme"}, "credential": {"token": GH}}
    wizard(c, auth(), body, plans={"exposure": {}})
    second = wizard(c, auth(), body, plans={"exposure": {}})
    assert second["created"][0]["name"] == "GitHub · acme (2)"
    names = sorted(row["display_name"] for row in c.get("/api/v1/source-connections", headers=auth()).json())
    assert names == ["GitHub · acme", "GitHub · acme (2)"]


def test_disabled_connection_cannot_scan():
    from cremore.onboarding.fixtures_test import content_source

    c = client()
    cid = content_source(c.app.state.repo, "notion", {}, name="ws").id
    c.patch(f"/api/v1/connections/{cid}", headers=auth(), json={"status": "DISABLED"})
    assert c.post(f"/api/v1/connections/{cid}/scan", headers=auth()).status_code == 409


def test_secrets_inventory_not_configured_returns_501():
    assert client().get("/api/v1/aws/secrets-inventory", headers=auth()).status_code == 501


def test_secrets_inventory_served_when_provider_wired():
    from cremore_aws_provider.investigation import SecretRecord, SecretsManagerInventory

    def provider(session):
        assert session.account_id == "111111111111"
        return SecretsManagerInventory(
            region="us-east-1",
            secrets=[
                SecretRecord(arn="arn:db", name="db", rotation_enabled=True),
                SecretRecord(arn="arn:legacy", name="legacy", rotation_enabled=False),
            ],
        )

    from cremore.api.dashboard_test import FakeSessions, switch_investigation_on
    from cremore.domain.models import AwsAccount

    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)
    repo = InMemoryRepository()
    c = TestClient(create_app(repo=repo, settings=settings, secrets_inventory_factory=provider,
                              aws_sessions=FakeSessions("111111111111")))
    # Wiring the factory is the installation allowing it; an Admin still switches
    # it on, and this route must honour that switch like every other path.
    off = c.get("/api/v1/aws/secrets-inventory", headers=auth())
    assert off.status_code == 501 and "SECRETS_INVENTORY_OFF" in off.json()["error"]
    switch_investigation_on(repo)
    # inventory is per account: without one named, only an explicit RUNTIME_IDENTITY account is used
    r = c.get("/api/v1/aws/secrets-inventory", headers=auth())
    assert r.status_code == 409 and "ACCOUNT_NOT_CONNECTED" in r.json()["error"]
    repo.create_aws_account(AwsAccount(account_id="111111111111", name="self", access="RUNTIME_IDENTITY"))
    body = c.get("/api/v1/aws/secrets-inventory", headers=auth()).json()
    assert body["account_id"] == "111111111111" and body["collected_via"] == "ROLE"
    assert body["total"] == 2
    assert body["without_rotation"] == 1
    assert body["region"] == "us-east-1"
    # no secret value field anywhere in the payload
    assert "SecretString" not in c.get("/api/v1/aws/secrets-inventory", headers=auth()).text


def test_acknowledge_and_resolve_finding():
    c = client()
    c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": f"token = {GH}",
            "source_type": "github",
            "resource_name": "r",
            "location": "a",
            "exposure": "public",
        },
    )
    fid = c.get("/api/v1/findings", headers=auth()).json()[0]["id"]

    ack = c.post(f"/api/v1/findings/{fid}/acknowledge", headers=auth())
    assert ack.json()["workflow_status"] == "ACKNOWLEDGED"

    res = c.post(f"/api/v1/findings/{fid}/resolve", headers=auth(), json={"resolution": "rotated"})
    assert res.json()["workflow_status"] == "RESOLVED"
    assert res.json()["resolution"] == "rotated"

    detail = c.get(f"/api/v1/findings/{fid}", headers=auth()).json()
    assert detail["workflow_status"] == "RESOLVED"


def _one_finding(c):
    c.post(
        "/api/v1/scan",
        headers=auth(),
        json={
            "text": f"token = {GH}",
            "source_type": "github",
            "resource_name": "r",
            "location": "a",
            "exposure": "public",
        },
    )
    return c.get("/api/v1/findings", headers=auth()).json()[0]["id"]


def test_assign_and_unassign_finding():
    c = client()
    fid = _one_finding(c)
    r = c.post(f"/api/v1/findings/{fid}/assign", headers=auth(), json={"assignee": "analyst-7"})
    assert r.json()["assigned_to"] == "analyst-7"
    assert c.get("/api/v1/findings", headers=auth()).json()[0]["assigned_to"] == "analyst-7"
    # unassign
    r2 = c.post(f"/api/v1/findings/{fid}/assign", headers=auth(), json={"assignee": None})
    assert r2.json()["assigned_to"] is None


def test_reopen_clears_resolution():
    c = client()
    fid = _one_finding(c)
    c.post(f"/api/v1/findings/{fid}/resolve", headers=auth(), json={"resolution": "rotated"})
    reopened = c.post(f"/api/v1/findings/{fid}/reopen", headers=auth(), json={})
    assert reopened.json()["workflow_status"] == "OPEN"
    detail = c.get(f"/api/v1/findings/{fid}", headers=auth()).json()
    assert detail["workflow_status"] == "OPEN"


@pytest.mark.parametrize("action,field", [("resolve", "resolution"), ("reopen", "resolution"),
    ("ignore", "reason_code"), ("false-positive", "reason_code"), ("assign", "assignee"),
    ("bulk", "reason_code")])
@pytest.mark.parametrize("note", [GH, "xoxe-" + "a" * 30, "x" * 501])
def test_triage_rejects_credentials_before_state_audit_or_learning(action, field, note, monkeypatch):
    from cremore.scanning.learned_fp import LearnedFPService

    repo = InMemoryRepository()
    c = client(repo)
    fid = _one_finding(c)
    before = repo.get_finding(uuid.UUID(fid)).model_dump()
    events = [e.model_dump() for e in repo.list_finding_events(uuid.UUID(fid))]

    def unexpected(*args, **kwargs):
        pytest.fail("invalid triage note reached learning")

    monkeypatch.setattr(LearnedFPService, "record_contradiction", unexpected)
    monkeypatch.setattr(LearnedFPService, "record_false_positive", unexpected)
    url = f"/api/v1/findings/{fid}/{action}"
    body = {field: note}
    if action == "bulk":
        url = "/api/v1/findings/false-positive"
        body["finding_ids"] = [fid]
    response = c.post(url, headers=auth(), json=body)
    assert response.status_code == 422
    if len(note) <= 500:
        assert note not in response.text
    assert repo.get_finding(uuid.UUID(fid)).model_dump() == before
    assert [e.model_dump() for e in repo.list_finding_events(uuid.UUID(fid))] == events


def test_audit_trail_records_transitions():
    c = client()
    fid = _one_finding(c)
    c.post(f"/api/v1/findings/{fid}/acknowledge", headers=auth())
    c.post(f"/api/v1/findings/{fid}/assign", headers=auth(), json={"assignee": "analyst-7"})
    c.post(f"/api/v1/findings/{fid}/resolve", headers=auth(), json={"resolution": "rotated"})

    events = c.get(f"/api/v1/findings/{fid}/events", headers=auth()).json()
    types_in_order = [e["event_type"] for e in events]
    assert types_in_order == ["ROLLUP_UPDATED", "ACKNOWLEDGED", "ASSIGNED", "RESOLVED"]
    ack = events[1]
    assert ack["from_status"] == "OPEN" and ack["to_status"] == "ACKNOWLEDGED"
    assert ack["actor"]  # the operator subject was recorded
    assert events[3]["note"] == "rotated"


def test_bulk_false_positive_records_each_judgement_and_reports_unknown_ids():
    import uuid as _uuid

    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import Credential, Exposure

    repo = InMemoryRepository()
    ids = []
    for n in range(3):
        cred = repo.upsert_credential(Credential(fingerprint=f"fp{n}", credential_type="GENERIC_SECRET"))
        exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github",
                                                 resource_name="repo", location=f"f{n}.py", severity="LOW"))
        ids.append(str(repo.upsert_finding(cred.id, exposure.id, "LOW").id))
    stale = str(_uuid.uuid4())

    c = client(repo)
    body = c.post("/api/v1/findings/false-positive", headers=auth(),
                  json={"finding_ids": ids + [stale], "reason_code": "CODE_REFERENCE"}).json()
    assert body["confirmed_count"] == 3 and body["missing"] == [stale]

    # Each finding is transitioned and audited on its own, exactly as the
    # single-finding route does; a bulk action saves clicks, not the record.
    for finding_id in ids:
        finding = repo.get_finding(_uuid.UUID(finding_id))
        assert finding.workflow_status == "FALSE_POSITIVE"
    events = [e for e in repo.list_events(200) if e.event_type == "FALSE_POSITIVE"]
    assert len(events) == 3 and {e.note for e in events} == {"CODE_REFERENCE"}


def test_bulk_false_positive_refuses_an_empty_or_oversized_batch():
    import uuid as _uuid

    c = client()
    assert c.post("/api/v1/findings/false-positive", headers=auth(), json={"finding_ids": []}).status_code == 422
    many = [str(_uuid.uuid4()) for _ in range(201)]
    assert c.post("/api/v1/findings/false-positive", headers=auth(), json={"finding_ids": many}).status_code == 422


def test_openapi_component_names_are_unique_and_collector_schemas_keep_their_names():
    # FastAPI falls back to module-qualified names ("pkg__module__Model") when two request models share a
    # class name; the gcp-dashboard-oauth merge briefly renamed the collector's Start/Finish schemas that way.
    schemas = client().app.openapi()["components"]["schemas"]
    assert not [name for name in schemas if "__" in name]
    assert {"GcpOAuthStart", "GcpOAuthFinish", "GcpOAuthSession", "GcpOAuthProjects"} <= set(schemas)
    assert set(schemas["Start"]["properties"]) == {"contract", "request_id", "revision"}
    # completeness is additive: only an external vault's collector sends it.
    assert set(schemas["Finish"]["properties"]) == {"batch_count", "item_count", "reasons", "status", "completeness"}
