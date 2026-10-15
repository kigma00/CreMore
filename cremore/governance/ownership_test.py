"""A finding's context from synthetic GitHub and GitLab hosts (cremore.governance.ownership)."""

import datetime as dt
import os
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable PostgreSQL
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Connection, Credential, Exposure, ScopeCatalog, ScopeProfile
from cremore.governance import ownership
from cremore.scanning import scope
from cremore.secretstore.resolver import SecretResolver
from cremore.secretstore.sealed import seal_token

SETTINGS = Settings(AUTH_MODE="local", API_TOKEN="t" * 40, FINGERPRINT_KEY="ab" * 32)
COMMIT = "a" * 40
# Built at run time: a literal would read as a token to secret scanners.
GITHUB_TOKEN = "gh" + "p_" + "x" * 36
GITLAB_TOKEN = "gl" + "pat-" + "y" * 20


def approve(repo, connection, source, resource):
    from cremore.sources.registry import RESOURCE_SOURCE

    resource_type = next(kind for kind, value in RESOURCE_SOURCE.items() if value == source)
    item = scope.resource("source", connection.id, resource_type, resource, resource, resource, source)
    auth = scope.auth_revision("source", connection)
    repo.save_catalog(ScopeCatalog(kind="source", connection_id=connection.id, snapshot_id="approved",
                                  auth_revision=auth, items=[item], completeness="COMPLETE"))
    return repo.create_scope_profile(ScopeProfile(kind="source", connection_id=connection.id,
        name="Approved fixture", state="READY", selected_roots=[{"resource_id": item["id"], "paths": []}],
        auth_revision=auth, catalog_snapshot_id="approved", approved_by="admin", approved_at=dt.datetime.now(dt.UTC)))


def hosts(seen, *, github_members=200):
    def handler(request):
        seen.append(request)
        path, params = request.url.path, request.url.params
        if request.url.host == "api.github.com":
            assert request.headers["authorization"] == "Bearer " + GITHUB_TOKEN
            if path == "/repos/acme/app":
                return httpx.Response(200, json={"visibility": "private"})
            if path == "/repos/acme/app/contents/.github/CODEOWNERS":
                return httpx.Response(404)
            if path == "/repos/acme/app/contents/CODEOWNERS":
                assert params["ref"] == COMMIT
                return httpx.Response(200, content=b"* @acme/platform\n/deploy/ @kim-demo lee@example.com # ops\n")
            if path == "/repos/acme/app/commits":
                assert params["path"] == "deploy/app.env" and params["sha"] == COMMIT
                return httpx.Response(200, json=[{"sha": "b" * 40, "author": {"login": "lee-demo"}, "commit": {
                    "author": {"name": "Lee Demo", "email": "lee@example.com", "date": "2026-09-27T01:00:00Z"}}}])
            if path == "/repos/acme/app/collaborators":
                return httpx.Response(github_members, json=[{"login": "kim-demo", "role_name": "admin"},
                                                            {"login": "lee-demo", "role_name": "write"}])
        if request.url.host == "gitlab.example.com":
            assert request.headers["authorization"] == "Bearer " + GITLAB_TOKEN
            if path == "/api/v4/projects/42":
                return httpx.Response(200, json={"visibility": "internal", "repository_access_level": "enabled"})
            if path.endswith(("/repository/files/.gitlab%2FCODEOWNERS/raw", "/repository/files/.gitlab/CODEOWNERS/raw")):
                return httpx.Response(200, content=b"[Config] @data-team\nconfig/\n")
            if "/repository/files/" in path:
                return httpx.Response(404)
            if path == "/api/v4/projects/42/repository/commits":
                return httpx.Response(200, json=[{"id": "c" * 40, "author_name": "Han Demo", "author_email": "han@example.com",
                                                  "authored_date": "2026-09-26T00:00:00Z"}])
            if path == "/api/v4/projects/42/members/all":
                return httpx.Response(200, json=[{"username": "han", "name": "Han Demo", "access_level": 40, "state": "active"},
                                                 {"username": "old", "name": "Old", "access_level": 30, "state": "blocked"},
                                                 {"username": "min", "name": "Min", "access_level": 5, "state": "active"}])
        return httpx.Response(404)
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def seed(repo):
    github = repo.create_connection(Connection(provider="github", name="GitHub acme", config={"org": "acme"},
                                               secret_ref=seal_token(SETTINGS.sealing_keys, GITHUB_TOKEN)))
    gitlab = repo.create_connection(Connection(provider="gitlab", name="GitLab data", config={
        "base_url": "https://gitlab.example.com", "project": "42"}, secret_ref=seal_token(SETTINGS.sealing_keys, GITLAB_TOKEN)))
    approve(repo, github, "github", "acme/app")
    approve(repo, gitlab, "gitlab", "42")
    cred = repo.upsert_credential(Credential(fingerprint="f" * 64, credential_type="GITHUB_PAT", provider="github"))
    first = repo.upsert_exposure(Exposure(credential_id=cred.id, source_connection_id=github.id, source_type="github",
                                          resource_name="acme/app", location="deploy/app.env", line_number=3,
                                          metadata={"exposure": "private", "commit_sha": COMMIT}))
    repo.upsert_exposure(Exposure(credential_id=cred.id, source_connection_id=gitlab.id, source_type="gitlab",
                                  resource_name="42", location="config/prod.env", object_version=COMMIT,
                                  metadata={"exposure": "internal"}))
    return repo.upsert_finding(cred.id, first.id, "HIGH")


def collect(repo, finding, seen, **kwargs):
    return ownership.collect(repo, finding.id, secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
                             http_client_factory=hosts(seen, **kwargs))


def test_codeowners_authors_and_members_come_from_each_host():
    repo, seen = InMemoryRepository(), []
    finding = seed(repo)
    row = collect(repo, finding, seen)
    assert row["status"] == "COMPLETE"
    github, gitlab = row["body"]["locations"]
    assert github["codeowners"]["path"] == "CODEOWNERS"
    assert [owner["owner"] for owner in github["codeowners"]["owners"]] == ["@kim-demo", "lee@example.com"]
    assert github["author"] == {"status": "OBSERVED", "name": "Lee Demo", "login": "lee-demo", "email": "lee@example.com",
                                "at": "2026-09-27T01:00:00Z", "commit": "b" * 40}
    assert gitlab["codeowners"]["path"] == ".gitlab/CODEOWNERS"
    assert [owner["owner"] for owner in gitlab["codeowners"]["owners"]] == ["@data-team"]
    assert gitlab["author"]["email"] == "han@example.com"
    members = {item["source_type"]: item for item in row["body"]["repositories"]}
    assert [(p["login"], p["role"]) for p in members["github"]["people"]] == [("kim-demo", "admin"), ("lee-demo", "write")]
    assert [(p["login"], p["name"], p["role"]) for p in members["gitlab"]["people"]] == [("han", "Han Demo", "maintainer")]
    # The CODEOWNERS file itself is never kept.
    assert "@acme/platform" not in str(row["body"])
    review = ownership.review_context(row)
    assert (review["status"], review["repository"], review["codeowners_path"], review["file_match"]) == (
        "OBSERVED", "acme/app", "CODEOWNERS", True)
    assert [(item["owner"], item["kind"]) for item in review["candidates"]] == [("@kim-demo", "USER"), ("lee@example.com", "USER")]


def test_a_refused_member_list_is_partial_and_nothing_is_written_to_the_host():
    repo, seen = InMemoryRepository(), []
    finding = seed(repo)
    row = collect(repo, finding, seen, github_members=403)
    assert row["status"] == "PARTIAL" and row["body"]["reasons"] == ["CONTEXT_FORBIDDEN"]
    github = next(item for item in row["body"]["repositories"] if item["source_type"] == "github")
    assert github["status"] == "FORBIDDEN" and "people" not in github
    assert {request.method for request in seen} == {"GET"}


def test_what_a_credential_row_shows_and_the_routes():
    repo, seen = InMemoryRepository(), []
    finding = seed(repo)
    collect(repo, finding, seen)
    c = TestClient(create_app(repo=repo, settings=SETTINGS))
    headers = {"Authorization": "Bearer " + "t" * 40}
    [record] = [row for row in c.get("/api/v1/credential-records", headers=headers).json()["items"]
                if row.get("finding_id") == str(finding.id)]
    assert record["owner"] == {"name": "@kim-demo", "team": None, "basis": "CODEOWNERS", "where": "acme/app · CODEOWNERS"}
    assert record["access"]["count"] == 2 and record["access"]["basis"] == "GITHUB_REPOSITORY_COLLABORATORS"
    authors = {(item["resource_name"], item["location"]): item["author"] for item in record["exposures"]}
    assert authors[("acme/app", "deploy/app.env")] == "Lee Demo"
    assert "lee@example.com" not in str(record["exposures"])  # names only on a row everyone reads
    review = c.get(f"/api/v1/findings/{finding.id}/ownership-review", headers=headers).json()
    assert review["context"]["status"] == "OBSERVED"
    full = c.get(f"/api/v1/findings/{finding.id}/context", headers=headers).json()
    assert full["status"] == "COMPLETE" and full["locations"][0]["author"]["email"] == "lee@example.com"
    queued = c.post(f"/api/v1/findings/{finding.id}/context", headers=headers)
    assert queued.status_code == 202 and queued.json()["job_status"] == "QUEUED"
    again = c.post(f"/api/v1/findings/{finding.id}/context", headers=headers).json()
    assert again["job_id"] == queued.json()["job_id"]  # one read per finding at a time


def test_the_row_owner_is_a_person_first_then_a_team_with_the_file_that_names_it():
    def row(*owners):
        return {"collected_at": "2026-09-28T00:00:00+00:00", "body": {"repositories": [], "locations": [
            {"repository": f"acme/r{index}", "path": "a.env", "codeowners": {"path": "CODEOWNERS", "owners": listed}}
            for index, listed in enumerate(owners)]}}

    team = {"owner": "@acme/platform", "kind": "team", "line": 1}
    person = {"owner": "@kim-demo", "kind": "account", "line": 2}
    assert ownership.summary(row([team], [person]))["owner"] == {"name": "@kim-demo", "team": None, "where": "acme/r1 · CODEOWNERS"}
    assert ownership.summary(row([team]))["owner"] == {"name": None, "team": "@acme/platform", "where": "acme/r0 · CODEOWNERS"}
    assert ownership.summary(row([{"owner": "@@maintainer", "kind": "role", "line": 1}]))["owner"] is None


def test_the_sweep_queues_open_findings_without_a_context_once_a_slot():
    repo = InMemoryRepository()
    finding = seed(repo)
    now = dt.datetime(2026, 9, 28, tzinfo=dt.UTC)
    assert ownership.sweep(repo, now=now) == 1
    assert ownership.sweep(repo, now=now) == 0  # the slot is taken
    assert ownership._active(repo, finding.id).kind == ownership.JOB_KIND
    later = now + dt.timedelta(seconds=ownership.SWEEP_SECONDS)
    assert ownership.sweep(repo, now=later) == 1  # still none kept: queued again (the waiting job is reused)
    assert len([job for job in repo.list_jobs(100) if job.kind == ownership.JOB_KIND]) == 1


def test_the_worker_runs_the_job_under_its_lease():
    from cremore.detection.engine import Engine, EngineConfig
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.worker import JobWorker

    repo, seen = InMemoryRepository(), []
    finding = seed(repo)
    job = ownership.enqueue(repo, finding.id)
    engine = Engine(EngineConfig(fingerprint_key=bytes.fromhex("ab" * 32)))
    worker = JobWorker(repo, orchestrator=Orchestrator(repo, engine=engine, config=engine.config),
                       http_client_factory=hosts(seen), metadata_secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys))
    assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"
    assert ownership.ContextStore(repo).get(finding.id)["status"] == "COMPLETE"


@pytest.mark.parametrize("changed", ["none", "scope", "auth_changed", "denied", "credential", "cancel", "budget", "elapsed"])
@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_worker_continues_member_pages_after_restart_and_rechecks_scope(sql_repo, monkeypatch, changed, provider):
    from cremore.db import task_store
    from cremore.worker import JobWorker

    repo = sql_repo
    connection, _, _, _, finding = single_source(repo, provider=provider,
        config={"base_url": "https://gitlab.example.com", "project": "42"} if provider == "gitlab" else None,
        resource="42" if provider == "gitlab" else "acme/app")
    basis = "GITLAB_PROJECT_MEMBERS" if provider == "gitlab" else "GITHUB_REPOSITORY_COLLABORATORS"
    clock = [dt.datetime.now(dt.UTC)]
    monkeypatch.setattr(task_store, "_clock", lambda *_: clock[0])
    calls = []
    deny = [False]
    fallback = hosts([])()

    def handler(request):
        if request.url.path.endswith(("/collaborators", "/members/all")):
            page = int(request.url.params["page"])
            calls.append(page)
            if deny[0]:
                return httpx.Response(403)
            if changed == "cancel" and page == 4:
                repo.request_job_cancel(job.id)
            end = min(page * 100, 735)
            return httpx.Response(200, json=[({"login": f"user{i}", "role_name": "read", "type": "User"} if provider == "github"
                                             else {"username": f"user{i}", "access_level": 30, "state": "active"})
                                            for i in range((page - 1) * 100, end)])
        return fallback.send(request)

    def worker():
        resolver = SecretResolver(sealing_key=SETTINGS.sealing_keys)
        if changed == "credential" and calls:
            resolver = SecretResolver(sealing_key={})
        current = JobWorker(repo, settings=SETTINGS,
            http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
            metadata_secret_resolver=resolver)
        current.poll_triggers = lambda: None
        return current

    job = ownership.enqueue(repo, finding.id)
    assert worker().process_next()
    first = ownership.ContextStore(repo).get(finding.id)
    assert first["status"] == "PARTIAL" and first["summary"]["access"]["count"] == 300
    assert calls == [1, 2, 3]
    assert repo.get_job(job.id).status == "RUNNING"
    if changed == "scope":
        repo.update_connection(connection.id, status="DISABLED")
    if changed == "auth_changed":
        connection = repo.update_connection(connection.id,
            secret_ref=seal_token(SETTINGS.sealing_keys, "replacement-fixture-credential"))
        approve(repo, connection, provider, "42" if provider == "gitlab" else "acme/app")
    if changed == "budget":
        monkeypatch.setattr(ownership, "MAX_CONTEXT_REQUESTS", 0)
    if changed == "elapsed":
        monkeypatch.setattr(ownership, "_now", lambda: clock[0] + dt.timedelta(hours=2))
    deny[0] = changed == "denied"
    for _ in range(3):
        clock[0] += dt.timedelta(seconds=2)
        worker().process_next()  # A new worker has no in-memory cursor.
        if repo.get_job(job.id).status in {"SUCCEEDED", "CANCELLED"}:
            break
    final = ownership.ContextStore(repo).get(finding.id)
    if changed in {"scope", "auth_changed"}:
        assert calls == [1, 2, 3]
        assert final["body"]["repositories"][0]["status"] == "BLOCKED"
        assert ("SOURCE_CONNECTION_PAUSED" if changed == "scope" else "SOURCE_AUTHORIZATION_CHANGED") in final["body"]["reasons"]
    elif changed in {"denied", "credential", "budget", "elapsed"}:
        assert calls == ([1, 2, 3, 4] if changed == "denied" else [1, 2, 3])
        access = final["body"]["repositories"][0]
        assert access["status"] == ("FORBIDDEN" if changed == "denied" else "UNAVAILABLE")
        assert access["completeness"] == "PARTIAL" and access["basis"] == basis
        assert len(access["people"]) == 300 and access["observed_at"]
        assert access["observed_at"] == first["body"]["repositories"][0]["observed_at"]
        assert not access.get("next_page")
        if changed in {"budget", "elapsed"}:
            assert "CONTEXT_BUDGET_REACHED" in final["body"]["reasons"]
    elif changed == "cancel":
        assert calls == [1, 2, 3, 4]
        assert final == first  # A cancelled lease cannot commit the next chunk.
    else:
        assert final["status"] == "COMPLETE" and final["summary"]["access"]["count"] == 735
        access = final["body"]["repositories"][0]
        assert len({person["login"] for person in access["people"]}) == 735
        assert calls == list(range(1, 9)) and not access.get("next_page")
        assert "PAGED_LIST_NOT_ATOMIC" in access["limitations"]
        assert access["completeness"] == "COMPLETE"
        assert all(person["principal_kind"] == "USER" for person in access["people"])
    assert repo.get_job(job.id).status == ("CANCELLED" if changed == "cancel" else "SUCCEEDED")
    assert GITHUB_TOKEN not in str(final)
    assert GITLAB_TOKEN not in str(final)
    fallback.close()


def test_a_notion_page_names_its_last_editor_and_lists_no_one_with_access():
    notion_token = "ntn_" + "n" * 46
    page, editor = "0123456789abcdef0123456789abcdef", "7d1c5e6a-1111-4222-8333-444455556666"

    def handler(request):
        assert request.headers["authorization"] == "Bearer " + notion_token
        if request.url.path == f"/v1/pages/{page}":
            return httpx.Response(200, json={"object": "page", "id": page, "last_edited_time": "2026-09-21T01:00:00.000Z",
                                             "last_edited_by": {"object": "user", "id": editor}})
        if request.url.path == f"/v1/users/{editor}":
            return httpx.Response(200, json={"object": "user", "type": "person", "name": "Jung Demo", "person": {"email": "jung@example.com"}})
        return httpx.Response(404)

    repo = InMemoryRepository()
    notion = repo.create_connection(Connection(provider="notion", name="Notion", config={},
                                               secret_ref=seal_token(SETTINGS.sealing_keys, notion_token)))
    approve(repo, notion, "notion", page)
    cred = repo.upsert_credential(Credential(fingerprint="e" * 64, credential_type="SLACK_WEBHOOK_URL", provider="slack"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_connection_id=notion.id, source_type="notion",
                                             resource_name="Incident runbook", location="https://www.notion.so/" + page,
                                             metadata={"exposure": "internal", "page_id": page}))
    finding = repo.upsert_finding(cred.id, exposure.id, "HIGH")
    row = ownership.collect(repo, finding.id, secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
                            http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    [location] = row["body"]["locations"]
    assert row["status"] == "PARTIAL" and location["page_id"] == page
    assert row["body"]["repositories"][0]["status"] == "UNSUPPORTED"
    assert location["codeowners"] == {"status": "UNSUPPORTED"}
    assert (location["author"]["name"], location["author"]["email"]) == ("Jung Demo", "jung@example.com")
    assert row["summary"] == {"owner": None, "authors": [["Incident runbook", "https://www.notion.so/" + page, "Jung Demo"]],
                              "author_sources": [["notion", str(notion.id), "Incident runbook", "https://www.notion.so/" + page, "Jung Demo"]],
                              "access": None}


def test_a_numbered_version_reaches_the_reader_as_the_version():
    repo = InMemoryRepository()
    devops = repo.create_connection(Connection(provider="azure_devops", name="Azure DevOps", config={
        "organization": "acme", "project": "Platform", "version_control": "tfvc"}, secret_ref=seal_token(SETTINGS.sealing_keys, "pat")))
    cred = repo.upsert_credential(Credential(fingerprint="d" * 64, credential_type="GENERIC_API_KEY", provider="generic"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_connection_id=devops.id, source_type="azure_devops",
                                             resource_name="acme/Platform/$", location="src/app.config", object_version="42"))
    [place] = ownership._places([exposure])
    assert (place["commit"], place["version"], "page_id" in place) == ("", "42", False)


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def sql_repo(request):
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def test_the_database_keeps_one_context_a_finding_and_the_list_reads_summaries_only(sql_repo):
    store = ownership.ContextStore(sql_repo)
    first, earlier = uuid.uuid4(), dt.datetime(2026, 9, 20, tzinfo=dt.UTC)
    body = {"locations": [{"repository": "acme/app", "path": "a.env", "author": {"status": "OBSERVED", "name": "Lee Demo"},
                           "codeowners": {"path": "CODEOWNERS", "owners": [{"owner": "@kim-demo", "kind": "account", "line": 1}]}}],
            "repositories": [{"source_type": "github", "repository": "acme/app", "status": "OBSERVED",
                              "basis": "GITHUB_REPOSITORY_COLLABORATORS", "people": [{"login": "kim-demo", "name": None, "role": "admin"}]}],
            "reasons": []}
    store.save(first, "PARTIAL", {"locations": [], "repositories": [], "reasons": ["CONTEXT_FORBIDDEN"]}, earlier)
    store.save(first, "COMPLETE", body)  # a later read replaces the row
    row = store.get(first)
    assert (row["status"], row["body"]["repositories"][0]["people"][0]["login"]) == ("COMPLETE", "kim-demo")
    assert row["collected_at"] > earlier and store.get(uuid.uuid4()) is None
    # More ids than one query takes: the list asks 500 at a time.
    others = [uuid.uuid4() for _ in range(620)]
    for finding_id in others[:3]:
        store.save(finding_id, "UNSUPPORTED", {"locations": [], "repositories": [], "reasons": []}, earlier)
    found = store.summaries([*others, first])
    assert set(found) == {first, *others[:3]}
    assert found[first]["owner"] == {"name": "@kim-demo", "team": None, "where": "acme/app · CODEOWNERS"}
    assert found[first]["authors"] == [["acme/app", "a.env", "Lee Demo"]] and found[first]["access"]["count"] == 1
    assert found[others[0]] == {"owner": None, "authors": [], "access": None}
    ages = store.ages()
    assert set(ages) == {first, *others[:3]} and ages[others[0]] == earlier


def single_source(repo, *, provider="github", config=None, resource="acme/app", name="Source"):
    connection = repo.create_connection(Connection(provider=provider, name=name, config=config or {"org": "acme"},
        secret_ref=seal_token(SETTINGS.sealing_keys, GITHUB_TOKEN if provider == "github" else GITLAB_TOKEN)))
    profile = approve(repo, connection, provider, resource)
    credential = repo.upsert_credential(Credential(fingerprint="f" * 64, credential_type="GITHUB_PAT", provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_connection_id=connection.id,
        source_type=provider, resource_name=resource, location="deploy/app.env", metadata={"commit_sha": COMMIT}))
    return connection, profile, credential, exposure, repo.upsert_finding(credential.id, exposure.id, "HIGH")


@pytest.mark.parametrize("change", ["disabled", "revoked", "feature_paused", "paused", "unapproved", "root_removed", "excluded", "path_excluded", "auth_changed"])
def test_access_reads_require_current_connection_and_approved_location(change):
    repo, seen = InMemoryRepository(), []
    connection, profile, _, _, finding = single_source(repo)
    if change == "disabled":
        repo.update_connection(connection.id, status="DISABLED")
    elif change == "revoked":
        repo.update_connection(connection.id, credential_evidence={"revoked_at": "2026-10-03T00:00:00Z"})
    elif change == "feature_paused":
        from cremore.onboarding.store import ProviderConnectionStore

        store = ProviderConnectionStore(repo)
        parent = store.create({"provider": "github", "status": "ACTIVE", "disabled_purposes": ["exposure"]}, "admin")
        store.link(parent["id"], "exposure", "content", connection.id)
    elif change == "paused":
        repo.update_scope_profile(profile.id, state="PAUSED")
    elif change == "unapproved":
        repo.update_scope_profile(profile.id, approved_by="")
    elif change == "root_removed":
        repo.update_scope_profile(profile.id, selected_roots=[])
    elif change == "excluded":
        repo.update_scope_profile(profile.id, excluded_ids=[profile.selected_roots[0]["resource_id"]])
    elif change == "path_excluded":
        repo.update_scope_profile(profile.id, selected_roots=[{**profile.selected_roots[0], "excluded_paths": ["deploy/"]}])
    else:
        repo.update_connection(connection.id, secret_ref=seal_token(SETTINGS.sealing_keys, GITHUB_TOKEN + "changed"))
    row = collect(repo, finding, seen)
    assert row["status"] == "FAILED" and not seen
    assert row["body"]["repositories"][0]["status"] == "BLOCKED"
    assert row["body"]["queried_locations"] == 0


@pytest.mark.parametrize("change", ["disabled", "reapproved_token", "host"])
def test_a_mid_read_connection_change_stops_requests_and_discards_the_old_audience(change):
    repo, seen = InMemoryRepository(), []
    connection, _, _, _, finding = single_source(repo)
    def handler(request):
        seen.append(request)
        if change == "disabled":
            repo.update_connection(connection.id, status="DISABLED")
        elif change == "host":
            repo.update_connection(connection.id, config={**connection.config, "api_url": "https://other.example.com/api/v3"})
        else:
            repo.update_connection(connection.id, secret_ref=seal_token(SETTINGS.sealing_keys, GITHUB_TOKEN + "changed"))
            approve(repo, connection, "github", "acme/app")
        return httpx.Response(200, content=b"* @stale-owner")
    row = ownership.collect(repo, finding.id, secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
        http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    assert len(seen) == 1
    assert row["status"] == "FAILED" and row["body"]["repositories"][0]["status"] == "BLOCKED"
    assert "stale-owner" not in str(row)


def test_equal_project_names_on_different_connections_never_share_access(monkeypatch):
    from cremore.sources.registry import BY_SOURCE

    repo, seen = InMemoryRepository(), []
    first, _, credential, _, finding = single_source(repo, provider="gitlab", resource="42",
        config={"base_url": "https://one.example.com", "project": "42"}, name="First GitLab")
    second = repo.create_connection(Connection(provider="gitlab", name="Second GitLab", config={
        "base_url": "https://two.example.com", "project": "42"}, secret_ref=first.secret_ref))
    approve(repo, second, "gitlab", "42")
    repo.upsert_exposure(Exposure(credential_id=credential.id, source_connection_id=second.id,
        source_type="gitlab", resource_name="42", location="deploy/app.env"))
    def fake_context(payload, place, *, http_client, members):
        seen.append((payload["base_url"], members))
        return {"author": {"status": "OBSERVED", "name": "First author" if "one." in payload["base_url"] else "Second author"},
            "members": {"status": "OBSERVED", "basis": "GITLAB_PROJECT_MEMBERS",
            "people": [{"login": "first" if "one." in payload["base_url"] else "second", "read_access": "UNKNOWN"}]}}
    monkeypatch.setattr(BY_SOURCE["gitlab"], "exposure_context", fake_context)
    row = collect(repo, finding, [])
    assert seen == [("https://one.example.com", True), ("https://two.example.com", True)]
    audience = row["body"]["repositories"]
    assert len({entry["access_key"] for entry in audience}) == 2
    assert [entry["people"][0]["login"] for entry in audience] == ["first", "second"]
    assert {entry["source_label"] for entry in audience} == {"First GitLab", "Second GitLab"}
    from cremore.api.credential_records import _exposure

    sources = row["summary"]["author_sources"]
    exposures = repo.exposures_for_credential(credential.id)
    authors = {str(e.source_connection_id): _exposure(e, [e], sources)["author"] for e in exposures}
    assert authors == {str(first.id): "First author", str(second.id): "Second author"}


@pytest.mark.parametrize("source_type,provider", [("gcp", "gcp"), ("s3", "aws")])
def test_per_object_acl_context_never_reuses_other_objects_and_keeps_typed_grants(monkeypatch, source_type, provider):
    from cremore.sources.registry import BY_SOURCE

    repo, calls, sessions = InMemoryRepository(), [], object()
    connection = repo.create_connection(Connection(provider=provider, name="Object ACL fixture", config={
        "bucket": "poc-bucket", "account_id": "123456789012"} if source_type == "s3" else {"bucket": "poc-bucket"}))
    profile = approve(repo, connection, source_type, "poc-bucket")
    repo.update_scope_profile(profile.id, selected_roots=[{**profile.selected_roots[0], "all_current_objects": True}])
    cred = repo.upsert_credential(Credential(fingerprint="a" * 64, credential_type="GITHUB_PAT", provider="github"))
    exposures = [repo.upsert_exposure(Exposure(credential_id=cred.id, source_connection_id=connection.id,
        source_type=source_type, resource_name="poc-bucket", location=f"{name}.env", object_version="1234")) for name in ("a", "b")]
    finding = repo.upsert_finding(cred.id, exposures[0].id, "HIGH")
    def context(payload, place, *, http_client, members, **kwargs):
        calls.append((place["path"], members, place["object_version"]))
        if source_type == "s3":
            assert kwargs["aws_sessions"] is sessions
            kwargs["check_scope"]()
        return {"members": {"status": "OBSERVED", "basis": "AWS_S3_POLICY_ACL" if source_type == "s3" else "GCS_BUCKET_IAM_OBJECT_ACL",
            "people": [{"login": place["path"], "principal_id": "group:team@example.test", "principal_kind": "GROUP",
                "permission": "roles/storage.objectViewer", "effect": "ALLOW", "read_access": "UNKNOWN"}]}}
    monkeypatch.setattr(BY_SOURCE[source_type], "exposure_context", context)
    row = ownership.collect(repo, finding.id, aws_sessions=sessions)
    assert calls == [("a.env", True, "1234"), ("b.env", True, "1234")]
    entries = row["body"]["repositories"]
    assert len(entries) == 2 and len({entry["access_key"] for entry in entries}) == 2
    assert all(entry["evidence_kind"] == "PROVIDER_GRANTS" and entry["completeness"] == "COMPLETE" for entry in entries)
    assert all(entry["people"][0]["principal_kind"] == "GROUP" and entry["people"][0]["effect"] == "ALLOW" for entry in entries)
    assert all(entry["people"][0]["permission"] == "roles/storage.objectViewer" for entry in entries)


def test_scope_guard_wraps_oauth_token_client_factories(monkeypatch):
    from cremore.secretstore import resolver

    repo, requests = InMemoryRepository(), []
    connection, _profile, _credential, _exposure, finding = single_source(repo)
    def inject(kind, payload, resolver, *, github_client_factory, http_client_factory):
        assert github_client_factory is http_client_factory
        repo.update_connection(connection.id, status="DISABLED")
        with http_client_factory() as client:
            client.request("GET", "https://api.github.com/rate_limit")
        pytest.fail("Revoked scope must prevent token network I/O")
    monkeypatch.setattr(resolver, "inject_secret", inject)
    row = ownership.collect(repo, finding.id, http_client_factory=lambda: httpx.Client(
        transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(200))))
    assert requests == [] and row["status"] == "FAILED"


def test_location_budget_keeps_unqueried_and_unsupported_locations_visible(monkeypatch):
    from cremore.sources.registry import BY_SOURCE

    repo, calls = InMemoryRepository(), []
    connection, _, credential, _, finding = single_source(repo)
    repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="filesystem",
        resource_name="local", location="app.env"))
    for index in range(105):
        repo.upsert_exposure(Exposure(credential_id=credential.id, source_connection_id=connection.id,
            source_type="github", resource_name="acme/app", location=f"deploy/file-{index}.env"))
    def fake_context(payload, place, *, http_client, members):
        calls.append(place["path"])
        return {"author": {"status": "OBSERVED", "name": "Editor"}, **({"members": {
            "status": "OBSERVED", "basis": "GITHUB_REPOSITORY_COLLABORATORS", "people": []}} if members else {})}
    monkeypatch.setattr(BY_SOURCE["github"], "exposure_context", fake_context)
    row = collect(repo, finding, [])
    body = row["body"]
    assert row["status"] == "PARTIAL" and len(calls) == 5
    assert (body["location_count"], len(body["locations"]), body["queried_locations"], body["unqueried_locations"], body["omitted_locations"]) == (107, 100, 5, 102, 7)
    assert body["locations"][1]["context_status"] == "UNSUPPORTED"
    assert body["locations"][-1]["context_status"] == "LIMIT_REACHED"
    assert "CONTEXT_LOCATION_LIMIT" in body["reasons"]


@pytest.mark.parametrize("status", ["OBSERVED", "FORBIDDEN", "UNAVAILABLE"])
def test_partial_member_evidence_survives_without_claiming_complete_access(monkeypatch, status):
    from cremore.sources.registry import BY_SOURCE

    repo = InMemoryRepository()
    _, _, _, _, finding = single_source(repo)
    monkeypatch.setattr(BY_SOURCE["github"], "exposure_context", lambda *args, **kwargs: {"members": {
        "status": status, "basis": "GITHUB_REPOSITORY_COLLABORATORS", "truncated": True,
        "visibility": "PUBLIC", "limitations": ["MEMBER_PAGE_UNAVAILABLE"],
        "people": [{"login": "observed-person", "role": "read", "read_access": "REPORTED"}]}})
    row = collect(repo, finding, [])
    [access] = row["body"]["repositories"]
    assert row["status"] == "PARTIAL"
    assert access["status"] == status and access["completeness"] == "PARTIAL"
    assert access["visibility"] == "PUBLIC" and access["observed_at"]
    assert access["people"][0]["read_access"] == "REPORTED"
    assert "NOT_ACCESS_HISTORY" in access["limitations"] and "MEMBER_PAGE_UNAVAILABLE" in access["limitations"]
    assert row["summary"]["access"]["count"] == 1


def test_missing_source_connection_is_an_explicit_blocked_location():
    repo = InMemoryRepository()
    _, _, credential, _, finding = single_source(repo)
    repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
        resource_name="acme/missing", location="app.env"))
    row = collect(repo, finding, [])
    [missing] = [item for item in row["body"]["repositories"] if item["source_connection_id"] is None]
    assert missing["status"] == "BLOCKED" and missing["completeness"] == "UNKNOWN"
    assert "SOURCE_CONNECTION_GONE" in row["body"]["reasons"]


def test_database_roundtrips_additive_access_fields_and_keeps_old_bodies_compatible(sql_repo):
    repo = InMemoryRepository()
    _, _, _, _, finding = single_source(repo)
    row = collect(repo, finding, [])
    store = ownership.ContextStore(sql_repo)
    store.save(finding.id, row["status"], row["body"])
    assert ownership.public(store.get(finding.id))["repositories"] == row["body"]["repositories"]
    old_id = uuid.uuid4()
    old = {"locations": [{"repository": "old", "path": "app.env"}], "repositories": [], "reasons": []}
    store.save(old_id, "UNSUPPORTED", old)
    assert ownership.public(store.get(old_id))["locations"] == old["locations"]
