"""No live Notion: two-party setup, exact-byte signatures, scope and durable replay."""

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cremore.db.postgres_scan_test import pg  # noqa: F401 -- shared isolated DB fixture
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.scanning import notion_webhooks as hooks
from cremore.scanning.scope import ScopeError
from cremore.scanning.triggers_test import setup

SECRET = "secret_" + "a" * 42


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def ctx(request, tmp_path):
    repo = None
    if request.param == "postgres":
        _engine, repo = request.getfixturevalue("pg")
    if request.param == "sqlite":
        engine = make_engine("sqlite:///" + (tmp_path / "hooks.db").as_posix())
        create_all(engine)
        repo = SqlRepository(engine)
    repo, _connection, profile, item, settings = setup("notion", repo=repo)
    settings = settings.model_copy(update={"fingerprint_key": "ab" * 32})
    binding = hooks.create(repo, settings, str(profile.id), "admin")
    return repo, settings, profile, item, binding


def payload(item, **fields):
    return {"id": str(uuid.uuid4()), "timestamp": datetime.now(UTC).isoformat(),
            "workspace_id": str(uuid.UUID(int=1)), "subscription_id": str(uuid.UUID(int=2)),
            "integration_id": str(uuid.UUID(int=3)), "type": "page.content_updated",
            "entity": {"id": item["provider_resource_id"], "type": "page"}, **fields}


def send(ctx, value, signature=None):
    repo, settings, _profile, _item, binding = ctx
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode()
    signature = signature or "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hooks.receive(repo, settings, binding["id"], raw, signature)


def activate(ctx):
    repo, settings, _profile, item, binding = ctx
    assert send(ctx, {"verification_token": SECRET})["state"] == "PENDING"
    assert hooks.challenge(repo, settings, binding["id"])["verification_token"] == SECRET
    assert send(ctx, payload(item))["state"] == "PENDING"
    assert repo.list_jobs() == []
    probe = hooks.public(repo)[0]["probe"]
    hooks.confirm(repo, settings, binding["id"], "admin", probe_digest=probe["digest"])


def test_only_confirmed_signed_events_enqueue_once_and_repeated_scans_remain_queued(ctx):
    repo, settings, profile, item, binding = ctx
    activate(ctx)
    value = payload(item, data={"private_text": "MUST_NOT_PERSIST"}, authors=[{"name": "MUST_NOT_PERSIST"}])
    assert send(ctx, value)["enqueued"] == 1
    assert send(ctx, value)["enqueued"] == 0
    assert send(ctx, payload(item))["enqueued"] == 1
    jobs = repo.list_jobs()
    assert len(jobs) == 2 and all(j.status == "QUEUED" for j in jobs)
    assert all(j.connection_id == profile.connection_id for j in jobs)
    assert all([uuid.UUID(p) for p in j.payload["roots"][0]["exact_page_ids"]]
               == [uuid.UUID(item["provider_resource_id"])] for j in jobs)
    assert "MUST_NOT_PERSIST" not in json.dumps([j.model_dump(mode="json") for j in jobs])
    assert SECRET not in json.dumps(repo.get_setting(hooks.KEY), default=str)
    with pytest.raises(hooks.Error, match="VERIFICATION_UNAVAILABLE"):
        hooks.challenge(repo, settings, binding["id"])


def test_verification_cannot_activate_or_replace_a_key(ctx):
    repo, settings, _profile, item, binding = ctx
    with pytest.raises(hooks.Error, match="VERIFICATION_REQUIRED"):
        send(ctx, payload(item))
    send(ctx, {"verification_token": SECRET})
    with pytest.raises(hooks.Error, match="CHALLENGE_REFUSED"):
        send(ctx, {"verification_token": "secret_" + "b" * 42})
    with pytest.raises(hooks.Error, match="CONFIRMATION_STALE"):
        hooks.confirm(repo, settings, binding["id"], "admin", probe_digest="unobserved")
    assert repo.list_jobs() == []


@pytest.mark.parametrize("change", ["signature", "workspace", "expired", "future", "unknown-page", "paused"])
def test_invalid_and_out_of_scope_events_never_scan(ctx, change):
    repo, _settings, profile, item, _binding = ctx
    activate(ctx)
    value = payload(item)
    signature = None
    if change == "signature":
        signature = "sha256=" + "0" * 64
    elif change == "workspace":
        value["workspace_id"] = str(uuid.uuid4())
    elif change in {"expired", "future"}:
        value["timestamp"] = (datetime.now(UTC) + timedelta(days=-4 if change == "expired" else 1)).isoformat()
    elif change == "unknown-page":
        value["entity"]["id"] = str(uuid.uuid4())
    elif change == "paused":
        repo.update_scope_profile(profile.id, event_mode="DISABLED")
    if change == "unknown-page":
        assert send(ctx, value)["enqueued"] == 0
    else:
        with pytest.raises((hooks.Error, ScopeError)):
            send(ctx, value, signature)
    assert repo.list_jobs() == []


def test_api_admin_boundary_and_public_body_limit(ctx):
    from cremore.api.dashboard_test import auth, client

    repo, _settings, _profile, _item, binding = ctx
    browser = client(repo)
    assert browser.get("/api/v1/settings/notion-webhooks").status_code == 401
    assert browser.get("/api/v1/settings/notion-webhooks", headers=auth()).status_code == 200
    path = binding["path"]
    assert browser.post(path, content=b"x" * (hooks.provider.MAX_BODY + 1)).status_code == 413
    assert browser.post(path, json={"verification_token": SECRET}).status_code == 200
    response = browser.get(f"/api/v1/settings/notion-webhooks/{binding['id']}/verification", headers=auth())
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"


def test_parallel_signed_retries_commit_one_job(pg):  # noqa: F811 -- pytest fixture
    from concurrent.futures import ThreadPoolExecutor

    _engine, repo = pg
    repo, _connection, profile, item, settings = setup("notion", repo=repo)
    settings = settings.model_copy(update={"fingerprint_key": "ab" * 32})
    binding = hooks.create(repo, settings, str(profile.id), "admin")
    context = repo, settings, profile, item, binding
    activate(context)
    value = payload(item)
    with ThreadPoolExecutor(max_workers=6) as pool:
        counts = list(pool.map(lambda _: send(context, value)["enqueued"], range(12)))
    assert sum(counts) == 1 and len(repo.list_jobs()) == 1


def test_failed_commit_can_be_retried_without_losing_event(pg, monkeypatch):  # noqa: F811 -- pytest fixture
    _engine, repo = pg
    repo, _connection, profile, item, settings = setup("notion", repo=repo)
    settings = settings.model_copy(update={"fingerprint_key": "ab" * 32})
    binding = hooks.create(repo, settings, str(profile.id), "admin")
    context = repo, settings, profile, item, binding
    activate(context)
    value = payload(item)
    original = hooks._save
    with monkeypatch.context() as patch:
        patch.setattr(hooks, "_save", lambda *args: (_ for _ in ()).throw(RuntimeError("fixture commit failure")))
        with pytest.raises(RuntimeError, match="fixture commit failure"):
            send(context, value)
    assert hooks._save is original
    assert repo.list_jobs() == []
    assert send(context, value)["enqueued"] == 1
