"""Renewal failures use the persisted attempt time, not the last successful token read."""

import datetime as dt

import httpx
import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import renewal
from cremore.onboarding.gitlab_renewal_test import NOW, RESOLVER, SETTINGS, connected
from cremore.onboarding.store import ProviderConnectionStore


def provider(calls, status):
    def handler(request):
        calls.append((request.method, request.url.path))
        assert request.method == "GET"
        assert request.url.path == "/api/v4/personal_access_tokens/self"
        return httpx.Response(status, json={"id": 1, "active": True, "scopes": ["read_api"],
            "created_at": "2026-07-22T00:00:00Z", "expires_at": "2026-10-20"})

    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def failures(repo):
    return [event for event in repo.finding_events.values()
            if event.event_type == "PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED"]


@pytest.mark.parametrize("status,code", [(401, "GITLAB_TOKEN_REVOKED"), (503, "GITLAB_UNAVAILABLE")])
def test_a_failed_inspection_waits_a_day_from_the_persisted_failure(status, code):
    repo = InMemoryRepository()
    record, _view = connected(repo)
    calls = []
    fake = provider(calls, status)
    renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW)
    note = ProviderConnectionStore(repo).get(record["id"])["checks"]["renewal"]
    assert note["state"] == "FAILED" and note["code"] == code
    assert note["at"] == NOW.isoformat() and not note.get("keep")
    for hour in range(1, 24):
        assert renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW + dt.timedelta(hours=hour)) == 0
    assert len(calls) == len(failures(repo)) == 1
    assert renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW + dt.timedelta(days=1)) == 1
    assert len(calls) == len(failures(repo)) == 2


def test_missing_rotation_scope_keeps_the_expiry_notice_without_hourly_retries():
    repo = InMemoryRepository()
    record, _view = connected(repo)
    calls = []
    fake = provider(calls, 200)
    renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW)
    renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW + dt.timedelta(hours=1))
    note = ProviderConnectionStore(repo).get(record["id"])["checks"]["renewal"]
    assert note["state"] == "FAILED" and note["code"] == "GITLAB_SELF_ROTATE_SCOPE_REQUIRED"
    assert note["keep"]["self_rotate"] is False
    for hour in range(2, 25):
        assert renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW + dt.timedelta(hours=hour)) == 0
    assert len(calls) == 2 and len(failures(repo)) == 1
    for hour in (25, 26):
        renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW + dt.timedelta(hours=hour))
    assert len(calls) == 4 and len(failures(repo)) == 2
    assert all(event.note == "renew GITLAB_SELF_ROTATE_SCOPE_REQUIRED" for event in failures(repo))
