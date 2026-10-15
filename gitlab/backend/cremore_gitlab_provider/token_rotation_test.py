"""A GitLab token rotating itself, against a synthetic GitLab: the token is asked about itself first, only a
clear refusal moves on, and anything that may have rotated stops without ever using the old token again."""

import datetime as dt
import json

import httpx
import pytest

from cremore_gitlab_provider import token_rotation as tr

OLD, NEW = "glpat-" + "o" * 20, "glpat-" + "n" * 20
TODAY = dt.date(2026, 9, 29)


def gitlab(calls, *, scopes=("read_api", "self_rotate"), active=True, self_status=200, rotate=None):
    """``rotate``: path -> list of statuses answered in turn (200 answers with the successor)."""
    rotate = {key: list(value) for key, value in (rotate or {}).items()}

    def handler(request):
        calls.append((request.method, request.url.path, json.loads(request.content) if request.content else None))
        assert request.headers["PRIVATE-TOKEN"] == OLD
        if request.url.path == "/api/v4/personal_access_tokens/self":
            return httpx.Response(self_status, json={"id": 7, "scopes": list(scopes), "active": active, "revoked": not active,
                                                     "expires_at": "2026-10-20", "created_at": "2026-07-22T01:00:00Z"})
        answers = rotate.get(request.url.path) or [404]
        status = answers.pop(0) if len(answers) > 1 else answers[0]
        if status == "boom":
            raise httpx.ReadTimeout("synthetic")
        if status == 200:
            return httpx.Response(200, json={"id": 8, "token": NEW, "expires_at": "2026-12-28", "created_at": "2026-09-29T03:00:00Z"})
        return httpx.Response(status, json={"message": "no"})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_a_group_token_rotates_through_its_group_with_a_chosen_expiry():
    calls = []
    made = tr.rotate(gitlab(calls, rotate={"/api/v4/groups/42/access_tokens/self/rotate": [200]}), "https://gitlab.com",
                     OLD, "group", "42", today=TODAY)
    assert made == {"token": NEW, "expires_at": "2026-12-28", "created_at": "2026-09-29T03:00:00Z"}
    assert calls[0][1] == "/api/v4/personal_access_tokens/self"  # asked about itself before anything rotates
    assert calls[1] == ("POST", "/api/v4/groups/42/access_tokens/self/rotate", {"expires_at": "2026-12-28"})


@pytest.mark.parametrize("scope", ["group", "project"])
@pytest.mark.parametrize("status", [403, 404, 405])
def test_only_a_clear_refusal_moves_on_to_another_endpoint_or_a_shorter_life(scope, status):
    calls = []
    path = f"/api/v4/{scope}s/42/access_tokens/self/rotate"
    made = tr.rotate(gitlab(calls, rotate={path: [400, status], "/api/v4/personal_access_tokens/self/rotate": [200]}),
                     "https://gitlab.com", OLD, scope, "42", today=TODAY)
    assert made["token"] == NEW
    assert [(method, url, body and body["expires_at"]) for method, url, body in calls[1:]] == [
        ("POST", path, "2026-12-28"), ("POST", path, "2026-10-29"), ("POST", "/api/v4/personal_access_tokens/self/rotate", "2026-12-28")]


@pytest.mark.parametrize("scope", ["group", "project", "instance"])
def test_a_pat_endpoint_405_is_a_final_refusal_without_retry(scope):
    calls = []
    path = "/api/v4/personal_access_tokens/self/rotate"
    routes = {path: [405], f"/api/v4/{scope}s/42/access_tokens/self/rotate": [405]}
    with pytest.raises(tr.RotationError, match="GITLAB_ROTATION_REFUSED"):
        tr.rotate(gitlab(calls, rotate=routes), "https://gitlab.com", OLD, scope, "42", today=TODAY)
    posts = [url for method, url, _body in calls if method == "POST"]
    assert posts == ([f"/api/v4/{scope}s/42/access_tokens/self/rotate"] if scope != "instance" else []) + [path]


@pytest.mark.parametrize("answer", ["boom", 500, 202])
def test_an_answer_that_may_have_rotated_stops_and_never_tries_again(answer):
    calls = []
    with pytest.raises(tr.RotationError, match="GITLAB_ROTATION_UNCERTAIN"):
        tr.rotate(gitlab(calls, rotate={"/api/v4/projects/5/access_tokens/self/rotate": [answer]}), "https://gitlab.com",
                  OLD, "project", "5", today=TODAY)
    assert len([call for call in calls if call[0] == "POST"]) == 1


def test_a_revoked_or_unscoped_token_is_never_rotated():
    for kwargs, code in (({"self_status": 401}, "GITLAB_TOKEN_REVOKED"), ({"active": False}, "GITLAB_TOKEN_REVOKED"),
                         ({"scopes": ("read_api",)}, "GITLAB_SELF_ROTATE_SCOPE_REQUIRED")):
        calls = []
        with pytest.raises(tr.RotationError) as failed:
            tr.rotate(gitlab(calls, **kwargs), "https://gitlab.com", OLD, "group", "42", today=TODAY)
        assert failed.value.code == code and not [call for call in calls if call[0] == "POST"]
    with pytest.raises(tr.RotationError, match="GITLAB_ROTATION_REFUSED"):
        tr.rotate(gitlab([], rotate={}), "https://gitlab.com", OLD, "instance", "", today=TODAY)


def test_what_is_due_follows_what_gitlab_said_of_the_token():
    now = dt.datetime(2026, 9, 29, 3, tzinfo=dt.UTC)
    assert tr.due(None, now) == "inspect"
    seen = {"seen_at": now.isoformat(), "created_at": "2026-07-22T01:00:00Z"}
    assert tr.due({**seen, "expires_at": "2026-12-28"}, now) is None
    assert tr.due({**seen, "expires_at": "2026-10-20"}, now) == "renew"  # within the last 30 days of 90
    assert tr.due({**seen, "expires_at": None}, now) is None  # no expiry, nothing to renew before
    assert tr.due({**seen, "expires_at": "2026-09-01"}, now) is None  # expired: only a new token helps
    assert tr.due({**seen, "seen_at": (now - dt.timedelta(days=2)).isoformat(), "expires_at": "2026-12-28"}, now) == "inspect"
    info = tr.inspect(gitlab([]), "https://gitlab.com", OLD)
    assert info == {"id": 7, "expires_at": "2026-10-20", "created_at": "2026-07-22T01:00:00Z",
                    "scopes": ["read_api", "self_rotate"], "active": True}
