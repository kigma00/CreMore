"""Discovered finding secrets never come back through the v1 read API.

Individual endpoints assert this where it was easy to get wrong. Nothing swept
all of them, so a new route could serve a finding's raw match and every existing
test would still pass. This scans the v1 GET routes with seeded finding and
credential ids.

A route that needs an id it cannot guess is skipped and counted, so the test
says how much it actually covered rather than passing on an empty sweep.
"""

from __future__ import annotations

import json
import re

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import create_app

TOKEN = "sweep-token-" + "0" * 32
# Split so the repository's own scan of this file does not read it as a finding.
SECRET = "ghp_" + "sWeEp" + "0000000000000000000000000000000"
AWS_ID = "AKIA" + "SWEEPEXAMPLE0000"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYSWEEPKEY"


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def _seeded():
    repo = InMemoryRepository()
    client = TestClient(create_app(repo=repo, settings=Settings(
        AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)))
    for text, name in ((f"token = {SECRET}", "org/repo"),
                       (f"AWS_ACCESS_KEY_ID={AWS_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}", "org/infra")):
        r = client.post("/api/v1/scan", headers=auth(), json={
            "text": text, "source_type": "github", "resource_name": name,
            "location": "app.py", "exposure": "public"})
        assert r.status_code == 202, r.text
    findings = client.get("/api/v1/findings", headers=auth()).json()
    assert findings, "the sweep needs at least one finding to be meaningful"
    return client, repo, findings


def _fill(path: str, findings) -> str | None:
    """A concrete URL for a templated route, or None when nothing can fill it."""
    known = {
        "finding_id": findings[0]["id"],
        "credential_id": findings[0]["credential_id"],
        "connection_id": "00000000-0000-4000-8000-000000000000",
        "account_id": "000000000000",
        "job_id": "00000000-0000-4000-8000-000000000000",
        "kind": "source",
    }
    out = path
    for name in re.findall(r"\{([^}]+)\}", path):
        value = known.get(name)
        if not value:
            return None
        out = out.replace("{" + name + "}", str(value))
    return out


def test_no_get_route_returns_a_raw_secret():
    client, _repo, findings = _seeded()
    app = client.app
    swept, skipped = [], []
    for route in app.routes:
        path = getattr(route, "path", "")
        if "GET" not in getattr(route, "methods", set()) or not path.startswith("/api/v1"):
            continue
        url = _fill(path, findings)
        if url is None:
            skipped.append(path)
            continue
        body = client.get(url, headers=auth()).text
        swept.append(path)
        for secret, what in ((SECRET, "GitHub token"), (AWS_SECRET, "AWS secret key")):
            assert secret not in body, f"{path} returned the raw {what}"

    # Unknown ids may be skipped, but the seeded credential's reads must run.
    assert not [p for p in skipped if "{credential_id}" in p], skipped
    assert len(swept) >= 55, f"the sweep only reached {len(swept)} routes; it is not proving much"
    assert not [p for p in skipped if "{" not in p], f"these took no id yet were skipped: {skipped}"


def test_no_finding_in_the_database_carries_the_raw_secret():
    """The API could be clean while the row behind it is not."""
    _client, repo, _findings = _seeded()
    stored = json.dumps([
        {k: str(v) for k, v in vars(obj).items()}
        for table in (repo.findings, repo.credentials, getattr(repo, "exposures", {}))
        for obj in (table.values() if hasattr(table, "values") else table)
    ], default=str)
    for secret in (SECRET, AWS_SECRET):
        assert secret not in stored


def test_the_masked_hint_shows_too_little_to_reconstruct():
    client, _repo, findings = _seeded()
    detail = client.get(f"/api/v1/findings/{findings[0]['id']}", headers=auth()).text
    hints = re.findall(r'"identifier_hint":\s*"([^"]*)"', detail)
    assert hints, "a finding should carry a masked hint"
    for hint in hints:
        visible = re.sub(r"[^A-Za-z0-9/+_-]", "", hint)
        assert len(visible) <= 12, f"hint reveals {len(visible)} characters: {hint}"
