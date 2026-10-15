"""Full-stack integration: SQL repository + worker + API in one flow."""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
TOKEN = "integration-token-" + "0" * 32


def test_enqueue_worker_api_over_sqlite():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)

    # 1. Enqueue a scan job.
    job = repo.enqueue_job(ScanJob(kind="inline", payload={
        "text": f"config: {GH}", "source_type": "github",
        "resource_name": "acme/app", "location": "settings.py", "exposure": "public",
    }))

    # 2. The worker runs it.
    assert JobWorker(repo).process_next() is True
    assert repo.get_job(job.id).status == "SUCCEEDED"

    # 3. The API serves the resulting finding.
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32))
    client = TestClient(app)
    auth = {"Authorization": f"Bearer {TOKEN}"}

    findings = client.get("/api/v1/findings", headers=auth).json()
    assert len(findings) == 1
    assert findings[0]["credential_type"] == "GITHUB_TOKEN"
    assert findings[0]["severity"] == "MEDIUM"  # unverified github token, public repo

    fid = findings[0]["id"]
    detail = client.get(f"/api/v1/findings/{fid}", headers=auth).json()
    assert detail["exposures"][0]["location"] == "settings.py"
    assert "identifier" not in detail["credential"]  # raw secret/identifier never served
