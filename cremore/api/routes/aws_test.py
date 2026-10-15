"""AWS discovery hard locks are checked before any provider work."""

import pytest
from cremore_aws_provider import aws_access
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.dashboard_test import TOKEN, auth, sso_identity
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository


@pytest.mark.parametrize("source", ["org", "sso"])
@pytest.mark.parametrize("operation,method", [("discover", "post"), ("discoverable", "get")])
@pytest.mark.parametrize("isolated", [False, True])
def test_discovery_hard_lock_refuses_before_probe_or_sweep(source, operation, method, isolated):
    calls = []

    def discovery(*args):
        calls.append(args)
        return {"available": True, "accounts": []}

    repo = InMemoryRepository()
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32,
                        **{f"AWS_{source.upper()}_DISCOVERY_MODE": "disabled"})
    aws_access.save_approval(repo, aws_access.SCANNER, sso_identity(), "admin")
    client = TestClient(create_app(repo=repo, settings=settings, aws_identity_probe=sso_identity,
                                  aws_discovery_probe=discovery, aws_discovery_sweep=discovery))
    settings.isolated_deployment = isolated
    response = getattr(client, method)(f"/api/v1/aws/accounts/{operation}?source={source}", headers=auth())
    assert response.status_code == 409
    assert response.json()["error"] == "AWS_DISCOVERY_DISABLED"
    assert calls == []
    assert repo.list_jobs(50) == []
