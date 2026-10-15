from cremore_aws_provider import aws_controltower, aws_org_settings
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import AwsAccount

TOKEN = "synthetic-admin-" + "0" * 32
HEADERS = {"Authorization": "Bearer " + TOKEN}


def client(**overrides):
    repo = InMemoryRepository()
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN,
        FINGERPRINT_KEY="ab" * 32, **overrides), aws_identity_probe=lambda **kwargs: {"state": "NO_CREDENTIALS"})
    return TestClient(app), repo


def test_inventory_settings_are_off_by_default_authenticated_and_scope_checked():
    c, repo = client()
    path = "/api/v1/settings/aws-credential-inventory"
    assert c.get(path).status_code == 401
    assert c.get(path, headers=HEADERS).json()["enabled"] is False
    response = c.put(path, headers=HEADERS, json={"enabled": True, "account_ids": ["111111111111"],
        "cloudtrail_enabled": True, "regions": ["us-east-1"], "interval_minutes": 60})
    assert response.status_code == 200
    assert response.json()["account_ids"] == ["111111111111"] and response.json()["effective"]
    assert repo.list_jobs() == [] and repo.list_aws_accounts() == []  # opt-in grants no account access
    assert c.put(path, headers=HEADERS, json={"account_ids": ["invalid"]}).status_code == 422
    assert c.get(path, headers=HEADERS).json()["account_ids"] == ["111111111111"]
    locked, _ = client(SCAN_SCHEDULES_MODE="disabled")
    assert locked.put(path, headers=HEADERS, json={"enabled": True}).status_code == 409


def test_org_context_settings_validate_region_queue_and_immediately_block_exclusions():
    c, repo = client()
    account = repo.create_aws_account(AwsAccount(account_id="111111111111", name="Synthetic",
        source="ORGANIZATION", org_state="ACTIVE", org_present=True))
    path = "/api/v1/settings/aws-organizations"
    assert c.put(path, headers=HEADERS, json={"control_tower_enabled": True}).status_code == 422
    response = c.put(path, headers=HEADERS, json={"enabled": True, "external_id": "synthetic-external",
        "control_tower_enabled": True, "control_tower_region": "us-east-1", "excludes": [account.account_id],
        "lifecycle_queue_url": "https://sqs.us-east-1.amazonaws.com/999999999999/cremore-ct",
        "lifecycle_queue_acknowledged": True})
    assert response.status_code == 200 and response.json()["control_tower_enabled"]
    assert repo.get_aws_account(account.id).in_deployment_scope is False
    assert aws_controltower.rediscovery_pending(repo)["event"] == "SETTINGS_CHANGED"
    assert repo.get_setting(aws_org_settings.KEY)["value"]["lifecycle_queue_acknowledged"]
    assert c.put(path, headers=HEADERS, json={"control_tower_region": "eu-west-1"}).status_code == 422
