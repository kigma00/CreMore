"""Schema 1 Secret Manager reads when Google names resources by project number."""

import base64

import httpx
import pytest

from cremore.coverage.models import ConnectionSpec
from cremore.detection.engine import Engine, EngineConfig
from cremore_gcp_provider.coverage import collect_gcp

PROJECT = "synthetic-project"
NUMBER = "419699000000"
TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
PROJECT_RECORD = f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJECT}"


def collect(project_record, references=()):
    calls = []

    def handle(request):
        calls.append(str(request.url).split("?")[0])
        if str(request.url).startswith(PROJECT_RECORD):
            return httpx.Response(project_record[0], json=project_record[1])
        if request.url.path.endswith("/secrets"):
            return httpx.Response(200, json={"secrets": [{"name": f"projects/{NUMBER}/secrets/token"}]})
        assert request.url.path == f"/v1/projects/{PROJECT}/secrets/token/versions/latest:access"
        return httpx.Response(200, json={"name": f"projects/{NUMBER}/secrets/token/versions/3",
                                         "payload": {"data": base64.b64encode(TOKEN.encode()).decode()}})

    config = ConnectionSpec(name="GCP", provider="gcp_secret_manager", project=PROJECT, references=list(references))
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        return collect_gcp(config, client, lambda: "synthetic", Engine(EngineConfig(fingerprint_key=b"k" * 32))), calls


@pytest.mark.parametrize("references", [(), (f"projects/{PROJECT}/secrets/token",)])
def test_a_number_the_project_record_binds_is_read_under_the_approved_id(references):
    result, calls = collect((200, {"projectId": PROJECT, "name": f"projects/{NUMBER}"}), references)
    assert result.status == "COMPLETE" and not result.reasons
    assert [(item.reference, item.version, item.version_state) for item in result.items] == [
        (f"projects/{PROJECT}/secrets/token", "3", "CURRENT")]
    assert calls.count(PROJECT_RECORD) == 1


@pytest.mark.parametrize("project_record", [
    (403, {}), (200, {"projectId": "another-project", "name": f"projects/{NUMBER}"}),
    (200, {"projectId": PROJECT, "name": "projects/419699000001"})])
def test_an_unbound_number_stays_outside_the_scope_and_is_never_read(project_record):
    result, calls = collect(project_record)
    assert "PROVIDER_SCOPE_MISMATCH" in result.reasons and not result.items
    assert not any(call.endswith(":access") for call in calls)
