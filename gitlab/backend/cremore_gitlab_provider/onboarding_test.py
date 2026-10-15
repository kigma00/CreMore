"""Generated GitLab options reach the collector without model-default drift."""

from datetime import UTC, datetime
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_gitlab_provider.metadata.adapter import _config
from cremore_gitlab_provider.metadata.tests._responses import inventory_client
from cremore_gitlab_provider.metadata.tests.test_adapter import run
from cremore_gitlab_provider.onboarding import children


@pytest.mark.parametrize("edition,subscription", [
    ("cloud", "free"), ("cloud", "premium"), ("cloud", "ultimate"), ("cloud", None),
    ("self_managed", "free"), ("self_managed", "premium"), ("self_managed", "ultimate"),
    ("dedicated", None),
])
@pytest.mark.parametrize("purpose,scope", [("inventory", "group"), ("inventory", "project"),
                                          ("vault", "group"), ("vault", "project"),
                                          ("inventory", "instance")])
def test_generated_specs_only_schedule_applicable_managed_lists(edition, subscription, purpose, scope):
    if scope == "instance" and edition == "cloud":
        pytest.skip("GitLab.com does not offer instance administration")
    target = {"scope": scope, "id": "10" if scope == "group" else "100"}
    if subscription is not None:
        target["subscription"] = subscription
    if edition != "cloud":
        target["host"] = "https://gitlab.example"
    connection = {"provider": "gitlab", "edition": edition, "auth_method": "token", "target": target}
    plan = {"instance_sources": ["instance_pat"]} if scope == "instance" else {}
    [child] = children(connection, purpose, plan)
    spec = MetadataConnectionSpec.model_validate({**child["spec"],
                                                 "secret_refs": {"token": "vault://synthetic/gitlab"}})
    config = _config(spec)
    managed = edition == "cloud" and subscription != "free"
    assert spec.options.include_resource_access_tokens is managed
    assert config.include_resource_access_tokens is managed
    assert config.include_enterprise_pat is (managed and purpose == "inventory")
    client = inventory_client(config)
    client.routes["/user"]["is_admin"] = True
    client.routes["/groups/10/variables"] = []
    client.routes["/projects/100/variables"] = []
    with patch("cremore_gitlab_provider.metadata.model.datetime") as clock:
        clock.now.return_value = datetime(2026, 10, 13, tzinfo=UTC)
        pages = run(spec, client=client)
    assert pages[-1].status == "COMPLETE", pages[-1].reasons
    assert pages[-1].checkpoint["phase"] == "done"
    paths = {urlsplit(url).path.removeprefix("/api/v4") for url in client.calls}
    assert ("/groups/10/manage/personal_access_tokens" in paths) is (
        managed and purpose == "inventory" and scope == "group")
    if not managed:
        assert not any("/manage/" in path for path in paths)
    if edition != "cloud" and scope in {"group", "project"}:
        assert f"/{scope}s/{target['id']}/access_tokens" in paths
