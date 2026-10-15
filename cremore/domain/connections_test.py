"""Connection onboarding validation tests."""

from __future__ import annotations

import pytest

from cremore.domain.connections import (
    ConnectionError,
    job_kind_for,
    job_payload_for,
    validate_connection,
)
from cremore.domain.models import Connection


def test_valid_github_connection():
    conn = Connection(provider="github", name="acme", config={"owner": "acme", "repo": "app"})
    validate_connection(conn)  # no raise
    assert job_kind_for(conn) == "github"
    assert job_payload_for(conn) == {"owner": "acme", "repo": "app", "ref": "HEAD", "github_host": "", "base_url": "https://api.github.com"}


def test_github_org_connection():
    conn = Connection(provider="github", name="acme-org", config={"org": "acme"})
    validate_connection(conn)
    assert job_kind_for(conn) == "github-org"
    assert job_payload_for(conn) == {"org": "acme", "max_repos": 1000, "github_host": "", "base_url": "https://api.github.com"}


def test_github_needs_org_or_owner_repo():
    with pytest.raises(ConnectionError):
        validate_connection(Connection(provider="github", name="x", config={"owner": "a"}))


def test_aws_connection_needs_bucket():
    with pytest.raises(ConnectionError):
        validate_connection(Connection(provider="aws", name="prod", config={}))
    conn = Connection(provider="aws", name="prod", config={"bucket": "b", "region": "us-east-1"})
    validate_connection(conn)
    assert job_kind_for(conn) == "s3"
    assert job_payload_for(conn)["bucket"] == "b"


def test_notion_connection_needs_no_scope():
    conn = Connection(provider="notion", name="workspace", config={})
    validate_connection(conn)
    assert job_kind_for(conn) == "notion"


def test_unknown_provider_rejected():
    with pytest.raises(ConnectionError):
        validate_connection(Connection(provider="dropbox", name="x", config={}))


@pytest.mark.parametrize("bad_key", ["token", "aws_secret_access_key", "Password", "client_secret"])
def test_config_with_secret_rejected(bad_key):
    conn = Connection(provider="github", name="acme",
                      config={"owner": "a", "repo": "b", bad_key: "shhh"})
    with pytest.raises(ConnectionError) as exc:
        validate_connection(conn)
    assert "secret" in str(exc.value).lower()
