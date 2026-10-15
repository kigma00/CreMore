"""Metadata-only listers for the catalog-refresh job (fake clients, no network)."""

import datetime as _dt
import uuid

import pytest

from cremore.collectors.base import CollectorError, RequestBudget, RequestBudgetExceeded
from cremore.scanning.catalog import list_resources

CID = str(uuid.uuid4())


class Resp:
    def __init__(self, status, payload):
        self.status_code, self._payload = status, payload

    def json(self):
        return self._payload


class FakeS3:
    def __init__(self, buckets, denied=()):
        self.buckets, self.denied, self.calls = buckets, set(denied), []

    def list_buckets(self, **kwargs):
        self.calls.append("list_buckets")
        return {"Buckets": [{"Name": b, "CreationDate": _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)} for b in self.buckets]}

    def head_bucket(self, Bucket):
        self.calls.append(f"head:{Bucket}")
        if Bucket in self.denied:
            raise RuntimeError("Forbidden")

    def get_object(self, **_):  # pragma: no cover - must never be called by a lister
        raise AssertionError("content read during a metadata listing")


def test_aws_account_listing_is_buckets_only_and_never_reads_content():
    s3 = FakeS3(["logs", "archive"])
    items, completeness = list_resources({"connection_kind": "aws", "connection_id": CID, "provider": "aws",
                                          "account_id": "123456789012"}, s3_client=lambda: s3)
    assert completeness == "COMPLETE" and [i["provider_resource_id"] for i in items] == ["logs", "archive"]
    assert items[0]["resource_type"] == "S3_BUCKET" and items[0]["account_id"] == "123456789012"
    assert items[0]["canonical_reference"] == "arn:aws:s3:::logs" and items[0]["content_readiness"] == "NOT_PROBED"
    assert s3.calls == ["list_buckets"]
    # a source connection is exactly its one bucket, confirmed with HeadBucket
    s3 = FakeS3([], denied=["secret"])
    items, _ = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "aws", "bucket": "secret"},
                              s3_client=lambda: s3)
    assert items[0]["list_visibility"] == "DENIED" and items[0]["reason_code"] == "RuntimeError"
    # an approved reference outside the connection's scope is never confirmed
    items, _ = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "aws", "bucket": "a",
                               "reference": "other"}, s3_client=lambda: s3)
    assert items[0]["list_visibility"] == "DENIED" and items[0]["reason_code"] == "OUT_OF_CONNECTION_SCOPE"


def test_aws_listing_failure_is_a_collector_error():
    class Broken(FakeS3):
        def list_buckets(self):
            raise RuntimeError("NoCredentials")

    with pytest.raises(CollectorError) as exc:
        list_resources({"connection_kind": "aws", "connection_id": CID, "provider": "aws"}, s3_client=lambda: Broken([]))
    assert exc.value.code == "S3_LIST_FAILED"


class FakeGH:
    def __init__(self, repos):
        self.repos = repos

    def get(self, url, headers=None):
        assert headers["Authorization"] == "Bearer ghp_t"
        if "/orgs/example-org/repos" in url:
            page = int(url.rsplit("page=", 1)[1])
            return Resp(200, self.repos if page == 1 else [])
        for r in self.repos:
            if url.endswith(f"/repos/{r['full_name']}"):
                return Resp(200, r)
        return Resp(404, {})


def _repo(name, **extra):
    return {"full_name": f"example-org/{name}", "name": name, "owner": {"login": "example-org"}, "private": True,
            "visibility": "private", "archived": False, "fork": False, "language": "Python", "topics": ["infra"],
            "default_branch": "main", "pushed_at": "2026-09-01T00:00:00Z", "html_url": f"https://github.com/example-org/{name}",
            **extra}


def test_github_personal_account_lists_its_own_private_repositories():
    class Personal:
        def __init__(self, login):
            self.login, self.urls = login, []

        def get(self, url, headers=None):
            self.urls.append(url)
            if "/orgs/" in url:
                return Resp(404, {})
            if url.endswith("/user"):
                return Resp(200, {"login": self.login})
            mine = [_repo("app", full_name="jun/app", owner={"login": "jun"}),
                    _repo("fork", full_name="elsewhere/fork", owner={"login": "elsewhere"})]
            return Resp(200, mine)

    payload = {"connection_kind": "source", "connection_id": CID, "provider": "github", "org": "jun", "token": "ghp_t"}
    own = Personal("JUN")
    items, completeness = list_resources(payload, http_client=lambda: own)
    # private repositories of the token's own account; a repository of another owner never enters the scope
    assert completeness == "COMPLETE" and [i["provider_resource_id"] for i in items] == ["jun/app"]
    assert items[0]["visibility"] == "PRIVATE" and "/user/repos?type=owner" in own.urls[-1]
    other = Personal("someone-else")
    items, completeness = list_resources(payload, http_client=lambda: other)
    assert completeness == "PARTIAL" and "/users/jun/repos?type=owner" in other.urls[-1]


def test_github_org_listing_carries_repository_metadata():
    gh = FakeGH([_repo("app"), _repo("infra", topics=[])])
    items, completeness = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "github",
                                          "org": "example-org", "token": "ghp_t"}, http_client=lambda: gh)
    assert completeness == "COMPLETE" and [i["provider_resource_id"] for i in items] == ["example-org/app", "example-org/infra"]
    app = items[0]
    assert app["resource_type"] == "GITHUB_REPOSITORY" and app["visibility"] == "PRIVATE" and app["default_branch"] == "main"
    assert app["organization_id"] == "example-org" and app["language"] == "Python" and app["last_edited_at"] == "2026-09-01T00:00:00Z"
    assert items[1]["topics"] == []
    # a reference outside the organisation is refused, one inside is confirmed
    with pytest.raises(CollectorError) as exc:
        list_resources({"connection_kind": "source", "connection_id": CID, "provider": "github", "org": "example-org",
                        "token": "ghp_t", "reference": "someone/else"}, http_client=lambda: gh)
    assert exc.value.code == "OUT_OF_CONNECTION_SCOPE"
    items, completeness = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "github",
                                          "org": "example-org", "token": "ghp_t", "reference": "example-org/app"},
                                         http_client=lambda: gh)
    assert completeness == "PARTIAL" and items[0]["provider_resource_id"] == "example-org/app"


class FakeNotion:
    def __init__(self, results):
        self.results, self.queries = results, []

    def post(self, url, headers=None, json=None):
        self.queries.append(json)
        return Resp(200, {"results": self.results, "has_more": False, "next_cursor": None})

    def get(self, url, headers=None):
        for r in self.results:
            if url.endswith(f"/v1/pages/{r['id']}") and r["object"] == "page":
                return Resp(200, r)
        return Resp(404, {})


def test_notion_search_lists_pages_and_data_sources_with_parents():
    page = {"object": "page", "id": "11111111-2222-3333-4444-555555555555", "url": "https://www.notion.so/Runbook-11111111222233334444555555555555",
            "parent": {"type": "database_id", "database_id": "db-1"}, "last_edited_time": "2026-09-02T00:00:00.000Z",
            "properties": {"Name": {"type": "title", "title": [{"plain_text": "Runbook"}]}}}
    db = {"object": "database", "id": "db-1", "title": [{"plain_text": "Ops"}], "parent": {"type": "workspace", "workspace": True}}
    notion = FakeNotion([page, db])
    items, completeness = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "notion", "token": "ntn_x"},
                                         http_client=lambda: notion)
    assert completeness == "COMPLETE" and [i["resource_type"] for i in items] == ["NOTION_PAGE", "NOTION_DATA_SOURCE"]
    assert items[0]["display_name"] == "Runbook" and items[0]["parent_id"] == "db-1" and items[0]["known_root_ids"] == ["db-1"]
    assert "parent_id" not in items[1] and items[1]["display_name"] == "Ops"
    # explicit metadata search passes the query and stays PARTIAL
    items, completeness = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "notion", "token": "ntn_x",
                                          "query": "Runbook"}, http_client=lambda: notion)
    assert completeness == "PARTIAL" and notion.queries[-1]["query"] == "Runbook"
    # a reference is confirmed by id (URL or dashed) through GET /v1/pages
    items, _ = list_resources({"connection_kind": "source", "connection_id": CID, "provider": "notion", "token": "ntn_x",
                               "reference": "https://www.notion.so/Runbook-11111111222233334444555555555555"}, http_client=lambda: notion)
    assert items[0]["provider_resource_id"] == page["id"] and items[0]["list_visibility"] == "VISIBLE"


def test_catalog_refresh_has_a_hard_provider_request_budget():
    gh = FakeGH([_repo(str(i)) for i in range(100)])
    with pytest.raises(RequestBudgetExceeded):
        list_resources(
            {"connection_kind": "source", "connection_id": CID, "provider": "github",
             "org": "example-org", "token": "ghp_t"},
            http_client=lambda: gh,
            request_budget=RequestBudget(1),
        )
