import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import ClassVar

import cremore_aws_provider.collectors.s3 as s3_module
import pytest
from cremore_aws_provider.collectors.s3 import S3Collector
from cremore_notion_provider.collectors.notion import NOTION_COLLECTOR_EPOCH, NotionCollector

from cremore.collectors.base import (
    CollectedObject,
    CollectorError,
    RequestBudget,
    RequestBudgetExceeded,
)
from cremore.collectors.scoped import ScopedCollector
from cremore.detection import ResourceRef


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status
        self.headers = {"Retry-After": "0"}

    def json(self):
        return self.data


class Notion:
    def __init__(self, blocks):
        self.blocks, self.calls = blocks, []

    def get(self, url, **kwargs):
        self.calls.append(url)
        if "/v1/pages/" in url:
            page = url.rsplit("/", 1)[1]
            return Response({"object": "page", "id": page, "url": f"https://notion.so/{page}",
                             "last_edited_time": "2026-09-15T00:00:00Z"})
        page = url.split("/v1/blocks/")[1].split("/")[0]
        return Response({"results": self.blocks[page], "has_more": False})

    def post(self, *_args, **_kwargs):
        raise AssertionError("an explicit page list must never search")


def paragraph(text):
    return {"type": "paragraph", "paragraph": {"rich_text": [{"plain_text": text}]}}


def test_notion_child_assets_are_boundaries_but_page_blocks_still_recurse():
    client = Notion({"parent": [
        {"type": "child_page", "id": "child", "has_children": True},
        {"type": "child_database", "id": "database", "has_children": True},
        {"type": "toggle", "id": "toggle", "has_children": True},
    ], "toggle": [paragraph("approved page body")], "child": [paragraph("separate body")]})
    collector = NotionCollector(client, "synthetic", page_ids=["parent"])
    [obj] = list(collector.collect())
    assert obj.data == b"approved page body" and obj.complete
    assert obj.resource.metadata["collector_epoch"] == NOTION_COLLECTOR_EPOCH
    assert obj.resource.metadata["page_id"] == "parent"
    assert obj.resource.revision == "2026-09-15T00:00:00Z"
    assert not collector.authoritative_listing and collector.failed_objects == 0
    assert not any("/blocks/child/" in call or "/blocks/database/" in call for call in client.calls)
    [child] = list(NotionCollector(client, "synthetic", page_ids=["child"]).collect())
    assert child.data == b"separate body" and child.resource.metadata["page_id"] == "child"


def test_notion_explicit_empty_scope_empty_page_and_partial_page_are_distinct():
    client = Notion({"empty": [], "long": [paragraph("long content")]})
    assert list(NotionCollector(client, "synthetic", page_ids=[]).collect()) == []
    assert client.calls == []
    [empty] = list(NotionCollector(client, "synthetic", page_ids=["empty"]).collect())
    assert empty.data == b"" and empty.complete
    collector = NotionCollector(client, "synthetic", page_ids=["long"], max_object_bytes=4)
    [partial] = list(collector.collect())
    assert partial.data == b"long" and not partial.complete and collector.failed_objects == 1


def test_notion_retry_budget_exhaustion_is_not_swallowed(monkeypatch):
    monkeypatch.setattr("cremore.http_client.time.sleep", lambda _delay: None)
    client = Notion({})
    client.get = lambda *_args, **_kwargs: Response({}, 429)
    collector = NotionCollector(client, "synthetic", page_ids=["parent"], request_budget=RequestBudget(1))
    with pytest.raises(RequestBudgetExceeded):
        list(collector.collect())
    assert collector.requests == 1


class Archived(Exception):
    response: ClassVar[dict] = {"Error": {"Code": "InvalidObjectState"}}


class S3:
    def __init__(self, objects):
        self.objects, self.downloads, self.list_calls, self.bodies = objects, [], [], []

    def list_objects_v2(self, **kwargs):
        self.list_calls.append(kwargs)
        return {"Contents": [{"Key": key, "Size": len(value.get("data", b"")),
                              "ETag": f'"{key}"', "LastModified": value["modified"],
                              "StorageClass": value.get("storage", "STANDARD")}
                             for key, value in self.objects.items()]}

    def get_object(self, *, Bucket, Key):
        self.downloads.append(Key)
        value = self.objects[Key]
        if value.get("archive"):
            raise Archived()
        body = BytesIO(value["data"])
        self.bodies.append(body)
        return {"Body": body, "ContentLength": len(value["data"]), "ETag": f'"{Key}"',
                "LastModified": value["modified"]}


def test_s3_archive_response_is_skipped_and_glacier_instant_retrieval_is_read():
    now = datetime.now(UTC)
    client = S3({"archived": {"modified": now, "data": b"x", "archive": True,
                              "storage": "INTELLIGENT_TIERING"},
                 "instant": {"modified": now, "data": b"readable", "storage": "GLACIER_IR"}})
    collector = S3Collector(client, "bucket")
    scoped = ScopedCollector([collector])
    [obj] = list(scoped.collect())
    assert obj.resource.location == "instant" and obj.data == b"readable"
    assert collector.failed_objects == 0 and collector.skipped_archived == 1
    assert scoped.coverage["skipped"] == 1 and scoped.coverage["skipped_archived"] == 1
    assert collector.failed_keys == {"archived"}
    assert all(body.closed for body in client.bodies)


@pytest.mark.parametrize("watermark", [None, "2026-09-14T00:00:00Z"])
def test_s3_normalizes_each_observation_once_and_uses_get_revision(monkeypatch, watermark):
    listed_modified = "2026-09-15T09:00:00+09:00"
    observed_modified = datetime(2026, 9, 15, 1, tzinfo=UTC)

    class UpdatedS3(S3):
        def get_object(self, **kwargs):
            return {**super().get_object(**kwargs), "ETag": '"updated"', "VersionId": "v2"}

    client = UpdatedS3({"config": {"modified": listed_modified, "data": b"old"}})
    collector = S3Collector(client, "bucket", lazy=True, watermark_since=watermark)
    normalized = []
    original_timestamp = s3_module._timestamp

    def timestamp(value):
        normalized.append(value)
        return original_timestamp(value)

    monkeypatch.setattr(s3_module, "_timestamp", timestamp)
    [obj] = list(collector.collect())
    listed_normalizations = normalized.copy()
    assert obj.resource.revision == json.dumps(
        ['"config"', 3, "2026-09-15T00:00:00+00:00"], separators=(",", ":"))
    assert obj.resource.metadata["last_modified"] == "2026-09-15T00:00:00+00:00"
    assert client.downloads == []

    # The object changes after LIST; the revision must still describe GET's bytes.
    client.objects["config"] = {"modified": observed_modified, "data": b"updated"}
    assert obj.read() == b"updated"
    assert obj.resource.revision == json.dumps(
        ['"updated"', 7, "2026-09-15T01:00:00+00:00"], separators=(",", ":"))
    assert obj.resource.metadata["last_modified"] == "2026-09-15T01:00:00+00:00"
    assert obj.resource.metadata["etag"] == '"updated"'
    assert obj.resource.version_id == "v2" and obj.resource.size == 7
    assert client.downloads == ["config"] and client.bodies[0].closed
    assert listed_normalizations == [listed_modified]
    assert normalized == [listed_modified, observed_modified]


def test_s3_watermark_filters_downloads_but_keeps_failed_and_boundary_keys():
    boundary = datetime(2026, 9, 15, tzinfo=UTC)
    older = boundary - timedelta(hours=1)
    client = S3({"old": {"modified": older, "data": b"unchanged"},
                 "retry": {"modified": older, "data": b"retry"},
                 "boundary": {"modified": boundary, "data": b"new"}})
    collector = S3Collector(client, "bucket", watermark_since=boundary, failed_keys=["retry"])
    objects = list(collector.collect())
    assert client.list_calls == [{"Bucket": "bucket"}]
    assert client.downloads == ["retry", "boundary"]
    assert collector.skipped_unchanged == 1 and collector.skipped_objects == 0
    assert collector.failed_keys == set() and not collector.authoritative_listing
    assert all(obj.resource.revision for obj in objects)


def test_lazy_reads_have_no_calls_on_cache_hit_and_charge_size_before_download():
    now = datetime.now(UTC)
    client = S3({"large": {"modified": now, "data": b"0123456789"}})
    collector = S3Collector(client, "bucket", lazy=True)
    scoped = ScopedCollector([collector], budget_bytes=5)
    assert list(scoped.collect()) == [] and client.downloads == []
    assert scoped.coverage["stopped_reason"] == "BUDGET_BYTES"
    [obj] = list(S3Collector(client, "bucket", lazy=True).collect())
    assert obj.data is None and client.downloads == []
    assert obj.read() == b"0123456789" and obj.read() == b"0123456789"
    assert client.downloads == ["large"]
    failed = CollectedObject(ResourceRef(), None, loader=lambda: None)
    assert failed.read() is None and failed.loader is None


def test_s3_missing_continuation_is_not_successful_absence():
    client = S3({})
    client.list_objects_v2 = lambda **_kwargs: {"IsTruncated": True}
    with pytest.raises(CollectorError, match="S3_LIST_INCOMPLETE"):
        list(S3Collector(client, "bucket").collect())
