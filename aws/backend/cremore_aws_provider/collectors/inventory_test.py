"""Inventory fixtures contain only synthetic metadata and mock S3 responses."""

import csv
import gzip
import hashlib
import io
import json
from datetime import UTC, datetime
from urllib.parse import quote

import pytest

from cremore.collectors.base import CollectorError, RequestBudget, RequestBudgetExceeded
from cremore_aws_provider.collectors import inventory
from cremore_aws_provider.collectors.inventory import S3InventoryCollector

SCHEMA = ["Bucket", "Key", "Size", "LastModifiedDate", "ETag"]
VERSIONS = ["Bucket", "Key", "VersionId", "IsLatest", "IsDeleteMarker", "Size", "LastModifiedDate", "ETag"]
PREFIX = "reports/source/config/"
CURRENT = PREFIX + "2026-09-10T00-00Z/manifest.json"
PRIOR = PREFIX + "2026-09-09T00-00Z/manifest.json"


def _row(key, *, etag="revision1", size=3, **fields):
    return {"Bucket": "source", "Key": quote(key, safe=""), "Size": str(size),
            "LastModifiedDate": "2026-09-08T00:00:00Z", "ETag": etag, **fields}


class S3Error(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class MockS3:
    def __init__(self, source=None):
        self.source = dict(source or {})
        self.reports = {}
        self.calls = []
        self.bodies = []
        self.denied = set()
        self.head_denied = set()

    def add_report(self, key, rows, *, schema=SCHEMA, compressed=True, **overrides):
        text = io.StringIO(newline="")
        writer = csv.writer(text)
        writer.writerows([[row.get(column, "") for column in schema] for row in rows])
        data = text.getvalue().encode()
        if compressed:
            data = gzip.compress(data)
        filename = key.split("/")[-2] + (".csv.gz" if compressed else ".csv")
        data_key = PREFIX + "data/" + filename
        self.reports[data_key] = data
        timestamp = "1788998400000" if key == PRIOR else "1789084800000"
        manifest = {"sourceBucket": "source", "destinationBucket": "arn:aws:s3:::inventory",
                    "version": "2016-11-30", "creationTimestamp": timestamp, "fileFormat": "CSV",
                    "fileSchema": ", ".join(schema), "files": [{"key": data_key, "size": len(data),
                    "MD5checksum": hashlib.md5(data, usedforsecurity=False).hexdigest()}], **overrides}
        self.reports[key] = json.dumps(manifest).encode()
        return manifest

    def get_object(self, *, Bucket, Key):
        self.calls.append(("get", Bucket, Key))
        if Key in self.denied:
            raise S3Error("AccessDenied")
        if Bucket == "inventory":
            data = self.reports[Key]
            extra = {}
        elif Bucket == "source":
            if Key not in self.source:
                raise S3Error("NoSuchKey")
            data = self.source[Key]
            extra = {"ETag": '"actual-get-etag"', "LastModified": datetime(2026, 9, 11, tzinfo=UTC),
                     "VersionId": "current-get-version"}
        else:
            raise AssertionError("unapproved bucket")
        body = io.BytesIO(data)
        self.bodies.append(body)
        return {"Body": body, "ContentLength": len(data), **extra}

    def head_object(self, *, Bucket, Key):
        self.calls.append(("head", Bucket, Key))
        assert Bucket == "source"
        if Key in self.head_denied:
            raise S3Error("AccessDenied")
        if Key not in self.source:
            raise S3Error("NoSuchKey")
        return {"ContentLength": len(self.source[Key])}

    def collector(self, **kwargs):
        return S3InventoryCollector(self, "source", manifest_bucket="inventory", manifest_key=CURRENT, **kwargs)


def test_unordered_create_update_delete_and_actual_get_revision():
    fake = MockS3({"unchanged": b"old", "updated": b"new", "created": b"new"})
    fake.add_report(PRIOR, [_row("deleted"), _row("updated"), _row("unchanged")])
    fake.add_report(CURRENT, [_row("unchanged"), _row("created"), _row("updated", etag="revision2")])
    collector = fake.collector(prior_manifest_key=PRIOR, known_finding_keys=["deleted", "unchanged"])
    objects = list(collector.collect())
    assert {obj.resource.location for obj in objects} == {"created", "updated"}
    assert collector.inventory_complete and not collector.authoritative_listing
    assert collector.skipped_unchanged == 1 and collector.failed_objects == 0
    assert collector.missing_finding_keys == collector.confirmed_missing_keys == {"deleted"}
    assert [call for call in fake.calls if call[0] == "head"] == [("head", "source", "deleted")]
    assert all(obj.resource.version_id == "current-get-version" for obj in objects)
    assert all("actual-get-etag" in obj.resource.revision for obj in objects)
    assert all(obj.resource.metadata["inventory_timestamp"] == collector.manifest_timestamp for obj in objects)
    assert all(body.closed for body in fake.bodies)


def test_scope_filters_key_decoding_and_failed_unchanged_retry():
    key = "approved/file name+value"
    fake = MockS3({key: b"new", "approved/excluded/key": b"old", "outside": b"old"})
    rows = [_row(key), _row("approved/excluded/key"), _row("outside")]
    fake.add_report(PRIOR, rows)
    fake.add_report(CURRENT, list(reversed(rows)), compressed=False)
    collector = fake.collector(prior_manifest_key=PRIOR, prefixes=["approved/"],
                               excluded_prefixes=["approved/excluded/"], failed_keys=[key, "outside"])
    assert [obj.resource.location for obj in collector.collect()] == [key]
    assert not collector.failed_keys
    assert [call[2] for call in fake.calls if call[:2] == ("get", "source")] == [key]


def test_version_history_and_delete_markers_only_select_latest_live_objects():
    fake = MockS3({"live": b"new"})
    rows = [_row("live", VersionId="old", IsLatest="false", IsDeleteMarker="false"),
            _row("live", VersionId="new", IsLatest="true", IsDeleteMarker="false"),
            _row("deleted", VersionId="old", IsLatest="false", IsDeleteMarker="false"),
            _row("deleted", VersionId="marker", IsLatest="true", IsDeleteMarker="true", Size="", ETag="")]
    fake.add_report(CURRENT, rows, schema=VERSIONS)
    collector = fake.collector(known_finding_keys=["deleted"])
    objects = list(collector.collect())
    assert [obj.resource.location for obj in objects] == ["live"]
    assert json.loads(objects[0].resource.metadata["inventory_revision"]) == ["version", "new"]
    assert collector.confirmed_missing_keys == {"deleted"}
    assert not any("VersionId" in str(call) for call in fake.calls)


@pytest.mark.parametrize("field", ["IsLatest", "IsDeleteMarker"])
def test_invalid_version_flags_never_publish_complete_coverage(field):
    fake = MockS3()
    row = _row("key", VersionId="current", IsLatest="true", IsDeleteMarker="false")
    row[field] = "invalid"
    fake.add_report(CURRENT, [row], schema=VERSIONS)
    collector = fake.collector()
    with pytest.raises(CollectorError, match="INVENTORY_INVALID_VERSION_FLAGS"):
        list(collector.collect())
    assert not collector.inventory_complete and not collector.confirmed_missing_keys


def test_missing_snapshot_object_recreated_now_is_read_not_removed():
    fake = MockS3({"recreated": b"new"})
    fake.add_report(CURRENT, [])
    collector = fake.collector(known_finding_keys=["recreated"])
    assert [obj.data for obj in collector.collect()] == [b"new"]
    assert collector.missing_finding_keys == {"recreated"} and not collector.confirmed_missing_keys


def test_an_object_deleted_after_the_report_is_confirmed_missing_by_its_read_not_failed():
    """Live in the report but deleted since: its GET's 404 is gone, not failed, and the inventory run keeps it as an
    exact removal (the runtime settles every part's confirmed_missing_keys)."""
    fake = MockS3({"kept": b"new"})
    fake.add_report(CURRENT, [_row("kept"), _row("deleted-since")])
    collector = fake.collector(known_finding_keys=["deleted-since"])
    assert [obj.resource.location for obj in collector.collect()] == ["kept"]
    assert [call[2] for call in fake.calls if call[:2] == ("get", "source")] == ["deleted-since", "kept"]
    assert not collector.missing_finding_keys and not [call for call in fake.calls if call[0] == "head"]
    assert collector.confirmed_missing_keys == {"deleted-since"}
    assert collector.failed_objects == 0 and not collector.failed_keys


def test_access_denied_is_not_absence_and_unreadable_keys_remain_retryable():
    fake = MockS3({"changed": b"new"})
    fake.denied.update({"changed", "uncertain"})
    fake.head_denied.add("uncertain")
    fake.add_report(CURRENT, [_row("changed")])
    collector = fake.collector(known_finding_keys=["uncertain"])
    assert list(collector.collect()) == []
    assert not collector.confirmed_missing_keys
    assert collector.failed_keys == {"changed", "uncertain"} and collector.failed_objects > 0


@pytest.mark.parametrize("override,code", [
    ({"sourceBucket": "another-source"}, "INVENTORY_BUCKET_MISMATCH"),
    ({"destinationBucket": "another-destination"}, "INVENTORY_BUCKET_MISMATCH"),
    ({"fileFormat": "Parquet"}, "INVENTORY_UNSUPPORTED_FORMAT"),
    ({"fileFormat": "ORC"}, "INVENTORY_UNSUPPORTED_FORMAT"),
    ({"fileSchema": "Bucket, Key"}, "INVENTORY_UNSUPPORTED_SCHEMA"),
    ({"version": "unknown"}, "INVENTORY_UNSUPPORTED_MANIFEST_VERSION"),
])
def test_misbound_or_unsupported_manifest_fails_before_data_reads(override, code):
    fake = MockS3()
    fake.add_report(CURRENT, [], **override)
    collector = fake.collector()
    with pytest.raises(CollectorError) as error:
        list(collector.collect())
    assert error.value.code == code and not collector.inventory_complete
    assert fake.calls == [("get", "inventory", CURRENT)]


@pytest.mark.parametrize("mutation", ["checksum", "file_prefix", "csv", "gzip", "row_bucket", "duplicate"])
def test_corrupt_reports_never_publish_complete_coverage(mutation):
    fake = MockS3()
    rows = [_row("key", Bucket="other" if mutation == "row_bucket" else "source")]
    if mutation == "duplicate":
        rows.append(rows[0])
    manifest = fake.add_report(CURRENT, rows)
    file = manifest["files"][0]
    if mutation == "checksum":
        file["MD5checksum"] = "0" * 32
    elif mutation == "file_prefix":
        file["key"] = "unapproved/private.csv.gz"
    elif mutation in ("csv", "gzip"):
        data = gzip.compress(b'"unclosed') if mutation == "csv" else b"not-gzip"
        fake.reports[file["key"]] = data
        file["size"] = len(data)
        file["MD5checksum"] = hashlib.md5(data, usedforsecurity=False).hexdigest()
    fake.reports[CURRENT] = json.dumps(manifest).encode()
    collector = fake.collector(known_finding_keys=["old"])
    with pytest.raises(CollectorError):
        list(collector.collect())
    assert not collector.inventory_complete and not collector.confirmed_missing_keys
    assert not any(call[0] == "head" or call[1] == "source" for call in fake.calls)
    assert all(body.closed for body in fake.bodies)


@pytest.mark.parametrize("limit,value", [("MAX_COMPRESSED_BYTES", 1), ("MAX_EXPANDED_BYTES", 1),
                                        ("MAX_ROWS", 0), ("MAX_FILES", 0), ("MAX_SECONDS", -1)])
def test_inventory_limits_fail_closed(limit, value, monkeypatch):
    fake = MockS3()
    fake.add_report(CURRENT, [_row("key")])
    monkeypatch.setattr(inventory, limit, value)
    collector = fake.collector()
    with pytest.raises(CollectorError):
        list(collector.collect())
    assert not collector.inventory_complete


def test_temporary_metadata_is_removed_after_success_and_failure(monkeypatch):
    created = []
    original = inventory.tempfile.TemporaryDirectory

    def temporary(**kwargs):
        result = original(**kwargs)
        created.append(result.name)
        return result

    monkeypatch.setattr(inventory.tempfile, "TemporaryDirectory", temporary)
    fake = MockS3({"key": b"new"})
    fake.add_report(CURRENT, [_row("key")])
    assert list(fake.collector().collect())
    fake.add_report(CURRENT, [_row("key", Bucket="wrong")])
    with pytest.raises(CollectorError):
        list(fake.collector().collect())
    assert len(created) == 2
    assert all(not inventory.Path(path).exists() for path in created)


def test_temporary_metadata_is_removed_when_consumer_closes_early(monkeypatch):
    created = []
    original = inventory.tempfile.TemporaryDirectory

    def temporary(**kwargs):
        result = original(**kwargs)
        created.append(result.name)
        return result

    monkeypatch.setattr(inventory.tempfile, "TemporaryDirectory", temporary)
    fake = MockS3({"one": b"new", "two": b"new"})
    fake.add_report(CURRENT, [_row("one"), _row("two")])
    stream = fake.collector().collect()
    assert next(stream).data == b"new"
    assert inventory.Path(created[0]).exists()
    stream.close()
    assert not inventory.Path(created[0]).exists()


def test_inventory_and_exact_reads_share_the_request_budget():
    fake = MockS3({"key": b"new"})
    fake.add_report(CURRENT, [_row("key")])
    collector = fake.collector(request_budget=RequestBudget(2))
    with pytest.raises(RequestBudgetExceeded):
        list(collector.collect())
    assert len(fake.calls) == collector.requests == 2


def test_prior_manifest_must_share_configuration_and_not_be_newer():
    fake = MockS3()
    with pytest.raises(ValueError):
        fake.collector(prior_manifest_key="other/config/2026-09-09/manifest.json")
    fake.add_report(CURRENT, [])
    fake.add_report(PRIOR, [], creationTimestamp="1789171200000")
    with pytest.raises(CollectorError) as error:
        list(fake.collector(prior_manifest_key=PRIOR).collect())
    assert error.value.code == "INVENTORY_MANIFEST_ORDER"
