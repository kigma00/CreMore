"""Opt-in S3 Inventory acceleration; never configures a bucket or inventory.

Only CSV reports at explicitly configured manifest locations are supported.
Unordered reports are compared in a bounded, per-run SQLite file inside a
private temporary directory. That file contains sensitive object names and
revision metadata, never object bodies, and is deleted even on failed runs.
Inventory is a delayed snapshot, not proof of current absence: only known
finding paths receive a current HEAD before deletion can be confirmed.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

from cremore.collectors.base import (
    DEFAULT_MAX_OBJECT_BYTES,
    CollectorError,
    RequestBudget,
    RequestBudgetExceeded,
    error_label,
)
from cremore_aws_provider.collectors.s3 import S3Collector, _revision

MAX_MANIFEST_BYTES = 4 << 20
MAX_COMPRESSED_BYTES = 4 << 30
MAX_EXPANDED_BYTES = 8 << 30
MAX_FILES = 10_000
MAX_ROWS = 10_000_000
MAX_SECONDS = 300
MAX_SQLITE_BYTES = 2 << 30
_BATCH = 128
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_MD5 = re.compile(r"[0-9a-fA-F]{32}\Z")


def _bucket_name(value: str) -> str:
    if value.startswith("arn:"):
        matched = re.fullmatch(r"arn:aws(?:-[a-z]+)*:s3:::([^:/]+)", value)
        return matched[1] if matched else ""
    return value


class _Counted(io.RawIOBase):
    """Bound compressed and expanded streams before CSV buffering."""

    def __init__(self, source, owner, *, compressed=False, expected=None):
        self.source, self.owner = source, owner
        self.compressed, self.expected = compressed, expected
        self.total = 0
        self.digest = hashlib.md5(usedforsecurity=False)

    def readable(self):
        return True

    def readinto(self, buffer):
        self.owner._check_time()
        data = self.source.read(min(len(buffer), 64 << 10))
        if not isinstance(data, bytes):
            raise CollectorError("INVENTORY_INVALID_STREAM")
        self.total += len(data)
        if self.compressed:
            self.owner._compressed += len(data)
            self.digest.update(data)
            if self.owner._compressed > MAX_COMPRESSED_BYTES or (
                self.expected is not None and self.total > self.expected
            ):
                raise CollectorError("INVENTORY_COMPRESSED_LIMIT")
        else:
            self.owner._expanded += len(data)
            if self.owner._expanded > MAX_EXPANDED_BYTES:
                raise CollectorError("INVENTORY_EXPANDED_LIMIT")
        buffer[:len(data)] = data
        return len(data)


class S3InventoryCollector:
    # A snapshot/delta must never trigger the legacy whole-connection reconcile.
    authoritative_listing = False

    def __init__(
        self, client, bucket: str, *, manifest_bucket: str, manifest_key: str,
        prior_manifest_key: str | None = None, prefixes: list[str] | None = None,
        excluded_prefixes: list[str] | None = None, known_finding_keys=(), failed_keys=(),
        region: str = "", account_id: str = "", max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
        partition: str = "aws",
        request_budget: RequestBudget | None = None,
    ):
        if not bucket or not manifest_bucket or max_object_bytes <= 0:
            raise ValueError("inventory requires source/destination buckets and a positive object limit")
        if partition not in ("aws", "aws-cn", "aws-us-gov", "aws-eusc"):
            raise ValueError("AWS_PARTITION_UNAVAILABLE")
        self.client, self.bucket = client, bucket
        self.manifest_bucket, self.manifest_key = manifest_bucket, manifest_key
        self.prior_manifest_key = prior_manifest_key
        self._report_prefix = self._manifest_prefix(manifest_key)
        if prior_manifest_key and self._manifest_prefix(prior_manifest_key) != self._report_prefix:
            raise ValueError("prior manifest must belong to the same inventory configuration")
        self.prefixes, self.excluded_prefixes = list(prefixes or []), list(excluded_prefixes or [])
        self.known_finding_keys = {key for key in known_finding_keys if self._selected(key)}
        self.failed_keys = {key for key in failed_keys if self._selected(key)}
        self.region, self.account_id = region, account_id
        self.partition = partition
        self.max_object_bytes = max_object_bytes
        self.request_budget = request_budget or RequestBudget()
        self.failed_objects = self.skipped_archived = self.skipped_unchanged = 0
        self.inventory_complete = False
        self.manifest_timestamp: str | None = None
        self.missing_finding_keys: set[str] = set()
        self.confirmed_missing_keys: set[str] = set()
        self._missing_checked = False
        self._current_finding_keys: set[str] = set()
        self._requests = self._source_requests = 0
        self._compressed = self._expanded = self._rows = 0
        self._active_child = None
        self._deadline = 0.0

    @staticmethod
    def _manifest_prefix(key):
        parts = key.split("/")
        if len(parts) < 3 or parts[-1] != "manifest.json" or any(p in ("", ".", "..") for p in parts):
            raise ValueError("inventory manifest must use its existing configuration/date/manifest.json path")
        return "/".join(parts[:-2]) + "/"

    def _selected(self, key):
        return (isinstance(key, str) and bool(key) and len(key.encode("utf-8")) <= 1024
                and (not self.prefixes or any(key.startswith(p) for p in self.prefixes))
                and not any(key.startswith(p) for p in self.excluded_prefixes))

    @property
    def requests(self):
        return self._requests + self._source_requests + (self._active_child.requests if self._active_child else 0)

    @property
    def skipped_objects(self):
        return self.skipped_archived

    def _check_time(self):
        if time.monotonic() > self._deadline:
            raise CollectorError("INVENTORY_TIME_LIMIT")

    def _request(self):
        self._check_time()
        self.request_budget.consume()
        self._requests += 1

    def _manifest(self, key):
        self._request()
        response = self.client.get_object(Bucket=self.manifest_bucket, Key=key)
        body = response["Body"]
        try:
            if int(response.get("ContentLength", 0)) > MAX_MANIFEST_BYTES:
                raise CollectorError("INVENTORY_MANIFEST_LIMIT")
            data = body.read(MAX_MANIFEST_BYTES + 1)
            if len(data) > MAX_MANIFEST_BYTES:
                raise CollectorError("INVENTORY_MANIFEST_LIMIT")
            manifest = json.loads(data)
        finally:
            body.close()
        if not isinstance(manifest, dict):
            raise CollectorError("INVENTORY_INVALID_MANIFEST")
        if (_bucket_name(str(manifest.get("sourceBucket", ""))) != self.bucket
                or _bucket_name(str(manifest.get("destinationBucket", ""))) != self.manifest_bucket):
            raise CollectorError("INVENTORY_BUCKET_MISMATCH")
        if manifest.get("fileFormat") != "CSV":
            raise CollectorError("INVENTORY_UNSUPPORTED_FORMAT", "CSV_REQUIRED")
        if manifest.get("version") != "2016-11-30":
            raise CollectorError("INVENTORY_UNSUPPORTED_MANIFEST_VERSION")
        schema = [part.strip() for part in str(manifest.get("fileSchema", "")).split(",")]
        required = {"Bucket", "Key", "Size", "LastModifiedDate", "ETag"}
        versions = {"VersionId", "IsLatest", "IsDeleteMarker"}
        if (len(schema) != len(set(schema)) or not required.issubset(schema)
                or (versions.intersection(schema) and not versions.issubset(schema))):
            raise CollectorError("INVENTORY_UNSUPPORTED_SCHEMA")
        timestamp = datetime.fromtimestamp(int(manifest["creationTimestamp"]) / 1000, UTC)
        if timestamp > datetime.now(UTC):
            raise CollectorError("INVENTORY_FUTURE_MANIFEST")
        files = manifest.get("files")
        if not isinstance(files, list) or len(files) > MAX_FILES:
            raise CollectorError("INVENTORY_FILE_LIMIT")
        seen = set()
        for item in files:
            name = item.get("key", "")
            if (not isinstance(name, str) or not name.startswith(self._report_prefix + "data/")
                    or any(p in ("", ".", "..") for p in name.split("/"))
                    or not name.endswith((".csv", ".csv.gz")) or name in seen):
                raise CollectorError("INVENTORY_UNTRUSTED_DATA_KEY")
            seen.add(name)
            if not isinstance(item.get("size"), int) or item["size"] < 0:
                raise CollectorError("INVENTORY_INVALID_FILE_SIZE")
            checksum = item.get("MD5checksum")
            if checksum is not None and not _MD5.fullmatch(str(checksum)):
                raise CollectorError("INVENTORY_INVALID_CHECKSUM")
        return manifest, schema, timestamp

    def _rows_from_file(self, item, schema):
        self._request()
        response = self.client.get_object(Bucket=self.manifest_bucket, Key=item["key"])
        body = response["Body"]
        try:
            if response.get("ContentLength") is not None and int(response["ContentLength"]) != item["size"]:
                raise CollectorError("INVENTORY_FILE_SIZE_MISMATCH")
            counted = _Counted(body, self, compressed=True, expected=item["size"])
            with io.BufferedReader(counted) as compressed:
                decoded = gzip.GzipFile(fileobj=compressed, mode="rb") if item["key"].endswith(".gz") else compressed
                try:
                    with io.TextIOWrapper(io.BufferedReader(_Counted(decoded, self)), encoding="utf-8", newline="") as text:
                        for row in csv.reader(text, strict=True):
                            self._rows += 1
                            if self._rows > MAX_ROWS:
                                raise CollectorError("INVENTORY_ROW_LIMIT")
                            if len(row) != len(schema):
                                raise CollectorError("INVENTORY_ROW_SCHEMA_MISMATCH")
                            yield dict(zip(schema, row))
                finally:
                    if decoded is not compressed:
                        decoded.close()
            if counted.total != item["size"]:
                raise CollectorError("INVENTORY_FILE_SIZE_MISMATCH")
            if item.get("MD5checksum") and counted.digest.hexdigest() != item["MD5checksum"].lower():
                raise CollectorError("INVENTORY_CHECKSUM_MISMATCH")
        finally:
            body.close()

    def _read_report(self, db, table, manifest, schema):
        batch = []
        for item in manifest["files"]:
            for row in self._rows_from_file(item, schema):
                if row["Bucket"] != self.bucket:
                    raise CollectorError("INVENTORY_ROW_BUCKET_MISMATCH")
                encoded = row["Key"]
                if _BAD_PERCENT.search(encoded):
                    raise CollectorError("INVENTORY_INVALID_KEY_ENCODING")
                key = unquote(encoded, encoding="utf-8", errors="strict")
                if not key or len(key.encode("utf-8")) > 1024:
                    raise CollectorError("INVENTORY_INVALID_KEY")
                deleted = False
                if "IsLatest" in row:
                    if row["IsLatest"] not in ("true", "false") or row["IsDeleteMarker"] not in ("true", "false"):
                        raise CollectorError("INVENTORY_INVALID_VERSION_FLAGS")
                    if row["IsLatest"] == "false":
                        continue
                    deleted = row["IsDeleteMarker"] == "true"
                if not self._selected(key):
                    continue
                revision = ""
                if not deleted:
                    size = int(row["Size"])
                    if size < 0:
                        raise CollectorError("INVENTORY_INVALID_OBJECT_SIZE")
                    revision = _revision({"ETag": row["ETag"], "Size": size, "LastModified": row["LastModifiedDate"]})
                    if not revision:
                        raise CollectorError("INVENTORY_INVALID_REVISION")
                    version = row.get("VersionId")
                    if version and version != "null":
                        revision = json.dumps(["version", version], separators=(",", ":"))
                batch.append((key, revision, int(deleted)))
                if len(batch) >= _BATCH:
                    db.executemany(f"INSERT INTO {table} VALUES (?,?,?)", batch)
                    batch.clear()
        if batch:
            db.executemany(f"INSERT INTO {table} VALUES (?,?,?)", batch)

    def confirm_missing(self):
        """Confirm only finding paths absent from the validated delayed snapshot."""
        if not self.inventory_complete:
            raise ValueError("inventory must complete before checking absence")
        if self._missing_checked:
            return set(self.confirmed_missing_keys)
        for key in sorted(self.missing_finding_keys):
            if not self._selected(key):
                continue
            self._request()
            try:
                self.client.head_object(Bucket=self.bucket, Key=key)
                self._current_finding_keys.add(key)
            except Exception as exc:  # noqa: BLE001 -- SDK and injected clients expose different error types
                if error_label(exc) in ("NoSuchKey", "NotFound", "404"):
                    self.confirmed_missing_keys.add(key)
                    self.failed_keys.discard(key)
                else:
                    self.failed_objects += 1
                    self.failed_keys.add(key)
        self._missing_checked = True
        return set(self.confirmed_missing_keys)

    def collect(self):
        self._deadline = time.monotonic() + MAX_SECONDS
        try:
            current, current_schema, current_time = self._manifest(self.manifest_key)
            previous = self._manifest(self.prior_manifest_key) if self.prior_manifest_key else None
            if previous is not None and previous[2] > current_time:
                raise CollectorError("INVENTORY_MANIFEST_ORDER")
            # ponytail: per-run disk limit; partition the inventory for larger reports.
            with tempfile.TemporaryDirectory(prefix="cremore-inventory-") as directory:
                os.chmod(directory, 0o700)
                path = Path(directory) / "revisions.sqlite3"
                db = sqlite3.connect(path)
                os.chmod(path, 0o600)
                try:
                    db.execute("PRAGMA journal_mode=OFF")
                    db.execute("PRAGMA temp_store=MEMORY")
                    db.execute("PRAGMA cache_size=-8192")
                    page_size = db.execute("PRAGMA page_size").fetchone()[0]
                    db.execute(f"PRAGMA max_page_count={max(1, MAX_SQLITE_BYTES // page_size)}")
                    for table in ("current_objects", "prior_objects"):
                        db.execute(f"CREATE TABLE {table} (key TEXT PRIMARY KEY, revision TEXT NOT NULL, deleted INTEGER NOT NULL)")
                    if previous is not None:
                        self._read_report(db, "prior_objects", previous[0], previous[1])
                    self._read_report(db, "current_objects", current, current_schema)
                    db.execute("CREATE TABLE watched (key TEXT PRIMARY KEY)")
                    db.executemany("INSERT INTO watched VALUES (?)", ((key,) for key in self.known_finding_keys))
                    self.missing_finding_keys = {row[0] for row in db.execute(
                        "SELECT w.key FROM watched w LEFT JOIN current_objects c ON c.key=w.key "
                        "WHERE c.key IS NULL OR c.deleted=1"
                    )}
                    self.inventory_complete = True
                    self.manifest_timestamp = current_time.isoformat()
                    self.confirm_missing()
                    db.execute("CREATE TABLE work (key TEXT PRIMARY KEY, revision TEXT NOT NULL)")
                    db.execute("INSERT INTO work SELECT c.key,c.revision FROM current_objects c "
                               "LEFT JOIN prior_objects p ON p.key=c.key "
                               "WHERE c.deleted=0 AND (p.key IS NULL OR p.deleted=1 OR p.revision!=c.revision)")
                    db.executemany("INSERT OR IGNORE INTO work VALUES (?, '')", (
                        (key,) for key in (self.failed_keys | self._current_finding_keys) - self.confirmed_missing_keys
                        if self._selected(key)
                    ))
                    self.skipped_unchanged = db.execute(
                        "SELECT COUNT(*) FROM current_objects c WHERE c.deleted=0 "
                        "AND NOT EXISTS (SELECT 1 FROM work w WHERE w.key=c.key)"
                    ).fetchone()[0]
                    cursor = db.execute("SELECT key,revision FROM work ORDER BY key")
                    while batch := cursor.fetchmany(_BATCH):
                        self._check_time()
                        revisions = dict(batch)
                        child = S3Collector(
                            self.client, self.bucket, keys=list(revisions), region=self.region,
                            account_id=self.account_id, excluded_prefixes=self.excluded_prefixes,
                            partition=self.partition,
                            max_object_bytes=self.max_object_bytes, request_budget=self.request_budget,
                        )
                        self._active_child = child
                        try:
                            for obj in child.collect():
                                if self._selected(obj.resource.location):
                                    obj.resource.metadata["inventory_revision"] = revisions[obj.resource.location]
                                    obj.resource.metadata["inventory_timestamp"] = self.manifest_timestamp
                                    self.failed_keys.discard(obj.resource.location)
                                    yield obj
                        finally:
                            self._source_requests += child.requests
                            self.failed_objects += child.failed_objects
                            self.skipped_archived += child.skipped_archived
                            self.failed_keys.update(child.failed_keys)
                            # A GET's 404 (deleted since the report) is an exact removal, settled with this run's.
                            self.confirmed_missing_keys.update(child.confirmed_missing_keys)
                            self._active_child = None
                finally:
                    db.close()
        except (CollectorError, RequestBudgetExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 -- persist only a safe label, never keys or provider response bodies
            raise CollectorError("INVENTORY_INVALID_REPORT", error_label(exc)) from None
