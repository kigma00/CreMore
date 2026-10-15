"""AWS S3 collector.

Lists and reads objects in a bucket (optionally under a prefix) and yields them
for scanning. The boto3 S3 client is injected so the collector is testable
without AWS. Reachability is read from the bucket's public-access configuration
when available and recorded so the risk model can score exposure.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime

from cremore.collectors.base import (
    DEFAULT_MAX_OBJECT_BYTES,
    CollectedObject,
    CollectorError,
    RequestBudget,
    error_label,
)
from cremore.detection import ResourceRef

# A resumed run HEADs at most this many watched keys at or before its cursor (confirm_before_start), from a place its run
# id picks; the others wait for the next whole run or another resumed run.
MAX_REMOVAL_CHECKS = 1000


class S3Collector:
    authoritative_listing = True
    # Lazy GETs overlap on the scan's read-ahead threads (cremore.scanning.prefetch);
    # every counter and failure set a GET touches is changed under ``_lock``.
    read_concurrency = 8
    counts_read_failures = True

    def __init__(
        self,
        client,
        bucket: str,
        *,
        prefix: str = "",
        region: str = "",
        account_id: str = "",
        partition: str = "aws",
        max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
        max_requests: int = 10000,
        prefixes: list[str] | None = None,
        excluded_prefixes: list[str] | None = None,
        keys: list[str] | None = None,
        request_budget: RequestBudget | None = None,
        watermark_since: datetime | str | None = None,
        failed_keys: list[str] | None = None,
        lazy: bool = False,
        watched_keys: list[str] | None = None,
        start_after: str = "",
    ) -> None:
        if max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be positive")
        if partition not in ("aws", "aws-cn", "aws-us-gov", "aws-eusc"):
            raise ValueError("AWS_PARTITION_UNAVAILABLE")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.region = region
        self.account_id = account_id
        self.partition = partition
        self.max_object_bytes = max_object_bytes
        self.request_budget = request_budget or RequestBudget(max_requests)
        # Approved scope: several included key prefixes (each listed on its own),
        # excluded prefixes (exclusions win), or exact keys (a rescan: read
        # only those, never list).
        self.prefixes = list(prefixes or [])
        self.excluded_prefixes = list(excluded_prefixes or [])
        self.keys = list(keys or [])
        self.watermark_since = _timestamp(watermark_since) if watermark_since is not None else None
        if watermark_since is not None and self.watermark_since is None:
            raise ValueError("watermark_since must be an ISO timestamp")
        self.retry_keys = frozenset(failed_keys or [])
        self.failed_keys: set[str] = set(self.retry_keys)
        # Those of failed_keys refused as archived: reported as skipped, not failed. ``unarchived``: keys that failed here
        # otherwise, so an earlier attempt's archive refusal of them no longer stands (a read that works drops the key
        # from the failures themselves).
        self.archived_keys: set[str] = set()
        self.unarchived: set[str] = set()
        self.retry_overflow = False
        # False when the task already read again every failed key at or before start_after: they stay in failed_keys,
        # and are not read again (cremore.worker.runtime sets it on an attempt resumed after that).
        self.retry_before_start = True
        self.lazy = lazy
        self.start_after = start_after
        self.missing_keys = set(watched_keys or [])
        self.confirmed_missing_keys: set[str] = set()
        # Keys older than the delta watermark still need an exact revision
        # comparison before a stored exposure can be observed again.
        self._watched = frozenset(watched_keys or [])
        self.unchanged_locations: set[str] = set()
        self.unchanged_revisions: dict[str, str] = {}
        self.listing_complete = False
        # Watched keys after start_after that a resumed listing, run to its end, did not name. Every approved prefix
        # is listed from StartAfter on, so that listing is complete for the approved keys after the cursor; keys at or
        # before it are settled only by a 404, a GET's (confirmed_missing_keys) or confirm_before_start's HEAD.
        self.missing_after_start: set[str] = set()
        # The approved watched keys at or before start_after that such a listing neither named nor read again, sorted:
        # confirm_before_start checks them.
        self.unseen_before_start: list[str] = []
        self.last_key = ""
        # Exact keys were never listed. Delta runs intentionally omit unchanged
        # detections and cannot support the legacy seen-exposure reconciliation.
        self.authoritative_listing = not self.keys and self.watermark_since is None
        # Objects that were listed but could not be read (permission, transient).
        self.failed_objects = 0
        self.skipped_archived = 0
        self.skipped_unchanged = 0
        # S3 API calls made (list pages + object reads).
        self.requests = 0
        self._lock = threading.Lock()

    def _request(self) -> None:
        self.request_budget.consume()
        with self._lock:
            self.requests += 1

    def _failed(self, key, counter="failed_objects"):
        with self._lock:
            setattr(self, counter, getattr(self, counter) + 1)
            if key in self.failed_keys or len(self.failed_keys) < 10_000:
                self.failed_keys.add(key)
                if counter == "skipped_archived":
                    self.archived_keys.add(key)
                    self.unarchived.discard(key)
                else:
                    self.archived_keys.discard(key)
                    self.unarchived.add(key)
            else:
                self.retry_overflow = True

    def _exposure(self) -> str:
        """internal when public access is fully blocked, else unknown."""

        get_pab = getattr(self.client, "get_public_access_block", None)
        if get_pab is None:
            return "unknown"
        self._request()
        try:
            cfg = get_pab(Bucket=self.bucket).get("PublicAccessBlockConfiguration", {})
        except Exception:  # noqa: BLE001 -- A failed public-access lookup establishes neither public nor private access.
            return "unknown"
        if cfg and all(cfg.get(k) for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
        )):
            return "internal"
        return "unknown"

    def collect(self) -> Iterator[CollectedObject]:
        exposure = self._exposure()
        if self.keys:
            for key in self.keys:
                if not self._excluded(key):
                    obj = self._object(key, {}, exposure)
                    # Without listing metadata an exact-key read has no safe
                    # size estimate for the lazy collector's byte budget.
                    if obj.read() is not None:
                        yield obj
            return
        # A resumed suffix must still retry earlier failures, once a task. The cursor
        # marks committed progress, not proof that every preceding object was read.
        if self.start_after and self.retry_before_start:
            for key in sorted(self.retry_keys):
                if key <= self.start_after and self._approved(key):
                    obj = self._object(key, {}, exposure)
                    if obj.read() is not None:
                        yield obj
        for prefix in (self.prefixes or [self.prefix]):
            yield from self._list(prefix, exposure)
        self.listing_complete = not self.start_after
        if self.start_after:
            self.missing_after_start = {
                key for key in self.missing_keys if key > self.start_after and self._approved(key)}
            read_again = self.retry_keys if self.retry_before_start else frozenset()
            self.unseen_before_start = sorted(
                key for key in self.missing_keys
                if key <= self.start_after and key not in read_again and self._approved(key))

    def confirm_before_start(self, run_id: str) -> None:
        """HEAD at most MAX_REMOVAL_CHECKS of ``unseen_before_start``, once the run committed what it listed.

        Keys of no earlier failure (open exposures) come first, then earlier failures, each from a place a digest of
        ``run_id`` picks: with more candidates than the cap, successive runs check different ones. Only a 404 confirms
        a key missing; a denial or any other answer settles nothing for it. A spent budget ends the checks with what
        they confirmed, as the cap does: the keys left wait for the next whole run or another resumed run.
        """
        from cremore_aws_provider.aws_identity import is_login_required

        exposures = [key for key in self.unseen_before_start if key not in self.retry_keys]
        failures = [key for key in self.unseen_before_start if key in self.retry_keys]
        keys = (_rotated(exposures, run_id) + _rotated(failures, run_id))[:MAX_REMOVAL_CHECKS]
        self.unseen_before_start = []
        for key in keys:
            try:
                self._request()
            except CollectorError as exc:
                if exc.code.startswith("BUDGET_"):
                    return
                raise
            try:
                self.client.head_object(Bucket=self.bucket, Key=key)
            except Exception as exc:  # SDK and injected clients expose different error classes.
                if is_login_required(exc):
                    raise
                if error_label(exc) in ("NoSuchKey", "NotFound", "404"):
                    with self._lock:
                        self.confirmed_missing_keys.add(key)

    def _excluded(self, key: str) -> bool:
        return any(key.startswith(p) for p in self.excluded_prefixes)

    def _approved(self, key: str) -> bool:
        return not self._excluded(key) and any(key.startswith(p) for p in (self.prefixes or [self.prefix]))

    @property
    def skipped_objects(self) -> int:
        return self.skipped_archived

    def _object(self, key: str, listed: dict, exposure: str, modified: str = "") -> CollectedObject:
        resource = ResourceRef(
                source_type="s3",
                resource=self.bucket,
                location=key,
                resource_arn=f"arn:{self.partition}:s3:::{self.bucket}/{key}",
                account_id=self.account_id,
                region=self.region,
                size=int(listed.get("Size", 0) or 0),
                revision=_revision(listed, modified),
                metadata={"exposure": exposure, "root_id": self.bucket,
                          "last_modified": modified,
                          "etag": str(listed.get("ETag") or "")},
        )
        return CollectedObject(resource, None, loader=lambda: self._get(key, resource))

    def _list(self, prefix: str, exposure: str) -> Iterator[CollectedObject]:
        token: str | None = None
        while True:
            kwargs = {"Bucket": self.bucket}
            if prefix:
                kwargs["Prefix"] = prefix
            if token:
                kwargs["ContinuationToken"] = token
            elif self.start_after:
                kwargs["StartAfter"] = self.start_after
            self._request()
            try:
                page = self.client.list_objects_v2(**kwargs)
            except Exception as exc:
                # No credentials, AccessDenied, NoSuchBucket…: the scope was
                # never listed, so this run must not read as a clean, empty one.
                raise CollectorError("S3_LIST_FAILED", error_label(exc)) from exc
            for obj in page.get("Contents", []):
                key = obj.get("Key", "")
                size = int(obj.get("Size", 0) or 0)
                if not key or self._excluded(key):
                    continue
                self.missing_keys.discard(key)
                if size > self.max_object_bytes:
                    self._failed(key)
                    continue
                modified = _timestamp(obj.get("LastModified"))
                if (self.watermark_since is not None and modified is not None
                        and modified < self.watermark_since and key not in self.retry_keys):
                    self.skipped_unchanged += 1
                    if key in self._watched:
                        self.unchanged_locations.add(key)
                        self.unchanged_revisions[key] = _revision(obj, modified.isoformat())
                    continue
                collected = self._object(
                    key, obj, exposure, modified.isoformat() if modified is not None else "")
                if self.lazy or collected.read() is not None:
                    yield collected
                self.last_key = key
            if not page.get("IsTruncated"):
                return
            next_token = page.get("NextContinuationToken")
            if not next_token or next_token == token:
                raise CollectorError("S3_LIST_INCOMPLETE", "invalid continuation token")
            token = next_token

    def _get(self, key: str, resource: ResourceRef) -> bytes | None:
        self._request()
        body = None
        try:
            resp = self.client.get_object(Bucket=self.bucket, Key=key)
            body = resp["Body"]
            # A retried key that failed on its listed size, or an object grown since it was listed: refused on the
            # size GET reports, before its body is read.
            if int(resp.get("ContentLength") or 0) > self.max_object_bytes:
                self._failed(key)
                return None
            data = body.read(self.max_object_bytes + 1)
            if len(data) > self.max_object_bytes:
                self._failed(key)
                return None
            # GET's metadata describes the bytes actually read even if the
            # object changed after ListObjectsV2; no per-object HEAD is needed.
            observed = {"ETag": resp.get("ETag"), "Size": resp.get("ContentLength", len(data)),
                        "LastModified": resp.get("LastModified")}
            modified = _iso(observed["LastModified"])
            resource.revision = _revision(observed, modified)
            resource.version_id = str(resp.get("VersionId") or "")
            resource.size = len(data)
            if observed["LastModified"] is not None:
                resource.metadata["last_modified"] = modified
            if observed["ETag"] is not None:
                resource.metadata["etag"] = str(observed["ETag"])
            with self._lock:
                self.failed_keys.discard(key)
                self.archived_keys.discard(key)
            return data
        except Exception as exc:  # SDK and injected clients expose different error classes.
            from cremore_aws_provider.aws_identity import is_login_required

            if is_login_required(exc):
                raise  # an expired sign-in pauses the whole root; it is not one unreadable object
            if error_label(exc) in ("NoSuchKey", "NotFound", "404"):
                # Gone, not unreadable: the run settles it as removed (cremore.worker.runtime), never as a failure.
                with self._lock:
                    self.confirmed_missing_keys.add(key)
                    self.failed_keys.discard(key)
                    self.archived_keys.discard(key)
                return None
            # InvalidObjectState includes Intelligent-Tiering archive access. GLACIER_IR
            # is immediately readable and must not be excluded by its name.
            self._failed(key, "skipped_archived" if error_label(exc) == "InvalidObjectState" else "failed_objects")
            return None
        finally:
            close = getattr(body, "close", None)
            if close:
                try:
                    close()
                except Exception:  # noqa: BLE001, S110 -- Best-effort close must not replace the result or log credential-bearing errors.
                    pass


def _rotated(keys: list[str], seed: str) -> list[str]:
    """``keys`` in order from a place a digest of ``seed`` picks, wrapping around."""
    if not keys:
        return keys
    start = int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big") % len(keys)
    return keys[start:] + keys[:start]


def _timestamp(value) -> datetime | None:
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        return None


def _iso(value) -> str:
    timestamp = _timestamp(value)
    return timestamp.isoformat() if timestamp is not None else ""


def _revision(metadata: dict, modified: str | None = None) -> str:
    if modified is None:
        modified = _iso(metadata.get("LastModified"))
    etag = metadata.get("ETag")
    if not etag or not modified:
        return ""
    return json.dumps([str(etag), int(metadata.get("Size", 0) or 0), modified], separators=(",", ":"))
