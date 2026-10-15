"""S3 reads on concurrent threads keep exact failure counts and failure keys."""

import io
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import ClassVar

from cremore.collectors.base import RequestBudget
from cremore_aws_provider.collectors.s3 import S3Collector

MODIFIED = datetime(2020, 1, 1, tzinfo=UTC)


class Denied(Exception):
    response: ClassVar[dict] = {"Error": {"Code": "AccessDenied"}}


class Archived(Exception):
    response: ClassVar[dict] = {"Error": {"Code": "InvalidObjectState"}}


class Bucket:
    def __init__(self, objects, *, together=1):
        self.objects, self.gets = objects, []
        self.barrier = threading.Barrier(together, timeout=5)

    def list_objects_v2(self, **_kwargs):
        return {"Contents": [{"Key": k, "Size": len(v), "ETag": f'"{k}"', "LastModified": MODIFIED}
                             for k, v in sorted(self.objects.items())], "IsTruncated": False}

    def get_object(self, Bucket, Key):
        self.gets.append(Key)
        try:
            self.barrier.wait()  # readers are inside their GETs at the same time
        except threading.BrokenBarrierError:
            pass
        if Key.startswith("denied/"):
            raise Denied()
        if Key.startswith("archived/"):
            raise Archived()
        data = self.objects[Key]
        return {"Body": io.BytesIO(data), "ContentLength": len(data), "ETag": f'"{Key}"', "LastModified": MODIFIED}


def test_concurrent_reads_keep_every_count_and_failure_key_exact():
    kinds = ("ok", "denied", "archived", "grown")
    objects = {f"{kinds[i % 4]}/{i:03d}": b"ordinary" for i in range(160)}
    bucket = Bucket(objects, together=8)
    budget = RequestBudget(10_000)
    collector = S3Collector(bucket, "bucket", lazy=True, max_object_bytes=32, request_budget=budget)
    listed = list(collector.collect())
    for key in objects:
        if key.startswith("grown/"):
            objects[key] = b"z" * 64  # changed after LIST: GET reads past the limit
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda obj: obj.read(), listed))
    assert collector.read_concurrency == 8 and collector.counts_read_failures is True
    assert sum(data is not None for data in results) == 40
    assert collector.failed_objects == 80 and collector.skipped_archived == 40
    assert collector.failed_keys == {k for k in objects if not k.startswith("ok/")}
    assert collector.requests == budget.used == 1 + 160
