"""Worker-level scan benchmark: a first scan, an unchanged full rescan, serial against overlapping reads.

Synthetic and local: the in-memory repository and a fake S3 client that waits ``--latency`` seconds
per GET. No network, no database server. The bucket mixes plain text, a few credential-bearing
files, PNG images, PDF-like documents and binary blobs. The figures are an upper bound for the
runtime itself (no database round trips, no real network), not production timings.

    python scripts/benchmark_worker_scan.py --assert

Prints "WORKER BENCH OK first=<s>s rescan_reads=0 ..."; with --assert it exits nonzero when the
unchanged RECONCILE rescan reads any object or overlapping reads are not faster than serial reads.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import time

TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
MODIFIED = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


class Bucket:
    """Fake S3: sorted single-page listings, GETs that wait a fixed latency."""

    def __init__(self, objects, latency):
        self.objects, self.latency, self.reads = objects, latency, []

    def etag(self, key):
        return '"' + hashlib.sha256(self.objects[key]).hexdigest()[:16] + '"'

    def list_objects_v2(self, **kwargs):
        keys = sorted(k for k in self.objects if k.startswith(kwargs.get("Prefix", "")) and k > kwargs.get("StartAfter", ""))
        return {"Contents": [{"Key": k, "Size": len(self.objects[k]), "ETag": self.etag(k), "LastModified": MODIFIED}
                             for k in keys], "IsTruncated": False}

    def get_object(self, Bucket, Key):
        time.sleep(self.latency)
        self.reads.append(Key)
        data = self.objects[Key]
        return {"Body": io.BytesIO(data), "ContentLength": len(data), "ETag": self.etag(Key), "LastModified": MODIFIED}


def corpus(text, secrets, images, documents, binaries):
    objects = {f"data/text/{i:04d}.txt": f"service log line {i}\nstatus=ok\n".encode() * 8 for i in range(text)}
    objects.update({f"data/keys/{i:02d}.env": f"TOKEN={TOKEN[:-2]}{i:02d}\n".encode() for i in range(secrets)})
    objects.update({f"data/img/{i:03d}.png": b"\x89PNG\r\n\x1a\n" + bytes(range(64)) * 4 for i in range(images)})
    objects.update({f"data/doc/{i:02d}.pdf": b"%PDF-1.4\n1 0 obj << >> endobj\n" + bytes([i]) for i in range(documents)})
    objects.update({f"data/bin/{i:03d}.bin": bytes(range(256)) + i.to_bytes(2, "big") for i in range(binaries)})
    return objects


class Scope:
    """One approved S3 root in a fresh in-memory installation, scanned by the real worker runtime."""

    def __init__(self, objects, latency):
        from cremore.db.repository import InMemoryRepository
        from cremore.domain.models import Connection, ScopeCatalog, ScopeProfile
        from cremore.scanning import scope
        from cremore.worker.factory import build_collector
        from cremore.worker.worker import JobWorker

        self.scope = scope
        self.repo = InMemoryRepository()
        self.conn = self.repo.create_connection(Connection(provider="aws", name="bench", config={"bucket": "bench"}))
        item = scope.resource("source", self.conn.id, "S3_BUCKET", "bench", "bench", "arn:aws:s3:::bench", "aws")
        auth = scope.auth_revision("source", self.conn)
        self.catalog = self.repo.save_catalog(ScopeCatalog(
            kind="source", connection_id=self.conn.id, snapshot_id="v1", auth_revision=auth, items=[item],
            completeness="COMPLETE"))
        self.profile = self.repo.create_scope_profile(ScopeProfile(
            kind="source", connection_id=self.conn.id, name="bench", state="READY", auth_revision=auth,
            catalog_snapshot_id="v1", budgets={"requests": 1_000_000, "bytes": 1 << 34, "seconds": 3600},
            selected_roots=[{"resource_id": item["id"], "prefixes": ["data/"], "all_current_objects": False,
                             "include_future_descendants": False}]))
        self.bucket = Bucket(objects, latency)
        self.worker = JobWorker(self.repo, collector_factory=lambda job: build_collector(
            job, s3_client_factory=lambda _: self.bucket))

    def run(self, mode):
        from cremore.domain.models import ScanJob

        plan = self.scope.build_plan(self.profile, self.catalog, auth=self.profile.auth_revision, enabled=True)
        payload = self.scope.run_payload(self.repo.create_plan(plan), self.profile, {}, "s3")
        payload["mode"] = mode
        job = self.repo.enqueue_job(ScanJob(kind="scope", connection_id=self.conn.id, payload=payload))
        self.bucket.reads.clear()
        started = time.perf_counter()
        for _ in range(50):
            self.worker.process_next()
            done = self.repo.get_job(job.id)
            if done.status not in ("QUEUED", "RUNNING"):
                break
        elapsed = time.perf_counter() - started
        if done.status != "SUCCEEDED":
            raise SystemExit(f"WORKER BENCH FAILED run {mode} ended {done.status}")
        return elapsed, len(self.bucket.reads), done


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--assert", dest="check", action="store_true", help="exit nonzero on a failed expectation")
    parser.add_argument("--latency", type=float, default=0.02, help="seconds each fake GET waits")
    parser.add_argument("--objects", type=int, default=240, help="plain text objects in the mixed bucket")
    args = parser.parse_args(argv)
    from cremore_aws_provider.collectors.s3 import S3Collector

    objects = corpus(args.objects, secrets=4, images=40, documents=4, binaries=20)
    mixed = Scope(objects, args.latency)
    first, first_reads, done = mixed.run("BASELINE")
    rescan, rescan_reads, again = mixed.run("RECONCILE")
    coverage = again.coverage or {}

    # Same text-only bucket, reads one at a time and then overlapped (the collector's default).
    text = corpus(96, secrets=0, images=0, documents=0, binaries=0)
    default = S3Collector.read_concurrency
    try:
        S3Collector.read_concurrency = 1
        serial, _, _ = Scope(text, args.latency).run("BASELINE")
    finally:
        S3Collector.read_concurrency = default
    overlapped, _, _ = Scope(text, args.latency).run("BASELINE")

    ok = rescan_reads == 0 and overlapped < serial and first_reads == len(objects)
    print(f"WORKER BENCH {'OK' if ok else 'FAILED'} first={first:.2f}s rescan_reads={rescan_reads} "
          f"rescan={rescan:.2f}s objects={len(objects)} first_reads={first_reads} reused={coverage.get('reused', 0)} "
          f"findings={done.findings} serial_reads={serial:.2f}s overlapped_reads={overlapped:.2f}s "
          f"speedup={serial / overlapped:.1f}x latency={args.latency:.3f}s "
          "basis=in-memory-upper-bound")
    return 1 if args.check and not ok else 0


if __name__ == "__main__":
    raise SystemExit(main())
