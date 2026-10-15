"""Offline S3 collector + scan-service microbenchmark; JSON results on stdout.

Run from the repository root: python -m scripts.benchmark_s3_scan
Each repetition alternates baseline/worktree order in fresh subprocesses. Tracked
baseline Python modules are loaded from an in-memory Git archive, never checked
out over the worktree. No cloud, database, .env, or artificial network latency.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.abc
import importlib.util
import inspect
import io
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASELINE = "8780f9d31191090d35e81f86df8394e4c002da10"
ROOT = Path(__file__).resolve().parents[1]
BASELINE_START = datetime(2024, 1, 1, tzinfo=UTC)
PAGE_SIZE = 1000


def git(*arguments):
    return subprocess.check_output(["git", "-C", str(ROOT), *arguments])


def source_snapshot(variant):
    if variant == "baseline":
        with tarfile.open(fileobj=io.BytesIO(git("archive", BASELINE, "cremore"))) as archive:
            return {member.name: archive.extractfile(member).read() for member in archive
                    if member.isfile() and member.name.endswith(".py")}
    paths = git("ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "cremore").decode().split("\0")
    return {path: (ROOT / path).read_bytes() for path in paths
            if path.endswith(".py") and (ROOT / path).is_file()}


class SnapshotImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Never mix baseline cremore modules with worktree cremore modules."""

    def __init__(self, sources, variant):
        self.sources, self.variant, self.loaded = sources, variant, set()

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "cremore" and not fullname.startswith("cremore."):
            return None
        stem = fullname.replace(".", "/")
        for relative, package in ((stem + "/__init__.py", True), (stem + ".py", False)):
            if relative in self.sources:
                spec = importlib.util.spec_from_loader(fullname, self, is_package=package)
                spec.loader_state = relative
                return spec
        raise ModuleNotFoundError(f"Module {fullname} is absent from the {self.variant} snapshot")

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        relative = module.__spec__.loader_state
        module.__file__ = f"{self.variant}:{relative}"
        self.loaded.add(relative)
        exec(compile(self.sources[relative], module.__file__, "exec"), module.__dict__)  # noqa: S102 -- execute only the explicitly compared local code snapshot


def offline_guard(event, arguments):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
        raise RuntimeError("Benchmark forbids network/database socket access")
    if event == "open" and isinstance(arguments[0], (str, bytes, os.PathLike)):
        name = Path(os.fsdecode(arguments[0])).name
        if name == ".env" or name.startswith(".env."):
            raise RuntimeError("Benchmark forbids .env access")


class MeasuredBody(io.BytesIO):
    def __init__(self, data, counters):
        super().__init__(data)
        self.counters = counters

    def read(self, size=-1):
        data = super().read(size)
        self.counters["object_bytes_read"] += len(data)
        return data


class SyntheticS3:
    """Paginated local provider, deliberately without network sleeps."""

    def __init__(self, count, size):
        self.size = size
        self.data = {f"dataset/document-{index:08d}.txt": self.document(index, 0)
                     for index in range(count)}
        self.entries = [self.entry(key, data, datetime(2020, 1, 1, tzinfo=UTC))
                        for key, data in self.data.items()]
        self.by_key = {entry["Key"]: entry for entry in self.entries}
        self.reset()

    def document(self, index, generation):
        header = f"Document {index:08d}. Edition {generation:02d}.\n".encode()
        line = b"Ordinary local example document with harmless prose.\n"
        return (header + line * (self.size // len(line) + 1))[:self.size]

    @staticmethod
    def entry(key, data, modified):
        return {"Key": key, "Size": len(data), "ETag": hashlib.sha256(data).hexdigest(),
                "LastModified": modified}

    def reset(self):
        self.counters = {key: 0 for key in (
            "list_calls", "listed_objects", "get_calls", "metadata_calls",
            "object_bytes_read", "engine_calls", "engine_input_bytes")}

    def mutate(self, changed):
        for index, entry in enumerate(self.entries[:changed]):
            key = entry["Key"]
            self.data[key] = self.document(index, 1)
            entry.update(self.entry(key, self.data[key], datetime(2025, 1, 1, tzinfo=UTC)))

    def dataset_digest(self):
        digest = hashlib.sha256()
        for key, data in self.data.items():
            digest.update(key.encode() + b"\0" + data)
        return digest.hexdigest()

    def get_public_access_block(self, **kwargs):
        assert kwargs == {"Bucket": "synthetic-benchmark"}
        self.counters["metadata_calls"] += 1
        return {"PublicAccessBlockConfiguration": {key: True for key in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}}

    def list_objects_v2(self, **kwargs):
        assert kwargs["Bucket"] == "synthetic-benchmark"
        assert set(kwargs) <= {"Bucket", "Prefix", "ContinuationToken"}
        assert kwargs.get("Prefix", "") in ("", "dataset/")
        start = int(kwargs.get("ContinuationToken", 0))
        entries = self.entries[start:start + PAGE_SIZE]
        more = start + PAGE_SIZE < len(self.entries)
        self.counters["list_calls"] += 1
        self.counters["listed_objects"] += len(entries)
        return {"Contents": entries, "IsTruncated": more,
                **({"NextContinuationToken": str(start + PAGE_SIZE)} if more else {})}

    def get_object(self, **kwargs):
        assert kwargs["Bucket"] == "synthetic-benchmark"
        key = kwargs["Key"]
        self.counters["get_calls"] += 1
        entry = self.by_key[key]
        return {"Body": MeasuredBody(self.data[key], self.counters),
                "ContentLength": entry["Size"], "ETag": entry["ETag"],
                "LastModified": entry["LastModified"]}


def worker(args):
    sys.addaudithook(offline_guard)
    sources = source_snapshot(args.variant)
    importer = SnapshotImporter(sources, args.variant)
    sys.meta_path.insert(0, importer)
    from cremore.collectors.s3 import S3Collector
    from cremore.db.repository import InMemoryRepository
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.scanning.service import ScanService

    signature = inspect.signature(S3Collector)
    supports_delta = "watermark_since" in signature.parameters
    if args.variant == "baseline":
        assert not supports_delta, "Baseline capability changed: revisit comparison methodology"
    else:
        assert supports_delta, "Worktree lacks the measured watermark path"
    changed = round(args.objects * args.change_rate)
    request_budget = args.objects + math.ceil(args.objects / PAGE_SIZE) + 1
    samples, dataset_digests = [], {}
    for repeat in range(args.repeats):
        bucket = SyntheticS3(args.objects, args.object_bytes)
        repo = InMemoryRepository()
        orchestrator = Orchestrator(repo)
        service = ScanService(orchestrator)
        original_scan = orchestrator.engine.scan

        def measured_scan(item, measured_bucket=bucket, scan=original_scan):
            measured_bucket.counters["engine_calls"] += 1
            measured_bucket.counters["engine_input_bytes"] += len(item.data)
            return scan(item)

        orchestrator.engine.scan = measured_scan
        connection_id = uuid.UUID(int=1)
        for phase in ("initial", "rescan"):
            if phase == "rescan":
                bucket.mutate(changed)
            dataset_digests[phase] = bucket.dataset_digest()
            bucket.reset()
            options = {"bucket": "synthetic-benchmark", "prefix": "dataset/",
                       "max_requests": request_budget, "max_object_bytes": args.object_bytes}
            if supports_delta:
                options["lazy"] = True  # The worktree scope runtime uses lazy collectors.
                if phase == "rescan":
                    options["watermark_since"] = BASELINE_START - timedelta(minutes=5)
            collector = S3Collector(bucket, **options)
            extra = {"reconcile_objects": True} if supports_delta else {}
            started = time.perf_counter()
            result = service.run(collector, source_connection_id=connection_id,
                                 scan_id=uuid.UUID(int=repeat + 2), verify=False, **extra)
            seconds = time.perf_counter() - started
            expected = changed if supports_delta and phase == "rescan" else args.objects
            counters = bucket.counters
            assert result.objects_failed == result.detections == result.findings == 0
            assert result.objects == counters["get_calls"] == counters["engine_calls"] == expected
            assert counters["object_bytes_read"] == counters["engine_input_bytes"] == expected * args.object_bytes
            assert counters["listed_objects"] == args.objects
            assert counters["list_calls"] == math.ceil(args.objects / PAGE_SIZE)
            assert counters["metadata_calls"] == 1
            assert collector.requests == counters["list_calls"] + counters["get_calls"] + 1
            assert result.objects + getattr(collector, "skipped_unchanged", 0) == args.objects
            assert not repo.list_findings()
            if supports_delta:
                assert collector.listing_complete
            samples.append({"repeat": repeat + 1, "phase": phase, "wall_seconds": seconds,
                **counters, "objects_scanned": result.objects, "detections": result.detections,
                "failed_objects": result.objects_failed, "coverage_accounted_objects": args.objects,
                "skipped_unchanged": getattr(collector, "skipped_unchanged", 0),
                "reused_cached_objects": getattr(result, "reused", 0)})
    digest = hashlib.sha256()
    for path in sorted(importer.loaded):
        digest.update(path.encode() + b"\0" + sources[path])
    return {"variant": args.variant, "revision": BASELINE if args.variant == "baseline" else "worktree",
        "loaded_source_sha256": digest.hexdigest(), "loaded_module_count": len(importer.loaded),
        "builtin_catalog_source_sha256": hashlib.sha256(sources["cremore/detection/catalog.py"]).hexdigest(),
        "supports_watermark_delta": supports_delta, "dataset_sha256": dataset_digests,
        "median": phase_medians(samples), "samples": samples}


def phase_medians(samples):
    medians = {}
    for phase in ("initial", "rescan"):
        rows = [row for row in samples if row["phase"] == phase]
        medians[phase] = {key: statistics.median(row[key] for row in rows)
                          for key in rows[0] if key not in {"phase", "repeat"}}
    return medians


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objects", type=int, default=10_000)
    parser.add_argument("--object-bytes", type=int, default=4096)
    parser.add_argument("--change-rate", type=float, default=0.01)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--variant", choices=("baseline", "worktree"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    minimum_repeats = 1 if args.variant else 3
    if args.objects < 1 or args.object_bytes < 64 or args.repeats < minimum_repeats or not 0 <= args.change_rate <= 1:
        parser.error("Require objects >= 1, object-bytes >= 64, repeats >= 3, change-rate in [0,1]")
    if args.variant:
        print(json.dumps(worker(args)))
        return
    results, identities, execution_order = {}, {}, []
    for repeat in range(1, args.repeats + 1):
        order = ("baseline", "worktree") if repeat % 2 else ("worktree", "baseline")
        execution_order.append({"repeat": repeat, "variants": list(order)})
        for variant in order:
            command = [sys.executable, str(Path(__file__).resolve()), "--variant", variant,
                "--objects", str(args.objects), "--object-bytes", str(args.object_bytes),
                "--change-rate", str(args.change_rate), "--repeats", "1"]
            trial = json.loads(subprocess.check_output(command, cwd=ROOT))
            identity = {key: value for key, value in trial.items() if key not in {"samples", "median"}}
            if variant not in results:
                identities[variant] = identity
                results[variant] = {**identity, "samples": []}
            elif identities[variant] != identity:
                raise RuntimeError("Compared code or synthetic corpus changed between repetitions; discard this run")
            assert len(trial["samples"]) == 2 and {s["phase"] for s in trial["samples"]} == {"initial", "rescan"}
            results[variant]["samples"].extend({**sample, "repeat": repeat} for sample in trial["samples"])
    assert results["baseline"]["dataset_sha256"] == results["worktree"]["dataset_sha256"]
    for result in results.values():
        assert len(result["samples"]) == 2 * args.repeats
        result["median"] = phase_medians(result["samples"])
    output = {"metadata": {
        "benchmark": "s3_collector_scan_service_microbenchmark", "schema_version": 2,
        "baseline_revision": BASELINE, "current_head": git("rev-parse", "HEAD").decode().strip(),
        "provider": "in_process_synthetic_s3", "actual_cloud_measurement": False,
        "network_allowed": False, "artificial_latency_seconds": 0, "database": "InMemoryRepository",
        "objects": args.objects, "object_bytes": args.object_bytes,
        "changed_objects": round(args.objects * args.change_rate), "change_rate_requested": args.change_rate,
        "change_rate_actual": round(args.objects * args.change_rate) / args.objects,
        "repeats": args.repeats, "page_size": PAGE_SIZE, "verification_enabled": False,
        "execution_order": execution_order,
        "process_isolation": "One fresh subprocess per variant per repetition; each measures one initial/rescan pair",
        "python": platform.python_version(), "platform": platform.platform(),
        "logical_cpus": os.cpu_count(), "timed_region": "ScanService.run only",
        "excluded_from_timing": ["imports", "engine construction", "synthetic data/metadata generation",
            "collector construction", "data mutation", "digest checks", "post-run assertions"],
        "cache_method": "Fresh repository for each repeat; no initial cache warmup; initial state retained for rescan",
        "warmup_method": "No explicit warmup or cross-repetition process cache; initial and rescan share only their own subprocess/repository",
        "rescan_method": "Baseline normal full scan; worktree DELTA with successful-baseline watermark and 5-minute overlap",
        "watermark_method": "Applied directly to collector; durable worker/checkpoint overhead is not measured",
        "common_request_budget": args.objects + math.ceil(args.objects / PAGE_SIZE) + 1,
        "byte_metric": "Object body bytes actually read; excludes listing metadata and transport framing",
        "coverage_assertion": "All N objects listed; scanned + unchanged = N; zero findings/failures in both variants",
        "limitations": ["No cloud latency, throttling, permissions or object errors",
            "No SQL, leases, task scheduling or production concurrency",
            "Harmless zero-finding fixture does not measure positive-detection persistence costs",
            "Whole-project or 100k production latency cannot be inferred directly"],
    }, "results": results}
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
