"""Local collector + ScanService microbenchmarks; no network or user database.

Run from the repository with its existing Python dependencies installed:
  python scripts/benchmark_github_notion_scan.py --items 10000 --repeats 3

Legacy collectors, ScanService and bounded HTTP helper are loaded in memory
from the fixed Git commit. Both variants share the current real detection
engine/orchestrator and a fresh InMemoryRepository per repetition. This isolates
collection/service changes, not a complete release or worker-queue comparison.
Initial scans are measured and their state is retained unchanged for rescans.
Use --versioned-engine to also compare each version's Engine implementation;
the catalog, helpers, domain models and memory repository remain shared.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import platform
import re
import socket
import statistics
import subprocess
import sys
import tarfile
import time
import types
import uuid
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx

from cremore.collectors.base import RequestBudget
from cremore.collectors.github import GitHubCollector
from cremore.collectors.notion import NotionCollector
from cremore.db.repository import InMemoryRepository
from cremore.detection.engine import Engine, EngineConfig
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import ScanService

BASELINE = "8780f9d31191090d35e81f86df8394e4c002da10"
SOURCE_PATHS = (
    "cremore/collectors/github.py", "cremore/collectors/notion.py",
    "cremore/scanning/service.py", "cremore/http_client.py",
)
CURRENT_PATHS = SOURCE_PATHS + (
    "cremore/collectors/github_archive.py", "cremore/db/scan_store.py",
    "cremore/detection/engine.py", "cremore/scanning/orchestrator.py",
    "cremore/db/repository.py", "cremore/collectors/base.py",
)
OLD_TIME = "2026-09-01T00:00:00Z"
# Represents a successful 2026-09-02T00:00:00Z initial scan's five-minute overlap.
WATERMARK_SINCE = "2026-09-01T23:55:00Z"
NEW_TIME = "2026-09-03T00:00:00Z"
CONNECTION_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def git(*args: str) -> bytes:
    return subprocess.check_output(
        ["git", "--no-pager", *args], cwd=ROOT, stderr=subprocess.PIPE,
    )


def load_legacy(revision: str, *, versioned_engine=False):
    modules, hashes = {}, {}
    source_paths = SOURCE_PATHS + (("cremore/detection/engine.py",) if versioned_engine else ())
    for source_path in source_paths:
        data = git("show", f"{revision}:{source_path}")
        name = "_cremore_benchmark_legacy_" + source_path.replace("/", "_").removesuffix(".py")
        module = types.ModuleType(name)
        module.__file__ = f"git:{revision}:{source_path}"
        sys.modules[name] = module
        exec(compile(data, module.__file__, "exec"), module.__dict__)  # noqa: S102 -- explicit local Git source, fixed full revision and paths
        modules[source_path] = module
        hashes[source_path] = hashlib.sha256(data).hexdigest()
    # Use the legacy response reader too; other imported domain/engine helpers
    # are deliberately shared to isolate collector + service work.
    for path in SOURCE_PATHS[:2]:
        modules[path].bounded_request = modules["cremore/http_client.py"].bounded_request
    return modules, hashes


@contextmanager
def deny_network():
    def blocked(*_args, **_kwargs):
        raise RuntimeError("BENCHMARK_NETWORK_DISABLED")

    with (patch.object(socket, "create_connection", blocked),
          patch.object(socket.socket, "connect", blocked),
          patch.object(socket.socket, "connect_ex", blocked)):
        yield


def prose(index: int, edition: int, size: int) -> bytes:
    lead = f"Document {index:06d}, edition {edition}.\n".encode()
    sentence = b"This is ordinary synthetic prose for a local reading exercise.\n"
    return (lead + sentence * (size // len(sentence) + 1))[:size]


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


class CountedStream(httpx.SyncByteStream):
    def __init__(self, data: bytes, counts: Counter):
        self.data, self.counts = data, counts

    def __iter__(self):
        for offset in range(0, len(self.data), 64 << 10):
            chunk = self.data[offset:offset + (64 << 10)]
            self.counts["http_response_body_bytes"] += len(chunk)
            yield chunk


class FixtureHTTP:
    """Memory-only MockTransport; only explicitly constructed routes exist."""

    def __init__(self, routes: dict, *, pages=None):
        self.routes, self.pages = routes, pages
        self.counts = Counter()
        self.by_kind = Counter()

    def __call__(self, request):
        self.counts["http_calls"] += 1
        if request.method == "POST" and str(request.url) == "https://api.notion.com/v1/search":
            body = json.loads(request.content)
            offset = int(body.get("start_cursor", "0"))
            rows = self.pages[offset:offset + 100]
            next_offset = offset + len(rows)
            result = {"results": rows, "has_more": next_offset < len(self.pages),
                      "next_cursor": str(next_offset) if next_offset < len(self.pages) else None}
            route = ("search", json.dumps(result, separators=(",", ":")).encode(), 0, 200, {})
        else:
            route = self.routes.get((request.method, str(request.url)))
        if route is None:
            raise AssertionError(f"Unexpected synthetic route: {request.method} {request.url}")
        kind, data, source_bytes, status, headers = route
        self.by_kind[kind] += 1
        self.counts["source_content_bytes_fetched"] += source_bytes
        return httpx.Response(status, headers={"Content-Length": str(len(data)), **headers},
                              stream=CountedStream(data, self.counts), request=request)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self), trust_env=False, follow_redirects=False)


def json_route(kind, value, source_bytes=0):
    return kind, json.dumps(value, separators=(",", ":")).encode(), source_bytes, 200, {"Content-Type": "application/json"}


def github_fixture(items: int, changed: int, size: int):
    bodies = {f"documents/{i:06d}.txt": prose(i, int(i < changed), size) for i in range(items)}
    entries = [{"path": path, "mode": "100644", "type": "blob", "sha": blob_sha(data), "size": len(data)}
               for path, data in bodies.items()]
    tree_sha = hashlib.sha1(json.dumps(entries, sort_keys=True).encode(), usedforsecurity=False).hexdigest()
    commit = hashlib.sha1(("commit:" + tree_sha).encode(), usedforsecurity=False).hexdigest()
    repo = "https://api.github.com/repos/synthetic/benchmark"
    routes = {
        ("GET", repo): json_route("repository_metadata", {"private": False}),
        ("GET", repo + "/commits/HEAD"): json_route("commit", {"sha": commit, "commit": {"tree": {"sha": tree_sha}}}),
    }
    tree = json_route("tree", {"sha": tree_sha, "truncated": False, "tree": entries})
    routes["GET", repo + "/git/trees/HEAD?recursive=1"] = tree
    routes["GET", repo + f"/git/trees/{tree_sha}?recursive=1"] = tree
    for path, data in bodies.items():
        routes["GET", repo + "/git/blobs/" + blob_sha(data)] = json_route(
            "blob", {"encoding": "base64", "content": base64.b64encode(data).decode()}, len(data))
    # Generate and compress fixtures before any scan timer, as a remote server
    # would already have the source data. No files are extracted or written.
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, data in bodies.items():
            member = tarfile.TarInfo("synthetic-root/" + path)
            member.size, member.mtime = len(data), 0
            archive.addfile(member, io.BytesIO(data))
    compressed = gzip.compress(buffer.getvalue(), mtime=0)
    codeload = f"https://codeload.github.com/synthetic/benchmark/legacy.tar.gz/{commit}"
    routes["GET", repo + f"/tarball/{commit}"] = ("archive_redirect", b"", 0, 302, {"Location": codeload})
    routes["GET", codeload] = ("archive", compressed, sum(map(len, bodies.values())), 200, {"Content-Type": "application/gzip"})
    return routes, {"source_bytes": sum(map(len, bodies.values())), "archive_compressed_bytes": len(compressed),
                    "dataset_sha256": hashlib.sha256(b"".join(bodies.values())).hexdigest()}


def notion_fixture(items: int, changed: int, size: int, *, nested=False):
    ids = [f"{i + 1:032x}" for i in range(items)]
    # In the nested case, only CHILD pages change; their parents' timestamps do
    # not. Both generations explicitly approve every page in the same corpus.
    changed_ids = set(ids[items // 2:items // 2 + changed] if nested else ids[:changed])
    bodies = {page_id: prose(i, int(page_id in changed_ids), size) for i, page_id in enumerate(ids)}
    pages, routes = [], {}
    for index, page_id in enumerate(ids):
        page = {"object": "page", "id": page_id, "url": "https://www.notion.so/" + page_id,
                "last_edited_time": NEW_TIME if page_id in changed_ids else OLD_TIME,
                "properties": {"title": {"type": "title", "title": [{"plain_text": f"Document {index:06d}"}]}}}
        pages.append(page)
        routes["GET", "https://api.notion.com/v1/pages/" + page_id] = json_route("page_header", page)
        blocks = [{"object": "block", "id": "paragraph-" + page_id, "type": "paragraph", "has_children": False,
                   "paragraph": {"rich_text": [{"plain_text": bodies[page_id].decode()}]}}]
        if nested and index < items // 2:
            child = ids[index + items // 2]
            blocks.append({"object": "block", "id": child, "type": "child_page", "has_children": True,
                           "child_page": {"title": "Independently approved child"}})
        routes["GET", f"https://api.notion.com/v1/blocks/{page_id}/children?page_size=100"] = json_route(
            "block_body", {"results": blocks, "has_more": False, "next_cursor": None}, len(bodies[page_id]))
    return routes, pages, ids, {"source_bytes": sum(map(len, bodies.values())),
                               "dataset_sha256": hashlib.sha256(b"".join(bodies.values())).hexdigest()}


class CountedEngine:
    """Only count entrypoint work; every call runs the actual native Engine."""

    def __init__(self, engine_type=Engine):
        self.engine = engine_type(EngineConfig(fingerprint_key=b"local-benchmark-only-not-a-secret"))
        self.invocations = self.input_bytes = 0

    def __getattr__(self, name):
        return getattr(self.engine, name)

    def scan(self, value):
        self.invocations += 1
        self.input_bytes += len(value.data)
        return self.engine.scan(value)


def timed_scan(service, collector, fixture, engine):
    before_calls, before_bytes = engine.invocations, engine.input_bytes
    started = time.perf_counter()
    summary = service.run(collector, source_connection_id=CONNECTION_ID, verify=False)
    elapsed = time.perf_counter() - started
    if summary.objects_failed or summary.detections or summary.findings:
        raise AssertionError("Synthetic benchmark must complete without failures or detected credentials")
    if collector.requests != fixture.counts["http_calls"]:
        raise AssertionError("Collector request accounting differs from measured MockTransport calls")
    return {"wall_seconds": elapsed, "objects_processed": summary.objects,
            "engine_invocations": engine.invocations - before_calls,
            "engine_input_bytes": engine.input_bytes - before_bytes,
            "cache_reused": getattr(summary, "reused", 0),
            "unchanged_pages_skipped": getattr(collector, "skipped_unchanged", 0),
            "http_calls": fixture.counts["http_calls"],
            "http_response_body_bytes": fixture.counts["http_response_body_bytes"],
            "source_content_bytes_fetched": fixture.counts["source_content_bytes_fetched"],
            "http_calls_by_kind": dict(sorted(fixture.by_kind.items())), "failures": summary.objects_failed}


def branch(scenario, current, legacy, snapshots, items, *, versioned_engine=False):
    # Engine compilation/repository construction are outside the measured scan.
    # A measured initial scan, not an unreported warmup, populates any cache.
    engine_type = legacy["cremore/detection/engine.py"].Engine if versioned_engine and not current else Engine
    repo, engine = InMemoryRepository(), CountedEngine(engine_type)
    orchestrator = Orchestrator(repo, engine=engine)
    service_type = ScanService if current else legacy["cremore/scanning/service.py"].ScanService
    service = service_type(orchestrator)
    samples = {}
    for phase, snapshot in zip(("initial", "rescan_1pct_changed"), snapshots):
        routes = snapshot[0]
        fixture = FixtureHTTP(routes, pages=snapshot[1] if scenario != "github" else None)
        # Keep no artificially small request limit: both paths must cover the
        # full identical scope, including metadata consistency checks.
        budget = RequestBudget(max(100_000, items * 10))
        with fixture.client() as client:
            if scenario == "github":
                collector_type = GitHubCollector if current else legacy["cremore/collectors/github.py"].GitHubCollector
                options = {"lazy": True, "use_archive": phase == "initial"} if current else {}
                collector = collector_type(client, "synthetic", "benchmark", request_budget=budget, **options)
            else:
                collector_type = NotionCollector if current else legacy["cremore/collectors/notion.py"].NotionCollector
                options = {"watermark_since": WATERMARK_SINCE} if current and phase != "initial" else {}
                collector = collector_type(client, "synthetic-placeholder", page_ids=snapshot[2],
                                           max_pages=items, request_budget=budget, **options)
            samples[phase] = timed_scan(service, collector, fixture, engine)
        expected = items if phase == "initial" or not current or scenario == "github" else items // 100
        if samples[phase]["objects_processed"] != expected:
            raise AssertionError("Measured path did not process the expected explicitly approved scope")
        if (current and scenario == "github" and phase != "initial"
                and samples[phase]["cache_reused"] != items - items // 100):
            raise AssertionError("Measured current rescan did not preserve initial negative-result cache")
    return samples


def aggregate(samples):
    numeric = [key for key, value in samples[0].items() if isinstance(value, (int, float))]
    medians = {key: statistics.median(sample[key] for sample in samples) for key in numeric}
    kinds = sorted({key for sample in samples for key in sample["http_calls_by_kind"]})
    medians["http_calls_by_kind"] = {
        key: statistics.median(sample["http_calls_by_kind"].get(key, 0) for sample in samples) for key in kinds}
    return {"median": medians, "wall_min_seconds": min(s["wall_seconds"] for s in samples),
            "wall_max_seconds": max(s["wall_seconds"] for s in samples), "samples": samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=BASELINE, help="Exact existing local 40-character Git commit")
    parser.add_argument("--items", type=int, default=1000, help="1000..10000, divisible by 100")
    parser.add_argument("--bytes-per-item", type=int, default=4096, help="256..65536 synthetic ASCII bytes per object")
    parser.add_argument("--repeats", type=int, default=3, help="3..9 paired initial/rescan repetitions")
    parser.add_argument("--smoke", action="store_true", help="100 items, one repetition; functional proof only, not performance evidence")
    parser.add_argument("--include-nested", action="store_true", help="Also measure independently approved Notion parent/child boundaries")
    parser.add_argument("--versioned-engine", action="store_true", help="Compare the fixed baseline Engine too; default isolates collector/service changes")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.baseline):
        parser.error("--baseline must be a fixed full commit SHA, not HEAD or a branch")
    if not 1000 <= args.items <= 10000 or args.items % 100 or not 3 <= args.repeats <= 9:
        parser.error("use 1000..10000 items divisible by 100 and 3..9 repetitions")
    if not 256 <= args.bytes_per_item <= 65536:
        parser.error("--bytes-per-item must be 256..65536")
    if args.smoke:
        args.items, args.repeats = 100, 1
    legacy, baseline_hashes = load_legacy(args.baseline, versioned_engine=args.versioned_engine)
    current_hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in CURRENT_PATHS}
    changed = args.items // 100
    # One identical immutable corpus per scenario/phase, built before timers.
    snapshots = {
        "github": [github_fixture(args.items, n, args.bytes_per_item) for n in (0, changed)],
        "notion_flat_explicit_pages": [notion_fixture(args.items, n, args.bytes_per_item) for n in (0, changed)],
    }
    if args.include_nested:
        snapshots["notion_parent_child_all_explicitly_approved"] = [
            notion_fixture(args.items, n, args.bytes_per_item, nested=True) for n in (0, changed)]
    result = {"benchmark": "github_notion_collector_scan_service", "schema_version": 1,
              "parameters": {"items": args.items, "bytes_per_item": args.bytes_per_item,
                             "changed_items": changed, "changed_fraction": 0.01, "repetitions": args.repeats,
                             "smoke_only": args.smoke, "include_nested": args.include_nested,
                             "versioned_engine": args.versioned_engine},
              "metadata": {
                  "baseline_commit": args.baseline, "worktree_commit": git("rev-parse", "HEAD").decode().strip(),
                  "baseline_module_sha256": baseline_hashes, "current_module_sha256": current_hashes,
                  "python": platform.python_version(), "platform": platform.platform(),
                  "scope": "collector_service_and_engine_microbenchmark_not_release_or_worker_end_to_end" if args.versioned_engine else "collector_and_scan_service_microbenchmark_not_release_or_worker_end_to_end",
                  "shared_current_dependencies": ([] if args.versioned_engine else ["native builtin Engine"]) + ["builtin catalog", "detection helpers", "EngineConfig", "Orchestrator", "InMemoryRepository", "domain models", "HTTPX MockTransport"],
                  "timer_includes": ["actual collection and response parsing", "archive decompression/hash checks", "native engine.scan calls", "scan-service cache lookup/store", "in-memory orchestration"],
                  "timer_excludes": ["fixture generation/compression/serialization", "Git source loading", "engine compilation", "client/repository construction"],
                  "cache_preparation": "No artificial disabling or extra warmup; measured initial scan retained for the rescan of each branch/repetition",
                  "notion_watermark": "Explicit collector input represents successful initial scan start minus five-minute overlap; root runtime persistence is not benchmarked",
                  "network": "Disabled socket connects; memory-only MockTransport, no latency sleeps/proxy/env credentials",
                  "not_measured": ["cloud latency/rate limits/billing", "PostgreSQL/disk/WAL", "task leases/concurrency", "index lag/failures", "finding-heavy database writes", "real provider credentials"],
                  "bytes_definition": "http_response_body_bytes counts delivered synthetic serialized/compressed HTTP bodies; source_content_bytes_fetched counts uncompressed source bytes served (including duplicates); engine_input_bytes counts actual detector input",
                  "interpretation": "Local wall seconds only. Request reduction is not the same as wall-time speedup; no extrapolated cloud minutes.",
              }, "scenarios": {}}
    with deny_network():
        for scenario, versions in snapshots.items():
            collected = {phase: {"baseline": [], "current": []} for phase in ("initial", "rescan_1pct_changed")}
            for repeat in range(args.repeats):
                # Alternate branch order to avoid always favoring one side.
                for current in ((False, True) if repeat % 2 == 0 else (True, False)):
                    measured = branch(scenario, current, legacy, versions, args.items,
                                      versioned_engine=args.versioned_engine)
                    for phase, sample in measured.items():
                        collected[phase]["current" if current else "baseline"].append(sample)
            scenario_result = {"initial_dataset": versions[0][-1], "rescan_dataset": versions[1][-1]}
            for phase, variants in collected.items():
                rows = {name: aggregate(values) for name, values in variants.items()}
                rows["current_over_baseline_wall_ratio"] = rows["current"]["median"]["wall_seconds"] / rows["baseline"]["median"]["wall_seconds"]
                scenario_result[phase] = rows
            scenario_result["comparison_notes"] = (
                "Identical whole-repository approval; legacy per-blob reads versus current verified tarball on initial scan, lazy SHA cache on rescan. No baseline GitHub revision cache exists in the loaded service/collector."
                if scenario == "github" else
                "Identical explicit page IDs; current adds post-body header consistency checks, so initial HTTP calls can increase. Delta still reads every approved page header; only changed page bodies reach the engine. "
                + ("All parents and children are independently approved. Legacy repeats each child body in its parent; current separates them. Only child timestamps change in rescan; parent timestamps stay unchanged. Logical corpus is identical, emitted parent text differs intentionally."
                   if "parent_child" in scenario else "No nesting, so this isolates modified-time body skipping from boundary changes.")
            )
            result["scenarios"][scenario] = scenario_result
    if current_hashes != {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in CURRENT_PATHS}:
        raise RuntimeError("Worktree modules changed during benchmark; rerun against a stable tree")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
