"""Attribute GitHub/Notion initial scan costs offline, not a speed benchmark.

Uses the existing benchmark's real collectors/service, fixtures and assertions.
Only ScanService.run is profiled; fixture generation and engine setup are not.
Run: python -m scripts.profile_initial_scan --items 1000
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import platform
import pstats
import statistics
import time
import tracemalloc
from unittest.mock import patch

from cremore.collectors.base import DEFAULT_MAX_OBJECT_BYTES
from scripts import benchmark_github_notion_scan as bench


def profile_rows(profiler):
    rows = []
    for (filename, line, name), (primitive, calls, own, cumulative, _) in pstats.Stats(profiler).stats.items():
        filename = filename.replace("\\", "/")
        if "/cremore/" in filename:
            filename = "cremore/" + filename.split("/cremore/", 1)[1]
        elif ":cremore/" in filename:
            filename = "cremore/" + filename.split(":cremore/", 1)[1]
        elif "/httpx/" in filename:
            filename = "httpx/" + filename.split("/httpx/", 1)[1]
        else:
            filename = filename.rsplit("/", 1)[-1]
        rows.append({"file": filename, "line": line, "function": name,
                     "calls": calls, "primitive_calls": primitive,
                     "self_seconds": own, "cumulative_seconds": cumulative})
    # Include every product function plus the largest external costs. Nested
    # cumulative times must not be added; self times are non-overlapping.
    external = sorted((r for r in rows if not r["file"].startswith("cremore/")),
                      key=lambda r: r["cumulative_seconds"], reverse=True)[:25]
    product = [r for r in rows if r["file"].startswith("cremore/")]
    return {"total_profiled_self_seconds": sum(r["self_seconds"] for r in rows),
            "functions": sorted(product + external,
                                key=lambda r: r["cumulative_seconds"], reverse=True)}


def archive_read_probe(items, repeats):
    """Same verified archive bytes with two permitted per-object limits.

    Measures collector setup, metadata/tree parsing, archive reading, output
    hashing/assertions and teardown, not detection or production throughput.
    Tracemalloc is separate from time samples so its overhead is not mixed in.
    """
    routes, dataset = bench.github_fixture(items, 0, 4096)
    limits = (DEFAULT_MAX_OBJECT_BYTES, 4096)

    def consume(limit):
        fixture = bench.FixtureHTTP(routes)
        digest, objects, size = hashlib.sha256(), 0, 0
        with fixture.client() as client:
            collector = bench.GitHubCollector(client, "synthetic", "benchmark",
                                             lazy=True, use_archive=True, max_object_bytes=limit)
            for obj in collector.collect():
                data = obj.read()
                assert data is not None and len(data) == 4096
                objects += 1
                size += len(data)
                digest.update(data)
        assert objects == items and size == items * 4096
        assert digest.hexdigest() == dataset["dataset_sha256"]
        assert collector.failed_objects == 0 and fixture.counts["http_calls"] == 5
        assert fixture.by_kind["archive"] == 1 and fixture.by_kind["blob"] == 0

    values = {str(limit): {"wall_seconds": [], "cpu_seconds": []} for limit in limits}
    with bench.deny_network():
        for repeat in range(repeats):
            for limit in limits if repeat % 2 == 0 else reversed(limits):
                wall, cpu = time.perf_counter(), time.process_time()
                consume(limit)
                values[str(limit)]["cpu_seconds"].append(time.process_time() - cpu)
                values[str(limit)]["wall_seconds"].append(time.perf_counter() - wall)
        for limit in limits:
            tracemalloc.start()
            try:
                consume(limit)
                values[str(limit)]["separate_peak_traced_bytes"] = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            values[str(limit)]["median_wall_seconds"] = statistics.median(values[str(limit)]["wall_seconds"])
    return {"purpose": "Archive collector-path read-limit sensitivity, not end-to-end scan performance",
            "items": items, "object_bytes": 4096, "repetitions": repeats,
            "dataset": dataset, "limits": values,
            "checks": "Both limits emit identical bytes/SHA256, 5 requests, one archive, zero fallback/failures",
            "memory_method": "One additional tracemalloc-only pass per limit; excluded from time samples",
            "measurement_scope": "Collector/client setup, metadata/tree parsing, archive reading, output hashing/assertions and teardown; prebuilt fixture data excluded",
            "production_changes": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--items", type=int, default=1000)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--archive-read-probe", action="store_true")
    args = parser.parse_args()
    if not 1000 <= args.items <= 10000 or args.items % 100:
        parser.error("--items must be 1000..10000, divisible by 100")
    items, repeats = (100, 1) if args.smoke else (args.items, 3)
    if args.archive_read_probe:
        print(json.dumps(archive_read_probe(items, repeats), indent=2, sort_keys=True))
        return
    legacy, baseline_hashes = bench.load_legacy(bench.BASELINE)
    current_hashes = {p: hashlib.sha256((bench.ROOT / p).read_bytes()).hexdigest()
                      for p in bench.CURRENT_PATHS}
    result = {"purpose": "Initial cost attribution; profiler overhead is not benchmark latency",
              "items_per_scan": items, "bytes_per_item": 4096,
              "initial_scans_per_variant": repeats, "smoke_only": args.smoke,
              "baseline_commit": bench.BASELINE, "baseline_module_sha256": baseline_hashes,
              "current_module_sha256": current_hashes, "python": platform.python_version(),
              "scope": "ScanService.run only; shared current Engine/Orchestrator/memory repository",
              "excludes": ["network", "SQL", "worker leases/checkpoints", "provider verification",
                           "fixture construction", "engine construction", "object reconciliation"],
              "method": "Each initial scan starts with fresh memory repository; alternating variant order",
              "scenarios": {}}
    with bench.deny_network():
        for scenario, factory in (("github", bench.github_fixture), ("notion", bench.notion_fixture)):
            snapshot = factory(items, 0, 4096)
            profiles = {"baseline": cProfile.Profile(), "current": cProfile.Profile()}
            samples = {"baseline": [], "current": []}
            for repeat in range(repeats):
                for current in ((False, True) if repeat % 2 == 0 else (True, False)):
                    variant = "current" if current else "baseline"
                    service_type = bench.ScanService if current else legacy["cremore/scanning/service.py"].ScanService
                    original = service_type.run

                    def profiled_run(self, *run_args, _run=original, _profile=profiles[variant], **run_kwargs):
                        _profile.enable()
                        try:
                            return _run(self, *run_args, **run_kwargs)
                        finally:
                            _profile.disable()

                    with patch.object(service_type, "run", profiled_run):
                        measured = bench.branch(scenario, current, legacy, [snapshot], items)["initial"]
                    assert measured["engine_invocations"] == items
                    assert measured["engine_input_bytes"] == items * 4096
                    assert measured["cache_reused"] == measured["failures"] == 0
                    expected_calls = (5 if current else items + 2) if scenario == "github" else items * (3 if current else 2)
                    assert measured["http_calls"] == expected_calls
                    samples[variant].append(measured)
            result["scenarios"][scenario] = {
                "dataset": snapshot[-1],
                **{variant: {"samples": samples[variant], **profile_rows(profiles[variant])}
                   for variant in profiles}}
    assert current_hashes == {p: hashlib.sha256((bench.ROOT / p).read_bytes()).hexdigest()
                              for p in bench.CURRENT_PATHS}, "Product files changed during profiling"
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
