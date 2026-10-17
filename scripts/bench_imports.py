"""Cold-import cost and import boundary of platform and provider modules.

Adapted from the boundary checks of the refactor/saas-libraries branch: every
target is imported in a fresh interpreter, and the report records the median
import time and which heavy runtime packages (DB, web framework, unrelated SaaS
SDKs) or platform runtime modules the import pulled in. Run it against two
source trees with ``--root`` to compare a baseline with a change:

    python scripts/bench_imports.py --root <tree> --runs 7 --output before.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

# Provider roots loaded for the import cost measurement.
VENDOR_PATHS = ("aws/backend", "github/backend", "notion/backend", "slack/backend")
HEAVY = ("sqlalchemy", "psycopg", "fastapi", "starlette", "uvicorn", "boto3", "botocore", "google",
         "jwt", "azure", "httpx", "re2")
PLATFORM_RUNTIME = ("cremore.api", "cremore.db", "cremore.worker", "cremore.coverage.store",
                    "cremore.coverage.providers")
TARGETS = (
    # schema 2 metadata adapters
    "cremore_github_provider.metadata.adapter", "cremore_notion_provider.metadata.adapter",
    "cremore_slack_provider.metadata.adapter",
    # content source modules and collectors
    "cremore_aws_provider.source", "cremore_github_provider.source", "cremore_notion_provider.source",
    "cremore_github_provider.collectors.github", "cremore_aws_provider.collectors.s3",
    "cremore_notion_provider.collectors.notion",
    # schema 1 vault collectors
    "cremore_aws_provider.coverage",
    # platform contracts, registries and entry points
    "cremore.coverage.metadata_models", "cremore.coverage.collector_runtime",
    "cremore.coverage.providers", "cremore.sources.registry", "cremore.worker.worker",
    "cremore.api.app",
)

PROBE = r"""
import importlib, json, sys, time
start = time.perf_counter()
importlib.import_module(sys.argv[1])
elapsed = time.perf_counter() - start
heavy, runtime = json.loads(sys.argv[2]), json.loads(sys.argv[3])
loaded = set(sys.modules)
def hit(prefix):
    return any(name == prefix or name.startswith(prefix + ".") for name in loaded)
print(json.dumps({"seconds": elapsed, "modules": len(loaded),
                  "heavy": sorted(p for p in heavy if hit(p)),
                  "platform_runtime": sorted(p for p in runtime if hit(p))}))
"""


def measure(root: Path, module: str, runs: int) -> dict:
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        [str(root)] + [str(root / path) for path in VENDOR_PATHS]),
        AWS_EC2_METADATA_DISABLED="true", PYTHONDONTWRITEBYTECODE="1")
    samples, last = [], None
    for _ in range(runs):
        result = subprocess.run([sys.executable, "-B", "-c", PROBE, module, json.dumps(HEAVY),
                                 json.dumps(PLATFORM_RUNTIME)], cwd=root, env=env,
                                capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            return {"error": (result.stderr.strip().splitlines() or ["?"])[-1][:300]}
        last = json.loads(result.stdout.strip().splitlines()[-1])
        samples.append(last["seconds"])
    return {"median_ms": round(statistics.median(samples) * 1000, 2),
            "min_ms": round(min(samples) * 1000, 2), "modules": last["modules"],
            "heavy": last["heavy"], "platform_runtime": last["platform_runtime"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--output", type=Path)
    parser.add_argument("targets", nargs="*", help="module names (default: the built-in list)")
    args = parser.parse_args()
    root = args.root.resolve()
    report = {"root": str(root), "runs": args.runs, "python": sys.version.split()[0], "targets": {}}
    for module in args.targets or TARGETS:
        report["targets"][module] = measure(root, module, args.runs)
        row = report["targets"][module]
        print(f"{module:52s} " + (f"{row['median_ms']:8.1f} ms  modules={row['modules']:5d}  "
                                  f"heavy={row['heavy']} runtime={row['platform_runtime']}"
                                  if "error" not in row else "ERROR " + row["error"]), flush=True)
    if args.output:
        args.output.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
