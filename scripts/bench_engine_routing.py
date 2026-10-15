"""Keyword routing benchmark: the engine's alternation router against testing every keyword with ``in``.

Synthetic and local: reads this repository's own source and documents, makes no network or database call.
Prints "ROUTING OK speedup=<x>" only when every view routes to the same detectors and the router is at
least ``--min-speedup`` times faster.

    python scripts/bench_engine_routing.py --min-speedup 3

``--bundle web/.next/static/chunks`` measures one large view instead: the directory's ``.js`` files joined (a
built console bundle, after ``npm run build`` in ``web/``), or a single file.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-speedup", type=float, default=3.0)
    parser.add_argument("--files", type=int, default=600)
    parser.add_argument("--bundle")
    args = parser.parse_args(argv)
    from cremore.detection.engine import Engine

    engine = Engine()
    specs = engine._specs
    if args.bundle:
        path = ROOT / args.bundle
        parts = sorted(path.rglob("*.js")) if path.is_dir() else [path]
        views = [b"\n".join(part.read_bytes() for part in parts).lower()]
    else:
        files = [path for pattern in ("cremore/**/*.py", "docs/**/*.md", "web/console/**/*.tsx")
                 for path in sorted(ROOT.glob(pattern))][:args.files]
        views = [path.read_bytes().lower() for path in files]
    size = sum(map(len, views))
    if not size:
        print("ROUTING FAILED nothing to read")
        return 2

    started = time.perf_counter()
    plain = [[spec.catalog.id for spec in specs if not spec.keywords or any(k in view for k in spec.keywords)]
             for view in views]
    plain_seconds = time.perf_counter() - started

    started = time.perf_counter()
    routed = []
    for view in views:
        present = engine._router.present(view)
        routed.append([spec.catalog.id for spec in specs if not spec.keywords or any(k in present for k in spec.keywords)])
    routed_seconds = time.perf_counter() - started

    mismatches = sum(a != b for a, b in zip(plain, routed, strict=True))
    speedup = plain_seconds / routed_seconds if routed_seconds else float("inf")
    print(f"files={len(views)} bytes={size} plain={plain_seconds:.3f}s ({plain_seconds / size * 1e6:.3f}s/MB) "
          f"routed={routed_seconds:.3f}s ({routed_seconds / size * 1e6:.3f}s/MB) mismatches={mismatches}")
    if mismatches or speedup < args.min_speedup:
        print(f"ROUTING FAILED speedup={speedup:.1f}")
        return 1
    print(f"ROUTING OK speedup={speedup:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
