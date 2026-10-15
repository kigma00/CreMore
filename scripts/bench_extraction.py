"""Parser process benchmark: the POSIX fork server against one spawned parser per document.

Synthetic and local: builds small DOCX, ZIP and gzip documents in memory, makes no network
or database call and writes no files. Times extract() per document on a running server (its
one-time start is reported separately) and with the spawn-per-document path that Windows
uses. Prints "EXTRACTION OK speedup=<x>" only when both paths return the same result for
every document and the server is at least ``--min-speedup`` times faster.

    python scripts/bench_extraction.py --min-speedup 5
"""

from __future__ import annotations

import argparse
import gzip
import io
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def zipped(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return out.getvalue()


def documents(count):
    made = []
    for n in range(count):
        marker = b"SYNTHETIC_DOCUMENT_%08d" % n
        if n % 3 == 0:
            body = b"<document><p><t>" + marker + b"</t></p></document>"
            made.append((f"report{n}.docx", zipped({"word/document.xml": body}), marker))
        elif n % 3 == 1:
            made.append((f"bundle{n}.zip", zipped({"notes.txt": marker, "readme.md": b"ordinary"}), marker))
        else:
            made.append((f"notes{n}.txt.gz", gzip.compress(marker), marker))
    return made


def timed(extract, docs):
    started = time.perf_counter()
    results = [extract(data, filename=name) for name, data, _marker in docs]
    return time.perf_counter() - started, results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-speedup", type=float, default=5.0)
    parser.add_argument("--documents", type=int, default=60)
    args = parser.parse_args(argv)
    # Measure this checkout: the Linux gate runs the file by path in a container whose installed
    # cremore is older than the code under test.
    sys.path.insert(0, str(ROOT))
    from cremore.scanning import extraction

    if not extraction._FORK_SERVER:
        print("EXTRACTION FAILED: the parser server needs os.fork (POSIX)")
        return 1
    docs = documents(args.documents)
    started = time.perf_counter()
    extraction.extract(docs[0][1], filename=docs[0][0])  # start the server and load its parsers
    server_start = time.perf_counter() - started
    server_seconds, served = timed(extraction.extract, docs)
    extraction._FORK_SERVER = False
    try:
        spawn_seconds, spawned = timed(extraction.extract, docs)
    finally:
        extraction._FORK_SERVER = True
        extraction._SERVER.stop()
    mismatches = sum(a != b for a, b in zip(served, spawned, strict=True))
    unread = sum(not result.complete or marker not in result.data
                 for result, (_name, _data, marker) in zip(served, docs, strict=True))
    speedup = spawn_seconds / server_seconds if server_seconds else float("inf")
    count = len(docs)
    print(f"documents={count} server_start={server_start:.3f}s "
          f"server={server_seconds / count * 1000:.1f}ms/doc spawn={spawn_seconds / count * 1000:.1f}ms/doc "
          f"mismatches={mismatches} unread={unread}")
    if mismatches or unread or speedup < args.min_speedup:
        print(f"EXTRACTION FAILED speedup={speedup:.1f}")
        return 1
    print(f"EXTRACTION OK speedup={speedup:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
