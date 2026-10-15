"""Persistent POSIX parser server: every document is parsed in a fresh forked child.

The scanning process starts this fixed sibling script once, like worker.py (`-B -E -s`,
no inherited environment but a fixed malloc mmap threshold, its own process group). The
parser libraries are imported once here; each document is parsed by a new fork of this
single-threaded process (so fork never copies another thread's held lock), under RLIMIT_AS
and RLIMIT_CORE=0, and killed at the time limit. Nothing a child does carries over to the
next document, and the server zeroes every buffer that held a document or its text before
the next fork. Bytes and text stay in pipes and RAM. This is not an OS security sandbox:
deployment isolation still applies.

One request at a time over stdin/stdout:
  request  {"limits": {...}, "suffix": "...", "size": N}\\n + N document bytes
  reply    {"status": "exit"|"timeout"|"oversized", "returncode": R, "size": M}\\n
           + M bytes the child wrote (worker.py's frame), relayed without being read
"""

import codecs
import gc
import importlib
import json
import logging
import math
import os
import resource
import select
import signal
import sys
import time
import warnings

from contract import ExtractionLimits
from formats import parse
from worker import frame, memory_limit


def child(data, suffix, limits, read_end, write_end):
    """Runs in the forked child and never returns, whatever happens."""
    code = 1
    try:
        os.close(read_end)
        # The parser never sees the server's protocol pipes.
        null = os.open(os.devnull, os.O_RDWR)
        os.dup2(null, 0)
        os.dup2(null, 1)
        memory_limit(limits.memory_bytes)
        try:
            # Backstop only: the server's wall-clock kill comes first, but a child that
            # outlives a killed server still stops.
            cpu = math.ceil(limits.seconds) + 1
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        except (ValueError, OSError):
            pass
        view = memoryview(frame(parse(data, suffix, limits)))
        while view:
            view = view[os.write(write_end, view):]
        code = 0
    finally:
        os._exit(code)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def read_header(fd):
    """One request header line, read byte by byte so no document bytes are buffered."""
    line = bytearray()
    while len(line) <= 4096:
        byte = os.read(fd, 1)
        if not byte:
            return None
        if byte == b"\n":
            return bytes(line)
        line += byte
    return None


def run(data, suffix, limits, requests, replies):
    """Parse one document in a forked child and reply; False when the parent left."""
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        child(data, suffix, limits, read_end, write_end)
    os.close(write_end)
    deadline = time.monotonic() + limits.seconds
    cap = limits.text_bytes + 4096
    # The child's output, in 1 MiB buffers filled one after another: large enough to be
    # separate mappings the allocator returns when freed, and zeroed after the reply.
    chunks = []
    size = 0
    status = "timeout"
    try:
        try:
            while (remaining := deadline - time.monotonic()) > 0:
                ready = select.select([read_end, requests], [], [], remaining)[0]
                if requests in ready:
                    # Nothing is sent during a request: this is EOF or a broken protocol.
                    status = None
                    break
                if ready:
                    if not chunks or chunks[-1][1] == len(chunks[-1][0]):
                        chunks.append([bytearray(min(1 << 20, cap + 1 - size)), 0])
                    chunk = chunks[-1]
                    count = os.readv(read_end, [memoryview(chunk[0])[chunk[1]:]])
                    if not count:
                        status = "exit"
                        break
                    chunk[1] += count
                    size += count
                    if size > cap:
                        status = "oversized"
                        break
        finally:
            os.close(read_end)
            if status != "exit":
                os.kill(pid, signal.SIGKILL)
            returncode = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
        if status is None:
            return False
        header = {"status": status, "returncode": returncode, "size": size if status == "exit" else 0}
        write_all(replies, json.dumps(header).encode("ascii") + b"\n")
        if status == "exit":
            for buffer, used in chunks:
                write_all(replies, memoryview(buffer)[:used])
        return True
    finally:
        for buffer, used in chunks:
            buffer[:used] = bytes(used)


def serve(requests, replies):
    while (header := read_header(requests)) is not None:
        request = json.loads(header)
        limits = ExtractionLimits(**request["limits"])
        size = request["size"]
        if type(size) is not int or not 0 <= size <= limits.input_bytes:
            return
        data = bytearray(size)
        try:
            with memoryview(data) as view:
                position = 0
                while position < size:
                    count = os.readv(requests, [view[position:]])
                    if not count:
                        return
                    position += count
            if not run(data, request["suffix"], limits, requests, replies):
                return
        finally:
            # A later child is a fork of this process: it must find no earlier document,
            # not even in freed memory.
            data[:] = bytes(size)


def main():
    # Suppress diagnostics before loading any parser; children inherit this state.
    logging.disable(logging.CRITICAL)
    warnings.simplefilter("ignore")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # this process holds document bytes too
    for name in ("pypdf", "olefile", "defusedxml.ElementTree", "striprtf.striprtf"):
        try:
            importlib.import_module(name)  # once here instead of once per document
        except ImportError:
            pass  # the child that needs it reports PARSER_UNAVAILABLE, as worker.py does
    for encoding in ("utf-8-sig", "utf-16", "utf-32", "cp949", "cp1252", "cp437", "latin-1"):
        codecs.lookup(encoding)  # the readers' decoders, also loaded once
    # Children's garbage collections skip these preloaded objects instead of copying
    # every page they touch.
    gc.freeze()
    serve(sys.stdin.fileno(), sys.stdout.fileno())


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 -- never emit tracebacks; the parent restarts the server
        sys.exit(1)
