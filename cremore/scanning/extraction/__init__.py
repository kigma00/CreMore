"""Bounded document-to-detector input, private to the scanning pipeline.

Plain text and binaries stay on the fast path. Parsers receive bytes over an
anonymous pipe and return bounded UTF-8 over another pipe; no document/output
temporary files. On POSIX one persistent parser server (server.py) forks a fresh
child per document; elsewhere each document gets its own process (worker.py).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath

from .contract import (
    DEFAULT_LIMITS,
    EXTRACTOR_EPOCH,
    PLAIN_KINDS,
    ExtractionLimits,
    ExtractionResult,
    kind,
    plain_content,
)

__all__ = ["DEFAULT_LIMITS", "ExtractionLimits", "ExtractionResult", "cache_digest", "extract"]

# Internal switch, not a setting: tests and scripts/bench_extraction.py compare against
# spawn-per-document, which stays the only path where os.fork does not exist (Windows).
_FORK_SERVER = hasattr(os, "fork")
_SERVER_SCRIPT = Path(__file__).with_name("server.py")
# glibc's adaptive mmap threshold would let large replies grow the server's heap, so a child's
# memory limit would depend on earlier documents. A fixed threshold returns large blocks to
# the system when freed. Nothing else is passed from this process's environment.
_SERVER_ENV = {"MALLOC_MMAP_THRESHOLD_": "131072"}
_FORMAT = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_REASON = re.compile(r"|[A-Z][A-Z_]{0,63}")


def _parser_versions():
    result = {}
    for name in ("pypdf", "olefile", "defusedxml", "striprtf"):
        try:
            result[name] = version(name)
        except PackageNotFoundError:
            result[name] = "missing"
    return result


_PARSER_VERSIONS = _parser_versions()


def cache_digest(engine_digest: str, *, limits: ExtractionLimits = DEFAULT_LIMITS) -> str:
    policy = [engine_digest, EXTRACTOR_EPOCH, asdict(limits), _PARSER_VERSIONS]
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode("ascii")).hexdigest()


def extract(data: bytes, *, filename: str = "", limits: ExtractionLimits = DEFAULT_LIMITS,
            progress=None) -> ExtractionResult:
    if len(data) > limits.input_bytes:
        return ExtractionResult(reason="INPUT_LIMIT")
    suffix = PurePosixPath(filename.split("?", 1)[0].replace("\\", "/")).suffix.lower()
    file_kind = kind(data, suffix)
    if file_kind == "image":
        return ExtractionResult(format="image", reason="MEDIA_FORMAT")
    if file_kind == "unsupported":
        return ExtractionResult(reason="UNSUPPORTED_FORMAT")
    if file_kind in PLAIN_KINDS:
        result = plain_content(data, file_kind, limits.text_bytes)
        if len(result.data) > limits.text_bytes:
            return ExtractionResult(result.data[:limits.text_bytes], result.format, False,
                                    result.reason or "TEXT_LIMIT")
        return result
    if progress is not None:
        progress()
    # The suffix never changes interpretation (bytes decide); bounding it keeps the
    # request header one short line for both parser paths.
    request = {"limits": asdict(limits), "suffix": suffix[:32]}
    if _FORK_SERVER:
        return _SERVER.extract(request, data, limits, file_kind, progress)
    return _spawn(request, data, limits, file_kind, progress)


def _result(returncode, output, limits, file_kind):
    """Both parser paths map the child's exit status and frame the same way."""
    if returncode or len(output) > limits.text_bytes + 4096:
        return ExtractionResult(format=file_kind, reason="PARSER_RESOURCE_LIMIT")
    try:
        header, text = output.split(b"\n", 1)
        fields = json.loads(header)
        if len(header) > 4096 or fields["size"] != len(text):
            raise ValueError
        result = ExtractionResult(text, fields["format"], fields["complete"], fields["reason"])
        # Only the fixed vocabulary leaves the parser: a format name and a reason code that
        # agrees with the completeness flag.
        if (type(result.complete) is not bool or not isinstance(result.format, str)
                or not isinstance(result.reason, str) or not _FORMAT.fullmatch(result.format)
                or not _REASON.fullmatch(result.reason) or result.complete == bool(result.reason)):
            raise ValueError
        return result
    except (ValueError, KeyError, TypeError):
        return ExtractionResult(format=file_kind, reason="PARSER_FAILURE")


def _spawn(request, data, limits, file_kind, progress):
    # Executing this fixed sibling script avoids importing the provider/DB graph
    # into the parser process. Normal Python script imports resolve its siblings;
    # no dynamic sys.path modifications or untrusted program paths are used.
    command = [sys.executable, "-B", "-E", "-s", str(Path(__file__).with_name("worker.py"))]
    payload = json.dumps(request).encode("ascii") + b"\n" + data
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL,
                                   # Do not pass collector credentials, proxies,
                                   # cloud identities or DB URLs into parsers.
                                   env={k: os.environ[k] for k in ("SystemRoot", "WINDIR")
                                        if k in os.environ} if os.name == "nt" else {},
                                   close_fds=True,
                                   creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except OSError:
        return ExtractionResult(format=file_kind, reason="PARSER_UNAVAILABLE")
    deadline = time.monotonic() + limits.seconds
    try:
        pending = payload
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ExtractionResult(format=file_kind, reason="PARSE_TIMEOUT")
            try:
                output, _ = process.communicate(input=pending, timeout=min(0.2, remaining))
                break
            except subprocess.TimeoutExpired:
                pending = None
                if progress is not None:
                    progress()
        return _result(process.returncode, output, limits, file_kind)
    finally:
        # Cancellation/progress exceptions propagate after the process is reaped.
        if process.poll() is None:
            process.kill()
        process.communicate()


class _Fault(Exception):
    """The parser server failed, not the document; the reason is retryable."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class _ForkServer:
    """Parent side of server.py: one persistent parser server per scanning process.

    Requests are serialized by the lock. A server that breaks the protocol, closes its
    pipes or overruns the time limit by `margin` is discarded and replaced with the
    next document, as is a server whose child died by a signal and every server after
    `recycle_after` documents.
    """

    recycle_after = 500
    # Seconds beyond limits.seconds before the server itself counts as hung. It also covers
    # starting a server and loading its parsers from a slow disk; the server enforces the
    # parse time limit itself, so only a broken server ever waits this long.
    margin = 30.0

    def __init__(self):
        self.lock = threading.Lock()
        self.process = None
        self.served = 0

    def forget(self):
        # A forked copy of this process must never share the parent's server pipes.
        self.lock = threading.Lock()
        if self.process is not None:
            for stream in (self.process.stdin, self.process.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
        self.process, self.served = None, 0

    def stop(self):
        process, self.process, self.served = self.process, None, 0
        if process is None:
            return
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        # Closed pipes make an orderly server kill and reap its running child and exit 0.
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        if process.returncode != 0:
            # Hung, crashed or killed mid-request: a parser child may still run. The group id
            # stays the server's while it is unreaped or any child is left in the group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            process.wait()

    def extract(self, request, data, limits, file_kind, progress):
        lock = self.lock
        while not lock.acquire(timeout=0.2):
            if progress is not None:
                progress()
        try:
            return self._extract(request, data, limits, file_kind, progress)
        finally:
            lock.release()

    def _extract(self, request, data, limits, file_kind, progress):
        if self.process is not None and (self.served >= self.recycle_after
                                         or self.process.poll() is not None):
            self.stop()
        if self.process is None:
            try:
                # Same isolation as worker.py: fixed sibling script, no inherited
                # environment (collector credentials, proxies, DB URLs) or handles.
                process = subprocess.Popen(
                    [sys.executable, "-B", "-E", "-s", str(_SERVER_SCRIPT)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    env=dict(_SERVER_ENV), close_fds=True, start_new_session=True)
            except OSError:
                return ExtractionResult(format=file_kind, reason="PARSER_UNAVAILABLE")
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            self.process = process
        self.served += 1
        header = json.dumps({**request, "size": len(data)}).encode("ascii") + b"\n"
        try:
            status, returncode, output = self._exchange(header, data, limits, progress)
        except _Fault as fault:
            self.stop()
            return ExtractionResult(format=file_kind, reason=fault.reason)
        except BaseException:
            self.stop()  # cancellation mid-request: this server's state is unknown
            raise
        if status == "timeout":
            result = ExtractionResult(format=file_kind, reason="PARSE_TIMEOUT")
        elif status == "oversized":
            result = ExtractionResult(format=file_kind, reason="PARSER_RESOURCE_LIMIT")
        elif returncode == -signal.SIGKILL:
            # Killed from outside (the OOM killer, say): says nothing about the document.
            result = ExtractionResult(format=file_kind, reason="PARSER_UNAVAILABLE")
        else:
            result = _result(returncode, output, limits, file_kind)
        if returncode < 0:
            # A child died by a signal: the next document gets a fresh server, so a crash
            # never repeats against the same memory layout and state.
            self.stop()
        return result

    def _exchange(self, header, data, limits, progress):
        """Write the request and read the reply without blocking; progress every 0.2 s."""
        to_server, from_server = self.process.stdin.fileno(), self.process.stdout.fileno()
        pending = [memoryview(header), memoryview(data)]
        reply = bytearray()
        fields = None
        cap = limits.text_bytes + 4096
        now = time.monotonic()
        deadline, tick = now + limits.seconds + self.margin, now + 0.2
        with selectors.DefaultSelector() as selector:
            selector.register(to_server, selectors.EVENT_WRITE)
            selector.register(from_server, selectors.EVENT_READ)
            while True:
                now = time.monotonic()
                if now >= tick:
                    if progress is not None:
                        progress()
                    tick = now + 0.2
                if now >= deadline:
                    raise _Fault("PARSE_TIMEOUT")
                for key, _ in selector.select(min(tick, deadline) - now):
                    try:
                        if key.fd == to_server:
                            pending[0] = pending[0][os.write(to_server, pending[0]):]
                            if not pending[0]:
                                pending.pop(0)
                            if not pending:
                                selector.unregister(to_server)
                            continue
                        chunk = os.read(from_server, 1 << 20)
                    except BlockingIOError:
                        continue
                    except OSError:
                        raise _Fault("PARSER_UNAVAILABLE") from None
                    if not chunk:
                        raise _Fault("PARSER_UNAVAILABLE")
                    reply += chunk
                    if fields is None:
                        end = reply.find(b"\n")
                        if end < 0:
                            if len(reply) > 4096:
                                raise _Fault("PARSER_UNAVAILABLE")
                            continue
                        fields = _reply_fields(reply[:end], cap)
                        del reply[:end + 1]
                    # The server answers only a whole request, with exactly `size` bytes.
                    if pending or len(reply) > fields["size"]:
                        raise _Fault("PARSER_UNAVAILABLE")
                    if len(reply) == fields["size"]:
                        return fields["status"], fields["returncode"], bytes(reply)


def _reply_fields(line, cap):
    try:
        fields = json.loads(line)
        status, returncode, size = fields["status"], fields["returncode"], fields["size"]
    except (ValueError, KeyError, TypeError):
        raise _Fault("PARSER_UNAVAILABLE") from None
    if (status not in ("exit", "timeout", "oversized") or type(returncode) is not int
            or type(size) is not int or not 0 <= size <= (cap if status == "exit" else 0)):
        raise _Fault("PARSER_UNAVAILABLE")
    return fields


_SERVER = _ForkServer()
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_SERVER.forget)
