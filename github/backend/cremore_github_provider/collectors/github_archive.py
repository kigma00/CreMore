"""Read a pinned GitHub archive without extracting or retaining repository files."""

from __future__ import annotations

import gzip
import hashlib
import tarfile
import time
from collections.abc import Callable, Iterator
from contextlib import closing
from urllib.parse import urljoin, urlsplit

from cremore.collectors.base import run_stop

MAX_COMPRESSED_BYTES = 256 << 20
MAX_EXPANDED_BYTES = 1 << 30
MAX_MEMBERS = 200_000
# Seconds spent waiting on GitHub (the response and each body read). Unpacking and the
# scan of every yielded file run between reads and are not counted here, only in
# MAX_TOTAL_SECONDS: a slow scan of a large repository keeps its archive.
MAX_SECONDS = 120
MAX_TOTAL_SECONDS = 30 * 60
MAX_COMPRESSION_RATIO = 1000
TRUSTED_HOSTS = frozenset({"api.github.com", "codeload.github.com"})


class ArchiveUnavailable(RuntimeError):
    """The optional archive path could not complete; use individual blobs."""


def _origin(url: str, hosts=TRUSTED_HOSTS) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ArchiveUnavailable("UNTRUSTED_ARCHIVE_REDIRECT")
    return parsed.scheme, parsed.hostname, parsed.port or 443


class _Clock:
    """Network waiting against MAX_SECONDS, the whole read against MAX_TOTAL_SECONDS."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.waited = 0.0

    def check(self) -> None:
        if self.waited > MAX_SECONDS or time.monotonic() - self.started > MAX_TOTAL_SECONDS:
            raise ArchiveUnavailable("ARCHIVE_TIME_LIMIT")

    def wait(self, call, *args, **kwargs):
        """One wait on the network: the response, or the next body chunk."""
        self.check()
        began = time.monotonic()
        try:
            return call(*args, **kwargs)
        finally:
            self.waited += time.monotonic() - began


class _Chunks:
    def __init__(self, chunks, clock: _Clock) -> None:
        self.chunks = iter(chunks)
        self.buffer = b""
        self.total = 0
        self.clock = clock

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise ArchiveUnavailable("UNBOUNDED_ARCHIVE_READ")
        out = bytearray()
        while len(out) < size:
            if not self.buffer:
                chunk = self.clock.wait(next, self.chunks, None)
                if chunk is None:
                    break
                self.buffer = chunk
                self.total += len(self.buffer)
                if self.total > MAX_COMPRESSED_BYTES:
                    raise ArchiveUnavailable("ARCHIVE_COMPRESSED_LIMIT")
            take = min(size - len(out), len(self.buffer))
            out.extend(self.buffer[:take])
            self.buffer = self.buffer[take:]
        return bytes(out)


class _Expanded:
    def __init__(self, reader, compressed: _Chunks) -> None:
        self.reader, self.compressed = reader, compressed
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > (64 << 10):
            raise ArchiveUnavailable("UNBOUNDED_ARCHIVE_READ")
        self.compressed.clock.check()
        data = self.reader.read(size)
        self.total += len(data)
        if (self.total > MAX_EXPANDED_BYTES
                or self.total > max(1 << 20, self.compressed.total * MAX_COMPRESSION_RATIO)):
            raise ArchiveUnavailable("ARCHIVE_EXPANDED_LIMIT")
        return data


def archive_blobs(
    client, url: str, headers: dict, entries: dict[str, dict], max_object_bytes: int,
    request: Callable[[], None], *, hosts=TRUSTED_HOSTS,
) -> Iterator[tuple[str, bytes]]:
    """Yield only regular members matching the pinned tree's Git blob SHA.

    Missing and substituted files are deliberately not yielded; the caller
    retrieves them through the blob API. Requests and redirects stay on
    ``hosts`` (github.com's API and codeload, or an Enterprise Server's own
    host). Redirect credentials never cross an origin boundary, including a
    redirect back to the original origin.
    """

    clock = _Clock()
    current, current_headers = url, dict(headers)
    strip_credentials = False
    try:
        origin = _origin(current, hosts)
        for _ in range(4):
            clock.check()
            request()
            outgoing = client.build_request("GET", current, headers=current_headers)
            if strip_credentials:
                # Strip after client defaults and its cookie jar are merged.
                for name in ("authorization", "cookie", "proxy-authorization"):
                    outgoing.headers.pop(name, None)
            sent = clock.wait(client.send, outgoing, stream=True, auth=None, follow_redirects=False)
            with closing(sent) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    if not location:
                        raise ArchiveUnavailable("ARCHIVE_REDIRECT_WITHOUT_LOCATION")
                    target = urljoin(current, location)
                    target_origin = _origin(target, hosts)
                    if target_origin != origin:
                        strip_credentials = True
                        current_headers = {
                            key: value for key, value in current_headers.items()
                            if key.lower() not in ("authorization", "cookie", "proxy-authorization")
                        }
                    current, origin = target, target_origin
                    continue
                if response.status_code != 200:
                    raise ArchiveUnavailable("ARCHIVE_HTTP_ERROR")
                length = response.headers.get("content-length")
                if length is not None and int(length) > MAX_COMPRESSED_BYTES:
                    raise ArchiveUnavailable("ARCHIVE_COMPRESSED_LIMIT")
                compressed = _Chunks(response.iter_bytes(chunk_size=64 << 10), clock)
                with gzip.GzipFile(fileobj=compressed, mode="rb") as decoded:
                    expanded = _Expanded(decoded, compressed)
                    with tarfile.open(fileobj=expanded, mode="r|") as archive:
                        seen: set[str] = set()
                        for count, member in enumerate(archive, 1):
                            if count > MAX_MEMBERS:
                                raise ArchiveUnavailable("ARCHIVE_MEMBER_LIMIT")
                            # The first component is GitHub's generated root.
                            components = member.name.split("/")
                            if (len(components) < 2 or any(p in ("", ".", "..") for p in components)
                                    or "\\" in member.name or not member.isfile()):
                                continue
                            path = "/".join(components[1:])
                            entry = entries.get(path)
                            if entry is None or path in seen or member.size > max_object_bytes:
                                continue
                            if member.size != int(entry.get("size", 0) or 0):
                                continue
                            stream = archive.extractfile(member)
                            if stream is None:
                                continue
                            # The member size already matches the tree and is
                            # within the cap; avoid reserving the full cap.
                            data = stream.read(member.size)
                            stream.close()
                            if len(data) != member.size:
                                continue
                            digest = hashlib.sha1(
                                b"blob %d\0" % len(data) + data, usedforsecurity=False
                            ).hexdigest()
                            if digest != entry.get("sha"):
                                continue
                            seen.add(path)
                            yield path, data
                return
        raise ArchiveUnavailable("ARCHIVE_REDIRECT_LIMIT")
    except ArchiveUnavailable:
        raise
    except Exception as exc:  # an optional transport or parser failure uses the pinned blob fallback
        if run_stop(exc):
            raise  # a spent budget or a cancelled or yielding run ends the run; nothing falls back
        # No provider URL, token-bearing redirect or response body is logged.
        raise ArchiveUnavailable(type(exc).__name__) from None
