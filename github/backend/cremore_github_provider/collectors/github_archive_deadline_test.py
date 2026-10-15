"""The archive's time limit counts waiting on GitHub, not the scan, and Enterprise Server archives stay on the server."""

import base64
import hashlib
import io
import random
import tarfile
from types import SimpleNamespace

import httpx
import pytest

from cremore_github_provider.collectors import github_archive
from cremore_github_provider.collectors.github import GitHubCollector

COMMIT, TREE = "a" * 40, "b" * 40


def _sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _tar(files):
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w:gz") as archive:
        for path, data in files.items():
            info = tarfile.TarInfo("generated-root/" + path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return body.getvalue()


def _files(count=6, size=60_000):
    # Incompressible, so the archive arrives in several network chunks between the files it holds.
    rng = random.Random(7)
    return {f"dir/file{i}.bin": rng.randbytes(size) for i in range(count)}


class Clock:
    def __init__(self):
        self.now = 0.0


@pytest.fixture
def clock(monkeypatch):
    value = Clock()
    monkeypatch.setattr(github_archive, "time", SimpleNamespace(monotonic=lambda: value.now))
    return value


class Wire(httpx.SyncByteStream):
    """An archive body arriving 16 KiB at a time, each piece taking ``seconds`` on the network."""

    def __init__(self, body, clock, seconds):
        self.body, self.clock, self.seconds = body, clock, seconds

    def __iter__(self):
        for start in range(0, len(self.body), 16 << 10):
            if self.clock is not None:
                self.clock.now += self.seconds
            yield self.body[start:start + (16 << 10)]


class Server:
    def __init__(self, files, *, api="https://api.github.com", redirect="https://codeload.github.com/o/r/archive",
                 clock=None, seconds=0.0):
        self.files, self.api, self.redirect = files, api, redirect
        self.archive = _tar(files)
        self.clock, self.seconds = clock, seconds
        self.requests = []
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        self.requests.append(request)
        if str(request.url).split("?")[0] == self.redirect.split("?")[0]:
            return httpx.Response(200, stream=Wire(self.archive, self.clock, self.seconds))
        prefix = httpx.URL(self.api).path.rstrip("/")
        assert request.url.host == httpx.URL(self.api).host, request.url
        path = request.url.path.removeprefix(prefix)
        if path == "/repos/o/r":
            return httpx.Response(200, json={"private": True})
        if path == "/repos/o/r/commits/main":
            return httpx.Response(200, json={"sha": COMMIT, "commit": {"tree": {"sha": TREE}}})
        if path == f"/repos/o/r/git/trees/{TREE}":
            return httpx.Response(200, json={"tree": [
                {"type": "blob", "path": p, "sha": _sha(d), "size": len(d)} for p, d in self.files.items()]})
        if path == f"/repos/o/r/tarball/{COMMIT}":
            return httpx.Response(302, headers={"location": self.redirect})
        if "/git/blobs/" in path:
            data = next(d for d in self.files.values() if _sha(d) == path.rsplit("/", 1)[1])
            return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(data).decode()})
        raise AssertionError(f"unexpected request {request.url}")

    def collector(self):
        return GitHubCollector(self.client, "o", "r", ref="main", token="synthetic-token", base_url=self.api,
                               use_archive=True)

    def blob_reads(self):
        return [r.url.path.rsplit("/", 1)[1] for r in self.requests if "/git/blobs/" in r.url.path]


def collect(server, clock=None, scan_seconds=0.0):
    """Every object in listing order, the clock moving ``scan_seconds`` while each is scanned."""
    got = []
    for obj in server.collector().collect():
        got.append((obj.resource.location, obj.data))
        if clock is not None:
            clock.now += scan_seconds
    return got


def test_a_slow_scan_of_the_yielded_files_leaves_the_archive_in_use(clock):
    # Six files scanned for 100 s each is far past the 120 s network limit; the network took ~22 s.
    server = Server(_files(), clock=clock, seconds=1.0)
    got = collect(server, clock, scan_seconds=100.0)
    assert dict(got) == server.files and len(got) == len(server.files)
    assert server.blob_reads() == []  # every file came from the archive
    assert clock.now > github_archive.MAX_SECONDS


def test_waiting_on_the_network_past_the_limit_falls_back_to_the_blob_api(clock):
    server = Server(_files(), clock=clock, seconds=10.0)  # ~230 s on the wire in all
    got = collect(server, clock)
    assert dict(got) == server.files and len(got) == len(server.files)  # nothing lost, nothing twice
    reads = server.blob_reads()
    assert reads and len(reads) < len(server.files)
    archived = [path for path, _data in got[:len(got) - len(reads)]]
    assert archived and {_sha(server.files[path]) for path in archived}.isdisjoint(reads)


def test_the_whole_read_ends_after_thirty_minutes_and_the_rest_is_read_by_blob(clock):
    server = Server(_files(), clock=clock, seconds=0.5)
    got = collect(server, clock, scan_seconds=10 * 60.0)
    assert dict(got) == server.files and len(got) == len(server.files)
    reads = server.blob_reads()
    # Three files fit in thirty minutes of scanning; the others are read one by one, each exactly once.
    assert len(reads) == len(server.files) - 3
    assert {_sha(server.files[path]) for path, _data in got[:3]}.isdisjoint(reads)


def test_the_limits_keep_their_values():
    assert github_archive.MAX_SECONDS == 120 and github_archive.MAX_TOTAL_SECONDS == 30 * 60


GHES = "https://ghe.example.test/api/v3"


def test_an_enterprise_server_archive_is_read_while_its_redirect_stays_on_the_server():
    target = f"https://ghe.example.test/_codeload/o/r/legacy.tar.gz/{COMMIT}?token=synthetic-download"
    server = Server(_files(3, 2000), api=GHES, redirect=target)
    assert dict(collect(server)) == server.files
    assert server.blob_reads() == []
    archive = [r for r in server.requests if "/_codeload/" in r.url.path or "/tarball/" in r.url.path]
    assert [r.url.host for r in archive] == ["ghe.example.test", "ghe.example.test"]
    # The same origin: the server's own credential is not sent anywhere else.
    assert all(r.url.host == "ghe.example.test" for r in server.requests)


@pytest.mark.parametrize("target", [
    "https://codeload.ghe.example.test/o/r/legacy.tar.gz/main",  # subdomain isolation: another host
    "https://codeload.github.com/o/r/legacy.tar.gz/main",  # github.com's codeload is not this server's
    "http://ghe.example.test/_codeload/o/r/legacy.tar.gz/main",
    "https://ghe.example.test:8443/_codeload/o/r/legacy.tar.gz/main",
])
def test_an_enterprise_redirect_anywhere_else_falls_back_without_following_it(target):
    server = Server(_files(3, 2000), api=GHES, redirect=target)
    assert dict(collect(server)) == server.files
    assert len(server.blob_reads()) == 3
    assert all(r.url.host == "ghe.example.test" and r.url.port in (None, 443) for r in server.requests)
