"""Read-ahead contracts: overlap, listing-order effects, owner-only database work, bounds."""

import base64
import io
import json
import threading
import time
import uuid
from concurrent.futures import Future
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx
import pytest
from cremore_aws_provider.collectors.s3 import S3Collector

from cremore.collectors.base import (
    CollectedObject,
    CollectorError,
    RequestBudget,
    check_request_guard,
    guard_requests,
)
from cremore.collectors.scoped import ScopedCollector
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.detection import ResourceRef
from cremore.scanning import prefetch
from cremore.scanning import service as service_module
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.prefetch import OwnerCalls, ReadAhead, ReadAheadStopped
from cremore.scanning.service import ScanService

TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
MODIFIED = datetime(2020, 1, 1, tzinfo=UTC)


class Boom(BaseException):
    """A failure no collector catches: it must surface at its own object."""


class SlowS3:
    """Fake S3 whose GET waits ``latency`` seconds; it records concurrency and threads."""

    def __init__(self, objects, *, latency=0.0, explode=()):
        self.objects, self.latency, self.explode = objects, latency, set(explode)
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.reads = []

    def list_objects_v2(self, **kwargs):
        keys = sorted(k for k in self.objects if k > kwargs.get("StartAfter", ""))
        return {"Contents": [{"Key": k, "Size": len(self.objects[k]), "ETag": f'"{k}"', "LastModified": MODIFIED}
                             for k in keys], "IsTruncated": False}

    def get_object(self, Bucket, Key):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.latency)
            if Key in self.explode:
                raise Boom()
            self.reads.append(Key)
            data = self.objects[Key]
            return {"Body": io.BytesIO(data), "ContentLength": len(data), "ETag": f'"{Key}"', "LastModified": MODIFIED}
        finally:
            with self.lock:
                self.active -= 1


def scan(client, **kwargs):
    repo = InMemoryRepository()
    service = ScanService(Orchestrator(repo))
    collector = S3Collector(client, "bucket", lazy=True, request_budget=kwargs.pop("budget", None))
    return repo, collector, service.run(collector, source_connection_id=uuid.uuid4(), **kwargs)


def readers_alive():
    return [t for t in threading.enumerate() if t.name.startswith("scan-read")]


def test_reads_overlap_well_under_serial_time():
    objects = {f"data/{i:03d}": b"ordinary text" for i in range(64)}
    client = SlowS3(objects, latency=0.05)
    started = time.perf_counter()
    _repo, _collector, summary = scan(client)
    elapsed = time.perf_counter() - started
    serial = 64 * 0.05
    assert summary.objects == 64 and sorted(client.reads) == sorted(objects)
    assert client.peak <= S3Collector.read_concurrency
    assert elapsed < serial / 2, (elapsed, serial)
    assert not readers_alive()


def test_a_reader_error_surfaces_at_its_own_object_after_earlier_objects_commit():
    objects = {f"data/{i:03d}": f"key={TOKEN[:-2]}{i:02d}".encode() for i in range(30)}
    client = SlowS3(objects, latency=0.01, explode={"data/012"})
    repo = InMemoryRepository()
    collector = S3Collector(client, "bucket", lazy=True)
    with pytest.raises(Boom):
        ScanService(Orchestrator(repo)).run(collector, source_connection_id=uuid.uuid4())
    committed = {e.location for e in repo.exposures.values()}
    assert committed == {f"data/{i:03d}" for i in range(12)}
    assert not readers_alive()


def test_only_the_owner_thread_touches_the_database_or_the_request_guard(monkeypatch):
    owner = threading.get_ident()
    seen = []

    def owner_only(name):
        seen.append((name, threading.get_ident()))

    original_cache, original_lookup = ScanStore.cache, ScanStore.cached_many
    monkeypatch.setattr(ScanStore, "cache", lambda self, *a, **k: (owner_only("cache"), original_cache(self, *a, **k))[1])
    monkeypatch.setattr(ScanStore, "cached_many",
                        lambda self, *a, **k: (owner_only("lookup"), original_lookup(self, *a, **k))[1])
    repo = InMemoryRepository()

    @contextmanager
    def write_context():
        owner_only("write")
        yield repo

    objects = {f"data/{i:03d}": (TOKEN.encode() if i % 7 == 0 else b"plain") for i in range(40)}
    client = SlowS3(objects, latency=0.01)
    collector = S3Collector(client, "bucket", lazy=True, request_budget=RequestBudget(1000))
    with guard_requests(lambda: owner_only("guard")):
        ScanService(Orchestrator(repo)).run(collector, source_connection_id=uuid.uuid4(), write_context=write_context)
    names = {name for name, _ in seen}
    assert {"cache", "lookup", "write", "guard"} <= names
    assert all(ident == owner for _, ident in seen)
    assert client.peak > 1  # reads did overlap, and still asked the owner


def test_in_flight_known_bytes_stay_within_the_bound(monkeypatch):
    monkeypatch.setattr(prefetch, "MAX_BYTES", 3 * 100)
    objects = {f"data/{i:03d}": b"x" * 100 for i in range(24)}
    client = SlowS3(objects, latency=0.02)
    _repo, _collector, summary = scan(client)
    assert summary.objects == 24 and 1 < client.peak <= 3


def test_reads_ahead_never_spend_requests_past_the_budget():
    # One listing request plus five reads: the sixth object is denied in listing order.
    objects = {f"data/{i:03d}": b"plain" for i in range(20)}
    client = SlowS3(objects, latency=0.01)
    budget = RequestBudget(6)
    with pytest.raises(Exception, match="BUDGET_REQUESTS"):
        scan(client, budget=budget)
    assert sorted(client.reads) == [f"data/{i:03d}" for i in range(5)]
    assert budget.used == 6 and not readers_alive()


def test_owner_calls_return_results_and_send_errors_to_the_asking_reader():
    calls = OwnerCalls()
    box = {}

    def reader():
        box["value"] = calls.call(lambda: threading.get_ident())
        try:
            calls.call(lambda: (_ for _ in ()).throw(ValueError("denied")))
        except ValueError as exc:
            box["error"] = str(exc)

    thread = threading.Thread(target=reader)
    thread.start()
    deadline = time.monotonic() + 5
    while thread.is_alive() and time.monotonic() < deadline:
        calls.pump(0.01)
    thread.join(1)
    assert box == {"value": calls.owner, "error": "denied"}


def test_a_stopped_read_ahead_unwinds_a_waiting_reader():
    calls = OwnerCalls()
    outcome = []

    def reader():
        try:
            calls.call(check_request_guard)
        except ReadAheadStopped:
            outcome.append("stopped")

    thread = threading.Thread(target=reader)
    thread.start()
    calls.stopped.set()
    thread.join(2)
    assert outcome == ["stopped"]


def test_read_ahead_holds_what_reads_downloaded_or_may_still_download():
    reader = ReadAhead(2)
    try:
        done, running = Future(), Future()
        done.set_result(b"")
        reader.reads = {done: (SimpleNamespace(data=b"x" * 10), 1000), running: (SimpleNamespace(data=None), 500)}
        assert reader.held() == 10 + 500
    finally:
        reader.reads = {}
        reader.close()


class EagerAndLazy:
    """Even objects come with their bytes (read while listing); odd ones are read ahead."""

    read_concurrency, counts_read_failures, failed_objects = 8, True, 0

    def __init__(self, count, size):
        self.max_object_bytes, self.size, self.count = size, size, count
        self.lock = threading.Lock()
        self.held = self.peak = 0

    def hold(self, change):
        with self.lock:
            self.held += change
            self.peak = max(self.peak, self.held)

    def load(self):
        time.sleep(0.005)
        self.hold(self.size)
        return b"y" * self.size

    def collect(self):
        for i in range(self.count):
            resource = ResourceRef(source_type="synthetic", resource="root", location=f"obj/{i:03d}", size=self.size)
            if i % 2 == 0:
                self.hold(self.size)
                yield CollectedObject(resource, b"y" * self.size)
            else:
                yield CollectedObject(resource, None, loader=self.load)


def test_listing_downloads_and_reads_ahead_share_one_bound(monkeypatch):
    monkeypatch.setattr(prefetch, "MAX_BYTES", 3 * 100)
    collector = EagerAndLazy(40, 100)
    real = service_module.extract

    def extract(data, **kwargs):
        collector.hold(-len(data))  # inspected: no longer held ahead
        return real(data, **kwargs)

    monkeypatch.setattr(service_module, "extract", extract)
    assert ScanService(Orchestrator(InMemoryRepository())).run(collector).objects == 40
    # One bound for both kinds, overshot by at most the object admitted when there was room.
    assert collector.peak <= 3 * 100 + 100


class UnknownSizes:
    """Lazy objects without a listed size, as content collectors list them."""

    read_concurrency, counts_read_failures, failed_objects = 8, True, 0

    def __init__(self, count, size):
        self.max_object_bytes, self.size = size, size
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.count = count

    def load(self):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.02)
        with self.lock:
            self.active -= 1
        return b"y" * self.size

    def collect(self):
        for i in range(self.count):
            resource = ResourceRef(source_type="synthetic", resource="root", location=f"obj/{i:03d}")
            yield CollectedObject(resource, None, loader=self.load)


def test_an_unknown_size_is_held_as_the_object_limit(monkeypatch):
    monkeypatch.setattr(prefetch, "MAX_BYTES", 3 * 100)
    collector = UnknownSizes(24, 100)
    summary = ScanService(Orchestrator(InMemoryRepository())).run(collector)
    assert summary.objects == 24 and 1 < collector.peak <= 3


def test_a_scoped_run_charges_lazy_objects_only_when_they_are_read():
    objects = {f"data/{i:03d}": b"ordinary text" for i in range(10)}  # 13 bytes each
    client = SlowS3(objects)
    repo, connection = InMemoryRepository(), uuid.uuid4()
    first = ScopedCollector([S3Collector(client, "bucket", lazy=True)])
    assert ScanService(Orchestrator(repo)).run(first, source_connection_id=connection).objects == 10
    assert first.bytes == 13 * 10 and len(client.reads) == 10
    # Every object is a cache hit now: nothing is downloaded, so nothing is spent, and a byte
    # budget smaller than the listed sizes no longer stops the rescan.
    client.reads.clear()
    again = ScopedCollector([S3Collector(client, "bucket", lazy=True)], budget_bytes=20)
    summary = ScanService(Orchestrator(repo)).run(again, source_connection_id=connection)
    assert summary.objects == 10 and summary.reused == 10 and client.reads == []
    assert again.bytes == 0 and again.stopped is None


def test_reads_ahead_never_download_past_a_scoped_byte_budget():
    objects = {f"data/{i:03d}": b"x" * 100 for i in range(20)}
    client = SlowS3(objects, latency=0.01)
    scoped = ScopedCollector([S3Collector(client, "bucket", lazy=True)], budget_bytes=350)
    with pytest.raises(CollectorError, match="BUDGET_BYTES"):
        ScanService(Orchestrator(InMemoryRepository())).run(scoped, source_connection_id=uuid.uuid4())
    assert len(client.reads) <= 3 and scoped.bytes <= 350 and scoped.stopped == "BUDGET_BYTES"
    # However many readers found no room, the stop is recorded once.
    assert scoped.skipped == 1 and scoped.coverage["skipped"] == 1
    assert not readers_alive()


def test_a_read_that_yields_to_a_change_scan_stops_the_run_and_is_not_a_failed_object():
    from cremore_gcp_provider.content import Collector as GcsCollector

    class Yielding(RequestBudget):
        def consume(self):
            super().consume()
            if self.used > 3:  # the listing passed; a read finds the sweep yielding to a change scan
                raise CollectorError("YIELDED_TO_EVENT")

    api = ProviderAPI("gcp", count=6)
    collector = GcsCollector({"bucket": "synthetic-bucket", "token": "t", "_lazy": True}, api,
                             request_budget=Yielding(100))
    with pytest.raises(CollectorError, match="YIELDED_TO_EVENT"):
        ScanService(Orchestrator(InMemoryRepository())).run(collector, source_connection_id=uuid.uuid4())
    assert collector.failed_objects == 0 and not readers_alive()


def test_a_failed_commit_on_the_way_out_never_replaces_the_stop_that_ended_the_run():
    objects = {f"data/{i:03d}": b"plain" for i in range(10)}
    client = SlowS3(objects, latency=0.001)
    collector = S3Collector(client, "bucket", lazy=True, request_budget=RequestBudget(6))

    def commit_objects(_repo, outcomes):
        if len(outcomes) > 1:
            raise RuntimeError("the batch could not be written")
        return 1

    with pytest.raises(Exception, match="BUDGET_REQUESTS"):
        ScanService(Orchestrator(InMemoryRepository())).run(
            collector, source_connection_id=uuid.uuid4(), commit_objects=commit_objects, batchable=lambda _r: True)


class Reply:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code, self.content, self.headers = status, body, headers or {}

    def json(self):
        return json.loads(self.content)

    def close(self):
        pass


class ProviderAPI:
    """One provider's paginated listing and slow content reads; each object's bytes name it.

    Unknown routes answer 404 and are recorded, so a request sent to a wrong base or with
    another object's address fails the test instead of passing unnoticed.
    """

    def __init__(self, provider, count=150):
        self.provider, self.count = provider, count
        self.keys = [f"dir{i % 3}/file{i:03d}.txt" for i in range(count)]
        self.blobs = {f"{i + 1:040x}": key for i, key in enumerate(self.keys)}
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.reads, self.unexpected = [], []

    @staticmethod
    def content(key):
        return f"content of {key}\n".encode()

    def read(self, key):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(0.005)
            with self.lock:
                self.reads.append(key)
            return Reply(200, self.content(key))
        finally:
            with self.lock:
                self.active -= 1

    def get(self, url, params=None, headers=None, **_kwargs):
        parts = urlsplit(url)
        query = {**dict(parse_qsl(parts.query)), **{k: str(v) for k, v in (params or {}).items()}}
        expected = "Basic " + base64.b64encode(b":t").decode() if self.provider == "azure_devops" else "Bearer t"
        reply = None
        if (headers or {}).get("Authorization") == expected:
            reply = getattr(self, self.provider)(parts, query, headers or {})
        if reply is None:
            with self.lock:
                self.unexpected.append(url)
            return Reply(404)
        return reply

    @staticmethod
    def body(value, headers=None):
        return Reply(200, json.dumps(value).encode(), headers)

    def gitlab(self, parts, query, _headers):
        route = parts.path.removeprefix("/api/v4/projects/7")
        if route == "":
            return self.body({"id": 7, "path_with_namespace": "org/project"})
        if route == "/repository/commits/HEAD":
            return self.body({"id": "a" * 40})
        if route == "/repository/tree":
            page = int(query["page"])
            rows = [{"type": "blob", "path": key, "id": blob}
                    for blob, key in list(self.blobs.items())[(page - 1) * 100:page * 100]]
            return self.body(rows, {"x-next-page": str(page + 1) if page * 100 < self.count else ""})
        if route.startswith("/repository/blobs/") and route.endswith("/raw") and route.split("/")[3] in self.blobs:
            return self.read(self.blobs[route.split("/")[3]])
        return None

    def gcp(self, parts, query, _headers):
        base = "/storage/v1/b/synthetic-bucket/o"
        if parts.path == base:
            start = int(query.get("pageToken") or 0)
            rows = [{"name": key, "generation": "7", "size": str(len(self.content(key)))}
                    for key in self.keys[start:start + 100]]
            more = {"nextPageToken": str(start + 100)} if start + 100 < self.count else {}
            return self.body({"items": rows, **more})
        key = unquote(parts.path.removeprefix(base + "/"))
        if query.get("alt") == "media" and query.get("generation") == "7" and key in self.keys:
            return self.read(key)
        return None

    def azure_blob(self, parts, query, headers):
        if parts.netloc != "synthacct.blob.core.windows.net" or not headers.get("x-ms-version"):
            return None
        if parts.path == "/data" and query.get("comp") == "list":
            start = int(query.get("marker") or 0)
            rows = "".join(f"<Blob><Name>{key}</Name><Properties><Etag>&quot;0x{index}&quot;</Etag>"
                           f"<Content-Length>{len(self.content(key))}</Content-Length></Properties></Blob>"
                           for index, key in enumerate(self.keys[start:start + 50], start))
            marker = str(start + 50) if start + 50 < self.count else ""
            return Reply(200, ("<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults>"
                               f"<Blobs>{rows}</Blobs><NextMarker>{marker}</NextMarker></EnumerationResults>").encode())
        key = unquote(parts.path.removeprefix("/data/"))
        if key in self.keys and headers.get("If-Match") == f'"0x{self.keys.index(key)}"':
            return self.read(key)
        return None

    def azure_devops(self, parts, query, _headers):
        repo = "/acme/Platform/_apis/git/repositories/api"
        if parts.netloc != "dev.azure.com" or query.get("api-version") != "7.1":
            return None
        if parts.path == repo:
            return self.body({"name": "api", "defaultBranch": "refs/heads/main"})
        if parts.path == repo + "/refs":
            return self.body({"value": [{"name": "refs/heads/main", "objectId": "a" * 40}]})
        if parts.path == repo + "/items" and query.get("recursionLevel") == "Full":
            return self.body({"value": [{"path": "/" + key, "gitObjectType": "blob", "objectId": blob}
                                        for blob, key in self.blobs.items()]})
        blob = parts.path.removeprefix(repo + "/blobs/")
        return self.read(self.blobs[blob]) if blob in self.blobs else None

    def bitbucket(self, parts, query, _headers):
        repo = "/2.0/repositories/team/repo"
        tree = repo + "/src/" + "a" * 40 + "/"
        if parts.path == repo:
            return self.body({"mainbranch": {"name": "main"}})
        if parts.path == repo + "/commit/main":
            return self.body({"hash": "a" * 40})
        if not parts.path.startswith(tree):
            return None
        rest = unquote(parts.path.removeprefix(tree))
        directories = sorted({key.split("/")[0] for key in self.keys})
        if rest == "":
            return self.body({"values": [{"type": "commit_directory", "path": d} for d in directories]})
        if rest in directories:
            files = [key for key in self.keys if key.startswith(rest + "/")]
            page = int(query.get("page", "1"))
            more = ({"next": f"https://api.bitbucket.org{tree}{rest}?page={page + 1}"}
                    if page * 20 < len(files) else {})
            return self.body({"values": [{"type": "commit_file", "path": key}
                                         for key in files[(page - 1) * 20:page * 20]], **more})
        return self.read(rest) if rest in self.keys else None

    def github(self, parts, query, _headers):
        repo = "/repos/o/r"
        if parts.netloc != "api.github.com":
            return None
        if parts.path == repo:
            return self.body({"private": True})
        if parts.path == repo + "/commits/HEAD":
            return self.body({"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}})
        if parts.path == repo + "/git/trees/" + "b" * 40 and query.get("recursive") == "1":
            return self.body({"tree": [{"type": "blob", "path": key, "sha": blob, "size": len(self.content(key))}
                                       for blob, key in self.blobs.items()]})
        blob = parts.path.removeprefix(repo + "/git/blobs/")
        if blob not in self.blobs:
            return None
        data = self.read(self.blobs[blob]).content
        return self.body({"encoding": "base64", "content": base64.b64encode(data).decode()})


def provider_collector(provider, client):
    from cremore_atlassian_provider import bitbucket_content
    from cremore_azure_provider import blob_content, devops_content
    from cremore_gcp_provider import content as gcs_content
    from cremore_github_provider.collectors.github import GitHubCollector
    from cremore_gitlab_provider import content as gitlab_content

    if provider == "github":
        return GitHubCollector(client, "o", "r", token="t", lazy=True)
    module, payload = {
        "gitlab": (gitlab_content, {"project": "7", "base_url": "https://gitlab.example.test"}),
        "gcp": (gcs_content, {"bucket": "synthetic-bucket"}),
        "azure_blob": (blob_content, {"account": "synthacct", "container": "data"}),
        "azure_devops": (devops_content, {"organization": "acme", "project": "Platform", "repository": "api"}),
        "bitbucket": (bitbucket_content, {"workspace": "team", "repo": "repo", "edition": "cloud",
                                          "base_url": "https://api.bitbucket.org"}),
    }[provider]
    return module.Collector({**payload, "token": "t", "_lazy": True}, client)


@pytest.mark.parametrize("provider", ["gitlab", "gcp", "azure_blob", "azure_devops", "bitbucket", "github"])
def test_each_concurrent_content_collector_reads_every_object_once_with_its_own_bytes(monkeypatch, provider):
    # These collectors keep read_concurrency 8: their loaders share no mutable state. A
    # later loader that does would send requests to wrong addresses and fail here.
    api = ProviderAPI(provider)
    seen = {}
    real = service_module.extract

    def extract(data, *, filename="", **kwargs):
        seen[filename] = data
        return real(data, filename=filename, **kwargs)

    monkeypatch.setattr(service_module, "extract", extract)
    if provider == "github":
        from cremore_github_provider.collectors import github

        # GitHub's ten-a-second pacing has its own tests; against this fake's 5 ms reads it would leave
        # nothing to overlap, so this case checks the readers alone.
        monkeypatch.setattr(github, "REQUEST_INTERVAL", 0.0)
    collector = provider_collector(provider, api)
    assert collector.read_concurrency == 8
    summary = ScanService(Orchestrator(InMemoryRepository())).run(collector, source_connection_id=uuid.uuid4())
    assert summary.objects == api.count and summary.objects_failed == 0 and api.unexpected == []
    assert seen == {key: api.content(key) for key in api.keys}
    assert sorted(api.reads) == sorted(api.keys) and api.peak > 1


class ConfluenceClient:
    """120 attachments in two listing pages: the second page is requested while downloads run."""

    SITE = "https://example.atlassian.net/wiki"
    MEDIA = "https://media.example.test/file/"

    def __init__(self):
        self.urls, self.lock = [], threading.Lock()
        self.active = self.peak = 0

    def get(self, url, params=None, headers=None, **_kwargs):
        if (headers or {}).get("Host"):  # a pinned hop off the site dials the address and names the host
            assert httpx.URL(url).host == "93.184.216.34"
            url = str(httpx.URL(url).copy_with(host=headers["Host"]))
        with self.lock:
            self.urls.append(url)
        if url == self.SITE + "/api/v2/pages/1":
            return Reply(200, json.dumps({"id": "1", "spaceId": "S", "version": {"number": 3},
                                          "body": {"storage": {"value": "hello"}}}).encode())
        if url == self.SITE + "/api/v2/pages/1/attachments":
            first = (params or {}).get("cursor") != "c2"
            start, count = (0, 100) if first else (100, 20)
            rows = [{"id": f"att{i}", "downloadLink": f"/download/attachments/1/f{i}.txt", "version": {"number": 1}}
                    for i in range(start, start + count)]
            links = {"next": "/wiki/api/v2/pages/1/attachments?cursor=c2"} if first else {}
            return Reply(200, json.dumps({"results": rows, "_links": links}).encode())
        prefix = self.SITE + "/rest/api/content/1/child/attachment/att"
        if url.startswith(prefix) and url.endswith("/download"):
            # The REST download answers with where the bytes are served (another host, no token).
            return Reply(302, headers={"location": self.MEDIA + url.removeprefix(prefix).removesuffix("/download")})
        if url.startswith(self.MEDIA):
            assert "Authorization" not in (headers or {})
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                time.sleep(0.005)
                # Each attachment's bytes name it, so a download sent for another one is caught.
                return Reply(200, f"attachment att{url.removeprefix(self.MEDIA)}".encode())
            finally:
                with self.lock:
                    self.active -= 1
        return Reply(404)


def test_confluence_attachments_are_read_concurrently_from_the_site_while_the_api_base_stays(monkeypatch):
    from cremore_atlassian_provider import confluence_content
    from cremore_atlassian_provider.confluence_content import Collector

    monkeypatch.setattr(confluence_content, "_resolve", lambda host, _port: {"93.184.216.34"})
    client = ConfluenceClient()
    collector = Collector({"edition": "cloud", "base_url": ConfluenceClient.SITE, "space": "S", "page_id": "1",
                           "token": "t", "_lazy": True}, client)
    assert collector.read_concurrency == 8 and collector.counts_read_failures is True
    seen = {}
    real = service_module.extract

    def extract(data, *, filename="", **kwargs):
        seen[filename] = data
        return real(data, filename=filename, **kwargs)

    monkeypatch.setattr(service_module, "extract", extract)
    summary = ScanService(Orchestrator(InMemoryRepository())).run(collector, source_connection_id=uuid.uuid4())
    assert summary.objects == 121 and summary.objects_failed == 0
    assert all(url.startswith((ConfluenceClient.SITE + "/api/v2/", ConfluenceClient.SITE + "/rest/api/content/1/",
                               ConfluenceClient.MEDIA)) for url in client.urls)
    assert collector.http.base == ConfluenceClient.SITE + "/api/v2"
    downloads = [url for url in client.urls if url.startswith(ConfluenceClient.MEDIA)]
    assert sorted(downloads) == sorted(f"{ConfluenceClient.MEDIA}{i}" for i in range(120))
    assert seen == {"body": b"hello", **{f"attachments/att{i}": f"attachment att{i}".encode() for i in range(120)}}
    assert client.peak > 1
