"""A website scan through the worker and the public factory (N4b): a verified domain, a synthetic DNS and a synthetic
site, never the network. The finding names the map source it was read from and that the page was public."""

from __future__ import annotations

import datetime as dt
import json
import urllib.request

import httpx
import pytest

from cremore import domains
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker
from cremore.worker.factory import build_collector
from cremore_website_provider import fetch, source

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)
TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"  # synthetic, built at run time
MAP_SOURCE = "https://acme.com/app.js.map!/webpack://app/src/config.ts"


def site(monkeypatch):
    """acme.com's synthetic site behind one public address; each request's address, Host, TLS name and path kept."""
    pages = {
        "/": ("text/html", b'<script src="/app.js"></script><script src="https://cdn.example/x.js"></script>'),
        "/app.js": ("application/javascript", b"run();\n//# sourceMappingURL=app.js.map\n"),
        "/app.js.map": ("application/json", json.dumps({
            "version": 3, "sources": ["webpack://app/src/config.ts"],
            "sourcesContent": [f"export const token = '{TOKEN}';\n"]}).encode()),
    }
    asked = []

    def handle(request):
        asked.append((request.url.host, request.headers["host"], request.extensions.get("sni_hostname"),
                      request.url.path))
        kind, body = pages.get(request.url.path, ("text/plain", b""))
        return httpx.Response(200 if request.url.path in pages else 404, headers={"content-type": kind},
                              stream=httpx.ByteStream(body))  # not yet read, as a real transport hands it over

    monkeypatch.setattr(fetch, "_resolve", lambda host, port: {"8.8.8.9"} if host == "acme.com" else set())
    monkeypatch.setattr(fetch, "_client", lambda proxied: httpx.Client(transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(urllib.request, "getproxies_environment", dict)  # no proxy from the machine running the test
    return asked


def test_a_verified_domains_source_map_is_scanned_through_the_worker(monkeypatch):
    asked = site(monkeypatch)
    repo = InMemoryRepository()
    now = dt.datetime.now(dt.UTC)
    added = domains.add(repo, "acme.com", "alice", now)
    record = {added["record"]["name"] + ".": [added["record"]["value"]]}
    assert domains.verify(repo, SETTINGS, "acme.com", "alice", now, lambda fqdn, servers: record[fqdn])["status"] == (
        "VERIFIED")

    job = repo.enqueue_job(ScanJob(kind="website", payload=source.job_payload({"domain": "acme.com"})))
    assert JobWorker(repo).process_next() is True
    done = repo.get_job(job.id)
    assert (done.status, done.objects_failed) == ("SUCCEEDED", 0)
    # Every request went to the checked address under the verified name; the CDN's script was never asked for.
    assert asked == [("8.8.8.9", "acme.com", "acme.com", path) for path in ("/", "/app.js", "/app.js.map")]
    [exposure] = repo.exposures.values()
    assert (exposure.source_type, exposure.resource_name, exposure.location, exposure.metadata["exposure"]) == (
        "website", "acme.com", MAP_SOURCE, "public")
    [finding] = repo.list_findings()
    assert repo.get_credential(finding.credential_id).credential_type == "GITHUB_TOKEN"
    assert TOKEN not in json.dumps([event.model_dump(mode="json") for event in repo.list_events(100)])


def test_an_approved_root_reads_only_the_paths_it_names(monkeypatch):
    asked = site(monkeypatch)

    def cover(host):
        return {"name": "acme.com", "host": host, "allow_internal": False} if host == "acme.com" else None

    def read(root):
        asked.clear()
        payload = {**source.job_payload({"domain": "acme.com"}), "roots": [
            {"resource_type": "WEBSITE", "provider_resource_id": "acme.com", "all_current_objects": False, **root}]}
        collector = build_collector(ScanJob(kind="scope", payload=payload), domain_cover=cover)
        return [item.resource.location for item in collector.collect()], [path for *_, path in asked]

    # A rescan of one finding reads the map it was in again; an empty rescan reads nothing.
    assert read({"exact_paths": [MAP_SOURCE]}) == ([MAP_SOURCE], ["/app.js.map"])
    assert read({"exact_paths": []}) == ([], [])
    # Excluded paths are never asked for; a start page outside the approved paths is not read and fails nothing.
    assert read({"excluded_paths": ["/app.js"]}) == (["https://acme.com/"], ["/"])
    assert read({"paths": ["/docs/"]}) == ([], [])


def test_the_platform_checks_a_website_rescan_as_the_run_reads_it():
    from cremore.scanning import scope

    approved = {"resource_type": "WEBSITE", "paths": ["/static"], "excluded_paths": ["/static/private"]}
    assert scope._exact_within({"exact_paths": ["https://acme.com/static/app.js.map!/webpack://app/src/config.ts"]},
                               approved)
    # /static/PRIVATE is excluded as the run excludes it (the most lenient server's reading), not rescanned to nothing.
    for outside in ("https://acme.com/static/private/x.js", "https://acme.com/static/PRIVATE/x.js",
                    "https://acme.com/other.js", "https://acme.com/staticx.js"):
        assert not scope._exact_within({"exact_paths": [outside]}, approved), outside
    # Entries are read like the URLs, so an encoded Hangul entry admits the location the run would read.
    hangul = {"resource_type": "WEBSITE", "paths": ["/%EA%B4%80%EB%A6%AC%EC%9E%90/"], "excluded_paths": []}
    assert scope._exact_within({"exact_paths": ["https://acme.com/%EA%B4%80%EB%A6%AC%EC%9E%90/app.js"]}, hangul)
    # An entry that is not a URL path admits nothing, and a plan names it before a run would fail on it.
    loose = {"resource_type": "WEBSITE", "paths": [], "excluded_paths": ["admin/"]}
    assert not scope._exact_within({"exact_paths": ["https://acme.com/x.js"]}, loose)
    assert scope._root_problem(loose, {"resource_type": "WEBSITE"}) == "WEBSITE_SCOPE_PATH_INVALID"
    assert scope._root_problem(approved, {"resource_type": "WEBSITE"}) is None


def test_an_event_names_website_locations_as_the_run_reads_them():
    from types import SimpleNamespace

    from cremore.scanning import scope, triggers

    plan = SimpleNamespace(roots=[{"resource_id": "r1", "resource_type": "WEBSITE", "provider_resource_id": "acme.com",
                                   "paths": ["/static"], "excluded_paths": ["/static/private"]}])
    narrowed, mode = triggers._event_root(plan, {"resource_id": "r1", "paths": ["https://acme.com/static/app.js"]})
    assert (narrowed["exact_paths"], mode) == (["https://acme.com/static/app.js"], "EVENT")
    with pytest.raises(scope.ScopeError) as refused:
        triggers._event_root(plan, {"resource_id": "r1", "paths": ["https://acme.com/static/PRIVATE/x.js"]})
    assert refused.value.code == "EVENT_OUT_OF_SCOPE"
