"""The website connection's target, check and records (N4b). Synthetic domains, a synthetic site."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest

from cremore import domains
from cremore.db.repository import InMemoryRepository
from cremore_website_provider import onboarding

NOW = dt.datetime.now(dt.UTC)


def test_the_target_keeps_domains_and_start_pages_under_them():
    target = onboarding.target("website", "web", {
        "domains": ["Acme.COM", "intranet.acme.test", "Bücher.example"],
        "start_urls": "https://www.acme.com/app\n\nhttp://intranet.acme.test:8080/\nhttps://acme.com/#top\n"
                      "https://shop.BÜCHER.example?q=1"})
    assert target == {"domains": ["acme.com", "intranet.acme.test", "xn--bcher-kva.example"],
                      "start_urls": "https://www.acme.com/app\nhttp://intranet.acme.test:8080/\nhttps://acme.com/\n"
                                    "https://shop.xn--bcher-kva.example/?q=1"}
    # A page under two listed domains belongs to the closer one.
    assert onboarding.children({"target": onboarding.target("website", "web", {
        "domains": ["acme.com", "app.acme.com"], "start_urls": "https://x.app.acme.com/"})}, "exposure", {})[1][
        "config"]["start_urls"] == ["https://x.app.acme.com/"]
    for bad in ({"domains": []}, {"domains": ["127.0x1"]}, {"domains": ["acme.com"], "start_urls": "https://evil.test/"},
                {"domains": ["acme.com"], "start_urls": "https://user:pw@acme.com/"},
                {"domains": ["acme.com"], "start_urls": "ftp://acme.com/"},
                {"domains": ["acme.com", "acme.org"],  # more start pages than one domain may have
                 "start_urls": "\n".join(f"https://acme.com/{n}" for n in range(21))}):
        with pytest.raises(onboarding.OnboardingValueError):
            onboarding.target("website", "web", bad)


def test_one_content_source_per_domain_with_its_own_start_pages():
    connection = {"target": {"domains": ["acme.com", "intranet.acme.test"],
                             "start_urls": "https://www.acme.com/app\nhttp://intranet.acme.test:8080/"}}
    children = onboarding.children(connection, "exposure", {})
    assert [(child["source_type"], child["config"]) for child in children] == [
        ("website", {"domain": "acme.com", "start_urls": ["https://www.acme.com/app"]}),
        ("website", {"domain": "intranet.acme.test", "start_urls": ["http://intranet.acme.test:8080/"]})]
    assert onboarding.children({"target": {"domains": ["acme.com"], "start_urls": ""}}, "exposure", {})[0]["config"][
        "start_urls"] == ["https://acme.com/"]


def test_the_connection_keeps_no_secret_and_takes_no_stored_secret_in_its_place():
    from cremore.config import Settings
    from cremore.onboarding import service
    from cremore.onboarding.store import ProviderConnectionStore

    repo, settings = InMemoryRepository(), Settings(FINGERPRINT_KEY="ab" * 32)
    body = {"provider": "website", "edition": "web", "purposes": ["exposure"], "auth_method": "none",
            "target": {"domains": ["acme.com"]}}
    record = service.create(repo, settings, body, "admin")
    assert ProviderConnectionStore(repo).get(record["id"])["secret_refs"] == {}
    with pytest.raises(service.OnboardingError) as refused:
        service.create(repo, settings, {**body, "credential": {"vault_ref": "vault://cremore/any"}}, "admin")
    assert refused.value.code == "CREDENTIAL_REFERENCE_NOT_ALLOWED"


def test_the_check_names_an_unverified_domain_and_reaches_nothing_for_it():
    repo = InMemoryRepository()
    domains.add(repo, "acme.com", "alice", NOW)  # added, never verified
    items = onboarding.check({"target": {"domains": ["acme.com"], "start_urls": ""}}, "exposure", {},
                             SimpleNamespace(repo=repo))
    assert items == [{"permission": "domains_verified", "status": "MISSING", "detail": "DOMAIN_NOT_VERIFIED",
                      "subject": "acme.com"},
                     {"permission": "site_reachable", "status": "NOT_REPORTED", "detail": "DOMAIN_NOT_VERIFIED"}]


@pytest.mark.parametrize("with_length", [False, True])
@pytest.mark.parametrize(("size", "limit_mb", "status"), [
    (2 << 20, 50, "GRANTED"),
    (5 << 20, 50, "GRANTED"),
    ((5 << 20) + 1, 50, "MISSING"),
    (2 << 20, 1, "MISSING"),
    (2 << 20, 2, "GRANTED"),
])
def test_reachability_uses_the_scan_object_bound(monkeypatch, size, limit_mb, status, with_length):
    from cremore_website_provider import fetch, source
    from cremore_website_provider.fetch_test import Site, cover

    stamp = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)

    class Clock:
        @staticmethod
        def now(tz):
            return stamp

    def covering(repo, host, now):
        assert now == stamp
        return cover(host)

    monkeypatch.setattr(onboarding, "_dt", SimpleNamespace(datetime=Clock, UTC=dt.UTC))
    monkeypatch.setattr(domains, "covering", covering)
    site = Site({("acme.test", "/"): (200, {"content-length": str(size)} if with_length else {}, b"x" * size)})
    real_fetcher = fetch.Fetcher
    bounds = []

    def fetcher(cover, **kwargs):
        bounds.append(kwargs["max_bytes"])
        return real_fetcher(cover, **kwargs, resolve=lambda host, port: {"8.8.8.10"}, client_factory=site, proxies={})

    monkeypatch.setattr(fetch, "Fetcher", fetcher)
    settings = SimpleNamespace(max_object_size_mb=limit_mb)
    items = onboarding.check({"target": {"domains": ["acme.test"], "start_urls": ""}}, "exposure", {},
                             SimpleNamespace(repo=InMemoryRepository(), settings=settings))
    reachability = items[-1]
    assert reachability["status"] == status
    assert reachability.get("detail") == ("TOO_LARGE" if status == "MISSING" else None)
    payload = source.job_payload({"domain": "acme.test"})
    collector = source.build_collector(None, {**payload, "domain_cover": cover}, max_object_bytes=limit_mb << 20)
    try:
        assert bounds == [min(limit_mb << 20, 5 << 20)] * 2
    finally:
        collector.fetcher.close()
