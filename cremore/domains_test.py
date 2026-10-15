"""Company domains: a DNS TXT record carrying this installation's challenge proves ownership, asked again daily (N4a)."""

from __future__ import annotations

import datetime as dt

import pytest

from cremore import domains
from cremore.config import Settings
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine

NOW = dt.datetime(2026, 9, 30, 12, tzinfo=dt.UTC)
SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
    elif request.param == "sqlite":
        engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'domains.db').as_posix()}")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()
    else:
        yield request.getfixturevalue("pg")[1]  # the disposable cremore_test database, when one is set


class DNS:
    """A synthetic DNS: the TXT values each name holds, or an outage; every question is kept."""

    def __init__(self):
        self.records, self.down, self.asked = {}, False, []

    def __call__(self, fqdn, nameservers):
        self.asked.append((fqdn, tuple(nameservers)))
        if self.down:
            raise domains.Unavailable()
        if fqdn not in self.records:
            raise domains.Missing()
        return list(self.records[fqdn])

    def publish(self, view):
        self.records[view["record"]["name"] + "."] = ["v=spf1 -all", view["record"]["value"]]


def trail(repo, actor=None):
    return [(event.event_type, event.note) for event in reversed(repo.list_events(200))
            if event.target_type == "domain" and (actor is None or event.actor == actor)]


def test_a_domain_is_verified_only_by_the_record_carrying_this_installations_challenge(repo):
    dns = DNS()
    added = domains.add(repo, "Acme.COM.", "alice", NOW)
    assert (added["name"], added["status"]) == ("acme.com", "PENDING")
    assert added["record"]["name"] == "_cremore-challenge.acme.com"
    assert added["record"]["value"].startswith("cremore-domain-verification=") and len(added["record"]["value"]) > 50
    assert domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)["result"] == "TXT_NOT_FOUND"
    # Another installation's record for the same domain proves nothing here.
    dns.records["_cremore-challenge.acme.com."] = ["cremore-domain-verification=another-installation"]
    failed = domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)
    assert (failed["status"], failed["result"]) == ("PENDING", "TXT_MISMATCH")
    assert domains.covering(repo, "acme.com", NOW) is None
    dns.publish(added)
    verified = domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)
    assert (verified["status"], verified["result"], verified["verified_at"]) == ("VERIFIED", "VERIFIED", NOW.isoformat())
    assert dns.asked[-1] == ("_cremore-challenge.acme.com.", ())  # absolute, asked of the system's resolver
    # A verified domain covers its subdomains, never a lookalike, and names the host as the scan must reach it.
    assert domains.covering(repo, "App.Acme.com", NOW) == {"name": "acme.com", "host": "app.acme.com",
                                                           "allow_internal": False}
    for other in ("evilacme.com", "acme.com.evil.test", "acme.co", "127.0x1"):
        assert domains.covering(repo, other, NOW) is None
    # Confirmed more than a week ago covers nothing, even if the daily re-check stopped asking.
    assert domains.covering(repo, "acme.com", NOW + dt.timedelta(days=8)) is None
    # Whoever is not an admin sees the state, not the record or who added it.
    shown = domains.public(repo, admin=False)["domains"][0]
    assert "record" not in shown and "added_by" not in shown and shown["status"] == "VERIFIED"
    assert trail(repo) == [("DOMAIN_ADDED", "acme.com"), ("DOMAIN_VERIFICATION_FAILED", "acme.com TXT_NOT_FOUND"),
                           ("DOMAIN_VERIFICATION_FAILED", "acme.com TXT_MISMATCH"),
                           ("DOMAIN_VERIFIED", "acme.com was=PENDING")]


def test_names_are_kept_in_one_form_and_addresses_are_refused():
    assert domains.normalize("Bücher.Example.") == "xn--bcher-kva.example"
    assert domains.normalize("faß.de") == "xn--fa-hia.de"  # IDNA 2008, as a browser and httpx reach it (not fass.de)
    assert domains.normalize("ＡＣＭＥ。com") == "acme.com"  # full-width letters and the ideographic full stop
    assert domains.normalize(" intranet.corp ") == "intranet.corp"  # an intranet's zone is a domain too
    assert domains.normalize("0x7f.example.com") == "0x7f.example.com"  # a number is refused only as the last label
    longest = ".".join(["a" * 63] * 3 + ["b" * 42])
    assert len(longest) == domains.MAX_NAME and domains.normalize(longest) == longest
    # Addresses in any form browsers and getaddrinfo read (127.0x1 is 127.0.0.1), and names whose record would not
    # fit DNS, are refused.
    for bad in ("localhost", "10.0.0.1", "2001:db8::1", "127.0x1", "0x7f.0x1", "10.0x0", "1.2.3.0x4", "1.0x7f",
                "a.0x", "a..b", "-a.com", "a-.com", "a_b.com", "http://acme.com", "*.acme.com", "acme.com/x", "",
                "x" * 64 + ".com", longest + "b", 5, None):
        with pytest.raises(domains.DomainError) as refused:
            domains.normalize(bad)
        assert refused.value.code == "DOMAIN_INVALID"


def test_the_daily_recheck_lapses_a_removed_record_and_only_its_new_record_takes_it_back(repo):
    dns = DNS()
    added = domains.add(repo, "acme.com", "alice", NOW)
    domains.set_internal(repo, "acme.com", True, "alice")
    dns.publish(added)
    domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)
    assert domains.reverify_due(repo, SETTINGS, NOW + dt.timedelta(hours=23), dns) == 0  # asked less than a day ago
    del dns.records["_cremore-challenge.acme.com."]
    assert domains.reverify_due(repo, SETTINGS, NOW + dt.timedelta(days=1), dns) == 1
    lapsed = domains.public(repo, admin=True)["domains"][0]
    assert (lapsed["status"], lapsed["allow_internal"]) == ("LAPSED", False)
    assert domains.covering(repo, "acme.com", NOW + dt.timedelta(days=1)) is None  # a lapsed domain is not scanned
    # The old record is public: whoever registers the domain after it expires could publish it again. It proves
    # nothing now, and the daily check leaves a lapsed domain alone.
    assert lapsed["record"]["value"] != added["record"]["value"]
    dns.publish(added)
    assert domains.reverify_due(repo, SETTINGS, NOW + dt.timedelta(days=3), dns) == 0
    assert domains.verify(repo, SETTINGS, "acme.com", "alice", NOW + dt.timedelta(days=3), dns)["result"] == "TXT_MISMATCH"
    dns.publish(lapsed)  # the new record, which only an admin saw
    assert domains.verify(repo, SETTINGS, "acme.com", "alice", NOW + dt.timedelta(days=3), dns)["status"] == "VERIFIED"
    # Only changes are audited, as bookkeeping (not a person's action, so no SIEM audit event).
    assert trail(repo, domains.ACTOR) == [("DOMAIN_LAPSED", "acme.com TXT_NOT_FOUND challenge_renewed allow_internal=false")]
    assert trail(repo, "alice")[-1] == ("DOMAIN_VERIFIED", "acme.com was=LAPSED")
    from cremore.siem.events import is_system_actor

    assert is_system_actor(domains.ACTOR)


def test_an_answer_about_what_changed_meanwhile_is_dropped_and_one_replica_asks_a_minute(repo):
    dns = DNS()
    added = domains.add(repo, "acme.com", "alice", NOW)
    dns.publish(added)
    domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)
    later = NOW + dt.timedelta(days=1)

    def meanwhile(fqdn, nameservers):
        # While the worker waits for its answer, an admin finds the record gone: the domain lapses.
        domains.verify(repo, SETTINGS, "acme.com", "bob", later, DNS())
        return dns(fqdn, nameservers)

    assert domains.reverify_due(repo, SETTINGS, later, meanwhile) == 1
    assert domains.public(repo, admin=True)["domains"][0]["status"] == "LAPSED"
    assert trail(repo, domains.ACTOR) == []  # the worker's answer about the old record wrote nothing back
    # Another replica in the same minute asks nothing.
    fresh = domains.add(repo, "fresh.example", "alice", NOW)
    dns.publish(fresh)
    domains.verify(repo, SETTINGS, "fresh.example", "alice", NOW, dns)
    asked = len(dns.asked)
    assert domains.reverify_due(repo, SETTINGS, later + dt.timedelta(seconds=1), dns) == 0 and len(dns.asked) == asked


def test_the_worker_asks_again_from_its_maintenance_tick(monkeypatch):
    from cremore.worker.worker import JobWorker

    repo, dns = InMemoryRepository(), DNS()
    added = domains.add(repo, "acme.com", "alice", NOW)
    dns.publish(added)
    before = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
    domains.verify(repo, SETTINGS, "acme.com", "alice", before, dns)
    monkeypatch.setattr(domains, "query_txt", dns)  # never the network's DNS in a test
    JobWorker(repo, settings=SETTINGS).poll_triggers()
    assert dns.asked[-1] == ("_cremore-challenge.acme.com.", ())
    assert domains.public(repo, admin=True)["domains"][0]["checked_at"] > before.isoformat()


def test_a_week_without_any_answer_lapses_a_verified_domain(repo):
    dns = DNS()
    dns.publish(domains.add(repo, "acme.com", "alice", NOW))
    domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)
    dns.down = True
    domains.reverify_due(repo, SETTINGS, NOW + dt.timedelta(days=1), dns)
    kept = domains.public(repo, admin=True)["domains"][0]
    assert (kept["status"], kept["result"]) == ("VERIFIED", "DNS_UNAVAILABLE")  # a bad day proves nothing
    domains.reverify_due(repo, SETTINGS, NOW + dt.timedelta(days=8), dns)
    assert domains.public(repo, admin=True)["domains"][0]["status"] == "LAPSED"


def test_a_resolver_failing_in_any_way_counts_as_no_answer():
    def broken(fqdn, nameservers):
        raise RuntimeError("an unexpected resolver failure")

    assert domains.lookup("acme.com", "abc", [], broken) == "DNS_UNAVAILABLE"


def test_a_time_written_by_a_clock_running_ahead_confirms_nothing():
    repo, dns = InMemoryRepository(), DNS()
    dns.publish(domains.add(repo, "acme.com", "alice", NOW))
    ahead = NOW + dt.timedelta(days=30)
    domains.verify(repo, SETTINGS, "acme.com", "alice", ahead, dns)
    assert domains.covering(repo, "acme.com", NOW) is None
    assert domains.reverify_due(repo, SETTINGS, NOW, dns) == 1  # asked again now, which sets the times right
    assert domains.covering(repo, "acme.com", NOW) is not None


def test_a_renewed_challenge_waits_for_its_record_and_an_answer_about_the_old_one_is_dropped(repo):
    dns = DNS()
    added = domains.add(repo, "acme.com", "alice", NOW)
    dns.publish(added)
    domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)
    renewed = domains.renew_challenge(repo, "acme.com", "alice")
    assert renewed["status"] == "PENDING" and renewed["record"]["value"] != added["record"]["value"]
    assert domains.covering(repo, "acme.com", NOW) is None
    assert domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, dns)["result"] == "TXT_MISMATCH"  # the old record

    def renewed_meanwhile(fqdn, nameservers):
        domains.renew_challenge(repo, "acme.com", "bob")
        return [renewed["record"]["value"]]

    with pytest.raises(domains.DomainError) as changed:
        domains.verify(repo, SETTINGS, "acme.com", "alice", NOW, renewed_meanwhile)
    assert (changed.value.code, changed.value.http_status) == ("DOMAIN_CHANGED", 409)
    assert domains.public(repo, admin=True)["domains"][0]["status"] == "PENDING"


def test_internal_sites_limits_and_removal(repo):
    domains.add(repo, "intranet.corp", "alice", NOW)
    assert domains.set_internal(repo, "intranet.corp", True, "alice")["allow_internal"] is True
    with pytest.raises(domains.DomainError) as twice:
        domains.add(repo, "INTRANET.corp", "alice", NOW)
    assert (twice.value.code, twice.value.http_status) == ("DOMAIN_EXISTS", 409)
    with pytest.raises(domains.DomainError) as wrong:
        domains.set_internal(repo, "intranet.corp", "yes", "alice")
    assert wrong.value.code == "ALLOW_INTERNAL_INVALID"
    domains.remove(repo, "intranet.corp", "alice")
    assert domains.public(repo, admin=True)["domains"] == []
    with pytest.raises(domains.DomainError) as gone:
        domains.remove(repo, "intranet.corp", "alice")
    assert (gone.value.code, gone.value.http_status) == ("DOMAIN_NOT_FOUND", 404)
    assert [event for event, _note in trail(repo)] == ["DOMAIN_ADDED", "DOMAIN_INTERNAL_CHANGED", "DOMAIN_REMOVED"]


def test_at_most_a_hundred_domains():
    repo = InMemoryRepository()
    for n in range(domains.MAX_DOMAINS):
        domains.add(repo, f"d{n}.example", "alice", NOW)
    with pytest.raises(domains.DomainError) as full:
        domains.add(repo, "one-more.example", "alice", NOW)
    assert (full.value.code, full.value.http_status) == ("DOMAIN_LIMIT", 409)


def test_dns_servers_are_addresses_only_and_a_wrong_value_stops_start_up():
    assert domains.servers(Settings(FINGERPRINT_KEY="ab" * 32, DOMAIN_DNS_SERVERS=" 10.0.0.53, 2001:db8::53 ")) == [
        "10.0.0.53", "2001:db8::53"]
    assert domains.servers(SETTINGS) == []
    wrong = Settings(FINGERPRINT_KEY="ab" * 32, DOMAIN_DNS_SERVERS="dns.example")
    with pytest.raises(domains.DomainError) as named:
        domains.servers(wrong)
    assert named.value.code == "DNS_SERVERS_INVALID"
    # Checked before the worker runs: a wrong value would stop the daily re-check that lapses a gone record.
    with pytest.raises(ValueError, match="DOMAIN_DNS_SERVERS"):
        wrong.validate_safety("worker")


def test_the_resolvers_answers_become_codes(monkeypatch):
    import dns.exception
    import dns.resolver

    class Rdata:
        def __init__(self, *strings):
            self.strings = strings

    answers = {"_cremore-challenge.a.test.": [Rdata(b"cremore-domain-verification=", b"abc")],
               "_cremore-challenge.b.test.": dns.resolver.NXDOMAIN(),
               "_cremore-challenge.c.test.": dns.resolver.NoAnswer(),
               "_cremore-challenge.d.test.": dns.exception.Timeout(),
               "_cremore-challenge.e.test.": dns.resolver.NoNameservers()}

    class Resolver:
        def __init__(self, configure=True):
            self.configure, self.nameservers = configure, []

        def resolve(self, fqdn, rdtype, lifetime=None):
            Resolver.asked = (fqdn, rdtype, self.configure, list(self.nameservers), lifetime)
            outcome = answers[fqdn]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    monkeypatch.setattr(dns.resolver, "Resolver", Resolver)
    assert domains.lookup("a.test", "abc", ["10.0.0.53"]) == "VERIFIED"  # a record's strings are joined
    assert Resolver.asked == ("_cremore-challenge.a.test.", "TXT", False, ["10.0.0.53"], 5.0)
    assert domains.lookup("b.test", "abc", []) == "TXT_NOT_FOUND" and Resolver.asked[2] is True
    assert domains.lookup("c.test", "abc", []) == "TXT_NOT_FOUND"
    assert domains.lookup("d.test", "abc", []) == "DNS_UNAVAILABLE"
    assert domains.lookup("e.test", "abc", []) == "DNS_UNAVAILABLE"
