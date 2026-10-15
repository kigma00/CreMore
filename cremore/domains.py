"""The company's domains, owned as their DNS says (Integrations > Other settings > Domain verification).

An admin adds a domain; CreMore makes a random challenge for it and shows the record to publish:

    _cremore-challenge.<domain>  TXT  "cremore-domain-verification=<challenge>"

CreMore asks the DNS of the network it runs in (``DOMAIN_DNS_SERVERS`` names other servers), so a domain only an
intranet's DNS knows is verified as well as a public one. The challenge is this installation's own: a record another
company published for its CreMore proves nothing here. A verified domain covers its subdomains.

A verified domain is asked again every day: a record that is gone or changed lapses it, and so does a week without any
answer. A lapse draws a new challenge and turns ``allow_internal`` off: the old record is public, so whoever registers
an expired domain could publish it again, and only an admin sees the new one. Only a verified domain confirmed within
the week is scanned from outside (the web exposure scan, ``covering``); ``allow_internal`` lets that scan reach the
domain's sites on private addresses (an intranet), never loopback, link-local or cloud metadata addresses.

Everything is one settings document, changed under its own row lock with its audit row in the same transaction; the
DNS is asked outside the lock and a result is kept only for the challenge it was asked about.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import re
import secrets
import uuid

KEY = "company_domains"
LOCK_KEY = "company_domains_lock"
RECORD = "_cremore-challenge"
PREFIX = "cremore-domain-verification="
RESULTS = ("VERIFIED", "TXT_NOT_FOUND", "TXT_MISMATCH", "DNS_UNAVAILABLE")
MAX_DOMAINS = 100
REVERIFY = _dt.timedelta(hours=24)
SILENCE = _dt.timedelta(days=7)  # a verified domain nobody could ask about for this long lapses
SKEW = _dt.timedelta(minutes=5)  # a time written further ahead than this came from a wrong clock: it confirms nothing
ACTOR = "system:domains"  # the daily re-check: bookkeeping, not a person's action (cremore.siem.events)
SWEEP_KEY = "domains:reverify"  # one worker replica re-checks a minute
MAX_NAME = 253 - len(RECORD) - 1  # the record's name must fit DNS too
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
# A last label that is a number makes the name an IPv4 address to browsers and getaddrinfo (127.0x1 is 127.0.0.1):
# the WHATWG URL "ends in a number" rule.
_NUMBER = re.compile(r"0x[0-9a-f]*|[0-9]+")
_NAMESPACE = uuid.UUID("8d0f7b52-2a36-4f5c-9d61-0c3e5b7a9e41")

logger = logging.getLogger(__name__)


class DomainError(Exception):
    def __init__(self, code: str, http_status: int = 422) -> None:
        super().__init__(code)
        self.code, self.http_status = code, http_status


def normalize(value) -> str:
    """The domain as it is kept: lower case, IDNA ASCII, no trailing dot; two labels or more, never an address.
    IDNA 2008 with the UTS 46 mapping, as browsers and httpx encode a name (faß.de is xn--fa-hia.de, not fass.de)."""
    import idna

    if not isinstance(value, str) or len(value) > 300:
        raise DomainError("DOMAIN_INVALID")
    try:
        name = idna.encode(value.strip().rstrip("."), uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        raise DomainError("DOMAIN_INVALID") from None
    labels = name.split(".")
    if (len(name) > MAX_NAME or len(labels) < 2 or _NUMBER.fullmatch(labels[-1])
            or any(not _LABEL.fullmatch(label) for label in labels)):
        raise DomainError("DOMAIN_INVALID")
    return name


def record_name(name: str) -> str:
    return f"{RECORD}.{name}"


def _audit_id(name: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, name)


def _stamp(value: _dt.datetime) -> str:
    return value.astimezone(_dt.UTC).isoformat()


def _when(value) -> _dt.datetime | None:
    try:
        return _dt.datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _load(repo) -> dict:
    value = (repo.get_setting(KEY) or {}).get("value") or {}
    domains = value.get("domains")
    return {name: dict(record) for name, record in domains.items()} if isinstance(domains, dict) else {}


def _locked(repo):
    from cremore.db.settings_store import locked_settings

    if repo.get_setting(LOCK_KEY) is None:
        repo.claim_slot(LOCK_KEY, 0, ACTOR)  # insert-if-absent: racing first writers both find it after
    return locked_settings(repo, setting_key=LOCK_KEY)


def _save(bound, domains: dict, actor: str, name: str, event_type: str, note: str) -> None:
    from cremore.domain.models import FindingEvent

    bound.put_setting(KEY, {"domains": domains}, actor)
    bound.record_finding_event(FindingEvent(target_type="domain", target_id=_audit_id(name), actor=actor,
                                            event_type=event_type, note=f"{name} {note}".strip()))


def _view(record: dict, *, admin: bool) -> dict:
    out = {key: record.get(key) for key in ("name", "status", "allow_internal", "verified_at", "checked_at", "result")}
    if admin:
        # Published in the domain's DNS anyway; shown to whoever sets up the record.
        out.update(added_at=record.get("added_at"), added_by=record.get("added_by"),
                   record={"name": record_name(record["name"]), "type": "TXT", "value": PREFIX + record["challenge"]})
    return out


def public(repo, *, admin: bool) -> dict:
    """The domains as the console shows them; the record to publish only to an admin."""
    return {"domains": [_view(record, admin=admin) for _name, record in sorted(_load(repo).items())],
            "limit": MAX_DOMAINS}


def add(repo, value, actor: str, now: _dt.datetime) -> dict:
    name = normalize(value)
    with _locked(repo) as bound:
        domains = _load(bound)
        if name in domains:
            raise DomainError("DOMAIN_EXISTS", 409)
        if len(domains) >= MAX_DOMAINS:
            raise DomainError("DOMAIN_LIMIT", 409)
        domains[name] = {"name": name, "challenge": secrets.token_urlsafe(24), "status": "PENDING",
                         "allow_internal": False, "added_at": _stamp(now), "added_by": actor, "verified_at": None,
                         "checked_at": None, "result": None}
        _save(bound, domains, actor, name, "DOMAIN_ADDED", "")
    return _view(domains[name], admin=True)


def _change(repo, name: str, actor: str, change, event_type: str) -> dict:
    name = normalize(name)
    with _locked(repo) as bound:
        domains = _load(bound)
        if name not in domains:
            raise DomainError("DOMAIN_NOT_FOUND", 404)
        note = change(domains[name])
        _save(bound, domains, actor, name, event_type, note)
    return _view(domains[name], admin=True)


def set_internal(repo, name, allow, actor: str) -> dict:
    if not isinstance(allow, bool):
        raise DomainError("ALLOW_INTERNAL_INVALID")

    def change(record):
        record["allow_internal"] = allow
        return f"allow_internal={str(allow).lower()}"
    return _change(repo, name, actor, change, "DOMAIN_INTERNAL_CHANGED")


def renew_challenge(repo, name, actor: str) -> dict:
    """A new challenge: the domain waits for the new record, and nothing is scanned until then."""
    def change(record):
        was = record["status"]
        record.update(challenge=secrets.token_urlsafe(24), status="PENDING", verified_at=None, result=None)
        return f"was={was}"
    return _change(repo, name, actor, change, "DOMAIN_CHALLENGE_RENEWED")


def remove(repo, name, actor: str) -> None:
    name = normalize(name)
    with _locked(repo) as bound:
        domains = _load(bound)
        if domains.pop(name, None) is None:
            raise DomainError("DOMAIN_NOT_FOUND", 404)
        _save(bound, domains, actor, name, "DOMAIN_REMOVED", "")


# --- asking the DNS ------------------------------------------------------------------------------------------------

def servers(settings) -> list[str]:
    """The DNS servers ``DOMAIN_DNS_SERVERS`` names (addresses only), or [] for the system's resolver."""
    out = []
    for part in str(getattr(settings, "domain_dns_servers", "") or "").split(","):
        if part.strip():
            try:
                out.append(str(ipaddress.ip_address(part.strip())))
            except ValueError:
                raise DomainError("DNS_SERVERS_INVALID") from None
    return out


class Missing(Exception):
    """The DNS answered: no such record."""


class Unavailable(Exception):
    """The DNS gave no usable answer."""


def query_txt(fqdn: str, nameservers: list[str], timeout: float = 5.0) -> list[str]:
    """Every TXT value at ``fqdn`` (each record's strings joined), asked of ``nameservers`` or the system's."""
    import dns.exception
    import dns.resolver

    try:
        resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            resolver.nameservers = list(nameservers)
        answer = resolver.resolve(fqdn, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raise Missing() from None
    except dns.exception.DNSException:
        raise Unavailable() from None  # no servers, a timeout, a refusal: nothing is known
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]


def lookup(name: str, challenge: str, nameservers: list[str], query=None) -> str:
    """VERIFIED when the domain's record holds this challenge; TXT_NOT_FOUND, TXT_MISMATCH or DNS_UNAVAILABLE."""
    try:
        values = (query or query_txt)(record_name(name) + ".", nameservers)
    except Missing:
        return "TXT_NOT_FOUND"
    except Unavailable:
        return "DNS_UNAVAILABLE"
    except Exception as exc:  # noqa: BLE001 -- no usable answer: the week's silence applies, and the cause is logged
        logger.warning("domain lookup failed: %s", type(exc).__name__)
        return "DNS_UNAVAILABLE"
    return "VERIFIED" if PREFIX + challenge in values else ("TXT_MISMATCH" if values else "TXT_NOT_FOUND")


def _apply(record: dict, result: str, now: _dt.datetime) -> tuple[str | None, str]:
    """Record one answer; returns (event type or None, note)."""
    was = record["status"]
    record.update(checked_at=_stamp(now), result=result)
    if result == "VERIFIED":
        record.update(status="VERIFIED", verified_at=_stamp(now))
        return ("DOMAIN_VERIFIED" if was != "VERIFIED" else None), f"was={was}"
    confirmed = _when(record.get("verified_at"))
    if was == "VERIFIED" and (result != "DNS_UNAVAILABLE" or confirmed is None or now - confirmed > SILENCE):
        # The old record is public: coming back takes the new one, which only an admin sees.
        note = f"{result} challenge_renewed" + (" allow_internal=false" if record.get("allow_internal") else "")
        record.update(status="LAPSED", challenge=secrets.token_urlsafe(24), allow_internal=False)
        return "DOMAIN_LAPSED", note
    return None, result


def verify(repo, settings, name, actor: str, now: _dt.datetime, query=None) -> dict:
    """Ask the DNS now (an admin's request); the answer and any change of status are audited."""
    name = normalize(name)
    record = _load(repo).get(name)
    if record is None:
        raise DomainError("DOMAIN_NOT_FOUND", 404)
    result = lookup(name, record["challenge"], servers(settings), query)  # outside the lock: the DNS may be slow
    with _locked(repo) as bound:
        domains = _load(bound)
        current = domains.get(name)
        if current is None or current["challenge"] != record["challenge"]:
            raise DomainError("DOMAIN_CHANGED", 409)  # removed or renewed meanwhile: that answer is about nothing
        event, note = _apply(current, result, now)
        _save(bound, domains, actor, name, event or ("DOMAIN_VERIFICATION_FAILED" if result != "VERIFIED"
                                                     else "DOMAIN_VERIFIED"), note)
    return _view(domains[name], admin=True)


def reverify_due(repo, settings, now: _dt.datetime, query=None, limit: int = 20) -> int:
    """Ask again about verified domains last asked a day ago or more (the worker, once a minute, one replica);
    returns how many were asked. Only a change of status is audited. A lapsed domain waits for an admin."""
    nameservers = servers(settings)  # checked at start-up (Settings.validate_safety)

    def due_now(record):
        at = _when(record.get("checked_at"))
        return at is None or now - at >= REVERIFY or at > now + SKEW

    due = [record for record in _load(repo).values() if record["status"] == "VERIFIED" and due_now(record)]
    if not due or not repo.claim_slot(SWEEP_KEY, int(now.timestamp()) // 60, ACTOR):
        return 0
    for record in sorted(due, key=lambda item: item.get("checked_at") or "")[:limit]:
        result = lookup(record["name"], record["challenge"], nameservers, query)
        with _locked(repo) as bound:
            domains = _load(bound)
            current = domains.get(record["name"])
            if current is None or any(current.get(field) != record.get(field)
                                      for field in ("challenge", "status", "checked_at")):
                continue  # renewed, lapsed or asked about meanwhile: this answer is about what was
            event, note = _apply(current, result, now)
            if event:
                _save(bound, domains, ACTOR, record["name"], event, note)
            else:
                bound.put_setting(KEY, {"domains": domains}, ACTOR)
    return min(len(due), limit)


def covering(repo, host, now: _dt.datetime) -> dict | None:
    """The verified domain that covers ``host`` (itself or a subdomain), as the web exposure scan reads it, with
    ``host`` as the scan must reach it (IDNA ASCII). A domain not confirmed within the week covers nothing, even when
    the daily re-check stopped."""
    try:
        host = normalize(host)
    except DomainError:
        return None
    def confirmed(record):
        at = _when(record.get("verified_at"))
        return record["status"] == "VERIFIED" and at is not None and now - SILENCE <= at <= now + SKEW

    found = [record for record in _load(repo).values()
             if confirmed(record) and (host == record["name"] or host.endswith("." + record["name"]))]
    best = max(found, key=lambda record: len(record["name"]), default=None)  # the closest one decides
    return {"name": best["name"], "host": host, "allow_internal": bool(best["allow_internal"])} if best else None
