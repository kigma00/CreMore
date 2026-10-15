"""The web exposure scan as a content source (N4b): one verified domain per resource, its start pages, the scripts
they load and the sources their maps carry. No credential: what may be read is what the company's verified domains
cover (cremore.domains), handed to the collector by the worker as ``payload["domain_cover"]``.
"""

from __future__ import annotations

import functools
import urllib.parse

PROVIDER = "website"
SOURCE_TYPE = "website"
JOB_KINDS = ("website",)
RESOURCE_TYPES = ("WEBSITE",)
SCOPE_KIND = "path"
FILTERS = ()
CAPABILITY_ORDER = 10
STRUCTURED_CONFIG = True
TOKEN_AUTH = False
# Integration: a domain name is the company's own; it never repeats across instances.
INSTANCE_SCOPED = False
CAPABILITY = {"id": "website", "name": "Websites", "command": "website", "kind": "BATCH",
    "description": "Pages, scripts and source maps of the company's verified domains.",
    "credential_env": [], "external_credential_env": [], "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = None
MAX_START_URLS = 20
MAX_OBJECT_BYTES = 5 << 20
LIMITS = {"max_assets": (1, 1000, 200)}  # scripts per run; the start pages are at most MAX_START_URLS


def _domain(value) -> str:
    from cremore.domains import DomainError, normalize

    try:
        return normalize(value)
    except DomainError:
        raise ValueError("INVALID_WEBSITE_DOMAIN") from None


def _start_url(value, domain: str) -> str:
    """An http(s) URL on the domain or a subdomain, without credentials or a fragment."""
    from cremore.domains import DomainError, normalize

    if not isinstance(value, str) or len(value) > 2000:
        raise ValueError("INVALID_WEBSITE_START_URL")
    try:
        parts = urllib.parse.urlsplit(value.strip())
        port = parts.port
        host = normalize(parts.hostname or "")
    except (ValueError, DomainError):
        raise ValueError("INVALID_WEBSITE_START_URL") from None
    if (parts.scheme not in ("http", "https") or parts.username is not None or parts.password is not None
            or not (host == domain or host.endswith("." + domain))):
        raise ValueError("INVALID_WEBSITE_START_URL")
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def validate_config(cfg):
    if not isinstance(cfg, dict) or set(cfg) - {"domain", "start_urls", *LIMITS}:
        raise ValueError("INVALID_WEBSITE_CONFIG")
    domain = _domain(cfg.get("domain"))
    urls = cfg.get("start_urls") or [f"https://{domain}/"]
    if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_START_URLS:
        raise ValueError("INVALID_WEBSITE_START_URL")
    out = {"domain": domain, "start_urls": list(dict.fromkeys(_start_url(url, domain) for url in urls))}
    for name, (low, high, default) in LIMITS.items():
        value = cfg.get(name, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError("INVALID_WEBSITE_CONFIG")
        out[name] = value
    return out


def job_payload(cfg):
    return {**validate_config(cfg), "provider": PROVIDER}


def job_kind(cfg):
    return PROVIDER


def config_from_scope(scope, host=""):
    return {"domain": scope}


def scope_ref(cfg):
    return cfg.get("domain") or ""


def _ports(urls) -> dict:
    """The non-default ports the admin's own start URLs name, per host: the only other ports the scan uses."""
    out: dict = {}
    for url in urls:
        parts = urllib.parse.urlsplit(url)
        if parts.port is not None:
            out.setdefault(parts.hostname, set()).add(parts.port)
    return out


def _collector(payload, urls, *, max_object_bytes=None, request_budget=None, root=None):
    from cremore.sources._collectors import object_limit
    from cremore_website_provider.collector import WebsiteCollector
    from cremore_website_provider.fetch import Fetcher

    cover = payload.get("domain_cover")
    if not callable(cover):
        raise TypeError("website scan requires the worker's domain cover")
    fetcher = Fetcher(cover, ports=_ports(payload["start_urls"]),
                      max_bytes=min(object_limit(max_object_bytes), MAX_OBJECT_BYTES))
    collector = WebsiteCollector(fetcher, domain=payload["domain"], start_urls=urls, max_assets=payload["max_assets"],
                                 paths=(root or {}).get("paths") or (),
                                 excluded_paths=(root or {}).get("excluded_paths") or ())
    # Asked before every request, whichever budget the run holds when it asks: a scoped run swaps in its durable one,
    # which also notices a cancelled run or a lost lease (cremore/worker/runtime.py).
    collector.request_budget = request_budget
    fetcher.before_request = lambda: collector.request_budget.consume() if collector.request_budget is not None else None
    return collector


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None, max_object_bytes=None):
    return _collector(payload, payload["start_urls"], max_object_bytes=max_object_bytes)


def _located(location: str) -> str:
    """The URL a finding's location was read from: a map source is its map's (``…map!/src/x.ts``)."""
    return location.split("!/", 1)[0].split("#", 1)[0]


@functools.lru_cache(maxsize=16)
def _test(paths: tuple, excluded_paths: tuple):
    """One approved root's test, made once: a run's plan is checked again before each of its requests."""
    from cremore_website_provider.collector import scope

    return scope(paths, excluded_paths)


def scope_allows(location: str, paths, excluded_paths) -> bool:
    """Whether an approved root's paths admit a location (cremore.scanning.scope: exact rescans and events), by the test
    the run applies to every URL. An entry that is not a URL path admits nothing."""
    from cremore.collectors.base import CollectorError

    try:
        return _test(tuple(paths), tuple(excluded_paths))(_located(location))
    except (CollectorError, TypeError):  # TypeError: an entry that is no string (and no cache key)
        return False


def scope_problem(root) -> str | None:
    """Why an approved root's paths cannot bound a scan, found when its plan is made rather than when it runs."""
    from cremore.collectors.base import CollectorError

    try:
        _test(tuple(root.get("paths") or ()), tuple(root.get("excluded_paths") or ()))
    except CollectorError as error:
        return error.code
    except TypeError:
        return "WEBSITE_SCOPE_PATH_INVALID"
    return None


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None, max_object_bytes=None,
               request_budget=None):
    # An exact rescan reads the locations it names (an empty list reads nothing); otherwise the start pages.
    urls = ([_located(url) for url in root["exact_paths"]] if "exact_paths" in root else payload["start_urls"])
    return _collector(payload, list(dict.fromkeys(urls)), max_object_bytes=max_object_bytes,
                      request_budget=request_budget, root=root)


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget):
    """The domain itself: what a scope selects (its start pages are its exact paths)."""
    from cremore.scanning.scope import resource

    domain = payload["domain"]
    # Public or internal is known per address at fetch time, not here.
    return [resource(kind, cid, "WEBSITE", domain, domain, f"https://{domain}/", domain, now=now)], "COMPLETE"


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore.collectors.credential_result import ACTIVE, CredentialCheck

    # Nothing to sign in with: whether a domain may be read is its DNS verification, asked at every request.
    return CredentialCheck(ACTIVE, detail={"credential_mode": "VERIFIED_DOMAINS", "refresh_supported": False})
