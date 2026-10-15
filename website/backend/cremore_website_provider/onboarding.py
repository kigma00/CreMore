"""The company's websites in the connection wizard (N4b): an exposure scan of verified domains.

There is no credential: what may be read is what the company's verified domains cover (cremore.domains), so the
wizard starts from Integrations > Other settings > Domain verification (``entry``), not from the service grid. The
check asks, per listed domain, whether it is verified now and whether its first start page answers through the scan's
own fetcher (verified hosts, allowed addresses). Each domain becomes one content source with its start pages.
"""

from __future__ import annotations

import datetime as _dt

_SCANS = [{"id": "pages", "label": "Pages, scripts and source maps", "label_ko": "페이지·스크립트·소스맵",
           "description": "The start pages, the scripts they load and the original sources in the scripts' maps.",
           "description_ko": "시작 페이지, 페이지가 불러오는 스크립트, 스크립트 소스맵에 담긴 원본 소스입니다."}]

DESCRIPTORS = [{
    "provider": "website",
    "label": "Website", "label_ko": "웹사이트",  # the integration's name: "Website · acme.com"
    "category": "cloud",
    # Started from the domain screen, where the domains it may read are verified.
    "entry": "domains",
    "editions": [{"id": "web", "label": "Company websites", "label_ko": "회사 웹사이트"}],
    "target": [
        {"name": "domains", "label": "Verified domains", "label_ko": "확인된 도메인", "kind": "list", "required": True,
         "hint": "acme.com"},
        {"name": "start_urls", "label": "Start pages (one per line; the home page when empty)",
         "label_ko": "시작 페이지(한 줄에 하나, 비우면 홈페이지)", "kind": "multiline",
         "hint": "https://www.acme.com/\nhttps://app.acme.com/login"},
    ],
    "purposes": {
        "exposure": {"scans": _SCANS, "permissions": [
            {"id": "domains_verified", "label": "Every domain verified by DNS", "label_ko": "모든 도메인의 DNS 확인"},
            {"id": "site_reachable", "label": "Start pages answer", "label_ko": "시작 페이지 응답"}]},
    },
    # Nothing to sign in with, so no stored secret may stand for one either.
    "auth_methods": [{"id": "none", "label": "No sign-in (public and allowed internal pages)",
                      "label_ko": "로그인 없음(공개·허용된 사내 페이지)", "renewal": "NONE", "purposes": ["exposure"],
                      "reference": False, "fields": []}],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    from cremore_website_provider.source import MAX_START_URLS, _domain, _start_url

    try:
        names = list(dict.fromkeys(_domain(name) for name in values.get("domains") or []))
        lines = [line.strip() for line in str(values.get("start_urls") or "").splitlines() if line.strip()]
        if not names or len(names) > 20 or len(lines) > MAX_START_URLS * len(names):
            raise ValueError("INVALID_WEBSITE_CONFIG")
        urls = {}
        for line in lines:
            # Each start page belongs to the listed domain that covers it: the closest one.
            for name in sorted(names, key=len, reverse=True):
                try:
                    urls[_start_url(line, name)] = name
                    break
                except ValueError:
                    continue
            else:
                raise ValueError("INVALID_WEBSITE_START_URL")
        if any(list(urls.values()).count(name) > MAX_START_URLS for name in names):
            raise ValueError("INVALID_WEBSITE_START_URL")
    except ValueError as exc:
        raise OnboardingValueError(str(exc).split(":")[0] or "INVALID_WEBSITE_CONFIG") from None
    return {"domains": names, "start_urls": "\n".join(urls)}


def credential(provider, method, fields):
    return {}  # nothing to sign in with


def _pages(connection, domain):
    urls = [url for url in str(connection["target"].get("start_urls") or "").splitlines() if url]
    own = [url for url in urls if _owner(connection, url) == domain]
    return own or [f"https://{domain}/"]


def _owner(connection, url):
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    names = connection["target"].get("domains") or []
    return max((name for name in names if host == name or host.endswith("." + name)), key=len, default=None)


def check(connection, purpose, secrets, context):
    from cremore.domains import covering
    from cremore_website_provider.fetch import Fetcher, FetchRefused
    from cremore_website_provider.source import MAX_OBJECT_BYTES, _ports

    now = _dt.datetime.now(_dt.UTC)
    names = connection["target"].get("domains") or []
    unverified = [name for name in names if covering(context.repo, name, now) is None]
    items = [{"permission": "domains_verified", "status": "MISSING" if unverified else "GRANTED",
              **({"detail": "DOMAIN_NOT_VERIFIED", "subject": unverified[0]} if unverified else {})}]
    verified = [name for name in names if name not in unverified]
    if not verified:
        return items + [{"permission": "site_reachable", "status": "NOT_REPORTED", "detail": "DOMAIN_NOT_VERIFIED"}]
    first = _pages(connection, verified[0])[0]
    fetcher = Fetcher(lambda host: covering(context.repo, host, now),
                      ports=_ports(_pages(connection, verified[0])),
                      max_bytes=min(context.settings.max_object_size_mb << 20, MAX_OBJECT_BYTES))
    try:
        page = fetcher.get(first)
        status = "GRANTED" if page.status == 200 else "MISSING"
        detail = None if page.status == 200 else f"HTTP_{page.status}"
    except FetchRefused as refused:
        status, detail = "MISSING", refused.code
    finally:
        fetcher.close()
    return items + [{"permission": "site_reachable", "status": status, "subject": first[:256],
                     **({"detail": detail} if detail else {})}]


def children(connection, purpose, plan):
    return [{"kind": "content", "purpose": purpose, "source_type": "website", "name": f"Website · {domain}",
             "config": {"domain": domain, "start_urls": _pages(connection, domain)}, "secret_slots": {}}
            for domain in connection["target"].get("domains") or []]
