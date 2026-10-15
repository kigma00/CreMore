"""Dashboard switches for the two sensitive, discovered-token scan behaviours.

Both send a *verified* discovered token to a provider beyond the validity check,
so both are off by default and an Admin turns them on per installation from the
dashboard. The env value ``*_MODE`` allows the feature (default) or hard-locks it
off; a scan reads the current switch when it starts, exactly like verification.

* ``capability_probe`` — read-only calls to record what a token can reach.
* ``cross_host`` — retry a rejected GitHub token on the other registered hosts.
"""

from __future__ import annotations

from dataclasses import replace

PROBE_KEY = "capability_probe"
CROSS_HOST_KEY = "cross_host_verification"


def _switch(repo, key: str) -> dict:
    record = repo.get_setting(key)
    value = (record or {}).get("value") or {}
    return {"enabled": value.get("enabled", False) is True,
            "updated_by": (record or {}).get("updated_by") or None,
            "updated_at": (record or {}).get("updated_at")}


def probe_switch(repo) -> dict:
    return _switch(repo, PROBE_KEY)


def cross_host_switch(repo) -> dict:
    return _switch(repo, CROSS_HOST_KEY)


def probe_effective(settings, repo) -> bool:
    return bool(settings.capability_probe_allowed) and probe_switch(repo)["enabled"]


def cross_host_effective(settings, repo) -> bool:
    return bool(settings.cross_host_verification_allowed) and cross_host_switch(repo)["enabled"]


def _self_managed_gitlab_hosts(repo) -> tuple[str, ...]:
    """Hosts of GitLab instances registered as content or inventory connections."""
    from urllib.parse import urlsplit

    from cremore.coverage.store import CoverageStore
    urls = [(c.config or {}).get("base_url", "https://gitlab.com")
            for c in repo.list_connections() if c.provider == "gitlab"]
    urls += [row["spec"].get("origin", "") for row in CoverageStore(repo).list_connections()
             if row["spec"].get("provider") == "gitlab"]
    hosts = {(urlsplit(url).hostname or "").lower() for url in urls if isinstance(url, str)}
    return tuple(sorted(hosts - {"", "gitlab.com"}))


def verify_config_for(base, settings, repo):
    """A per-scan copy of ``base`` (a VerifierConfig) reflecting the live switches."""
    return replace(base, probe_capabilities=probe_effective(settings, repo),
                   cross_host=cross_host_effective(settings, repo),
                   known_github_hosts=tuple(settings.known_github_hosts),
                   known_gitlab_hosts=_self_managed_gitlab_hosts(repo))
