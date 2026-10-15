"""On a team install the people directory is the IdP people sign in with (owner decision 2026-10-02).

People sign in to the console through the company IdP (``AUTH_MODE=oidc``) and the API gives them roles from it.
The departed-owner check, owner contacts and the people list must name the same people, so a connection that reads
people (the ``identity`` purpose) is that IdP itself: the same Okta organization, Entra tenant, Keycloak realm or
Google Workspace. GitHub's identity link is no directory of people (it ties GitHub logins to the IdP's people) and
stays open. A single operator's install signs in with no IdP and takes any directory.

Each IdP's onboarding module says which of its targets a sign-in issuer names: ``sign_in_target(provider, issuer)``
returns the target fields, normalized as its ``target`` normalizes them, or None when the issuer is not that IdP's.
An issuer that names no field (Google's says nothing of the Workspace) leaves the directory people already use as
the one: another people directory of that provider must have its target.
"""

from __future__ import annotations

from cremore.onboarding import catalog

# Links GitHub accounts to the IdP's people; never a directory of people of its own.
EXEMPT = frozenset({"github"})


def _issuer(settings) -> str | None:
    if getattr(settings, "auth_mode", "local") != "oidc":
        return None
    return (getattr(settings, "oidc_issuer_url", "") or "").rstrip("/") or None


def _named(provider: str, issuer: str) -> dict | None:
    named = getattr(catalog.module(provider), "sign_in_target", None)
    target = named(provider, issuer) if callable(named) else None
    return dict(target) if isinstance(target, dict) else None


def idp(settings) -> dict | None:
    """The sign-in IdP as the wizard offers it as the people directory: ``{issuer, provider, target, exempt}``
    (provider and target None when no IdP CreMore reads names the issuer), or None on a single operator's install."""
    issuer = _issuer(settings)
    if issuer is None:
        return None
    found = {"issuer": issuer, "provider": None, "target": None, "exempt": sorted(EXEMPT)}
    for provider, descriptor in catalog.providers().items():
        if "identity" not in descriptor["purposes"] or provider in EXEMPT or descriptor.get("replaced_by"):
            continue
        target = _named(provider, issuer)
        if target is not None:
            return {**found, "provider": provider, "target": target}
    return found


def problem(settings, provider: str, target: dict, purposes, *, repo=None, excluding=None) -> str | None:
    """Why a connection may not read people on this install, or None. ``repo`` lets an issuer that names no target
    (Google) be held to the people directories already there; ``excluding`` is the connection asked about."""
    if "version" in target:
        from cremore.onboarding.targets import records_of

        for root in records_of({"target": target, "purposes": list(catalog.descriptor(provider)["purposes"])}):
            selected = [p for p in root["purposes"] if p in purposes]
            refused = problem(settings, provider, root["target"], selected, repo=repo, excluding=excluding)
            if refused:
                return refused
        return None
    issuer = _issuer(settings)
    if issuer is None or "identity" not in purposes or provider in EXEMPT:
        return None
    named = _named(provider, issuer)
    if named is None:
        return "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP" if idp(settings)["provider"] else "PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN"
    if any(target.get(name) != value for name, value in named.items()):
        return "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP"
    if not named and repo is not None:
        from cremore.onboarding.store import ProviderConnectionStore, active_plans
        from cremore.onboarding.targets import records_of

        fields = [field["name"] for field in catalog.descriptor(provider).get("target") or []]
        # Directories that read people now (an abandoned draft fixes nothing).
        others = [root["target"] for record in ProviderConnectionStore(repo).list()
                  if record["provider"] == provider and record["status"] != "DISABLED"
                  and "identity" in active_plans(record) and str(record["id"]) != str(excluding)
                  for root in records_of(record, "identity")]
        if others and not any(all(target.get(name) == other.get(name) for name in fields) for other in others):
            return "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP"
    return None
