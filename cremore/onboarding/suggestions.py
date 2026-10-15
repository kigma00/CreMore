"""Services the company's IdP already lists, to suggest connecting (a hint for the admin, never a security decision).

A Microsoft connection's Entra inventory keeps the applications and service principals it collected -- gallery apps
for single sign-on included -- with their display names (metadata entities of kind ``principal``). An Okta or Keycloak
people-directory connection with its app list on keeps the organization's app integrations or the realm's clients
(kind ``installation``, cremore.identity.idp) with their names and the catalog name or client ID they were made from.
An app whose name names a service CreMore connects, while no connection of that service exists (in any state), is
suggested with the names that matched.
Only stored inventory is read, of collections still on (an app list switched off suggests nothing): nothing is asked
of the IdP here.
"""

from __future__ import annotations

import re

# A service's own name as gallery and SaaS apps carry it ("GitHub Enterprise Cloud - Organization", "Slack",
# "Atlassian Cloud", "AWS IAM Identity Center"), also inside a custom name ("github_actions_deployer"): a word
# bounded by anything but a letter or digit. Microsoft's own apps name none of these ("Azure Key Vault").
_NAMES = {
    "github": "github", "gitlab": "gitlab", "bitbucket": "bitbucket", "confluence": "confluence",
    "atlassian": "atlassian|jira", "slack": "slack", "notion": "notion",
    # urn:amazon:webservices is the SAML audience an IdP's AWS sign-in app is made with.
    "aws": "aws|amazon web services|urn:amazon:webservices",
    "gcp": "google cloud|gcp", "okta": "okta", "keycloak": "keycloak", "vault": "hashicorp vault", "openbao": "openbao",
}
# Names that carry the word but not the service: Microsoft's Jira Server plugin (the organization is Cloud only),
# and the Google Workspace sign-in app, which says nothing about Google Cloud.
_NOT = {"atlassian": "by microsoft", "gcp": "g suite|workspace"}
_PATTERNS = {provider: re.compile(f"(?<![a-z0-9])(?:{words})(?![a-z0-9])", re.IGNORECASE) for provider, words in _NAMES.items()}
_EXCLUDED = {provider: re.compile(words, re.IGNORECASE) for provider, words in _NOT.items()}
SHOWN = 3
# Where each IdP keeps the apps it lists.
_LISTS = (("azure_entra", "principal"), ("okta", "installation"), ("keycloak", "installation"))


def _fact(summary, name) -> str:
    for fact in (summary or {}).get("facts") or []:
        if isinstance(fact, dict) and fact.get("name") == name and isinstance(fact.get("value"), str):
            return fact["value"][:200]
    return ""


def suggestions(repo, connections: list[dict]) -> list[dict]:
    """``[{provider, apps, count}]`` for services the IdP lists that no connection covers yet."""
    from cremore.coverage.metadata_store import MetadataStore

    # A connection being set up, or stopped on purpose, is the admin's choice already.
    connected = {c["provider"] for c in connections}
    found: dict[str, set[str]] = {}
    store = MetadataStore(repo)
    for idp, kind in _LISTS:
        for summary in store.summaries(provider=idp, object_kind=kind, enabled_only=True):
            name = _fact(summary, "display_name")
            if not name or summary.get("normalized_state") == "DISABLED":
                continue  # an app the IdP turned off suggests nothing
            # A label of the company's own says less than the catalog name or client ID the app was made from.
            said = f"{name} {_fact(summary, 'app_slug')} {_fact(summary, 'client_id')}"
            for provider, pattern in _PATTERNS.items():
                if (provider not in connected and pattern.search(said)
                        and not (provider in _EXCLUDED and _EXCLUDED[provider].search(said))):
                    found.setdefault(provider, set()).add(name)
    return [{"provider": provider, "apps": sorted(names)[:SHOWN], "count": len(names)}
            for provider, names in sorted(found.items())]
