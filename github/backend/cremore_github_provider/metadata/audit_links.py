"""Audit events joined to the credentials they name, by exact identifiers only.

The rules follow develop_github's CLI (json_evidence, 2026-09-26) over this adapter's
records. A fine-grained PAT id, an SSH or deploy-key fingerprint and the OAuth credential
id of an SSO grant name the credential an event is about; the installation-keyed hash of
the managed token names the target of an SSO authorization. A name, owner, title, time or
ordinary token_id never links. Only GitHub's own entries are joined: the keyed token-activity
summaries stay out of native exports (the finding view shows which token was used).

One credential seen by several sources (the Enterprise inventory, an organization's SSO or
fine-grained PAT list) is one candidate: its type and GitHub id, or its fingerprint, group
them. A reference that fits more than one credential, or none that this run observed, leaves
the event unmatched with the reason -- no link is not no event, and no event is not non-use.
The keyed hashes are compared here and never returned.
"""

from __future__ import annotations

import json

from cremore.coverage.errors import CoverageError

from .normalization import INVENTORY_ID_TYPES, fingerprint_key, record_values

FG_ACTIONS = frozenset({"personal_access_token.access_granted", "personal_access_token.access_revoked",
                        "personal_access_token.request_created"})
SSO_ACTIONS = frozenset({"org_credential_authorization.grant", "org_credential_authorization.deauthorize",
                         "org_credential_authorization.revoke"})
KEY_ACTIONS = frozenset({"public_key.create", "public_key.delete", "public_key.update", "public_key.verify",
                         "public_key.unverify", "public_key.verification_failure",
                         "public_key.unverification_failure"})
# The SAML SSO list names its credential types in words.
SSO_TYPES = {"personal access token": "classic_pat", "OAuth app token": "oauth_app_user_token",
             "GitHub app token": "github_app_user_token", "SSH key": "ssh_key"}
OAUTH_TYPES = frozenset({"oauth_app_user_token", "github_app_user_token"})


def _id(value):
    if isinstance(value, bool) or not isinstance(value, int | str):
        return None
    text = str(value)
    return text if 0 < len(text) <= 256 and text.isprintable() and not any(ch.isspace() for ch in text) else None


def _digest(record):
    match = record.get("value_match") or {}
    return match.get("fingerprint") if match.get("evidence") == "PROVIDER_DIGEST" else None


def _credential(record):
    """(key, credential type, aliases) of an observed credential, or None."""
    object_id = (record.get("identity") or {}).get("object_id") or ""
    values = record_values(record)
    prefix = object_id.split(":", 1)[0]
    if prefix == "deployKey":
        repository = values.get("repository")
        name = repository.get("full_name") if isinstance(repository, dict) else repository
        fingerprint = fingerprint_key(values.get("fingerprint"))
        if not (isinstance(name, str) and "/" in name and fingerprint):
            return None
        where = name.lower() + ":" + fingerprint
        return "deploy_key:" + where, "deploy_key", [("deploy_fingerprint", where)]
    if prefix == "inventory":
        kind, credential = values.get("credential_type"), _id(values.get("credential_id"))
    elif prefix == "sso":
        kind, credential = SSO_TYPES.get(values.get("credential_type")), _id(values.get("authorized_credential_id"))
    elif prefix == "fgpat":
        kind, credential = "fine_grained_pat", _id(values.get("token_id"))
    else:
        return None
    fingerprint = fingerprint_key(values.get("fingerprint"))
    aliases = []
    if kind == "ssh_key" and fingerprint:
        key = "ssh_key:fingerprint:" + fingerprint
        aliases.append(("ssh_fingerprint", fingerprint))
    elif kind in INVENTORY_ID_TYPES and credential:
        key = f"{kind}:id:{credential}"
        if kind == "fine_grained_pat":
            aliases.append(("fine_grained_pat_id", credential))
        if kind in OAUTH_TYPES:
            aliases.append(("oauth_credential_token_id", credential))
    else:
        return None
    digest = _digest(record) if prefix == "inventory" else None
    if digest:
        aliases.append(("token_hash", digest))
    return key, kind, aliases


def _references(record):
    """(relation, alias, value, basis) the event names; empty when it names nothing exact."""
    action = record.get("event_type") or ""
    values = record_values(record)
    refs = []
    if action in FG_ACTIONS and _id(values.get("user_programmatic_access_id")):
        refs.append(("target", "fine_grained_pat_id", _id(values["user_programmatic_access_id"]),
                     "documented_fine_grained_pat_target_id"))
    elif action in SSO_ACTIONS:
        token = _id(values.get("token_id"))
        if values.get("oauth_credential_type") == "OauthAccess" and token:
            # GitHub documents credential_id = audit token_id for OAuth and App
            # user tokens; they share one namespace, so a clash stays ambiguous.
            refs.append(("associated", "oauth_credential_token_id", token, "documented_credential_id_token_id"))
        digest, fingerprint = _digest(record), fingerprint_key(values.get("fingerprint"))
        if digest:
            refs.append(("target", "token_hash", digest, "exact_managed_credential_hash"))
        elif fingerprint:
            refs.append(("target", "ssh_fingerprint", fingerprint, "exact_sso_target_fingerprint"))
    elif action in KEY_ACTIONS:
        fingerprint = fingerprint_key(values.get("fingerprint"))
        repository = values.get("repo") or values.get("repository")
        if fingerprint and isinstance(repository, str) and "/" in repository:
            # A deploy key and a user's SSH key must not be conflated.
            refs.append(("target", "deploy_fingerprint", repository.lower() + ":" + fingerprint,
                         "exact_repository_and_target_fingerprint"))
        elif fingerprint and not values.get("repo_id") and not values.get("repository_id"):
            refs.append(("target", "ssh_fingerprint", fingerprint, "exact_user_key_target_fingerprint"))
    return refs


RELATIONS = ("target", "associated", "unmatched")
# The observations a credential can be keyed from; everything else is skipped before joining.
CREDENTIAL_PREFIXES = ("inventory:", "sso:", "fgpat:", "deployKey:")
# The facts _credential and _references read; a record keeps only these on its way in.
JOIN_FACTS = frozenset({"credential_type", "credential_id", "authorized_credential_id", "token_id", "fingerprint",
                        "repository", "repo", "repo_id", "repository_id", "user_programmatic_access_id",
                        "oauth_credential_type"})
# The view recomputes a whole run; past this many entries the record pages are the way to read them.
AUDIT_LINK_LIMIT = 50_000
# Includes repeated entity references in flattened rows, not just event count.
# Oversized views remain available through immutable run/record pages.
AUDIT_LINK_BYTES = 8 * 1024 * 1024


def link_inputs(records):
    """Provider events and credential observations, each reduced to what the join reads.

    Streams the records once; refuses a run with more entries than the view is for.
    """
    kept, events, size = [], 0, 0
    for record in records:
        kind = record.get("record_type")
        object_id = (record.get("identity") or {}).get("object_id") or ""
        if kind == "provider_event":
            events += 1
            if events > AUDIT_LINK_LIMIT:
                raise CoverageError("GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES")
        elif not (kind == "entity_observation" and object_id.startswith(CREDENTIAL_PREFIXES)):
            continue
        match = record.get("value_match") or {}
        item = {"record_type": kind, "event_type": record.get("event_type"), "event_id": record.get("event_id"),
                "occurred_at": record.get("occurred_at"), "identity": {"object_id": object_id},
                "value_match": {key: match.get(key) for key in ("evidence", "fingerprint")} if match else None,
                "facts": [fact for fact in record.get("facts") or [] if fact.get("name") in JOIN_FACTS]}
        size += len(json.dumps(item, ensure_ascii=True))
        if size > AUDIT_LINK_BYTES:
            raise CoverageError("GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES")
        kept.append(item)
    return kept


def audit_link_rows(result):
    """One row per event and the credential it names, then each unmatched event, oldest first."""
    rows, size = [], 2

    def charge(value):
        nonlocal size
        size += value
        if size > AUDIT_LINK_BYTES:
            raise CoverageError("GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES")

    for link in result["links"]:
        # Measure strings separately so calculating the budget never allocates
        # an already oversized serialized list or repeated event response.
        entities_size = 2 + sum(len(json.dumps(value, ensure_ascii=True)) + 2 for value in link["entities"])
        for event in link["events"]:
            row = {**event, "credential": link["credential"], "credential_type": link["credential_type"]}
            charge(len(json.dumps(row, ensure_ascii=True)) + entities_size + 16)
            rows.append({**row, "entities": link["entities"]})
    for event in result["unmatched"]:
        row = {**event, "relation": "unmatched"}
        charge(len(json.dumps(row, ensure_ascii=True)) + 2)
        rows.append(row)
    return sorted(rows, key=lambda row: (row.get("occurred_at") or "", row.get("event_id") or "",
                                         row.get("credential") or ""))


def select_rows(rows, *, relation=None, credential_type=None):
    """A credential type keeps only linked rows: an unmatched event names no credential to match."""
    return [row for row in rows if (not relation or row["relation"] == relation)
            and (not credential_type or row.get("credential_type") == credential_type)]


def audit_links(records):
    """Links per credential, and every event no exact identifier could place."""
    credentials, aliases = {}, {}
    for record in records:
        if record.get("record_type") != "entity_observation":
            continue
        found = _credential(record)
        if found is None:
            continue
        key, kind, names = found
        entry = credentials.setdefault(key, {"credential": key, "credential_type": kind,
                                             "entities": set(), "events": []})
        entry["entities"].add(record["identity"]["object_id"])
        for alias in names:
            aliases.setdefault(alias, set()).add(key)
    events = {}
    for record in records:
        if (record.get("record_type") == "provider_event" and record.get("event_type") != "token_activity"
                and record.get("event_id") not in events):
            events[record.get("event_id")] = record
    unmatched, linked = [], 0
    for event_id, record in sorted(events.items(), key=lambda item: (item[1].get("occurred_at") or "", item[0] or "")):
        refs = _references(record)
        matches, ambiguous = [], False
        for relation, alias, value, basis in refs:
            candidates = aliases.get((alias, value), set())
            if len(candidates) == 1:
                link = (next(iter(candidates)), relation, basis)
                if link not in matches:
                    matches.append(link)
            elif candidates:
                ambiguous = True
        summary = {"event_id": event_id, "action": record.get("event_type"), "occurred_at": record.get("occurred_at")}
        if matches:
            linked += 1
            for key, relation, basis in matches:
                credentials[key]["events"].append({**summary, "relation": relation, "basis": basis})
        else:
            unmatched.append({**summary, "reason": ("no_exact_reference" if not refs else "ambiguous_reference"
                                                    if ambiguous else "no_observed_credential")})
    links = [{"credential": key, "credential_type": entry["credential_type"], "entities": sorted(entry["entities"]),
              "events": entry["events"]}
             for key, entry in sorted(credentials.items()) if entry["events"]]
    return {"links": links, "unmatched": unmatched,
            "counts": {"events": linked + len(unmatched), "linked": linked, "unmatched": len(unmatched)}}
