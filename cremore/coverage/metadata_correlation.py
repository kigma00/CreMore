"""Passive links to issuer inventory, with value, identifier and candidate evidence.

Content location does not identify the issuer: a GCP key may live in GitLab.
Only an explicit shared identifier or compatible keyed value comparison links
an issued object. Nothing here authenticates with a discovered credential.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from cremore_github_provider.credential_digest import SCHEME as GITHUB_SCHEME

# Integration: moved from cremore.coverage.providers.facts, whose package import also ran the
# adapter registry (every provider library); the new path does not.
from cremore.coverage.facts import unpack_facts
from cremore.coverage.models import SCHEME
from cremore.coverage.store import CoverageError, utc

INVENTORY_PROVIDERS = {
    "github": "github", "gitlab": "gitlab", "gcp": "gcp", "notion": "notion",
    "atlassian": "atlassian", "bitbucket": "bitbucket", "azure": "azure_entra", "azure_devops": "azure_devops",
}
CANDIDATE_KIND = {"GITLAB_RUNNER_TOKEN": "runner"}
MAX_INVENTORY_ROWS = 10000
MAX_ACTIVITY_SUMMARIES = 1000
MAX_SAS_CANDIDATES = 1000
MAX_SAS_EXPOSURES = 1000
_DIGEST = re.compile(r"[a-f0-9]{64}")


def current_issuer_observation(entity, connection, *, now):
    """Current collected evidence, independently of equality or live validity."""
    run = entity.get("observation_run") or {}
    if (not connection or not connection["enabled"] or run.get("connection_id") != connection["id"]
            or run.get("revision") != connection["revision"] or run.get("status") not in {"COMPLETE", "PARTIAL"}
            or not run.get("finished_at")):
        return False
    freshness = timedelta(hours=connection["spec"]["freshness_hours"])
    if any(not observed or utc(observed) + freshness < now
           for observed in (run.get("started_at"), entity.get("observed_at"))):
        return False
    return any(collection["connection_id"] == connection["id"] and collection["enabled"]
               and collection["latest_run_id"] == run.get("id")
               and collection["status"] in {"COMPLETE", "PARTIAL"}
               and not set(collection["reasons"]) & {"CONNECTION_SCOPE_CHANGED", "STALE_COLLECTION"}
               for collection in entity["collections"])


def _owner_values(facts, parent=""):
    """Owner ids and logins an issued object's facts state: GitHub login or owner, GitLab
    observation metadata user_id, Notion creator."""
    for fact in facts or []:
        name = fact.get("name")
        if ((not parent and name == "login") or (parent in ("owner", "creator") and name in ("id", "login"))
                or (parent == "metadata" and name == "user_id")) and fact.get("value") not in (None, ""):
            yield str(fact["value"]).casefold()
        yield from _owner_values(fact.get("children"), name)


def _verified_owners(exposures, provider):
    """The owner a provider reported when the discovered token itself was verified, and the host it
    belongs to: owner ids are per instance. GitHub records its host; a GitLab result records the
    self-managed instance that verified it and no host for GitLab.com. None means a single-instance
    provider."""
    verified = [e.metadata for e in exposures if (e.metadata or {}).get("verification_state") in ("verified", "restricted")]
    owners = {str(m[key]).casefold() for m in verified for key in ("verification_owner_id", "verification_owner_name")
              if m.get(key)}
    hosts = ({str(m.get("verification_host") or "gitlab.com").lower() for m in verified} if provider == "gitlab" else
             {str(m["verification_host"]).lower() for m in verified if m.get("verification_host")}
             if provider == "github" else None)
    return owners, hosts


def _instance_key(url):
    """Comparable form of an HTTPS GitLab base URL (host, port, path), or None."""
    try:
        parts = urlsplit(url) if isinstance(url, str) else None
        return ((parts.hostname.lower(), parts.port, parts.path.rstrip("/"))
                if parts and parts.scheme == "https" and parts.hostname else None)
    except ValueError:
        return None


def _gitlab_verified_tokens(exposures):
    """(instance, token id) pairs that GitLab named when the discovered token was verified.

    A result without a host came from GitLab.com. A self-managed result came from the registered
    instance the token was found in (the only self-managed host a token is ever sent to), so its
    host must match that source instance.
    """
    pairs = set()
    for exposure in exposures:
        meta = exposure.metadata or {}
        if meta.get("verification_state") not in ("verified", "restricted") or not meta.get("verification_token_id"):
            continue
        host = str(meta.get("verification_host") or "").lower()
        key = _instance_key(meta.get("source_instance") if host else "https://gitlab.com")
        if key and key[0] == (host or "gitlab.com"):
            pairs.add((key, str(meta["verification_token_id"])))
    return pairs


# GitLab identity namespaces backed by a PersonalAccessToken, which /personal_access_tokens/self names:
# personal and service-account PATs, and group/project access tokens (gitlab metadata.model.identity).
_GITLAB_PAT_FAMILIES = {"personal_access_token", "resource_access_token"}


def _child_values(facts, parent):
    return {fact.get("name"): fact.get("value") for top in facts or [] if top.get("name") == parent
            for fact in top.get("children") or []}


def _compatible(meta, match):
    """Same installation key, detection engine and policy as the exposure's own digest."""
    private = meta.get("issuer_comparison") or {}
    return bool(private.get("key_id") and private["key_id"] == match.get("key_id")
                and meta.get("coverage_engine_digest") == match.get("engine_digest")
                and meta.get("coverage_policy_digest") == match.get("policy_digest")
                and match.get("material_kind") == "credential")


def _token_activity(store, exposures, reasons):
    """Entries GitHub's audit log recorded as made with this exact token.

    Provider-reported and bounded by the collected window, its retention and
    GitHub's seven days of Git events; a missing entry is never evidence the
    token went unused.
    """
    digests = {}
    for exposure in exposures:
        digest = ((exposure.metadata or {}).get("issuer_comparison") or {}).get("github_token_digest")
        if digest:
            digests.setdefault(digest, []).append(exposure.metadata)
    if not digests:
        return None
    rows = store.token_activity(digests, limit=MAX_ACTIVITY_SUMMARIES)
    if len(rows) >= MAX_ACTIVITY_SUMMARIES:
        reasons.add("TOKEN_ACTIVITY_LIMIT_REACHED")
    entries, first, last, values = set(), None, None, {"action": set(), "repo": set(), "actor": set()}
    for row in rows:
        match = row["body"].get("value_match") or {}
        if (match.get("evidence") != "PROVIDER_DIGEST" or match.get("scheme") != GITHUB_SCHEME
                or not any(_compatible(meta, match) for meta in digests.get(match.get("fingerprint"), []))):
            continue
        facts = unpack_facts(row["body"].get("facts") or [])
        # Legacy or machine-submitted facts may be scalar even when this
        # particular summary contract expects lists. Such rows prove no use.
        if any(not isinstance(facts.get(name, []), list)
               or any(not isinstance(value, str) for value in facts.get(name, []))
               for name in ("_document_id", "action", "repo", "actor")):
            reasons.add("TOKEN_ACTIVITY_FACTS_INVALID")
            continue
        try:
            seen = datetime.fromisoformat(facts["first_seen_at"]), datetime.fromisoformat(facts["last_seen_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if seen[0].tzinfo is None or seen[1].tzinfo is None:
            continue
        # Overlapping collection windows re-read an entry; count it once.
        entries.update(document for document in facts.get("_document_id") or [] if isinstance(document, str))
        first, last = min(filter(None, (first, seen[0]))), max(filter(None, (last, seen[1])))
        for name, found in values.items():
            found.update(value for value in facts.get(name) or [] if isinstance(value, str))
    if not entries:
        reasons.add("NO_TOKEN_ACTIVITY_COLLECTED")
        return None
    return {"events": len(entries), "first_seen_at": first.isoformat(), "last_seen_at": last.isoformat(),
            "actions": sorted(values["action"])[:32], "repositories": sorted(values["repo"])[:32],
            "actors": sorted(values["actor"])[:32]}


def _link(row, credential, exposures):
    """Return evidence only, never the internal comparison fingerprint."""
    if credential.credential_type == "GITLAB_PERSONAL_ACCESS_TOKEN":
        # The instance that verified the discovered token named this exact token. Token ids are
        # per instance, so the issued entry must come from that same instance.
        issued = _child_values((row.get("summary") or {}).get("facts"), "identity")
        if (issued.get("namespace") in _GITLAB_PAT_FAMILIES
                and (_instance_key(issued.get("instance")), str(issued.get("native_id"))) in _gitlab_verified_tokens(exposures)):
            return "IDENTIFIER", "PROVIDER_VERIFIED_TOKEN_ID"
    if credential.credential_type == "AZURE_SAS_TOKEN":
        match = (row.get("summary") or {}).get("value_match") or {}
        if (credential.fingerprint in (match.get("signed_fingerprints") or [])
                and any(_compatible(exposure.metadata or {}, match) for exposure in exposures)):
            # This key recomputed the SAS signature: it signed this exact SAS.
            return "VALUE", "SAS_SIGNATURE"
        # Otherwise only the storage account name is shared; the signing key is unconfirmed.
        accounts = {(exposure.metadata.get("azure_sas") or {}).get("account") for exposure in exposures} - {None, ""}
        _, marker, rest = row["object_id"].lower().partition("/storageaccounts/")
        if marker and len(accounts) == 1 and rest.split("/", 1)[0] in accounts:
            return "IDENTIFIER", "STORAGE_ACCOUNT_NAME"
        return "CANDIDATE", "NONE"
    if credential.credential_type == "GCP_SERVICE_ACCOUNT":
        identifiers = {identifier for exposure in exposures
                       for identifier in (exposure.metadata.get("issuer_comparison") or {}).get("gcp_service_account_keys", [])}
        if len(identifiers) == 1 and row["object_id"] in identifiers:
            return "IDENTIFIER", "SERVICE_ACCOUNT_KEY_ID"
    match = (row.get("summary") or {}).get("value_match") or {}
    if match.get("credential_type") != credential.credential_type or not _DIGEST.fullmatch(str(match.get("fingerprint", ""))):
        return "CANDIDATE", "NONE"
    for exposure in exposures:
        meta = exposure.metadata or {}
        private = meta.get("issuer_comparison") or {}
        if not _compatible(meta, match):
            continue
        if (match.get("evidence") == "PROVIDER_DIGEST" and match.get("scheme") == GITHUB_SCHEME
                and row["provider"] == "github" and credential.credential_type == "GITHUB_TOKEN"
                and private.get("github_token_digest") == match["fingerprint"]):
            return "VALUE", "PROVIDER_DIGEST"
        if (match.get("evidence") == "VALUE" and match.get("scheme") == SCHEME
                and credential.fingerprint == match["fingerprint"]):
            return "VALUE", "VALUE_FINGERPRINT"
    return "CANDIDATE", "NONE"


def sas_candidates(repo, accounts, *, status=None):
    """Discovered SAS naming an approved storage account, for the ARM collector's offline
    signer check. Only credential fingerprints and signed fields are handed over."""
    names = {account.rsplit("/", 1)[-1].lower() for account in accounts}
    # Unchecked SAS keep their account-name candidate links, never negative results.
    # Bound both findings and exposures before their models are materialized; the
    # worker propagates the incomplete candidate set into its operation report.
    hits, total = repo.search_findings("azure_sas_token", MAX_SAS_CANDIDATES)
    ids = [uuid.UUID(str(hit["id"])) for hit in hits if hit.get("label") == "AZURE_SAS_TOKEN"]
    output = []
    # One batched read for every candidate instead of three reads per finding (second review 2026-09-26).
    batch = repo.findings_with_exposures(ids, exposure_limit=MAX_SAS_EXPOSURES + 1)
    count = sum(len(exposures) for _, _, exposures in batch)
    if status is not None:
        status["complete"] = total <= len(hits) and count <= MAX_SAS_EXPOSURES
    remaining = MAX_SAS_EXPOSURES
    for finding, credential, exposures in batch:
        exposures = exposures[:remaining]
        remaining -= len(exposures)
        if credential is None or finding.workflow_status == "FALSE_POSITIVE":
            continue
        seen = []
        for exposure in exposures:
            facts = (exposure.metadata or {}).get("azure_sas") or {}
            if exposure.status in ("REMOVED", "FALSE_POSITIVE") or facts.get("account") not in names or facts in seen:
                continue
            seen.append(facts)
            output.append({"fingerprint": credential.fingerprint, "sas": facts})
    return output


def finding_links(store, repo, finding_id, *, offset=0, limit=50, now=None, include_removed=False):
    now = now or datetime.now(UTC)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise CoverageError("FINDING_NOT_FOUND")
    credential = repo.get_credential(finding.credential_id)
    if credential is None:
        raise CoverageError("CREDENTIAL_NOT_FOUND")
    exposures = [item for item in repo.exposures_for_credential(finding.credential_id)
                 if item.status != "FALSE_POSITIVE" and (include_removed or item.status != "REMOVED")]
    if finding.workflow_status == "FALSE_POSITIVE":
        exposures = []
    provider = INVENTORY_PROVIDERS.get(credential.provider or "", "")
    if credential.credential_type in ("AZURE_STORAGE_KEY", "AZURE_SAS_TOKEN"):
        provider = "azure_resource_manager"
    kind = CANDIDATE_KIND.get(credential.credential_type, "credential")
    result = {"schema_version": 2, "finding_id": str(finding_id),
              "credential_type": credential.credential_type, "provider": provider,
              "object_kind": kind, "origins": [], "evidence": "NONE", "items": [],
              "total": 0, "offset": offset, "limit": limit, "match_count": 0,
              "value_match_count": 0, "identifier_match_count": 0, "reasons": []}
    if not provider or not exposures:
        result["reasons"] = ["PROVIDER_HAS_NO_MANAGED_INVENTORY" if not provider else "NO_CURRENT_EXPOSURE"]
        return result
    reasons = {"ISSUER_INSTALLATION_NOT_INFERRED_FROM_CONTENT"}
    # ponytail: bounded inventory scan; index comparison evidence if this read
    # path becomes expensive. A truncated inventory is never absence evidence.
    # One read without per-row run/collection details (second review 2026-09-26: 20 paged
    # reads with details took ~1.3 s at 10,000 rows): ranking needs only the entity and its
    # summary, and the details are attached below to the displayed page alone.
    page = store.inventory(provider=provider, object_kind=kind, purpose="issuer_inventory",
                           offset=0, limit=MAX_INVENTORY_ROWS, details=False)
    rows = page["items"]
    if page["total"] > len(rows):
        reasons.add("CANDIDATE_LIMIT_REACHED")
    if credential.credential_type == "GITHUB_TOKEN":
        snapshots = store.snapshot_matches({
            (exposure.metadata.get("issuer_comparison") or {}).get("github_token_digest")
            for exposure in exposures} - {None}, limit=MAX_INVENTORY_ROWS)
        # Snapshot row identities are deliberately excluded from inventory. Only
        # an exact compatible value match may restore them as exposure evidence.
        rows.extend(row for row in snapshots["items"] if _link(row, credential, exposures)[0] == "VALUE")
        if snapshots["truncated"]:
            reasons.add("CANDIDATE_LIMIT_REACHED")
        activity = _token_activity(store, exposures, reasons)
        if activity is not None:
            result["token_activity"] = activity
    owners, owner_hosts = _verified_owners(exposures, provider)
    linked = []
    for row in rows:
        evidence, basis = _link(row, credential, exposures)
        if (evidence == "CANDIDATE" and owners
                and (owner_hosts is None or (urlsplit(row["origin"]).hostname or "").lower() in owner_hosts)
                and owners & set(_owner_values((row.get("summary") or {}).get("facts")))):
            # Same owner as the verified token: narrower, but still not this token.
            evidence, basis = "OWNER", "PROVIDER_REPORTED_OWNER"
        linked.append((row, evidence, basis))
    linked.sort(key=lambda item: {"VALUE": 0, "IDENTIFIER": 1, "OWNER": 2, "CANDIDATE": 3}[item[1]])
    result["value_match_count"] = sum(evidence == "VALUE" for _, evidence, _ in linked)
    result["identifier_match_count"] = sum(evidence == "IDENTIFIER" for _, evidence, _ in linked)
    result["owner_match_count"] = sum(evidence == "OWNER" for _, evidence, _ in linked)
    if result["owner_match_count"]:
        reasons.add("OWNER_MATCH_IS_NOT_A_TOKEN_MATCH")
    result["match_count"] = result["value_match_count"] + result["identifier_match_count"]
    if rows and not result["match_count"]:
        reasons.add("NO_SHARED_MATCHING_EVIDENCE")
    if not rows:
        reasons.add("NO_MANAGED_OBJECT_COLLECTED")
    shown = linked[offset:offset + limit]
    store.inventory_details([row for row, _, _ in shown])
    usage = store.usage_counts([row["id"] for row, _, _ in shown])
    connections = {row["id"]: row for row in store.list_connections()} if shown else {}
    items = []
    for row, evidence, basis in shown:
        stale = {reason for collection in row["collections"] for reason in collection["reasons"]}
        current = current_issuer_observation(row, connections.get((row["observation_run"] or {}).get("connection_id")), now=now)
        if not current:
            stale.add("ISSUER_OBSERVATION_NOT_CURRENT")
        items.append({**{key: row[key] for key in (
            "provider", "origin", "tenant", "tenant_confirmed", "object_kind", "object_id", "purpose",
            "observed_at", "observation_run", "collections")},
            "entity_id": row["id"], "verification": "NOT_PERFORMED", "evidence": evidence,
            "match_basis": basis, "current_evidence": current,
            "usage_events": usage.get(row["id"], 0), "reasons": sorted(stale)})
    result.update(items=items, total=len(rows), inventory_total=page["total"],
                  evidence="LINKED" if result["match_count"] else "CANDIDATE" if rows else "NONE",
                  reasons=sorted(reasons))
    return result
