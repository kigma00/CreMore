"""Where an organisation's exposed credentials gather, grouped by the identity
they belong to.

The finding list answers "what was found". This answers "whose key was it, and
how many places is it in" — one IAM user whose key sits in three repositories
and two buckets is one problem, not five, and the list cannot show that.

A group is keyed by a credential *identity* only: the IAM principal ARN the
provider returned, or the account name it returned when there is no ARN. Owner
and team attribution is a separate judgement with its own review workflow, so it
is not mixed in here; a credential with no identity goes to one unattributed
count rather than into a group that would read as a person.

One group uses one basis. Two groups are never merged across bases, because the
same human may appear under an ARN in one and a login name in the other and
merging them would assert an identity nobody established.

Nothing here calls a provider.
"""

from __future__ import annotations

from cremore.db.scan_state import SEVERITY_RANK

REVISION = "cremore-exposure-surface-v1"
# A match an analyst rejected, or one accepted as out of scope, is not surface.
EXCLUDED_STATUSES = ("FALSE_POSITIVE", "IGNORED")


def _identity(finding: dict) -> tuple[str, str, str]:
    """The strongest identity the credential carries: (key, basis, label)."""

    arn = (finding.get("principal") or "").strip()
    name = (finding.get("principal_name") or "").strip()
    if arn.startswith("arn:"):
        return arn, "PRINCIPAL_ARN", arn.rsplit("/", 1)[-1] or arn
    if name:
        return f"{finding.get('provider') or ''}:{name}", "PRINCIPAL_NAME", name
    if arn:
        return f"{finding.get('provider') or ''}:{arn}", "PRINCIPAL_NAME", arn
    return "", "", ""


def _account_of(key: str, basis: str) -> str:
    if basis != "PRINCIPAL_ARN":
        return ""
    parts = key.split(":")
    return parts[4] if len(parts) > 5 and parts[4].isdigit() else ""


def surface(findings) -> dict:
    """Group open findings by the identity their credential belongs to."""

    groups: dict[str, dict] = {}
    unattributed = {"credentials": 0, "locations": 0}
    for finding in findings:
        if finding.get("workflow_status") in EXCLUDED_STATUSES:
            continue
        locations = int(finding.get("exposure_count") or 0)
        key, basis, label = _identity(finding)
        if not key:
            unattributed["credentials"] += 1
            unattributed["locations"] += locations
            continue
        group = groups.setdefault(key, {
            "key": key, "basis": basis, "label": label, "account_id": _account_of(key, basis),
            "severity": "INFO", "credentials": 0, "locations": 0, "found_in": [], "findings": [],
        })
        group["credentials"] += 1
        group["locations"] += locations
        severity = str(finding.get("severity") or "INFO")
        if SEVERITY_RANK.get(severity, -1) > SEVERITY_RANK.get(group["severity"], -1):
            group["severity"] = severity
        provider = finding.get("provider") or ""
        # Where the credential turned up, not who issued it: the surface is the
        # set of places, and the issuer is already on every finding row.
        for source in set(finding.get("source_types") or [finding.get("source_type") or ""]) - {""}:
            if source not in group["found_in"]:
                group["found_in"].append(source)
        group["findings"].append({
            "id": finding.get("id"), "severity": severity, "provider": provider or None,
            "credential_type": finding.get("credential_type"),
            "identifier_hint": finding.get("identifier_hint"),
            "exposure_count": locations,
        })

    ranked = sorted(groups.values(), key=lambda group: (
        -SEVERITY_RANK.get(group["severity"], -1), -group["locations"], -group["credentials"], group["label"]))
    for group in ranked:
        group["found_in"].sort()
        group["findings"].sort(key=lambda row: (-SEVERITY_RANK.get(row["severity"], -1), str(row["id"])))
    return {
        "revision": REVISION,
        "principals": ranked,
        "unattributed": unattributed,
        # Only the bases actually present, so a reader is never offered a
        # grouping this installation's data cannot show.
        "bases": sorted({group["basis"] for group in ranked}),
        "totals": {
            "principals": len(ranked),
            "credentials": sum(group["credentials"] for group in ranked) + unattributed["credentials"],
            "locations": sum(group["locations"] for group in ranked) + unattributed["locations"],
            "shared_identities": sum(1 for group in ranked if group["credentials"] > 1),
        },
    }
