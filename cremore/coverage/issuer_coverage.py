"""Schema 2 issuance-to-vault projection without creating synthetic exposures."""

from cremore_github_provider.credential_digest import SCHEME as GITHUB_SCHEME

from cremore.coverage.metadata_correlation import current_issuer_observation
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import SCHEME


def issuance_rows(repo, contract, current, historical, blockers, *, key_id, now,
                  exposed_values, exposed_digests, limit):
    store = MetadataStore(repo)
    page = store.inventory(object_kind="credential", purpose="issuer_inventory", limit=max(0, limit))
    connections = {row["id"]: row for row in store.list_connections()}
    value_index, digest_index = {}, {}
    for item in current + historical:
        if item["evidence"] == "VALUE":
            value_index.setdefault((item["credential_type"], item["fingerprint"]), []).append(item)
            if item.get("provider_digest"):
                digest_index.setdefault(item["provider_digest"], []).append(item)
    snapshots = store.snapshot_matches(digest_index, limit=max(0, limit - len(page["items"])))
    snapshot_ids = {entity["id"] for entity in snapshots["items"]}

    def public(item):
        return {name: value for name, value in item.items()
                if name not in {"fingerprint", "provider_digest", "session_fingerprint"}}

    rows = []
    for entity in page["items"] + snapshots["items"]:
        observation = entity["summary"]
        match = observation.get("value_match") or {}
        run = entity["observation_run"] or {}
        connection = connections.get(run.get("connection_id"))
        spec = connection["spec"] if connection else {}
        reasons = {reason for collection in entity["collections"] for reason in collection["reasons"]}
        fresh = current_issuer_observation(entity, connection, now=now)
        if not fresh:
            reasons.add("ISSUER_OBSERVATION_NOT_CURRENT")
        credential_type = match.get("credential_type") or "ISSUED_CREDENTIAL"
        identifier = entity["object_id"]
        compared = False
        linked = []
        basis = "NONE"
        exposed = False
        compatible = (bool(key_id) and match.get("key_id") == key_id
                      and match.get("material_kind") == "credential"
                      and all(match.get(name) == contract[name] for name in ("engine_digest", "policy_digest")))
        if match.get("evidence") == "PROVIDER_DIGEST" and entity["provider"] == "github" and match.get("scheme") == GITHUB_SCHEME and compatible:
            linked = digest_index.get(match["fingerprint"], [])
            basis, compared = "PROVIDER_DIGEST", True
            exposed = match["fingerprint"] in exposed_digests
        elif match.get("evidence") == "VALUE" and match.get("scheme") == SCHEME and compatible:
            value_key = (credential_type, match["fingerprint"])
            linked = value_index.get(value_key, []) + value_index.get(("OPAQUE_VALUE", match["fingerprint"]), [])
            basis, compared = "VALUE_FINGERPRINT", True
            exposed = value_key in exposed_values
        else:
            reasons.add("ISSUER_COMPARISON_EVIDENCE_UNAVAILABLE")
            if match and not compatible:
                reasons.add("VALUE_FINGERPRINT_CONTRACT_MISMATCH")
        snapshot = entity["id"] in snapshot_ids
        if snapshot:
            if not linked:
                continue
            reasons.add("SNAPSHOT_OBSERVATION_NOT_UNIQUE_CREDENTIAL")
        present = [item for item in linked if item["current_evidence"]]
        history = [item for item in linked if not item["current_evidence"]]
        state = ("IDENTIFIER_ONLY" if basis == "IDENTIFIER" else "MATCHED") if present else "UNKNOWN"
        if not present:
            reasons.update(blockers)
            if not snapshot and not reasons and fresh and compared:
                # Like an AWS key ID, a key ID only shows what the vault did not name.
                state = "IDENTIFIER_NOT_OBSERVED" if basis == "IDENTIFIER" else "NO_VAULT_MATCH"
        if basis == "IDENTIFIER":
            reasons.add("IDENTIFIER_COMPARISON_ONLY")
        if not exposed:
            reasons.update({"NO_EXPOSURE_OBSERVED", "EXPOSURE_COLLECTION_NOT_PROVEN_COMPLETE"})
        issued = {"reference": identifier, "provider": entity["provider"], "origin": entity["origin"],
                  "tenant": entity["tenant"], "tenant_confirmed": entity["tenant_confirmed"],
                  "connection_id": str(run.get("connection_id", "")), "connection_name": spec.get("name", ""),
                  "run_id": str(run.get("id", "")), "observed_at": entity["observed_at"],
                  "state": observation.get("provider_state", "UNKNOWN"), "current_evidence": fresh}
        if snapshot:
            issued["snapshot_observation"] = True
        rows.append({"origin": "ISSUANCE", "entity_id": str(entity["id"]), "credential_type": credential_type,
                     "identifier": identifier, "issued": issued, "exposed": exposed, "state": state,
                     "match_basis": basis if linked else "NONE", "reasons": sorted(reasons),
                     "locations": [{**public(item), "match_basis": basis} for item in present],
                     "history": [{**public(item), "match_basis": basis} for item in history]})
    return rows, snapshots["truncated"] or page["total"] > len(page["items"])
