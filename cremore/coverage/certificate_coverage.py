"""Public certificate correspondence, separate from secret-value coverage."""

from datetime import timedelta

from cremore_azure_provider.public_certificates import certificate_evidence

# Integration: moved from cremore.coverage.providers.facts, whose package import also ran the
# adapter registry (every provider library); the new path does not.
from cremore.coverage.facts import unpack_facts
from cremore.coverage.metadata_correlation import current_issuer_observation
from cremore.coverage.store import utc

MAX_CERTIFICATE_QUERIES = 100
MAX_CERTIFICATE_LINKS = 100
BASIS = "PUBLIC_CERTIFICATE_SHA256"


def certificate_rows(store, connections, *, now, limit, scope_confirmed=False):
    """Spend only the caller's remaining record budget.

    Absence is only PUBLIC_CERTIFICATE_NOT_OBSERVED: the confirmed scope's
    selected Key Vault certificate reads are all current and complete and none
    holds this public DER. It never says the private key is not stored.

    Metadata-only connections are not scanned for value comparison and do not
    change that scope's denominator or completeness. A selected connection can
    retain stale public evidence, whose currentness is evaluated independently.
    """
    remaining, queries, truncated = max(0, limit), 0, False

    def selected(provider):
        return [owner for owner in connections.values()
                if owner["spec"].get("provider") == provider
                and "public_keys" in owner["spec"].get("capabilities", [])
                and "public_certificates" in owner["spec"].get("options", {}).get("sources", [])]

    def collect(provider, kind, purpose):
        nonlocal remaining, queries, truncated
        output, seen = [], set()
        for owner in selected(provider):
            if not remaining or queries >= MAX_CERTIFICATE_QUERIES:
                truncated = True
                break
            queries += 1
            page = store.inventory(provider=provider, object_kind=kind, purpose=purpose,
                                   connection_id=owner["id"], limit=remaining)
            remaining -= len(page["items"])
            truncated |= page["total"] > len(page["items"])
            for entity in page["items"]:
                if entity["id"] in seen:
                    continue
                seen.add(entity["id"])
                evidence = certificate_evidence(entity["summary"])
                historical = False
                if not evidence:
                    if not remaining or queries >= MAX_CERTIFICATE_QUERIES:
                        truncated = True
                        continue
                    queries += 1
                    operation = "azure.entra.public_certificates" if provider == "azure_entra" else "azure.key_vault.public_certificates"
                    retained = store.latest_finished_observation(entity["id"], operation)
                    if retained:
                        remaining -= 1
                        record = retained["record"]
                        evidence = certificate_evidence(record["body"])
                        entity = {**entity, "summary": record["body"], "observed_at": record["observed_at"],
                                  "observation_run": retained["run"]}
                        historical = True
                if evidence:
                    run = entity["observation_run"] or {}
                    observed_owner = connections.get(run.get("connection_id"))
                    # A shared entity may have most recently been observed by
                    # another connection. Judge the actual observation owner.
                    fresh = not historical and current_issuer_observation(entity, observed_owner, now=now)
                    output.append((entity, evidence, observed_owner, fresh))
        return output

    issued = collect("azure_entra", "public_key", "issuer_inventory")
    if not issued:
        return [], truncated
    vault = collect("azure_key_vault", "vault_version", "vault_metadata")

    def read_current(owner):
        runs = store.connection_runs(owner["id"], limit=1)["items"]
        return bool(owner["enabled"] and runs and runs[0]["status"] == "COMPLETE"
                    and runs[0]["revision"] == owner["revision"] and runs[0]["finished_at"]
                    and utc(runs[0]["started_at"]) + timedelta(hours=owner["spec"]["freshness_hours"]) >= now)

    vaults = selected("azure_key_vault")
    vaults_read = scope_confirmed and not truncated and bool(vaults) and all(map(read_current, vaults))
    by_fingerprint = {}
    for entity, evidence, owner, fresh in vault:
        body, run = entity["summary"], entity["observation_run"] or {}
        values = unpack_facts(body["facts"])
        item = {
            "entity_id": str(entity["id"]), "provider": entity["provider"],
            "origin": entity["origin"], "tenant": entity["tenant"],
            "connection_id": str(run.get("connection_id", "")),
            "connection_name": owner["spec"]["name"] if owner else "",
            "run_id": str(run.get("id", "")), "observed_at": entity["observed_at"],
            "reference": body["provenance"]["resource_id"], "version": values.get("version_id", ""),
            "version_state": "CURRENT" if evidence["current_version"] else "UNKNOWN",
            "current_evidence": fresh and evidence["current_version"],
            "credential_type": "AZURE_CERTIFICATE", "state": body.get("provider_state", "UNKNOWN"),
            "match_basis": BASIS,
        }
        by_fingerprint.setdefault(evidence["fingerprint"], []).append(item)
    rows = []
    link_budget = max(0, limit)
    for entity, evidence, owner, fresh in issued:
        run, body = entity["observation_run"] or {}, entity["summary"]
        candidates = sorted(by_fingerprint.get(evidence["fingerprint"], []),
                            key=lambda item: (not item["current_evidence"], item["reference"], item["connection_id"]))
        reasons = {"PUBLIC_CERTIFICATE_ONLY", "PRIVATE_KEY_STORAGE_NOT_PROVEN", "AUTHENTICATION_NOT_CHECKED",
                   "NO_EXPOSURE_OBSERVED", "EXPOSURE_COLLECTION_NOT_PROVEN_COMPLETE"}
        if not fresh:
            reasons.add("ISSUER_OBSERVATION_NOT_CURRENT")
        if not candidates:
            reasons.add("NO_PUBLIC_CERTIFICATE_MATCH_OBSERVED")
        visible = candidates[:min(MAX_CERTIFICATE_LINKS, link_budget)]
        link_budget -= len(visible)
        if len(visible) < len(candidates):
            truncated = True
            reasons.add("PUBLIC_CERTIFICATE_MATCHES_TRUNCATED")
        present = [item for item in visible if item["current_evidence"]]
        history = [item for item in visible if not item["current_evidence"]]
        if candidates and not any(item["current_evidence"] for item in candidates):
            reasons.add("PUBLIC_CERTIFICATE_STORAGE_OBSERVATION_NOT_CURRENT")
        rows.append({
            "origin": "ISSUANCE", "entity_id": str(entity["id"]), "credential_type": "AZURE_CERTIFICATE",
            "identifier": entity["object_id"], "exposed": False,
            "state": ("PUBLIC_CERTIFICATE_MATCH" if any(item["current_evidence"] for item in candidates)
                      else "PUBLIC_CERTIFICATE_NOT_OBSERVED" if not candidates and fresh and vaults_read else "UNKNOWN"),
            "match_basis": BASIS if candidates else "NONE", "reasons": sorted(reasons),
            "issued": {"reference": entity["object_id"], "provider": entity["provider"],
                       "origin": entity["origin"], "tenant": entity["tenant"], "tenant_confirmed": entity["tenant_confirmed"],
                       "connection_id": str(run.get("connection_id", "")),
                       "connection_name": owner["spec"]["name"] if owner else "", "run_id": str(run.get("id", "")),
                       "observed_at": entity["observed_at"], "state": body.get("provider_state", "UNKNOWN"),
                       "current_evidence": fresh},
            "locations": present, "history": history,
        })
    return rows, truncated
