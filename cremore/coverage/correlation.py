"""Evidence-based vault coverage; a key ID is never a secret-value match."""

import re
import uuid
from datetime import UTC, datetime, timedelta

from cremore.coverage.models import V1_PURPOSE, digest, weakest_completeness
from cremore.coverage.store import CoverageStore, utc

REPORT_LIMIT = 100000
_INVENTORY_LINK_LIMIT = 100
_AWS_ID = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
_DIGEST = re.compile(r"[a-f0-9]{64}")


def public_connection(row, *, include_references=False):
    from cremore.secretstore.sealed import public_ref
    result = {key: value for key, value in row.items() if key != "token_hash"}
    if result.get("spec", {}).get("schema_version") == 2:
        result["spec"] = {**result["spec"], "options": {
            k: v for k, v in result["spec"].get("options", {}).items() if k != "store_values"}}
    if "secret_refs" in result.get("spec", {}):
        result["spec"] = {**result["spec"], "secret_refs": {
            slot: public_ref(ref, include_reference=True) if include_references else "configured"
            for slot, ref in result["spec"]["secret_refs"].items()}}
    return result


def is_vault_spec(spec):
    return spec.get("schema_version", 1) == 1 and spec.get("provider") in {"aws_secrets_manager", "aws_ssm"}


def in_vault_scope(row):
    # A disabled vault leaves the declared scope. The revision changes, so
    # absence stays blocked until an admin confirms the smaller scope.
    return row["enabled"] and is_vault_spec(row["spec"])


def scope_revision(connections):
    return digest(sorted((str(row["id"]), row["revision"]) for row in connections if in_vault_scope(row)))


def _attach_key_creators(inventory, creations, states):
    """Join exact account/key IDs; creation is neither key use nor current validity."""
    by_key = {}
    for item in creations:
        by_key.setdefault((item["account_id"], item["identifier"]), []).append(item)
    for item in inventory:
        if item["evidence"] != "ISSUED" or item["credential_type"] != "AWS_ACCESS_KEY":
            continue
        candidates = by_key.get((item["account_id"], item["identifier"]), [])
        signatures = {(c["session"]["caller_arn"], c["session"]["issued_at"]) for c in candidates}
        item["creator"] = None
        if len(signatures) > 1:
            item["creator_status"] = "CONFLICT"
        elif candidates:
            candidate = max(candidates, key=lambda c: (c["current_evidence"], utc(c["observed_at"])))
            event = candidate["session"]
            item["creator"] = {"arn": event["caller_arn"], "at": event["issued_at"], "event_id": event["event_id"],
                "region": candidate["region"], "source": event["evidence_source"],
                "current": candidate["current_evidence"], "run_id": candidate["run_id"]}
            item["creator_status"] = "OBSERVED"
        else:
            trails = [s for s in states if s["spec"]["provider"] == "aws_cloudtrail"
                      and s["spec"]["account_id"] == item["account_id"] and s["enabled"]]
            item["creator_status"] = ("NOT_CONNECTED" if not trails else
                "NOT_COLLECTED" if all(not s["latest"] for s in trails) else
                "RUNNING" if any(s["latest"] and s["latest"]["status"] == "RUNNING" for s in trails) else
                "INCOMPLETE" if any(s["reasons"] or s.get("access_reasons") or s["truncated"] for s in trails)
                else "NOT_OBSERVED_IN_WINDOW")


def report(repo, contract, *, offset=0, limit=100, now=None, finding_id=None,
           state="", source_type="", vault_provider="", origin="", fingerprint_key_id=None, settings=None):
    now = now or datetime.now(UTC)
    store = CoverageStore(repo)
    all_connections = store.list_connections()
    connections = [row for row in all_connections if row["spec"].get("schema_version", 1) == 1
                   and row["spec"].get("provider") in V1_PURPOSE]
    inventory_refusals = {}
    if any(row["spec"]["provider"] in ("aws_iam", "aws_cloudtrail") for row in connections):
        from cremore_aws_provider import aws_access
        approved = aws_access.approval(repo, aws_access.SCANNER, settings)
        inventory_refusals = {account.account_id: aws_access.use_refusal(account, aws_access.SCANNER, approved)
                             for account in repo.list_aws_accounts()}
    declaration = (repo.get_setting("coverage_scope") or {}).get("value") or {}
    blockers = set()
    if not declaration.get("confirmed") or declaration.get("revision") != scope_revision(all_connections):
        blockers.add("VAULT_SCOPE_NOT_CONFIRMED")
    if not any(in_vault_scope(row) for row in all_connections):
        blockers.add("NO_VAULT_CONNECTED")
    current, historical, issued, roots, states, inventory, creations = [], [], [], [], [], [], []
    # How each in-scope store's newest run knows it listed everything.
    bases = []
    remaining = REPORT_LIMIT
    for connection in connections:
        cid, spec = connection["id"], connection["spec"]
        snapshots = store.snapshots(cid, max_items=remaining)
        remaining -= sum(len(snapshot["items"]) for snapshot in snapshots)
        truncated = any(snapshot["truncated"] for snapshot in snapshots)
        if truncated:
            blockers.add("REPORT_LIMIT_REACHED")
        latest = snapshots[0] if snapshots else None
        reasons = set()
        if spec["provider"] == "aws_secrets_manager" and spec["version_selector"] not in ("latest", "AWSCURRENT"):
            reasons.add("HISTORICAL_VERSION_SCOPE")
        if not connection["enabled"]:
            reasons.add("CONNECTION_DISABLED")
        if not latest:
            reasons.add("NEVER_COLLECTED")
        else:
            if latest["revision"] != connection["revision"]:
                reasons.add("SCOPE_CHANGED")
            if latest["contract"] != contract:
                reasons.add("CONTRACT_CHANGED")
            if not latest["finished_at"] or utc(latest["started_at"]) + timedelta(hours=spec["freshness_hours"]) < now:
                reasons.add("STALE_OR_RUNNING")
            reasons.update(latest["reasons"])
            if latest["status"] != "COMPLETE":
                reasons.add("COLLECTION_" + latest["status"])
        is_issuer = V1_PURPOSE[spec["provider"]] in ("issuer_inventory", "usage")
        refusal = inventory_refusals.get(spec.get("account_id")) if is_issuer else None
        access_reasons = [refusal] if refusal else []
        if in_vault_scope(connection):
            # Token-accessor and lease listing is management, never KV storage or its absence.
            blockers.update(reasons)
            # A run finished before completeness was recorded listed through the API.
            bases.append(None if not latest else latest.get("completeness") or (
                "API_LISTING" if latest["status"] == "COMPLETE" else None))
        states.append({**public_connection(connection), "latest": None if not latest else {
            **{key: latest[key] for key in ("id", "status", "started_at", "finished_at", "item_count", "revision")},
            "completeness": latest.get("completeness")},
            # The row budget cut this store's rows: its collection is not at fault, its rows here are not all.
            "reasons": sorted(reasons), "truncated": truncated, **({"access_reasons": access_reasons} if is_issuer else {})})
        # Issued rows come from the newest finished run: a running or failed run lists nothing, and
        # never deletes them. Keys a partial run did not list stay as history from the last complete run.
        finished = [s for s in snapshots if s["finished_at"] and s["status"] in ("COMPLETE", "PARTIAL")]
        issuer_run = max(finished, key=lambda s: s["sequence"], default=None)
        baseline = max((s for s in finished if s["status"] == "COMPLETE"), key=lambda s: s["sequence"], default=None)
        if issuer_run is not None and baseline is not None and baseline is not issuer_run:
            listed = {(o["evidence"], o["credential_type"], o["identifier"]) for o in issuer_run["items"]}
            carried = {id(o) for o in baseline["items"] if (o["evidence"], o["credential_type"], o["identifier"]) not in listed}
        else:
            carried = set()
        for index, snapshot in enumerate(snapshots):
            valid = (index == 0 and connection["enabled"] and snapshot["revision"] == connection["revision"]
                     and snapshot["contract"] == contract and snapshot["finished_at"] is not None
                     and utc(snapshot["started_at"]) + timedelta(hours=spec["freshness_hours"]) >= now
                     and snapshot["status"] in ("COMPLETE", "PARTIAL"))
            for observation in snapshot["items"]:
                item = {**observation, "connection_id": str(cid), "connection_name": spec["name"],
                        "provider": spec["provider"], "run_id": str(snapshot["id"]), "observed_at": snapshot["finished_at"],
                        "collection_status": snapshot["status"], "collection_reasons": snapshot["reasons"],
                        "current_evidence": valid and observation["version_state"] == "CURRENT"}
                if is_issuer:
                    # Access changes affect currentness, never the collected facts
                    # or independent Vault equality. Unregistered collectors keep
                    # their existing scoped evidence contract.
                    item["access_reasons"] = access_reasons
                    item["current_evidence"] = item["current_evidence"] and not access_reasons
                    if snapshot["finished_at"] and item["evidence"] in ("ISSUED", "SESSION_ISSUED", "USAGE"):
                        inventory.append(item)
                    if snapshot["finished_at"] and item["evidence"] == "KEY_CREATED":
                        creations.append(item)
                    if snapshot is issuer_run or (snapshot is baseline and id(observation) in carried):
                        (roots if item["evidence"] == "ROOT_STATUS" else issued).append(item)
                elif item["evidence"] in ("VALUE", "IDENTIFIER"):
                    (current if item["current_evidence"] else historical).append(item)
    _attach_key_creators(inventory, creations, states)
    by_value, old_values, by_id = {}, {}, {}
    for item in current:
        if item["evidence"] == "VALUE":
            by_value.setdefault((item["credential_type"], item["fingerprint"]), []).append(item)
    for item in historical:
        if item["evidence"] == "VALUE":
            old_values.setdefault((item["credential_type"], item["fingerprint"]), []).append(item)
    for item in current + historical:
        if item["identifier"]:
            by_id.setdefault((item["credential_type"], item["identifier"]), []).append(item)

    def location(item):
        return {key: value for key, value in item.items() if key not in ("fingerprint", "session_fingerprint", "provider_digest", "issuer_identifier")}

    inventory_by_id = {}
    for item in inventory:
        if item["credential_type"] == "AWS_ACCESS_KEY" and _AWS_ID.fullmatch(item["identifier"]):
            inventory_by_id.setdefault(item["identifier"], []).append(item)

    rows, exposed_values, exposed_ids = [], set(), set()
    exposed_digests = set()
    counts = {"exposed": 0, "matched": 0, "no_vault_match": 0, "unknown": 0, "issuance_only": 0, "vault_only": 0,
              "managed": 0}
    findings, finding_total = ([{"id": finding_id}], 1) if finding_id else repo.search_findings("", REPORT_LIMIT)
    if finding_total > REPORT_LIMIT:
        blockers.add("REPORT_LIMIT_REACHED")
    for hit in findings:
        finding = repo.get_finding(uuid.UUID(str(hit["id"])))
        if finding is None:
            continue
        if finding.workflow_status == "FALSE_POSITIVE":
            continue
        credential = repo.get_credential(finding.credential_id)
        exposures = repo.exposures_for_credential(finding.credential_id)
        exposures = [item for item in exposures if item.status not in ("REMOVED", "FALSE_POSITIVE")]
        if not credential or not exposures:
            continue
        for exposure in exposures:
            private = exposure.metadata.get("issuer_comparison") or {}
            if private.get("key_id") == fingerprint_key_id and private.get("github_token_digest"):
                exposed_digests.add(private["github_token_digest"])
        key = (credential.credential_type, credential.fingerprint)
        exposed_values.add(key)
        identifier_type = "AWS_ACCESS_KEY" if credential.credential_type == "AWS_ACCESS_KEY_ID" else credential.credential_type
        if credential.identifier:
            exposed_ids.add((identifier_type, credential.identifier))
        opaque_key = ("OPAQUE_VALUE", credential.fingerprint)
        opaque = by_value.get(opaque_key, []) if not credential.credential_type.startswith("AWS_") else []
        matches = by_value.get(key, []) + opaque
        if opaque:
            exposed_values.add(opaque_key)
        reasons = set(blockers)
        # A partial observation cannot establish the complete key's vault status.
        partial = credential.credential_type in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
        component_matches = matches if partial else []
        if partial:
            reasons.add("PARTIAL_AWS_MATERIAL")
            if component_matches:
                reasons.add("SECRET_COMPONENT_MATCHED")
            matches = []
        current_exposures = [item for item in exposures if item.last_seen_at and utc(item.last_seen_at) + timedelta(hours=24) >= now]
        if not any(item.metadata.get("coverage_engine_digest") == contract["engine_digest"]
                   and item.metadata.get("coverage_policy_digest") == contract["policy_digest"] for item in current_exposures):
            reasons.add("EXPOSURE_COMPATIBILITY_NOT_CONFIRMED")
        if not current_exposures:
            reasons.add("EXPOSURE_STALE")
        temporary = bool(credential.identifier and credential.identifier.startswith("ASIA"))
        session_fingerprints = {item.metadata.get("aws_session_fingerprint") for item in exposures
                                if item.metadata.get("aws_session_material") == "COMPLETE"
                                and _DIGEST.fullmatch(str(item.metadata.get("aws_session_fingerprint", "")))}
        session_match_state = "UNKNOWN" if temporary else "NOT_APPLICABLE"
        match_basis = "VALUE_FINGERPRINT" if matches or component_matches else "NONE"
        if temporary:
            reasons.add("TEMPORARY_CREDENTIAL_NOT_EXPECTED_IN_VAULT")
            pair_matches = matches
            matches = [item for item in pair_matches if item.get("session_fingerprint") in session_fingerprints]
            if matches:
                session_match_state, match_basis = "MATCHED", "SESSION_FINGERPRINT"
            elif pair_matches:
                component_matches = pair_matches
                session_match_state, match_basis = "PAIR_ONLY", "KEY_PAIR_FINGERPRINT"
                reasons.add("STS_SESSION_BINDING_NOT_CONFIRMED")
            if any(item.metadata.get("aws_session_material") == "AMBIGUOUS" for item in exposures):
                reasons.add("AMBIGUOUS_AWS_SESSION_MATERIAL")
        # Positive HMAC equality remains useful even for older scans; an absent
        # match requires proof that exposure and vault used the same contract.
        storage_state = "MATCHED" if matches else "UNKNOWN" if reasons else "NO_VAULT_MATCH"
        candidates = by_id.get((identifier_type, credential.identifier), []) if partial and credential.identifier else []
        current_candidates = [item for item in candidates if item["current_evidence"]]
        if current_candidates:
            storage_state = "IDENTIFIER_ONLY"
            match_basis = "IDENTIFIER"
        supported_identifier = (credential.provider == "aws" and credential.credential_type in {"AWS_ACCESS_KEY", "AWS_ACCESS_KEY_ID"}
                                and _AWS_ID.fullmatch(credential.identifier or ""))
        linked = inventory_by_id.get(credential.identifier, []) if supported_identifier else []
        linked = sorted(linked, key=lambda item: (not item["current_evidence"], -utc(item["observed_at"]).timestamp()))

        def vault_location(item, match_basis=match_basis, temporary=temporary, session_fingerprints=session_fingerprints):
            basis = match_basis
            if temporary and item["evidence"] == "VALUE" and item["credential_type"] == "AWS_ACCESS_KEY":
                basis = "SESSION_FINGERPRINT" if item.get("session_fingerprint") in session_fingerprints else "KEY_PAIR_FINGERPRINT"
            return {**location(item), "match_basis": basis}

        counts["exposed"] += 1
        counts[{"MATCHED": "matched", "NO_VAULT_MATCH": "no_vault_match"}.get(storage_state, "unknown")] += 1
        rows.append({"origin": "EXPOSURE", "credential_id": str(credential.id), "finding_id": str(finding.id),
                     "credential_type": credential.credential_type, "identifier": credential.identifier_hint or "",
                     "state": storage_state, "reasons": (["TEMPORARY_CREDENTIAL_NOT_EXPECTED_IN_VAULT"] if temporary else []) if matches else sorted(reasons),
                     "match_basis": match_basis, "session_match_state": session_match_state,
                     "locations": [vault_location(item) for item in (current_candidates or component_matches or matches)],
                     "history": [vault_location(item) for item in old_values.get(key, []) +
                                 (old_values.get(opaque_key, []) if not credential.credential_type.startswith("AWS_") else []) +
                                 [c for c in candidates if not c["current_evidence"]]],
                     "inventory_matches": [{**location(item), "match_basis": "IDENTIFIER"} for item in linked[:_INVENTORY_LINK_LIMIT]],
                     "inventory_match_count": len(linked), "inventory_matches_truncated": len(linked) > _INVENTORY_LINK_LIMIT,
                     "source_types": sorted({item.source_type for item in exposures}),
                     "exposure_count": sum(item.status != "REMOVED" for item in exposures)})
    if finding_id:
        return {"item": rows[0] if rows else None, "scope_reasons": sorted(blockers)}
    from cremore.coverage.issuer_coverage import issuance_rows
    metadata_rows, truncated = issuance_rows(repo, contract, current, historical, blockers,
        key_id=fingerprint_key_id, now=now, exposed_values=exposed_values, exposed_digests=exposed_digests,
        limit=remaining)
    if truncated:
        blockers.add("REPORT_LIMIT_REACHED")
    counts["issuance_only"] += sum(not row["exposed"] and not row["issued"].get("snapshot_observation") for row in metadata_rows)
    rows.extend(metadata_rows)
    seen_issued, counted_issued = set(), set()
    for item in issued:
        if item["evidence"] not in ("ISSUED", "SESSION_ISSUED", "USAGE"):
            continue
        key = (item["credential_type"], item["identifier"])
        observation_key = (*key, item["evidence"], item["connection_id"], item["reference"], item["region"])
        if observation_key in seen_issued:
            continue
        seen_issued.add(observation_key)
        if item["evidence"] == "ISSUED" and key not in counted_issued:
            counts["issuance_only"] += int(key not in exposed_ids)
            counted_issued.add(key)
        candidates = [candidate for candidate in by_id.get(key, []) if candidate["current_evidence"]]
        history = [candidate for candidate in by_id.get(key, []) if not candidate["current_evidence"]]
        no_identifier = not blockers and item["current_evidence"] and not item["identifier"].startswith("ASIA")
        usage_source = ("BOUNDED_TRAIL_LOG_EVIDENCE" if (item.get("session") or {}).get("evidence_source") == "TRAIL_S3"
                        else "BOUNDED_MANAGEMENT_EVENT_HISTORY")
        reasons = (["ISSUER_CANNOT_RETURN_SECRET_VALUE"] if item["evidence"] == "ISSUED" else
                   ["OBSERVED_SESSION_ISSUANCE", "NOT_COMPLETE_SESSION_INVENTORY"] if item["evidence"] == "SESSION_ISSUED" else
                   [usage_source, "USAGE_NOT_COMPLETE_ISSUANCE_INVENTORY"])
        reasons.append("IDENTIFIER_COMPARISON_ONLY")
        if key not in exposed_ids:
            reasons.extend(["NO_EXPOSURE_OBSERVED", "EXPOSURE_COLLECTION_NOT_PROVEN_COMPLETE"])
        if item["identifier"].startswith("ASIA"):
            reasons.append("TEMPORARY_CREDENTIAL_NOT_EXPECTED_IN_VAULT")
        rows.append({"origin": "ISSUANCE" if item["evidence"] in ("ISSUED", "SESSION_ISSUED") else "USAGE", "credential_type": item["credential_type"], "identifier": item["identifier"],
                     "state": "IDENTIFIER_ONLY" if candidates else "IDENTIFIER_NOT_OBSERVED" if no_identifier else "UNKNOWN", "issued": location(item),
                     "match_basis": "IDENTIFIER" if candidates else "NONE",
                     "exposed": key in exposed_ids, "locations": [{**location(c), "match_basis": "IDENTIFIER"} for c in candidates],
                     "history": [{**location(c), "match_basis": "IDENTIFIER"} for c in history], "reasons": reasons})
    for key, items in by_value.items():
        if key in exposed_values or key[0] == "OPAQUE_VALUE":
            continue
        counts["vault_only"] += 1
        rows.append({"origin": "VAULT", "credential_type": key[0], "identifier": "", "state": "OBSERVED_IN_VAULT",
                     "locations": [location(item) for item in items], "reasons": ["NO_EXPOSURE_OBSERVED"]})
    # One verdict per issued credential. Observed STS sessions are not expected
    # in a vault, and a key seen by several observations counts once.
    verdicts = {}
    for row in rows:
        if (row["origin"] == "ISSUANCE" and row["issued"].get("evidence") != "SESSION_ISSUED"
                and not row["issued"].get("snapshot_observation")):
            verdicts.setdefault(row.get("entity_id") or (row["credential_type"], row["identifier"]), set()).add(row["state"])
    counts.update(issued=len(verdicts), issued_in_vault=0, issued_not_in_vault=0, issued_unknown=0)
    for found in verdicts.values():
        counts["issued_in_vault" if found & {"MATCHED", "IDENTIFIER_ONLY", "PUBLIC_CERTIFICATE_MATCH"} else
               "issued_not_in_vault" if found & {"NO_VAULT_MATCH", "IDENTIFIER_NOT_OBSERVED", "PUBLIC_CERTIFICATE_NOT_OBSERVED"}
               else "issued_unknown"] += 1
    counts["matched_percent"] = round(100 * counts["matched"] / counts["exposed"], 1) if counts["exposed"] and not counts["unknown"] and not blockers else None
    counts["complete"] = "REPORT_LIMIT_REACHED" not in blockers
    # Absence is only ever as strong as the weakest store's own completeness:
    # an operator-declared export never reads as an API listing.
    absence_basis = weakest_completeness(bases) if bases and all(bases) else None
    for row in rows:
        if row["state"] in ("NO_VAULT_MATCH", "IDENTIFIER_NOT_OBSERVED"):
            row["absence_basis"] = absence_basis
    # Display filters never narrow the compared vault scope or its denominator.
    rows = [row for row in rows if (not state or row["state"] == state) and (not origin or row["origin"] == origin)
            and (not source_type or source_type in row.get("source_types", []))
            and (not vault_provider or any(item["provider"] == vault_provider
                 for item in row["locations"] + row.get("history", []) + ([row["issued"]] if row.get("issued") else [])))]
    return {"summary": counts, "scope_confirmed": not ("VAULT_SCOPE_NOT_CONFIRMED" in blockers),
            "scope_revision": scope_revision(all_connections), "scope_reasons": sorted(blockers),
            "absence_basis": absence_basis,
            "connections": states, "root_status": [location(item) for item in roots],
            "items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit}
