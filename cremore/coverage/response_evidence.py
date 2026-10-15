"""Saved issuer/vault proof for response completion. No network or credential use.

Unknown, stale, partial and identifier-only evidence cannot prove safe storage.
An approved AWS publish binds an immutable secret version to the successor;
other issuers need their existing compatible value/digest comparison.
"""
from __future__ import annotations

import hashlib
import uuid

from cremore.coverage import correlation, metadata_correlation
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import Contract
from cremore.governance.response import _when


def snapshot(repo, settings, orchestrator, now):
    orchestrator.refresh_rules()
    contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                        policy_digest=orchestrator.coverage_policy_digest).model_dump()
    key = orchestrator.config.fingerprint_key
    return correlation.report(repo, contract, limit=correlation.REPORT_LIMIT, now=now, settings=settings,
                              fingerprint_key_id=hashlib.sha256(key).hexdigest() if key else None)


def _check(state, reason, **refs):
    return {"state": state, "reason": reason, **{k: v for k, v in refs.items() if v is not None}}


def _ref(plan):
    return {"plan_id": str(plan.id), "at": plan.verified_at.isoformat(), "plan_hash": plan.plan_hash}


def linked(repo, finding, *, now):
    store = MetadataStore(repo)
    return metadata_correlation.finding_links(store, repo, finding.id, limit=100, now=now,
                                              include_removed=True)["items"]


def plans_for(repo, finding, links):
    credential = repo.get_credential(finding.credential_id)
    ids = {str(item["entity_id"]) for item in links if item["evidence"] in ("VALUE", "IDENTIFIER")}
    # Filter by the credential's reservation key, not the installation's newest
    # 500 plans (which can omit an older completed action in a large deployment).
    from cremore.remediation.provider_actions import target_key

    keys = {finding.credential_id}
    for link in links:
        if str(link["entity_id"]) in ids:
            from cremore.remediation.provider_actions import ProviderActionError, target_of

            try:
                keys.add(target_key(target_of(repo, link["entity_id"])))
            except ProviderActionError:
                pass
    candidates = {p.id: p for key in keys for p in repo.list_action_plans(credential_id=key)}
    return [plan for plan in candidates.values() if (
        (not plan.target and plan.credential_id == finding.credential_id
         and credential.provider == "aws" and plan.key_id == credential.identifier)
        or (plan.target and str(plan.target.get("entity_id")) in ids))]


def options(repo, finding, *, now, q=""):
    links = linked(repo, finding, now=now)
    plans = plans_for(repo, finding, links)
    origins = {(link["provider"], link["origin"], link["tenant"]) for link in links if link["evidence"] in ("VALUE", "IDENTIFIER")}
    old = {str(link["entity_id"]) for link in links if link["evidence"] in ("VALUE", "IDENTIFIER")}
    entities, truncated = {}, False
    store = MetadataStore(repo)
    for provider, origin, tenant in sorted(origins):
        page = store.inventory(provider=provider, origin=origin, tenant=tenant, object_kind="credential",
                               purpose="issuer_inventory", q=q, limit=100, details=False)
        truncated |= page["total"] > 100
        for e in page["items"]:
            if str(e["id"]) not in old and (e["provider"], e["origin"], e["tenant"]) in origins:
                entities[str(e["id"])] = {"id": str(e["id"]), "label": e["object_id"], "provider": e["provider"]}
    return {"entities": list(entities.values())[:100], "truncated": truncated or len(entities) > 100,
            "plans": [{"id": str(p.id), "action": p.action_type, "status": p.status,
                        "verified_at": p.verified_at.isoformat() if p.verified_at else None}
                       for p in plans if p.action_type == "PUBLISH_ACCESS_KEY_ROTATION"]}


def evaluate(repo, finding, cycle, compared, *, now):
    report = cycle.get("report") or {}
    credential = repo.get_credential(finding.credential_id)
    done = report.get("result") == "DONE"
    checks = {"report": _check("PASS" if done and cycle.get("answer") == "APPROVED" else "WAIT",
                              "OWNER_REPORT_AND_APPROVAL" if done else "OWNER_REPORT_REQUIRED",
                              report_id=report.get("id"), hash=report.get("hash")),
              "removal": _check("PASS" if (cycle.get("removal") or {}).get("removed") else "WAIT",
                                "COMPLETE_RESCAN_REQUIRED", **(cycle.get("removal") or {})),
              "retirement": _check("WAIT", "ISSUER_RETIREMENT_PROOF_REQUIRED"),
              "replacement": _check("NA" if report.get("path") == "RETIRED" else "WAIT", "REPLACEMENT_PROOF_REQUIRED"),
              "vault": _check("NA" if report.get("path") == "RETIRED" else "WAIT", "CURRENT_VALUE_STORAGE_REQUIRED"),
              "cutover": _check("NA" if report.get("path") == "RETIRED" else "PASS" if "CUTOVER" in report.get("actions", []) else "WAIT",
                                "OWNER_STATEMENT", report_id=report.get("id"))}
    if credential.credential_type == "AWS_ACCESS_KEY_ID":
        checks["retirement"] = _check("WAIT", "IDENTIFIER_ONLY_REQUIRES_REVIEW")
        return checks
    links = linked(repo, finding, now=now)
    plans = plans_for(repo, finding, links)
    since = _when(cycle["requested_at"])
    verified = [p for p in plans if p.status == "VERIFIED" and p.verified_at and _when(p.verified_at.isoformat()) >= since
                and p.approved_by and p.plan_hash]
    retired = [p for p in verified if p.action_type == "DELETE_ACCESS_KEY" or (
        p.action_type == "REVOKE_PROVIDER_CREDENTIAL" and not (p.target or {}).get("revokes"))]
    if retired:
        checks["retirement"] = _check("PASS", "PROVIDER_READBACK", **_ref(max(retired, key=lambda p: p.verified_at)))
    else:
        # Explicit issuer state, never a missing row or failed listing.
        store = MetadataStore(repo)
        for link in links:
            if (link["evidence"] not in ("VALUE", "IDENTIFIER") or not link["current_evidence"]
                    or (link.get("observation_run") or {}).get("status") != "COMPLETE"
                    or _when(str(link.get("observed_at"))) is None or _when(str(link["observed_at"])) < since):
                continue
            detail = store.entity_detail(uuid.UUID(str(link["entity_id"])), limit=1)
            state = (detail["entity"].get("summary") or {}).get("provider_state")
            from cremore.remediation.provider_actions import module

            adapter = module(link["provider"])
            if state in ("REVOKED", "EXPIRED") and not getattr(adapter, "REVOKES", None):
                checks["retirement"] = _check("PASS", "EXPLICIT_ISSUER_STATE", entity_id=str(link["entity_id"]),
                                              run_id=str(link["observation_run"]["id"]), at=str(link["observed_at"]))
    if not done or report.get("path") != "REPLACED":
        return checks
    connections = {str(c["id"]): c for c in compared["connections"]}

    def current(location):
        connection = connections.get(str(location.get("connection_id")), {})
        latest = connection.get("latest") or {}
        observed = _when(str(location.get("observed_at")))
        return (connection.get("enabled") and latest.get("status") == "COMPLETE" and not connection.get("reasons")
                and str(latest.get("id")) == str(location.get("run_id")) and location.get("current_evidence")
                and observed is not None and observed >= _when(report["performed_at"])
                and location.get("evidence") == "VALUE")

    replacement_plan = next((p for p in verified if str(p.id) == report.get("replacement_plan_id")
                             and p.action_type == "PUBLISH_ACCESS_KEY_ROTATION" and p.new_key_id
                             and p.new_key_id != p.key_id and p.pending_version), None)
    matched = []
    if replacement_plan:
        p = replacement_plan
        findings = repo.list_findings(limit=10001)
        exposed = [f for f in findings if not f.all_locations_removed
                   and f.workflow_status != "FALSE_POSITIVE"]
        # A bounded check cannot prove a clean successor when it truncated.
        if len(findings) > 10000 or any(c.identifier == p.new_key_id for f in exposed
                                      if (c := repo.get_credential(f.credential_id))):
            checks["replacement"] = _check("WAIT", "REPLACEMENT_EXPOSURE_REVIEW_REQUIRED")
            return checks
        checks["replacement"] = _check("PASS", "APPROVED_ROTATION_BINDING", **_ref(p))
        for row in compared["items"]:
            for loc in row.get("locations", []):
                if (current(loc) and loc.get("provider") == "aws_secrets_manager"
                        and loc.get("reference") == (p.rotation or {}).get("secret_arn")
                        and loc.get("version") == p.pending_version and loc.get("identifier") == p.new_key_id
                        and loc.get("credential_type") == "AWS_ACCESS_KEY"):
                    matched.append(loc)
    elif report.get("replacement_entity_id"):
        # Explicit owner-declared relation between exact inventoried objects;
        # independently verify value storage. Never match names or content URLs.
        old = {str(link["entity_id"]) for link in links if link["evidence"] in ("VALUE", "IDENTIFIER")}
        row = next((r for r in compared["items"] if r.get("entity_id") == report["replacement_entity_id"]), None)
        origins = {(link["provider"], link["origin"], link["tenant"]) for link in links
                   if str(link["entity_id"]) in old}
        issued = (row or {}).get("issued") or {}
        run = MetadataStore(repo).run_detail(uuid.UUID(issued["run_id"]), limit=1)["run"] if issued.get("run_id") else {}
        if (row and report["replacement_entity_id"] not in old and issued.get("current_evidence")
                and run.get("status") == "COMPLETE" and str(run.get("id")) == str(issued.get("run_id"))
                and issued.get("state") == "ACTIVE" and not row.get("exposed")
                and (issued.get("provider"), issued.get("origin"), issued.get("tenant")) in origins):
            checks["replacement"] = _check("PASS", "OWNER_DECLARED_INVENTORY_REFERENCE", entity_id=row["entity_id"],
                                           run_id=issued.get("run_id"))
            if row["state"] == "MATCHED" and row["match_basis"] in ("VALUE_FINGERPRINT", "PROVIDER_DIGEST"):
                matched = [loc for loc in row["locations"] if current(loc)]
    if matched:
        loc = matched[0]
        checks["vault"] = _check("PASS", "IMMUTABLE_ROTATION_VERSION" if replacement_plan else "COMPATIBLE_VALUE_MATCH",
                                  connection_id=str(loc["connection_id"]), run_id=str(loc["run_id"]),
                                  reference=loc["reference"], version=loc.get("version"), at=str(loc["observed_at"]))
    return checks
