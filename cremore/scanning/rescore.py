"""Re-evaluate existing masked evidence; never download or verify credentials.

One installation-wide digest/cursor is durable. Each batch updates at most
``batch_size`` exposures, the finding rollup and its audit in one transaction.
Missing historical facts keep their prior score and explicitly need a rescan.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

from cremore.db.rescore_store import RescoreStore
from cremore.db.scan_store import stable_digest
from cremore.db.task_store import _clock
from cremore.detection.custom import rule_detection_policy
from cremore.domain.models import FindingEvent
from cremore.risk import model as risk
from cremore.risk.verification import latest_verification
from cremore.scanning.learned_fp import LearnedFPService


def _owner_account(credential) -> str | None:
    from cremore_aws_provider.aws_sessions import account_of_arn

    return account_of_arn(credential.principal_arn)


class RescoreService:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.store = RescoreStore(orchestrator.repo)

    def evaluation_digest(self, conn=None):
        orch = self.orchestrator
        svc = orch.learned_fp
        # privilege_provenance: evaluations without a recorded account are re-examined once.
        # occurrence_basis: occurrences count distinct physical locations, not per-connection rows.
        return stable_digest({"version": 1, "risk_policy": risk.POLICY_VERSION, "privilege_provenance": 1,
            "occurrence_basis": 1, "verification_basis": 3, "learned_fp_basis": 2,
            "rules": {key: {"severity": r.severity, "detection": rule_detection_policy(r)}
                      for key, r in orch._rules.items()},
            "learned_fp": None if svc is None else {"enabled": svc.enabled, "min_samples": svc.min_samples,
                "threshold": svc.threshold, "max_confidence": svc.max_confidence,
                "profiles": self.store.profile_revision(conn) if svc.enabled else None}})

    _evidence = staticmethod(LearnedFPService.evidence)

    def _score(self, orch, credential, exposure, occurrences, verification):
        det, resource = self._evidence(exposure, credential)
        metadata = exposure.metadata or {}
        catalog_id = metadata.get("catalog_id", "")
        reason = ""
        severity = exposure.severity
        if not catalog_id:
            reason = "MISSING_CATALOG_ID"
        elif catalog_id.startswith("custom-"):
            rule = orch._rules.get(catalog_id)
            if rule is None:
                reason = "RULE_NOT_ACTIVE"
            elif metadata.get("rule_detection_digest") != stable_digest(rule_detection_policy(rule)):
                reason = "RULE_DETECTION_CHANGED"
            elif not orch._rule_applies(rule, resource, det):
                reason = "RULE_NOT_APPLICABLE"
            else:
                severity = rule.severity
        else:
            try:
                facts = risk.facts_from_snapshot(metadata["risk_facts"])
                facts = verification.apply(facts, credential=credential)
                if facts.provider != (credential.provider or "") or facts.credential_type != credential.credential_type:
                    raise ValueError("identity differs")
                if facts.exposure.level not in {"public", "public_inherited", "internal"}:
                    raise ValueError("publicness unobserved")
                if facts.exposure.level != metadata.get("exposure"):
                    raise ValueError("stored publicness observations disagree")
                facts = replace(facts, exposure=replace(facts.exposure, occurrences=occurrences))
                privilege = facts.verification.aws_privilege
                if privilege is not None and privilege.evaluated and privilege.account_id != _owner_account(credential):
                    # Scored from an IAM simulation not proven to have run in the
                    # principal's account: keep the prior score, re-collect it.
                    reason = "PRIVILEGE_ACCOUNT_UNVERIFIED"
                else:
                    severity = risk.assess(facts, credential.fingerprint).level
            except (KeyError, TypeError, ValueError, AttributeError):
                reason = "MISSING_RISK_EVIDENCE"
        publicness = metadata.get("exposure")
        if publicness not in {"public", "public_inherited", "internal"}:
            reason = reason or "MISSING_PUBLICNESS"
            severity = exposure.severity
        rescore = {"status": "NEEDS_RESCAN" if reason else "SCORED_STORED_EVIDENCE",
                   "needs_rescan": bool(reason), "reason": reason,
                   "evidence_as_of": exposure.last_seen_at.isoformat() if exposure.last_seen_at else None}
        orch.repo.set_exposure_severity(exposure.id, severity, metadata={"rescore": rescore})
        hit = None
        # Unknown/public reachability and old verified observations are never
        # evidence that a credential is a safe fixture. No provider is called.
        if not reason and orch.learned_fp is not None:
            hit = orch.learned_fp.evaluate_stored(exposure, credential, verification)
        return reason, hit

    def run_batch(self, batch_size=100):
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 1000:
            raise ValueError("RESCORE_BATCH_SIZE_MUST_BE_1_TO_1000")
        self.orchestrator.refresh_rules()
        digest = self.evaluation_digest()
        result = {"processed": 0, "needs_rescan": 0, "done": False, "digest": digest}
        with self.store.transaction(digest) as (repo, state, conn):
            if state.get("done"):
                return {**result, "done": True}
            finding = self.store.finding(conn, state)
            if finding is None:
                if state.get("finding_id"):
                    after = state["finding_id"]
                    state.clear()
                    state["after_finding"] = after
                else:
                    state["done"] = result["done"] = True
                return result
            orch = self.orchestrator.using(repo)
            credential = repo.get_credential(finding.credential_id)
            if not state.get("finding_id"):
                state.update(finding_id=str(finding.id), started_at=_clock(conn).isoformat(),
                    credential_updated_at=str(credential.updated_at), fp_eligible=True, seen=0)
            rows = self.store.page(conn, finding.credential_id, state.get("after_exposure"), batch_size + 1)
            occurrences = repo.count_exposures_for_credential(finding.credential_id)
            verification = latest_verification(repo.exposures_for_credential(finding.credential_id), credential)
            for exposure in rows[:batch_size]:
                reason, hit = self._score(orch, credential, exposure, occurrences, verification)
                result["processed"] += 1
                result["needs_rescan"] += bool(reason)
                state["seen"] += 1
                state["after_exposure"] = str(exposure.id)
                if hit is None:
                    state["fp_eligible"] = False
                elif not state.get("fp_profile"):
                    state.update(fp_profile=str(hit[0].id), fp_exposure=str(exposure.id), fp_score=hit[1])
                elif state["fp_profile"] != str(hit[0].id):
                    # One audit cannot represent several independent profiles.
                    # Keep these findings OPEN for analyst review.
                    state["fp_eligible"] = False
                else:
                    state["fp_score"] = min(state["fp_score"], hit[1])
            updated = repo.repair_finding_rollup(finding.credential_id) or finding
            if rows:
                repo.record_finding_event(FindingEvent(finding_id=finding.id, actor="system:rescore",
                    event_type="RISK_REEVALUATED", from_status=finding.workflow_status,
                    to_status=updated.workflow_status,
                    note=f"STORED_EVIDENCE_ONLY processed={result['processed']} needs_rescan={result['needs_rescan']}"))
            if len(rows) <= batch_size:
                if not state["fp_eligible"] and orch.learned_fp is not None:
                    updated = orch.learned_fp.reopen_auto(updated)
                if (state["seen"] and state["fp_eligible"] and updated.workflow_status == "OPEN"
                        and state["credential_updated_at"] == str(credential.updated_at)
                        and digest == self.evaluation_digest(conn)
                        and not self.store.observations_changed(conn, finding.credential_id, state["started_at"])):
                    profile = repo.get_fp_profile_by_id(uuid.UUID(state["fp_profile"]))
                    svc = orch.learned_fp
                    if (profile is not None and profile.active and not profile.contradictions
                            and profile.sample_count >= svc.min_samples and profile.distinct_actors >= 2
                            and state["fp_score"] >= svc.threshold):
                        from types import SimpleNamespace
                        orch.learned_fp.auto_triage(updated, SimpleNamespace(id=state["fp_exposure"]),
                                                   profile, state["fp_score"])
                after = str(finding.id)
                state.clear()
                state["after_finding"] = after
        return result

    def rescore_all(self, batch_size=100):
        result = {"processed": 0, "needs_rescan": 0, "done": False}
        while not result["done"]:
            batch = self.run_batch(batch_size)
            result["processed"] += batch["processed"]
            result["needs_rescan"] += batch["needs_rescan"]
            result["done"] = batch["done"]
            result["digest"] = batch["digest"]
        return result
