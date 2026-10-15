"""Scan orchestration: detect, score, persist.

Ties the detection engine to the risk model and the repository. For each
sanitized finding it upserts the credential identity, scores the exposure with
the risk model, records the exposure at its location, and rolls the credential
up into a finding at the highest severity seen. Deduplication is by fingerprint
throughout, so re-scanning the same content updates rather than duplicates.

Operator rules (``CustomRule``) run beside the built-in catalog: the engine is
rebuilt when the enabled rule set changes, a rule's scope filters are applied
per resource, and its matches carry the operator's severity rather than an
evidence-based score.

A *complete* rescan of a connection retires the exposures it no longer sees
(``reconcile_connection``); a retired exposure that reappears reopens its
finding. Partial or failed runs never retire anything.
"""

from __future__ import annotations

import fnmatch
import logging
import time
import uuid
from collections.abc import Callable
from copy import copy
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from cremore import risk
from cremore.db.repository import Repository
from cremore.db.scan_store import stable_digest
from cremore.detection import DetectorInput, Engine, ResourceRef, SanitizedDetection
from cremore.detection.catalog import builtin_definitions
from cremore.detection.custom import excluded_by_words, rule_definition, rule_detection_policy
from cremore.detection.engine import EngineConfig
from cremore.domain.mapping import credential_from_detection, exposure_from_detection
from cremore.risk.model import AWSPrivilegeSignal
from cremore.risk.verification import RISK_STATUS, latest_verification
from cremore.scanning.extraction import cache_digest

logger = logging.getLogger("cremore.scanning")

# Given a principal ARN, return an AWS privilege signal (IAM potential-access),
# or None when unavailable. Injected so the scan path can enrich AWS findings.
PotentialAccessProvider = Callable[[str], "AWSPrivilegeSignal | None"]
# Returns the operator rules (enabled or not); the orchestrator keeps the
# enabled ones compiled into the engine.
RuleProvider = Callable[[], list]

REMOVED_BY_RESCAN = "REMOVED_BY_RESCAN"


def scan_start(repo, scan_id=None):
    """A scan cannot confirm an owner's reply that arrived after it started."""
    job = repo.get_job(scan_id) if scan_id is not None else None
    return (job.started_at or job.created_at) if job is not None else datetime.now(UTC)


@dataclass
class ScanResourceResult:
    detections: int = 0
    credentials: int = 0
    exposures: int = 0
    findings: list = field(default_factory=list)
    exposure_ids: list = field(default_factory=list)
    complete: bool = True
    timings: dict = field(default_factory=dict)


class Orchestrator:
    def __init__(self, repo: Repository, engine: Engine | None = None,
                 config: EngineConfig | None = None,
                 potential_access_provider: PotentialAccessProvider | None = None,
                 rule_provider: RuleProvider | None = None,
                 learned_fp=None) -> None:
        self.repo = repo
        self.config = config or EngineConfig()
        self.engine = engine or Engine(self.config)
        self.potential_access_provider = potential_access_provider
        self.rule_provider = rule_provider
        # cremore.scanning.learned_fp.LearnedFPService (None = never auto-triage).
        self.learned_fp = learned_fp
        self._rules: dict[str, object] = {}  # catalog id -> CustomRule
        self._rule_signature: tuple | None = None
        # Built-in detectors an administrator turned off (cremore.detection.switches).
        self._disabled_builtins: frozenset[str] = frozenset()

    def using(self, repo):
        """Bind persistence to one fenced transaction, keeping the compiled engine."""
        if repo is self.repo:
            return self
        bound = copy(self)
        bound.repo = repo
        if self.learned_fp is not None:
            bound.learned_fp = copy(self.learned_fp)
            bound.learned_fp.repo = repo
        return bound

    @property
    def detection_policy_digest(self):
        # Path/context filters discard matches, so broadening them requires a
        # resweep. They do not invalidate the pre-filter engine-output cache.
        return stable_digest([cache_digest(self.engine.detection_digest), {
            name: rule_detection_policy(rule) for name, rule in self._rules.items()}])

    @property
    def coverage_policy_digest(self):
        """The fingerprint contract's policy (cremore.coverage.models.Contract): what an exposure's value is comparable
        with a vault's under. Document extraction decides what is found, not how a found value is fingerprinted, so
        unlike detection_policy_digest it leaves this alone; the customer-side collector computes the same."""
        return stable_digest([self.engine.detection_digest, {
            name: rule_detection_policy(rule) for name, rule in self._rules.items()}])

    @property
    def detection_evidence(self):
        """Record at execution time; a later release cannot identify an old run."""
        from cremore.detection import NAME, VERSION

        return {"detection_policy_digest": self.detection_policy_digest,
                "engine_name": NAME, "engine_version": VERSION}

    _rule_detection_policy = staticmethod(rule_detection_policy)  # compatibility

    # --- operator rules -----------------------------------------------------

    def refresh_rules(self) -> int:
        """Recompile the engine when the enabled operator rules or the built-in
        detectors an administrator turned off changed.

        Cheap when nothing changed (two repository reads, no compilation). Returns
        the number of rules currently compiled in.
        """

        if self.rule_provider is None:
            return 0
        from cremore.detection import switches

        rules = [r for r in self.rule_provider() if r.enabled]
        disabled = switches.disabled(self.repo)
        signature = (tuple(sorted((str(r.id), r.revision) for r in rules)), tuple(sorted(disabled)))
        if signature == self._rule_signature:
            return len(self._rules)
        definitions, index = [], {}
        for rule in rules:
            try:
                definition = rule_definition(rule)
            except Exception as exc:  # noqa: BLE001 -- a persisted invalid rule must not crash all scan workers
                logger.warning("custom rule %s skipped: %s", rule.id, type(exc).__name__)
                continue
            definitions.append(definition)
            index[definition.catalog.id] = rule
        builtins = [definition for definition in builtin_definitions() if definition.catalog.id not in disabled]
        self.engine = Engine(self.config, definitions=builtins + definitions)
        self._rules, self._rule_signature, self._disabled_builtins = index, signature, disabled
        return len(index)

    @staticmethod
    def _rule_applies(rule, resource: ResourceRef, det: SanitizedDetection) -> bool:
        if rule.scope_sources and resource.source_type not in rule.scope_sources:
            return False
        location = resource.location or ""
        if rule.include_globs and not any(fnmatch.fnmatch(location, g) for g in rule.include_globs):
            return False
        if any(fnmatch.fnmatch(location, g) for g in rule.exclude_globs):
            return False
        return not excluded_by_words(rule, det.redacted_line)

    # --- scanning -----------------------------------------------------------

    def scan_resource(
        self,
        data: bytes,
        resource: ResourceRef,
        *,
        source_connection_id: uuid.UUID | None = None,
        scan_id: uuid.UUID | None = None,
        verify: bool | None = None,
        verify_config=None,
        detections: list[SanitizedDetection] | None = None,
        scan_started_at: datetime | None = None,
    ) -> ScanResourceResult:
        scan_started_at = scan_started_at or scan_start(self.repo, scan_id)
        start = time.monotonic()
        if detections is None:
            detections = self.engine.scan(DetectorInput(data=data, resource=resource, verify=verify, verify_config=verify_config))
        engine_seconds = time.monotonic() - start
        result = ScanResourceResult(detections=len(detections),
                                    complete=getattr(detections, "complete", True))
        persisted_at = time.monotonic()
        touched_findings: dict[uuid.UUID, object] = {}
        coverage_policy = self.coverage_policy_digest

        for det in detections:
            rule = self._rules.get(det.extra_safe_data.get("catalog_id", "")) if self._rules else None
            if rule is not None and not self._rule_applies(rule, resource, det):
                result.detections -= 1
                continue
            # Copy: cached pre-filter output must remain independent of path rules.
            det = copy(det)
            det.extra_safe_data = dict(det.extra_safe_data)
            det.extra_safe_data["coverage_engine_digest"] = self.engine.detection_digest
            det.extra_safe_data["coverage_policy_digest"] = coverage_policy
            if rule is not None:
                det.extra_safe_data["rule_detection_digest"] = stable_digest(rule_detection_policy(rule))
            credential = self.repo.upsert_credential(credential_from_detection(det))
            result.credentials += 1

            # Record the exposure first (deduped), then count distinct locations
            # so a re-scan of the same location never inflates the occurrence count.
            exposure = self.repo.upsert_exposure(
                exposure_from_detection(
                    det, resource, credential.id,
                    source_connection_id=source_connection_id,
                    scan_id=scan_id,
                )
            )
            result.exposures += 1
            result.exposure_ids.append(exposure.id)
            occurrences = self.repo.count_exposures_for_credential(credential.id)

            if rule is not None:
                # An operator rule's severity is a declaration, not evidence.
                level = rule.severity
                self.repo.set_exposure_severity(exposure.id, level)
            else:
                # Persisted checks survive passive scans, with their original
                # times. Score that same saved evidence used by the dashboard.
                facts = self._facts(det, resource, occurrences)
                verification = latest_verification(self.repo.exposures_for_credential(credential.id), credential)
                facts = verification.apply(facts, credential=credential)
                level = risk.assess(facts, det.fingerprint).level
                safe_facts = asdict(facts)
                if facts.verification.aws_privilege is not None:
                    safe_facts["verification"]["aws_privilege"]["allowed_risks"] = sorted(facts.verification.aws_privilege.allowed_risks)
                self.repo.set_exposure_severity(exposure.id, level,
                    metadata={**exposure.metadata, "risk_facts": safe_facts})

            # The finding takes the highest severity across the credential's
            # exposures, and points at that most-severe exposure.
            finding = self.repo.get_finding_for_credential(credential.id)
            if finding is None:
                best = self._best_exposure(credential.id)
                finding = self.repo.upsert_finding(credential.id, best[1], best[0])
            finding = self.repo.repair_finding_rollup(credential.id) or finding
            touched_findings[credential.id] = finding

        result.findings = [self.learned_fp.apply_to_finding(f) if self.learned_fp is not None else f
                           for f in touched_findings.values()]
        for finding in result.findings:
            # A detected credential is positive evidence even in a truncated
            # object. Completeness is required only when proving absence.
            self.observe_response(finding, scan_id=scan_id, scan_started_at=scan_started_at)
        result.timings = {"engine_seconds": engine_seconds,
                          "persistence_seconds": time.monotonic() - persisted_at}
        return result

    def reconcile_connection(self, connection_id: uuid.UUID, seen_exposure_ids, *, seen_locations=None,
                             scan_id=None, scan_started_at=None) -> int:
        """After a *complete* run of a connection, retire exposures it did not see.

        Returns the number of exposures marked REMOVED. Location removal is not
        credential revocation. Repair all related rollups, including old crashes.
        """

        seen = set(seen_exposure_ids)
        removed = 0
        credentials: set[uuid.UUID] = set()
        confirmed_absent: set[uuid.UUID] = set()
        for exposure in self.repo.exposures_for_connection(connection_id):
            credentials.add(exposure.credential_id)
            if exposure.id not in seen:
                if seen_locations is not None and (exposure.source_type, exposure.resource_name, exposure.location) in seen_locations:
                    # An existing object is reconciled by its complete content,
                    # not by which detectors are currently enabled on this run.
                    continue
                confirmed_absent.add(exposure.credential_id)
                if exposure.status != "REMOVED":
                    self.repo.mark_exposure_removed(exposure.id)
                    removed += 1
        for credential_id in credentials:
            finding = self.repo.repair_finding_rollup(credential_id)
            # Positive evidence is recorded by scan_resource. Merely preserving
            # an unread/unsupported object's old exposure is not a fresh sighting.
            if finding and finding.all_locations_removed and credential_id in confirmed_absent:
                self.observe_response(finding, scan_id=scan_id, scan_started_at=scan_started_at)
        return removed

    def reconcile_resource(self, connection_id, resource, seen_exposure_ids, *, complete=True,
                           scan_id=None, scan_started_at=None):
        """Only a comparable, fully read object proves its old matches absent."""
        if not complete or connection_id is None:
            return 0
        seen = set(seen_exposure_ids)
        affected = set()
        removed = 0
        query = getattr(self.repo, "exposures_for_resource", None)
        if resource.source_type == "notion" and resource.metadata.get("page_id"):
            # A page's title and URL slug can change without changing its content
            # identity. The indexed page root retains those earlier locations.
            rows = self.repo.exposures_for_root(connection_id, resource.source_type,
                resource.resource or resource.location, page_id=resource.metadata["page_id"])
        else:
            rows = query(connection_id, resource.source_type, resource.resource or resource.location,
                         resource.location, page_id=resource.metadata.get("page_id"),
                         epoch=resource.metadata.get("collector_epoch")) if query else self.repo.exposures_for_connection(connection_id)
        for exposure in rows:
            if exposure.source_type != resource.source_type:
                continue
            if resource.source_type == "notion":
                epoch = resource.metadata.get("collector_epoch")
                if (not epoch or exposure.metadata.get("collector_epoch") != epoch
                        or exposure.metadata.get("page_id") != resource.metadata.get("page_id")):
                    continue
            elif (exposure.resource_name != (resource.resource or resource.location)
                  or exposure.location != resource.location):
                continue
            catalog_id = exposure.metadata.get("catalog_id", "")
            if catalog_id in self._disabled_builtins:
                continue  # a turned-off detector is not evidence of removal
            if catalog_id.startswith("custom-"):
                rule = self._rules.get(catalog_id)
                if (rule is None or exposure.metadata.get("rule_detection_digest") !=
                        stable_digest(rule_detection_policy(rule))):
                    # A disabled/narrowed detector is not evidence of removal.
                    continue
            affected.add(exposure.credential_id)
            if exposure.id not in seen and exposure.status != "REMOVED":
                self.repo.mark_exposure_removed(exposure.id)
                removed += 1
        for credential_id in affected:
            finding = self.repo.repair_finding_rollup(credential_id)
            # Another location may still have an old OPEN row. This clean object
            # supplies absence evidence only, not a fresh positive for that row.
            if finding and finding.all_locations_removed:
                self.observe_response(finding, scan_id=scan_id, scan_started_at=scan_started_at)
        return removed

    def observe_response(self, finding, *, scan_id=None, scan_started_at=None, authoritative=True):
        """Record actual scan evidence in the caller's fenced transaction, without delivery I/O."""
        if finding is None:
            return
        from cremore.governance.response import observe_scan

        observe_scan(self.repo, finding.id, removed=finding.all_locations_removed, observed_at=datetime.now(UTC),
                     scan_started_at=scan_started_at, authoritative=authoritative and scan_started_at is not None,
                     scan_id=str(scan_id) if scan_id is not None else None)

    def _best_exposure(self, credential_id: uuid.UUID) -> tuple[str, uuid.UUID | None]:
        finding = self.repo.get_finding_for_credential(credential_id)
        return self.repo.best_exposure_for_credential(
            credential_id, preferred_id=finding.primary_exposure_id if finding else None)

    def _facts(self, det: SanitizedDetection, resource: ResourceRef, occurrences: int) -> risk.Facts:
        extra = det.extra_safe_data
        status = RISK_STATUS.get(extra.get("verification_state", "not_attempted"), risk.model.UNKNOWN)
        scopes = tuple(
            s.strip() for s in extra.get("verification_scopes", "").split(",") if s.strip()
        )
        arn = extra.get("verification_arn", "")
        owner_kind = "root" if arn.endswith(":root") else ""

        # For an AWS principal, enrich the privilege axis with a curated IAM
        # potential-access evaluation when a provider is wired in.
        aws_privilege = None
        if det.provider == "aws" and arn and self.potential_access_provider is not None:
            aws_privilege = self.potential_access_provider(arn)

        exposure_level = resource.metadata.get("exposure", risk.model.EXPOSURE_UNKNOWN)
        return risk.Facts(
            provider=det.provider,
            credential_type=det.credential_type,
            verification=risk.Verification(
                status=status,
                owner_kind=owner_kind,
                scopes=scopes,
                aws_privilege=aws_privilege,
            ),
            exposure=risk.ExposureFacts(level=exposure_level, occurrences=occurrences),
            detection=risk.DetectionFacts(
                location_mapped=det.line_number is not None,
                # A match that is not a self-identifying format is treated as
                # low-confidence evidence until the provider confirms it.
                low_confidence_detector=det.confidence != "high",
            ),
        )
