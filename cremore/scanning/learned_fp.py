"""Learned false-positive profiles (docs/LEARNED_FALSE_POSITIVES.md).

An Analyst's ``FALSE_POSITIVE`` decision becomes one sample per exposure: the
redacted path and line-shape features of *where* the match sat — never the
match, identifier, hint or fingerprint. Samples aggregate into a profile per
(scope, source type, detector, credential type). An **active** profile (enough
independent confirmations, no contradiction) auto-triages a new detection whose
features are similar enough, by moving its finding to ``FALSE_POSITIVE`` with
the profile named in the resolution and an audit event. Reopening such a
finding is a contradiction: the profile is deactivated and its samples
dropped. Everything is deterministic and reproducible from stored data.
"""

from __future__ import annotations

import datetime as _dt
import re
import uuid
from collections import Counter

from cremore.detection import ResourceRef, SanitizedDetection
from cremore.domain.models import FindingEvent, FPProfile, FPSample
from cremore.risk import model as risk
from cremore.risk.verification import latest_verification

ACTOR = "system:learned-fp"
RESOLUTION_PREFIX = "LEARNED_FP_PROFILE "
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_SPLIT = re.compile(r"[/._\-\s]+")
_WORD = re.compile(r"[a-z][a-z_]{2,}")
_MASK = re.compile(r"[*•●x]{3,}|\[(?:redacted|masked)[^\]]*\]|<(?:redacted|masked)[^>]*>", re.IGNORECASE)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


# --- features ----------------------------------------------------------------


def path_features(location: str) -> set[str]:
    parts = [p for p in (location or "").lower().split("/") if p]
    if not parts:
        return set()
    name, dirs = parts[-1], parts[:-1]
    stem, ext = (name.rsplit(".", 1) + [""])[:2] if "." in name else (name, "")
    out = {f"ext:{ext}"} if ext else set()
    out.update(f"dir:{tok}" for d in dirs for tok in _SPLIT.split(d) if tok)
    out.update(f"name:{tok}" for tok in _SPLIT.split(stem) if tok)
    if len(dirs) > 0:
        out.add(f"depth:{min(len(dirs), 6)}")
    return out


def line_features(redacted_line: str) -> set[str]:
    """Shape of the already-masked line: its words and its character classes."""

    line = redacted_line or ""
    if not line:
        return set()
    # The masked value and anything glued to it (a format prefix such as
    # ``ghp_``) collapse to one marker: no part of the match is ever a feature.
    masked = re.sub(r"\S*#\S*", "#", _MASK.sub("#", line))
    words = {f"word:{w}" for w in _WORD.findall(masked.lower())}
    shape = re.sub(r"[A-Za-z]+", "a", re.sub(r"\d+", "9", masked))
    shape = re.sub(r"\s+", " ", shape).strip()[:40]
    return words | ({f"shape:{shape}"} if shape else set())


def features(location: str, redacted_line: str) -> set[str]:
    return path_features(location) | line_features(redacted_line)


def similarity(present: set[str], centroid: dict[str, float]) -> float:
    """Weighted Jaccard between a feature set (weight 1) and a centroid (0..1 weights)."""

    if not present or not centroid:
        return 0.0
    num = sum(min(1.0, float(w)) for f, w in centroid.items() if f in present)
    den = sum(max(1.0 if f in present else 0.0, float(w)) for f, w in centroid.items())
    den += sum(1.0 for f in present if f not in centroid)
    return round(num / den, 4) if den else 0.0


# --- service -----------------------------------------------------------------


def scope_of(exposure) -> tuple[str, uuid.UUID] | None:
    if exposure.source_connection_id is not None:
        return "source", exposure.source_connection_id
    if exposure.aws_account_id is not None:
        return "aws", exposure.aws_account_id
    return None


class LearnedFPService:
    # The policy is read from installation settings, briefly cached so a
    # per-finding check does not become a per-finding query. An Admin's change
    # therefore takes effect within seconds rather than at the next restart.
    _POLICY_TTL = 5.0

    def __init__(self, repo, settings=None, *, enabled: bool | None = None, min_samples: int | None = None,
                 threshold: float | None = None, max_confidence: str | None = None) -> None:
        self.repo = repo
        self.settings = settings
        # Explicit values pin this instance (tests, embedded use); None means
        # "whatever the installation currently says".
        self._fixed = {"enabled": enabled, "min_samples": min_samples,
                       "threshold": threshold, "max_confidence": max_confidence}
        self._cached: tuple[float, dict] | None = None

    def policy(self) -> dict:
        """The live auto-triage policy, with any constructor pins applied."""
        import time

        from cremore.scanning import learned_fp_settings

        now = time.monotonic()
        if self._cached is None or now - self._cached[0] >= self._POLICY_TTL:
            try:
                current = learned_fp_settings.config(self.settings, self.repo)
            except Exception:  # noqa: BLE001 -- policy never decides whether a scan runs
                current = {"enabled": False, **learned_fp_settings.DEFAULTS}
            self._cached = (now, current)
        current = dict(self._cached[1])
        for name, value in self._fixed.items():
            if value is not None:
                current[name] = value
        return current

    # Each reads the live policy; assigning one pins this instance to that value,
    # which is what an embedded caller or a test means by setting it.
    @property
    def enabled(self) -> bool:
        return bool(self.policy()["enabled"])

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._fixed["enabled"] = bool(value)

    @property
    def min_samples(self) -> int:
        from cremore.scanning.learned_fp_settings import MIN_SAMPLE_FLOOR

        return max(MIN_SAMPLE_FLOOR, int(self.policy()["min_samples"]))

    @min_samples.setter
    def min_samples(self, value: int) -> None:
        self._fixed["min_samples"] = int(value)

    @property
    def threshold(self) -> float:
        return float(self.policy()["threshold"])

    @threshold.setter
    def threshold(self, value: float) -> None:
        self._fixed["threshold"] = float(value)

    @property
    def max_confidence(self) -> str:
        return str(self.policy()["max_confidence"]).lower()

    @max_confidence.setter
    def max_confidence(self, value: str) -> None:
        self._fixed["max_confidence"] = str(value).lower()

    @staticmethod
    def _key(scope_kind: str, scope_id: uuid.UUID, source_type: str, detector_name: str, credential_type: str) -> dict:
        return {"scope_kind": scope_kind, "scope_id": scope_id, "source_type": source_type,
                "detector_name": detector_name, "credential_type": credential_type}

    # --- learning ------------------------------------------------------------

    def record_false_positive(self, finding, actor: str) -> int:
        """One sample per open exposure of a finding an Analyst marked false positive."""

        if not self.enabled:
            return 0
        credential = self.repo.get_credential(finding.credential_id)
        if credential is None:
            return 0
        recorded = 0
        for exposure in self.repo.exposures_for_credential(finding.credential_id):
            scope = scope_of(exposure)
            if exposure.status == "REMOVED" or scope is None:
                continue
            detector = (exposure.metadata or {}).get("detector_name") or credential.credential_type
            key = self._key(scope[0], scope[1], exposure.source_type, detector, credential.credential_type)
            self.repo.create_fp_sample(FPSample(
                **key, finding_id=finding.id, exposure_id=exposure.id, actor=actor,
                features=sorted(features(exposure.location, exposure.redacted_line or ""))))
            self.rebuild(key)
            recorded += 1
        return recorded

    def rebuild(self, key: dict) -> FPProfile:
        samples = self.repo.list_fp_samples(**key)
        existing = self.repo.get_fp_profile(**key)
        contradictions = existing.contradictions if existing else 0
        sample_count = len({(s.finding_id, s.actor) for s in samples})
        actors = len({s.actor for s in samples})
        counts = Counter(f for s in samples for f in set(s.features))
        centroid = {f: round(c / len(samples), 4) for f, c in counts.items()} if samples else {}
        return self.repo.save_fp_profile(FPProfile(
            **key, sample_count=sample_count, distinct_actors=actors, contradictions=contradictions,
            active=sample_count >= self.min_samples and actors >= 2 and contradictions == 0,
            threshold=self.threshold, min_samples=self.min_samples, centroid=centroid))

    def record_contradiction(self, finding) -> FPProfile | None:
        """An Analyst reopened an auto-triaged finding: the profile was too loose."""

        resolution = finding.resolution or ""
        if not resolution.startswith(RESOLUTION_PREFIX):
            return None
        try:
            profile = self.repo.get_fp_profile_by_id(uuid.UUID(resolution.split()[1]))
        except (IndexError, ValueError):
            return None
        if profile is None:
            return None
        key = self._key(profile.scope_kind, profile.scope_id, profile.source_type, profile.detector_name, profile.credential_type)
        self.repo.delete_fp_samples(**key)
        return self.repo.save_fp_profile(profile.model_copy(update={
            "sample_count": 0, "distinct_actors": 0, "centroid": {}, "active": False,
            "contradictions": profile.contradictions + 1}))

    def deactivate(self, profile_id: uuid.UUID) -> FPProfile | None:
        profile = self.repo.get_fp_profile_by_id(profile_id)
        if profile is None:
            return None
        return self.repo.save_fp_profile(profile.model_copy(update={"active": False, "contradictions": profile.contradictions + 1}))

    def reset(self, profile_id: uuid.UUID) -> FPProfile | None:
        profile = self.repo.get_fp_profile_by_id(profile_id)
        if profile is None:
            return None
        key = self._key(profile.scope_kind, profile.scope_id, profile.source_type, profile.detector_name, profile.credential_type)
        self.repo.delete_fp_samples(**key)
        return self.repo.save_fp_profile(profile.model_copy(update={
            "sample_count": 0, "distinct_actors": 0, "centroid": {}, "active": False, "contradictions": 0}))

    # --- application ---------------------------------------------------------

    @staticmethod
    def evidence(exposure, credential):
        metadata = exposure.metadata or {}
        resource = ResourceRef(source_type=exposure.source_type, resource=exposure.resource_name,
            location=exposure.location, metadata={"exposure": metadata.get("exposure", "unknown")})
        det = SanitizedDetection(detector_name=metadata.get("detector_name", ""),
            credential_type=credential.credential_type, fingerprint=credential.fingerprint,
            provider=credential.provider or "", confidence=metadata.get("detection_confidence", "high"),
            redacted_line=exposure.redacted_line or "", extra_safe_data=metadata)
        return det, resource

    def evaluate_stored(self, exposure, credential, verification):
        metadata = exposure.metadata or {}
        if (verification.risk_status in {risk.VALID, risk.RESTRICTED, risk.HISTORICAL_VALID, risk.HISTORICAL_RESTRICTED}
                or not metadata.get("detector_name") or not metadata.get("detection_confidence")
                or not exposure.redacted_line):
            return None
        det, resource = self.evidence(exposure, credential)
        return self.evaluate(det, resource, exposure)

    def apply_to_finding(self, finding):
        """Every active location must qualify under the same learned profile."""
        finding = finding.model_copy()
        credential = self.repo.get_credential(finding.credential_id)
        exposures = self.repo.exposures_for_credential(finding.credential_id)
        verification = latest_verification(exposures, credential)
        candidate, matched = None, None
        for exposure in exposures:
            if exposure.status == "REMOVED":
                continue
            hit = self.evaluate_stored(exposure, credential, verification)
            if hit is None or (candidate is not None and candidate[0].id != hit[0].id):
                return self.reopen_auto(finding)
            candidate = hit if candidate is None else (hit[0], min(candidate[1], hit[1]))
            matched = exposure
        if candidate is not None and finding.workflow_status == "OPEN":
            return self.auto_triage(finding, matched, *candidate)
        if (candidate is not None and (finding.resolution or "").startswith(RESOLUTION_PREFIX)
                and not finding.resolution.startswith(f"{RESOLUTION_PREFIX}{candidate[0].id} ")):
            return self.reopen_auto(finding)
        return finding if candidate is not None else self.reopen_auto(finding)

    def reopen_auto(self, finding):
        if finding.workflow_status != "FALSE_POSITIVE" or not (finding.resolution or "").startswith(RESOLUTION_PREFIX):
            return finding
        updated = self.repo.update_finding_status(finding.id, "OPEN", expected_updated_at=finding.updated_at,
                                                  expected_status=finding.workflow_status, expected_resolution=finding.resolution)
        if updated is None:
            return self.repo.get_finding(finding.id) or finding
        self.repo.record_finding_event(FindingEvent(
            finding_id=finding.id, actor=ACTOR, event_type="AUTO_FALSE_POSITIVE_REOPENED",
            from_status="FALSE_POSITIVE", to_status="OPEN", note="ACTIVE_EXPOSURES_NO_LONGER_QUALIFY"))
        return updated

    def evaluate(self, det, resource, exposure) -> tuple[FPProfile, float] | None:
        """(profile, similarity) when an active profile covers this detection, else None."""

        if not self.enabled:
            return None
        if CONFIDENCE_RANK.get(det.confidence, 2) > CONFIDENCE_RANK.get(self.max_confidence, 1):
            return None
        if det.extra_safe_data.get("verification_state") == "verified":
            return None
        if (resource.metadata or {}).get("exposure") != "internal":
            return None
        scope = scope_of(exposure)
        if scope is None:
            return None
        profile = self.repo.get_fp_profile(**self._key(scope[0], scope[1], resource.source_type, det.detector_name, det.credential_type))
        if (profile is None or not profile.active or profile.contradictions
                or profile.sample_count < self.min_samples or profile.distinct_actors < 2):
            return None
        score = similarity(features(resource.location, det.redacted_line), profile.centroid)
        # Profiles record the training settings for audit, not an operator
        # override. A runtime policy change must apply without new samples.
        return (profile, score) if score >= self.threshold else None

    def auto_triage(self, finding, exposure, profile: FPProfile, score: float):
        resolution = f"{RESOLUTION_PREFIX}{profile.id} similarity={score:.2f}"
        updated = self.repo.update_finding_status(finding.id, "FALSE_POSITIVE", resolution=resolution,
                                                  expected_updated_at=finding.updated_at,
                                                  expected_status=finding.workflow_status, expected_resolution=finding.resolution)
        if updated is None:
            return self.repo.get_finding(finding.id) or finding
        self.repo.record_finding_event(FindingEvent(
            finding_id=finding.id, actor=ACTOR, event_type="AUTO_FALSE_POSITIVE", from_status="OPEN",
            to_status="FALSE_POSITIVE", note=f"{resolution} exposure={exposure.id}"))
        return updated or finding

    # --- dashboard shape -----------------------------------------------------

    @staticmethod
    def public(profile: FPProfile, *, account_id: str, account_name: str) -> dict:
        return {"id": str(profile.id), "account_id": account_id, "account_name": account_name,
                "scope_kind": profile.scope_kind, "scope_id": str(profile.scope_id), "source_type": profile.source_type,
                "detector_name": profile.detector_name, "credential_type": profile.credential_type,
                "sample_count": profile.sample_count, "distinct_actors": profile.distinct_actors,
                "contradictions": profile.contradictions, "min_samples": profile.min_samples,
                "active": bool(profile.active), "threshold": float(profile.threshold), "model_type": "CONTEXT_SIMILARITY",
                "updated_at": (profile.updated_at or profile.created_at or _now()).isoformat()}
