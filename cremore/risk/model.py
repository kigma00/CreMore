"""Explainable, evidence-based risk model.

The score is the sum
of four axes — exploitability, credential impact, privilege scope and exposure —
each of which records the observation behind its points. Missing information is
scored at a small conservative floor (never a midpoint that would read as
measured risk, never zero that would read as safe) and is reported separately as
low confidence and missing evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields

POLICY_VERSION = "cremore-explainable-risk-v9"
SCHEMA_VERSION = 1

# Verification statuses.
VALID = "valid"
INVALID = "invalid"
EXPIRED = "expired"
HISTORICAL_VALID = "historical_valid"
HISTORICAL_RESTRICTED = "historical_restricted"
RESTRICTED = "restricted"
UNKNOWN = "unknown"
NOT_ATTEMPTED = "not_attempted"

# Exposure levels (source-neutral).
EXPOSURE_PUBLIC = "public"
EXPOSURE_PUBLIC_INHERITED = "public_inherited"
EXPOSURE_INTERNAL = "internal"
EXPOSURE_UNKNOWN = "unknown"

# Levels.
CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
CONF_HIGH, CONF_MEDIUM, CONF_LOW = "high", "medium", "low"

# Interpretation status for the privilege axis.
INTERP_DONE = "interpreted"
INTERP_INSUFFICIENT = "interpretation_structure_insufficient"
INTERP_MISSING_RULE = "interpreter_implementation_required"

MAX_EXPLOIT, MAX_IMPACT, MAX_PRIVILEGE, MAX_EXPOSURE = 35, 30, 20, 15

# Evidence-based exploitability: only a provider-confirmed status earns most of
# the axis; unattempted/inconclusive get a small non-zero floor.
_EXPLOIT_POINTS = {VALID: 35, RESTRICTED: 25, UNKNOWN: 5, NOT_ATTEMPTED: 2, INVALID: 0, EXPIRED: 0}
_EXPLOIT_POINTS.update({HISTORICAL_VALID: 35, HISTORICAL_RESTRICTED: 25})
_EXPLOIT_EXPLAIN = {
    VALID: "the provider confirmed the credential was usable at check time",
    RESTRICTED: "the provider accepted the request but policy or SSO restricts its use",
    UNKNOWN: "a transient or ambiguous response left current usability undetermined",
    NOT_ATTEMPTED: "verification was not performed, so current usability is unknown",
    INVALID: "the provider rejected the credential at check time",
    EXPIRED: "the expiration returned by the provider has elapsed",
    HISTORICAL_VALID: "last confirmed active; the latest inconclusive attempt does not erase that evidence",
    HISTORICAL_RESTRICTED: "last confirmed restricted; the latest inconclusive attempt does not erase that evidence",
}

_IMPACT_POINTS = {
    "AWS_ACCESS_KEY": 30, "AWS_SESSION_KEY": 25, "PRIVATE_KEY": 30,
    "AWS_ACCESS_KEY_ID": 5, "AWS_SECRET_ACCESS_KEY": 30,
    "GCP_SERVICE_ACCOUNT": 30, "GCP_API_KEY": 25, "AZURE": 30,
    "GITHUB_TOKEN": 25, "GITLAB_PERSONAL_ACCESS_TOKEN": 25,
    "STRIPE_SECRET_KEY": 25, "DB_CONNECTION_STRING": 25,
    "OPENAI_API_KEY": 20, "ANTHROPIC_API_KEY": 20, "SLACK_TOKEN": 20,
    "NOTION_TOKEN": 20, "JWT": 20, "SLACK_WEBHOOK": 15,
}
_DEFAULT_IMPACT = 20

# GitHub scope bands (from the platform's own scope table).
_GH_BROAD = {"repo", "admin:org", "admin:enterprise", "admin:repo_hook", "site_admin",
             "admin:gpg_key", "admin:public_key", "admin:org_hook", "delete_repo",
             "admin:ssh_signing_key", "workflow"}
_GH_WRITE = {"write:org", "write:packages", "write:discussion", "write:gpg_key",
             "write:public_key", "write:repo_hook"}
_GH_SENSITIVE = {"gist", "notifications", "user", "user:email", "read:org"}
_GH_LIMITED = {"read:user", "read:packages", "read:discussion", "read:gpg_key",
               "read:public_key", "read:repo_hook", "public_repo", "repo:status"}

_LEVELS = ((90, CRITICAL), (70, HIGH), (40, MEDIUM), (20, LOW), (0, INFO))


def level_for(score: int) -> str:
    for minimum, level in _LEVELS:
        if score >= minimum:
            return level
    return INFO


@dataclass
class AWSPrivilegeSignal:
    """A completed curated IAM SimulatePrincipalPolicy evaluation summary."""

    evaluated: bool = False
    allowed_risks: frozenset[str] = frozenset()
    allowed_count: int = 0
    actions_evaluated: int = 0
    # Account the simulation ran in; "" for evaluations recorded before this was tracked.
    account_id: str = ""


@dataclass
class Verification:
    status: str = NOT_ATTEMPTED
    owner_kind: str = ""
    owner_evidence_source: str = ""
    scopes: tuple[str, ...] = ()
    repository_count: int | None = None
    self_token: bool = False
    aws_privilege: AWSPrivilegeSignal | None = None


@dataclass
class ExposureFacts:
    level: str = EXPOSURE_UNKNOWN
    occurrences: int = 1


@dataclass
class DetectionFacts:
    location_mapped: bool = True
    stale: bool = False
    low_confidence_detector: bool = False


@dataclass
class Facts:
    provider: str = ""
    credential_type: str = ""
    verification: Verification = field(default_factory=Verification)
    exposure: ExposureFacts = field(default_factory=ExposureFacts)
    detection: DetectionFacts = field(default_factory=DetectionFacts)


def facts_from_snapshot(snapshot):
    """Read a complete saved model input; never infer missing historical facts."""
    for key, model in ((None, Facts), ("verification", Verification),
                       ("exposure", ExposureFacts), ("detection", DetectionFacts)):
        value = snapshot if key is None else snapshot[key]
        if not isinstance(value, dict) or any(f.name not in value for f in fields(model)):
            raise ValueError("incomplete stored risk facts")
    verification = dict(snapshot["verification"])
    verification["scopes"] = tuple(verification.get("scopes", ()))
    if verification.get("aws_privilege") is not None:
        signal = dict(verification["aws_privilege"])
        signal["allowed_risks"] = frozenset(signal.get("allowed_risks", ()))
        verification["aws_privilege"] = AWSPrivilegeSignal(**signal)
    return Facts(provider=snapshot["provider"], credential_type=snapshot["credential_type"],
        verification=Verification(**verification), exposure=ExposureFacts(**snapshot["exposure"]),
        detection=DetectionFacts(**snapshot["detection"]))


@dataclass
class Evidence:
    dimension: str
    points: int
    max_points: int
    reason_code: str
    explanation: str
    confirmed: bool = False
    interpretation_status: str = ""


@dataclass
class Override:
    reason_code: str
    explanation: str
    minimum_score: int = 0
    maximum_score: int = 0


@dataclass
class Result:
    score: int
    score_before_overrides: int
    level: str
    confidence: str
    confidence_reasons: list[str]
    evidence: list[Evidence]
    overrides: list[Override]
    missing_evidence: list[str]
    policy_version: str = POLICY_VERSION
    schema_version: int = SCHEMA_VERSION
    risk_id: str = ""


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def _exploitability(v: Verification) -> Evidence:
    status = v.status if v.status in _EXPLOIT_POINTS else NOT_ATTEMPTED
    return Evidence(
        dimension="exploitability",
        points=_EXPLOIT_POINTS[status],
        max_points=MAX_EXPLOIT,
        reason_code="verification_" + status,
        explanation=_EXPLOIT_EXPLAIN[status],
        confirmed=status in (VALID, INVALID, RESTRICTED, EXPIRED),
    )


def _impact(credential_type: str) -> Evidence:
    points = _IMPACT_POINTS.get(credential_type, _DEFAULT_IMPACT)
    return Evidence(
        dimension="credential_impact",
        points=points,
        max_points=MAX_IMPACT,
        reason_code="credential_type_" + credential_type.lower(),
        explanation={
            "AWS_ACCESS_KEY_ID": "an identifier alone cannot authenticate; retain it as an information-exposure observation",
            "AWS_SECRET_ACCESS_KEY": "secret material is exposed; a corresponding identifier and current usability are not established",
        }.get(credential_type, "credential type determines the impact band"),
        confirmed=credential_type in _IMPACT_POINTS,
    )


def _github_scope_points(scopes: tuple[str, ...]) -> tuple[int, str, str, bool]:
    points, reason, explanation = 5, "github_limited_scope", "reviewed limited or read scopes"
    uninterpreted = False
    for scope in scopes:
        s = scope.strip().lower()
        if s in _GH_BROAD:
            points, reason, explanation = MAX_PRIVILEGE, "github_broad_or_admin_scope", "a broad or administrative GitHub scope is present"
        elif s in _GH_WRITE:
            if points < 15:
                points, reason, explanation = 15, "github_write_scope", "a reviewed GitHub write scope is present"
        elif s in _GH_SENSITIVE:
            if points < 10:
                points, reason, explanation = 10, "github_sensitive_scope", "a sensitive GitHub feature scope is present"
        elif s not in _GH_LIMITED:
            uninterpreted = True
    if uninterpreted:
        return max(points, 5), "github_scope_semantics_incomplete", "one or more scopes have no reviewed interpretation; a low floor or higher known band applies", False
    return points, reason, explanation, True


def _aws_privilege_points(sig: AWSPrivilegeSignal) -> tuple[int, str, str]:
    r = sig.allowed_risks
    if "PRIVILEGE_ESCALATION" in r:
        return MAX_PRIVILEGE, "aws_iam_privilege_escalation_allowed", "the principal is allowed a privilege-escalation action"
    if r & {"DESTRUCTIVE", "SECRET_ACCESS", "CODE_MODIFICATION"}:
        return 18, "aws_iam_high_impact_actions_allowed", "the principal is allowed a destructive, secret-reading or code-changing action"
    if r & {"WRITE", "RESOURCE_CREATION", "EXECUTION"}:
        return 15, "aws_iam_write_actions_allowed", "the principal is allowed a write, resource-creation or execution action"
    if "READ" in r:
        return 10, "aws_iam_read_only_actions_allowed", "the principal is allowed only read actions among the curated set"
    return 5, "aws_iam_no_high_impact_actions_allowed", "no curated high-impact action was allowed; a floor applies, not proof of no access"


def _privilege(provider: str, v: Verification) -> tuple[Evidence, list[str]]:
    if provider == "aws" and v.owner_kind == "root":
        return (
            Evidence("privilege_scope", MAX_PRIVILEGE, MAX_PRIVILEGE, "aws_root_principal",
                     "the credential authenticates as the AWS account root principal",
                     confirmed=True, interpretation_status=INTERP_DONE),
            [],
        )
    if provider == "aws" and v.aws_privilege and v.aws_privilege.evaluated:
        points, reason, explanation = _aws_privilege_points(v.aws_privilege)
        return (
            Evidence("privilege_scope", points, MAX_PRIVILEGE, reason, explanation,
                     confirmed=True, interpretation_status=INTERP_DONE),
            [],
        )
    if v.scopes:
        if provider == "github":
            points, reason, explanation, interpreted = _github_scope_points(v.scopes)
            ev = Evidence("privilege_scope", points, MAX_PRIVILEGE, reason, explanation,
                          confirmed=interpreted,
                          interpretation_status=INTERP_DONE if interpreted else INTERP_MISSING_RULE)
            return (ev, [] if interpreted else ["provider_permission_interpreter_implementation_required"])
        return (
            Evidence("privilege_scope", 5, MAX_PRIVILEGE, "provider_scope_semantics_not_implemented",
                     "scopes were observed but no rule reads this provider's permissions yet; a low floor applies",
                     confirmed=False, interpretation_status=INTERP_MISSING_RULE),
            ["provider_permission_interpreter_implementation_required"],
        )
    return (
        Evidence("privilege_scope", 2, MAX_PRIVILEGE, "privilege_scope_unknown",
                 "permissions were not observed; a small conservative floor applies rather than an assumed level",
                 confirmed=False, interpretation_status=INTERP_INSUFFICIENT),
        ["provider_permission_interpretation_structure_insufficient"],
    )


def _exposure(e: ExposureFacts) -> tuple[Evidence, list[str]]:
    level = e.level or EXPOSURE_UNKNOWN
    if level in (EXPOSURE_PUBLIC, EXPOSURE_PUBLIC_INHERITED):
        points, reason, explanation = MAX_EXPOSURE, ("direct_public_exposure" if level == EXPOSURE_PUBLIC else "inherited_public_exposure"), "the location is publicly reachable"
    elif level == EXPOSURE_INTERNAL:
        points, reason, explanation = 5, "internal_plaintext_exposure", "the credential is stored in plaintext in an internal location"
    else:
        level, points, reason, explanation = EXPOSURE_UNKNOWN, 2, "exposure_unknown", "the reachability could not be determined; a small floor applies"
    bonus = _clamp(e.occurrences - 1, 0, 5)
    if bonus and points < MAX_EXPOSURE:
        points = _clamp(points + bonus, 0, MAX_EXPOSURE)
        reason += "_multiple_occurrences"
    ev = Evidence("exposure", points, MAX_EXPOSURE, reason, explanation,
                  confirmed=level != EXPOSURE_UNKNOWN)
    return (ev, ["exposure_not_observed"] if level == EXPOSURE_UNKNOWN else [])


def _lower(current: str, floor: str) -> str:
    order = {CONF_HIGH: 3, CONF_MEDIUM: 2, CONF_LOW: 1}
    return current if order[current] <= order[floor] else floor


def _confidence(f: Facts, privilege_known: bool) -> tuple[str, list[str]]:
    confidence = CONF_HIGH
    reasons: list[str] = []
    if f.detection.low_confidence_detector:
        confidence = _lower(confidence, CONF_MEDIUM)
        reasons.append("detection_confidence_not_high")
    if not f.detection.location_mapped:
        confidence = _lower(confidence, CONF_MEDIUM)
        reasons.append("location_not_fully_mapped")
    if f.verification.status in (NOT_ATTEMPTED, UNKNOWN, HISTORICAL_VALID, HISTORICAL_RESTRICTED):
        confidence = CONF_LOW
        reasons.append("verification_not_conclusive")
    if not privilege_known:
        confidence = _lower(confidence, CONF_MEDIUM)
        reasons.append("permission_scope_unknown")
    if f.exposure.level in (EXPOSURE_UNKNOWN, ""):
        confidence = CONF_LOW
        reasons.append("exposure_unknown")
    if f.detection.stale:
        confidence = CONF_LOW
        reasons.append("stale_detection")
    return confidence, sorted(set(reasons))


def _apply_overrides(score: int, f: Facts) -> tuple[int, list[Override]]:
    overrides: list[Override] = []
    status = f.verification.status
    public = f.exposure.level in (EXPOSURE_PUBLIC, EXPOSURE_PUBLIC_INHERITED)
    if status in (VALID, HISTORICAL_VALID) and public:
        score = max(score, 90)
        overrides.append(Override("valid_public_credential_minimum_critical",
                                  "a working credential exposed publicly is treated as at least CRITICAL", minimum_score=90))
    if status in (VALID, HISTORICAL_VALID) and f.provider == "aws" and f.verification.owner_kind == "root":
        score = max(score, 90)
        overrides.append(Override("valid_aws_root_minimum_critical",
                                  "a working AWS root credential is treated as at least CRITICAL", minimum_score=90))
    if status in (VALID, HISTORICAL_VALID) and f.verification.self_token:
        score = max(score, 90)
        overrides.append(Override("valid_scanner_self_token_minimum_critical",
                                  "a working credential for the scanner's own source is treated as at least CRITICAL", minimum_score=90))
    if status in (INVALID, EXPIRED) and score > 69:
        score = 69
        overrides.append(Override("invalid_credential_maximum_medium",
                                  "a credential the provider currently rejects does not exceed MEDIUM", maximum_score=69))
    return score, overrides


def _risk_id(fingerprint: str) -> str:
    digest = hashlib.sha256(("cremore-risk-v1\x00" + fingerprint).encode()).hexdigest()
    return "risk:" + digest[:32]


def assess(facts: Facts, fingerprint: str = "", *, provider_quarantine: bool = False) -> Result:
    """Score one exposure.

    ``provider_quarantine`` is retained for caller compatibility but ignored.
    An IAM policy attachment does not identify who attached it or which key, if
    any, was exposed. Only the observed exposure and verification facts score.
    """

    exploit = _exploitability(facts.verification)
    impact = _impact(facts.credential_type)
    privilege, privilege_missing = _privilege(facts.provider, facts.verification)
    exposure, exposure_missing = _exposure(facts.exposure)

    evidence = [exploit, impact, privilege, exposure]
    raw = sum(e.points for e in evidence)
    score = _clamp(raw, 0, 100)
    score, overrides = _apply_overrides(score, facts)

    missing = list(privilege_missing) + list(exposure_missing)
    if facts.credential_type == "AWS_ACCESS_KEY_ID":
        missing.append("aws_secret_component_not_observed")
    elif facts.credential_type == "AWS_SECRET_ACCESS_KEY":
        missing.append("aws_identifier_not_observed")
    if facts.verification.status in (NOT_ATTEMPTED, UNKNOWN, HISTORICAL_VALID, HISTORICAL_RESTRICTED):
        missing.append("provider_validity_not_confirmed")
    missing = sorted(set(missing))

    confidence, reasons = _confidence(facts, len(privilege_missing) == 0)

    return Result(
        score=score,
        score_before_overrides=raw,
        level=level_for(score),
        confidence=confidence,
        confidence_reasons=reasons,
        evidence=evidence,
        overrides=overrides,
        missing_evidence=missing,
        risk_id=_risk_id(fingerprint) if fingerprint else "",
    )
