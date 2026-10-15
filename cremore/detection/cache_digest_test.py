"""The passive engine digest describes bytes-to-masked-output, not location."""

import uuid
from dataclasses import asdict, replace

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.detection import DetectorInput, Engine, ResourceRef
from cremore.detection.custom import rule_definition
from cremore.detection.engine import EngineConfig
from cremore.detection.falsepositives import FPPolicy
from cremore.detection.verify import VerifierConfig
from cremore.domain.models import CustomRule
from cremore.risk import model as risk_model
from cremore.scanning.learned_fp import LearnedFPService
from cremore.scanning.orchestrator import Orchestrator


def sample_rule():
    return CustomRule(id=uuid.uuid4(), name="Synthetic digest", pattern=r"SYNTHETIC_DIGEST_[A-Z0-9]{8}", severity="HIGH")


def build(rule, config=None):
    return Engine(config or EngineConfig(), definitions=[rule_definition(rule)])


def test_same_bytes_have_identical_masked_engine_output_at_different_paths_and_sources():
    engine = build(sample_rule())
    data = b"token = SYNTHETIC_DIGEST_A1B2C3D4\n"
    original = engine.scan(DetectorInput(data, ResourceRef(source_type="github", resource="org/repo",
        location="tests/examples/dummy.txt", metadata={"exposure": "internal"})))
    moved = engine.scan(DetectorInput(data, ResourceRef(source_type="s3", resource="another-root",
        location="production/secrets.env", revision="different", metadata={"exposure": "public"})))
    assert original.complete and moved.complete and len(original) == 1
    assert [asdict(d) for d in original] == [asdict(d) for d in moved]
    assert "SYNTHETIC_DIGEST_A1B2C3D4" not in original[0].redacted_line


@pytest.mark.parametrize("config", [
    EngineConfig(max_detections=7),
    EngineConfig(fp_policy=FPPolicy(entropy=4.0)),
    EngineConfig(fp_policy=FPPolicy(retain=False)),
    EngineConfig(fingerprint_key=b"synthetic-installation-key"),
])
def test_actual_engine_input_policy_changes_invalidate_passive_output(config):
    rule = sample_rule()
    assert build(rule, config).detection_digest != build(rule).detection_digest


@pytest.mark.parametrize("change", [{"pattern": r"CHANGED_DIGEST_[A-Z0-9]{8}"}, {"keywords": ["synthetic"]}])
def test_pattern_or_keyword_changes_invalidate_passive_output(change):
    rule = sample_rule()
    assert build(rule.model_copy(update=change)).detection_digest != build(rule).detection_digest


def test_live_verifier_configuration_and_human_description_do_not_change_passive_digest():
    rule = sample_rule()
    baseline = build(rule).detection_digest
    live = EngineConfig(verify=VerifierConfig(enabled=True, timeout=2.0))
    assert build(rule, live).detection_digest == baseline
    assert build(rule.model_copy(update={"description": "New documentation", "severity": "LOW"})).detection_digest == baseline


@pytest.mark.parametrize("change", [
    {"scope_sources": ["github"]}, {"include_globs": ["src/*"]},
    {"exclude_globs": ["tests/*"]}, {"exclude_words": ["placeholder"]},
])
def test_post_engine_rule_scope_changes_root_detection_policy_but_not_output_cache(change):
    rule = sample_rule()
    repo = InMemoryRepository()
    orch = Orchestrator(repo, engine=build(rule))
    orch._rules = {f"custom-{rule.id}": rule}
    engine_digest, root_digest = orch.engine.detection_digest, orch.detection_policy_digest
    changed = rule.model_copy(update=change)
    orch._rules = {f"custom-{rule.id}": changed}
    orch.engine = build(changed)
    assert orch.engine.detection_digest == engine_digest
    assert orch.detection_policy_digest != root_digest


def test_severity_risk_and_learned_fp_policy_changes_do_not_invalidate_detection(monkeypatch):
    rule = sample_rule()
    repo = InMemoryRepository()
    learned = LearnedFPService(repo, enabled=True)
    orch = Orchestrator(repo, engine=build(rule), learned_fp=learned)
    orch._rules = {f"custom-{rule.id}": rule}
    engine_digest, root_digest = orch.engine.detection_digest, orch.detection_policy_digest
    rule.severity = "INFO"
    orch.engine = build(rule, replace(orch.config))
    learned.threshold = 0.99
    learned.min_samples = 10
    monkeypatch.setattr(risk_model, "POLICY_VERSION", "synthetic-next-risk-policy")
    assert orch.engine.detection_digest == engine_digest and orch.detection_policy_digest == root_digest
