"""Learned false-positive profiles: features, similarity, learning, auto-triage."""

import uuid

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.detection import ResourceRef
from cremore.scanning import Orchestrator
from cremore.scanning.learned_fp import (
    ACTOR,
    RESOLUTION_PREFIX,
    LearnedFPService,
    features,
    line_features,
    path_features,
    similarity,
)

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
CONN = uuid.uuid4()


def test_features_are_redacted_shape_only():
    p = path_features("tests/fixtures/github/sample_token.py")
    assert {"ext:py", "dir:tests", "dir:fixtures", "dir:github", "name:sample", "name:token", "depth:3"} <= p
    line = line_features("token = ghp_****************************")
    assert "word:token" in line and any(f.startswith("shape:") for f in line)
    assert not any("ghp" in f and f.startswith("word:") for f in line)  # the masked value never becomes a word
    assert features("", "") == set()


def test_similarity_is_weighted_jaccard():
    centroid = {"ext:py": 1.0, "dir:tests": 1.0, "word:token": 0.5}
    assert similarity({"ext:py", "dir:tests", "word:token"}, centroid) == 0.8333  # 2.5 / 3
    assert similarity({"ext:py", "dir:tests"}, centroid) == 0.8  # 2 / 2.5
    assert similarity({"ext:py", "dir:tests"}, {"ext:py": 1.0, "dir:tests": 1.0}) == 1.0
    assert similarity({"ext:go"}, centroid) == 0.0 and similarity(set(), centroid) == 0.0


def _tok(i: int) -> str:
    return GH[:-2] + f"{i:02d}"  # a distinct token (credential, finding) per case


def _scan(orch, location, *, case, connection=CONN, exposure="internal"):
    return orch.scan_resource(f"token = {_tok(case)}\n".encode(),
                              ResourceRef(source_type="github", resource="example-org/app", location=location,
                                          metadata={"exposure": exposure}),
                              source_connection_id=connection)


def _confirm(repo, svc, finding, actor):
    repo.update_finding_status(finding.id, "FALSE_POSITIVE")
    return svc.record_false_positive(finding, actor)


def test_profiles_learn_from_independent_confirmations_and_auto_triage_repeats():
    repo = InMemoryRepository()
    svc = LearnedFPService(repo, enabled=True, min_samples=3, threshold=0.6, max_confidence="high")
    orch = Orchestrator(repo, learned_fp=svc)
    # three fixture matches, each confirmed false positive (two distinct analysts)
    for i, actor in enumerate(("alice", "bob", "alice")):
        result = _scan(orch, f"tests/fixtures/case{i}/sample.py", case=i)
        assert _confirm(repo, svc, result.findings[0], actor) == 1
    profiles = repo.list_fp_profiles()
    assert len(profiles) == 1
    p = profiles[0]
    assert p.scope_kind == "source" and p.scope_id == CONN and p.detector_name and p.credential_type
    assert p.sample_count == 3 and p.distinct_actors == 2 and p.active and p.centroid["dir:tests"] == 1.0
    assert not any(":ghp" in f or "ab3de5" in f.lower() for f in p.centroid)  # nothing of the token is learned
    # a repeat of the same context is auto-triaged with an audit trail...
    auto = _scan(orch, "tests/fixtures/case9/sample.py", case=10).findings[0]
    assert auto.workflow_status == "FALSE_POSITIVE" and auto.resolution.startswith(f"{RESOLUTION_PREFIX}{p.id}")
    event = repo.list_finding_events(auto.id)[-1]
    assert event.actor == ACTOR and event.event_type == "AUTO_FALSE_POSITIVE" and str(p.id) in event.note
    # ...but a different context, a public exposure or another scope is not
    assert _scan(orch, "src/main/config.go", case=11).findings[0].workflow_status == "OPEN"
    assert _scan(orch, "tests/fixtures/case9/sample.py", case=12, exposure="public").findings[0].workflow_status == "OPEN"
    assert _scan(orch, "tests/fixtures/case9/sample.py", case=13, connection=uuid.uuid4()).findings[0].workflow_status == "OPEN"
    # reopening an auto-triaged finding contradicts the profile: deactivated, relearned from scratch
    contradicted = svc.record_contradiction(auto)
    assert contradicted.id == p.id and not contradicted.active and contradicted.contradictions == 1 and contradicted.sample_count == 0
    assert _scan(orch, "tests/fixtures/case9/sample.py", case=14).findings[0].workflow_status == "OPEN"


def test_high_confidence_verified_or_disabled_never_auto_triages():
    repo = InMemoryRepository()
    svc = LearnedFPService(repo, enabled=True, min_samples=1, threshold=0.5, max_confidence="medium")
    orch = Orchestrator(repo, learned_fp=svc)
    finding = _scan(orch, "tests/fixtures/a.py", case=0).findings[0]
    _confirm(repo, svc, finding, "alice")
    _confirm(repo, svc, finding, "bob")
    assert repo.list_fp_profiles()[0].active
    # a GitHub PAT is a high-confidence format: above the configured ceiling
    assert _scan(orch, "tests/fixtures/b.py", case=1).findings[0].workflow_status == "OPEN"
    off = Orchestrator(repo, learned_fp=LearnedFPService(repo, enabled=False))
    assert _scan(off, "tests/fixtures/b.py", case=2).findings[0].workflow_status == "OPEN"
    assert LearnedFPService(repo, enabled=False).record_false_positive(finding, "x") == 0


def test_current_settings_apply_to_existing_profiles_and_never_reactivate_disabled():
    from cremore.detection import SanitizedDetection
    from cremore.domain.models import Exposure, FPProfile

    repo = InMemoryRepository()
    svc = LearnedFPService(repo, enabled=True, min_samples=3, threshold=0.9, max_confidence="high")
    resource = ResourceRef(source_type="github", location="tests/example.py", metadata={"exposure": "internal"})
    det = SanitizedDetection(detector_name="test", credential_type="TEST", fingerprint="safe", redacted_line="token = ***")
    exposure = Exposure(credential_id=uuid.uuid4(), source_type="github", resource_name="repo",
                        location=resource.location, source_connection_id=CONN)
    centroid = {f: 0.8 for f in features(resource.location, det.redacted_line)}
    profile = repo.save_fp_profile(FPProfile(scope_kind="source", scope_id=CONN, source_type="github",
        detector_name="test", credential_type="TEST", sample_count=3, distinct_actors=2,
        active=True, threshold=0.5, min_samples=1, centroid=centroid))
    assert svc.evaluate(det, resource, exposure) is None  # current threshold, not training threshold
    svc.threshold = 0.7
    assert svc.evaluate(det, resource, exposure) is not None
    svc.min_samples = 4
    assert svc.evaluate(det, resource, exposure) is None
    svc.min_samples = 1
    svc.deactivate(profile.id)
    assert svc.evaluate(det, resource, exposure) is None


def test_old_automatic_resolution_cannot_claim_a_different_matching_profile():
    repo = InMemoryRepository()
    svc = LearnedFPService(repo, enabled=True, min_samples=2, threshold=0.5, max_confidence="high")
    orch = Orchestrator(repo, learned_fp=svc)
    for i, actor in enumerate(("alice", "bob")):
        finding = _scan(orch, f"tests/fixtures/case{i}/sample.py", case=i).findings[0]
        _confirm(repo, svc, finding, actor)
    finding = _scan(orch, "tests/fixtures/auto/sample.py", case=79).findings[0]
    assert finding.workflow_status == "FALSE_POSITIVE"
    stale = repo.update_finding_status(finding.id, "FALSE_POSITIVE",
        resolution=f"{RESOLUTION_PREFIX}{uuid.uuid4()} similarity=1.00")
    assert svc.apply_to_finding(stale).workflow_status == "OPEN"


@pytest.mark.parametrize("reachability", ["public", "public_inherited", "unknown", None])
@pytest.mark.parametrize("safe_first", [False, True])
def test_auto_triage_requires_every_active_location_and_reopens_only_system_decisions(reachability, safe_first):
    repo = InMemoryRepository()
    svc = LearnedFPService(repo, enabled=True, min_samples=2, threshold=0.5, max_confidence="high")
    orch = Orchestrator(repo, learned_fp=svc)
    for i, actor in enumerate(("alice", "bob")):
        finding = _scan(orch, f"tests/fixtures/case{i}/sample.py", case=i).findings[0]
        _confirm(repo, svc, finding, actor)
    locations = [("tests/fixtures/safe/sample.py", "internal"), ("prod/config.py", reachability)]
    for path, exposure in locations if safe_first else reversed(locations):
        finding = _scan(orch, path, case=77, exposure=exposure).findings[0]
    assert finding.workflow_status == "OPEN"
    manual = repo.update_finding_status(finding.id, "FALSE_POSITIVE", resolution="analyst decision")
    again = _scan(orch, "tests/fixtures/safe/sample.py", case=77).findings[0]
    assert again.workflow_status == manual.workflow_status == "FALSE_POSITIVE"
    assert again.resolution == "analyst decision"
