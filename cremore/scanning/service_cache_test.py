"""Passive cache contracts with real detection and fake lazy provider objects."""

import uuid
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cremore.collectors.base import CollectedObject
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore, stable_digest
from cremore.detection import Engine, ResourceRef
from cremore.detection.custom import rule_definition
from cremore.detection.engine import EngineConfig
from cremore.detection.verify import VerifierConfig
from cremore.domain.models import CustomRule
from cremore.scanning.extraction import DEFAULT_LIMITS, cache_digest
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import RETRYABLE_EXTRACTION_REASONS, ScanService

SYNTHETIC = b"SYNTHETIC_CACHE_A1B2C3D4"
SECOND = b"SYNTHETIC_CACHE_E5F6G7H8"


class LazySource:
    failed_objects = 0
    authoritative_listing = True

    def __init__(self, data, *, path="src/config.txt", revision="blob-v1", source="github", complete=True, forbid_read=False):
        self.reads = 0
        self.resource = ResourceRef(source_type=source, resource="org/repo" if source == "github" else "bucket",
            location=path, revision=revision, size=len(data or b""), metadata={"exposure": "internal"})

        def load():
            assert not forbid_read, "a reusable passive result should not download this object"
            self.reads += 1
            return data

        self.obj = CollectedObject(self.resource, data=None, complete=complete, loader=load)

    def collect(self):
        yield self.obj


def scanner(*, rule=None, config=None):
    repo = InMemoryRepository()
    rule = rule or CustomRule(id=uuid.uuid4(), name="Synthetic cache", pattern=r"SYNTHETIC_CACHE_[A-Z0-9]{8}")
    config = config or EngineConfig()
    # A real RE2 engine with one synthetic rule keeps this proof independent of
    # provider formats. Provider verification is disabled unless a test opts in.
    orch = Orchestrator(repo, engine=Engine(config, definitions=[rule_definition(rule)]), config=config)
    orch._rules = {f"custom-{rule.id}": rule}
    return orch, ScanService(orch), uuid.uuid4(), rule


def entry(orch, cid, resource):
    root = stable_digest([str(cid), resource.source_type, resource.resource])
    subject = resource.revision if resource.source_type == "github" else resource.location
    return ScanStore(orch.repo).cached(cid, root, subject, resource.revision, cache_digest(orch.engine.detection_digest))


def cached(orch, cid, resource):
    found = entry(orch, cid, resource)
    return None if found is None else found["detections"]


def test_partial_object_counted_by_collector_is_not_counted_twice():
    _orch, service, cid, _rule = scanner()
    source = LazySource(b"partially read", source="notion", complete=False)
    source.failed_objects = 1
    source.obj.failure_counted = True
    assert service.run(source, source_connection_id=cid).objects_failed == 1


def test_github_empty_sha_result_survives_rename_without_download_or_detection(monkeypatch):
    orch, service, cid, _ = scanner()
    first = LazySource(b"ordinary release notes", path="docs/old.txt")
    assert service.run(first, source_connection_id=cid).detections == 0
    assert first.reads == 1 and cached(orch, cid, first.resource) == []
    renamed = LazySource(None, path="docs/renamed.txt", forbid_read=True)

    def forbidden(*args):
        pytest.fail("a GitHub empty-result cache hit must not invoke the engine")

    monkeypatch.setattr(orch.engine, "scan", forbidden)
    result = service.run(renamed, source_connection_id=cid)
    assert result.reused == 1 and result.objects == 1 and result.objects_failed == 0
    assert renamed.reads == 0 and not orch.repo.exposures


def test_prefilter_custom_hit_reapplies_current_path_scope_and_severity():
    rule = CustomRule(id=uuid.uuid4(), name="Synthetic cache", pattern=r"SYNTHETIC_CACHE_[A-Z0-9]{8}",
                      include_globs=["src/*"], severity="HIGH")
    orch, service, cid, rule = scanner(rule=rule)
    first = LazySource(SYNTHETIC, path="docs/sample.txt")
    assert service.run(first, source_connection_id=cid).detections == 0
    assert not orch.repo.exposures
    raw = cached(orch, cid, first.resource)
    assert len(raw) == 1 and "rule_detection_digest" not in raw[0]["extra_safe_data"]
    old_policy, old_engine = orch.detection_policy_digest, orch.engine.detection_digest
    rule.include_globs = ["src/*", "config/*"]
    rule.severity = "LOW"
    # Recompiling a rule on a scope/severity-only change keeps engine outputs
    # reusable, while broadening its persisted-result scope changes root policy.
    orch.engine = Engine(orch.config, definitions=[rule_definition(rule)])
    assert orch.engine.detection_digest == old_engine and orch.detection_policy_digest != old_policy
    renamed = LazySource(None, path="config/settings.txt", forbid_read=True)
    result = service.run(renamed, source_connection_id=cid)
    assert result.reused == result.detections == 1 and renamed.reads == 0
    exposure = next(iter(orch.repo.exposures.values()))
    assert exposure.location == "config/settings.txt" and exposure.severity == "LOW"
    assert exposure.metadata["rule_detection_digest"] == stable_digest(orch._rule_detection_policy(rule))
    assert "rule_detection_digest" not in cached(orch, cid, renamed.resource)[0]["extra_safe_data"]
    denied = LazySource(None, path="docs/still-not-approved.txt", forbid_read=True)
    assert service.run(denied, source_connection_id=cid).detections == 0
    assert len(orch.repo.exposures) == 1


def test_s3_clean_result_is_cached_under_the_revision_it_read_and_reused_without_reading():
    orch, service, cid, _ = scanner()
    first = LazySource(b"ordinary notes", source="s3")
    assert service.run(first, source_connection_id=cid).reused == 0
    assert first.reads == 1 and cached(orch, cid, first.resource) == []
    unchanged = LazySource(None, source="s3", forbid_read=True)
    result = service.run(unchanged, source_connection_id=cid)
    assert result.reused == result.objects == 1 and result.objects_failed == 0
    changed = LazySource(b"ordinary notes", source="s3", revision="blob-v2")
    assert service.run(changed, source_connection_id=cid).reused == 0 and changed.reads == 1
    assert not orch.repo.exposures


def test_s3_row_names_the_revision_get_observed_not_the_listed_one():
    # The object changed between LIST and GET: the row describes the bytes read.
    orch, service, cid, _ = scanner()
    drifted = LazySource(b"ordinary notes", source="s3", revision="listed")
    load = drifted.obj.loader

    def get():
        drifted.resource.revision = "observed"
        return load()

    drifted.obj.loader = get
    service.run(drifted, source_connection_id=cid)
    assert cached(orch, cid, drifted.resource) == []
    listed = LazySource(b"ordinary notes", source="s3", revision="listed")
    assert service.run(listed, source_connection_id=cid).reused == 0 and listed.reads == 1


def test_live_verification_reuses_clean_rows_and_reads_rows_with_detections_or_skips_again(monkeypatch):
    from cremore.detection import verify

    orch, service, cid, rule = scanner()
    service.run(LazySource(b"no matching candidate"), source_connection_id=cid)
    service.run(LazySource(SYNTHETIC, revision="blob-v2"), source_connection_id=cid)
    service.run(LazySource(b"\x89PNG\r\n\x1a\n", revision="blob-v3"), source_connection_id=cid)
    digest = orch.engine.detection_digest
    monkeypatch.setattr(verify, "verifier_for", lambda _catalog_id: None)
    orch.engine = Engine(replace(orch.config, verify=VerifierConfig(enabled=True)), definitions=[rule_definition(rule)])
    assert orch.engine.detection_digest == digest  # verification is not passive detection
    clean = LazySource(None, forbid_read=True)
    assert service.run(clean, source_connection_id=cid, verify=True).reused == 1
    detected = LazySource(SYNTHETIC, revision="blob-v2")
    assert service.run(detected, source_connection_id=cid, verify=True).reused == 0 and detected.reads == 1
    image = LazySource(b"\x89PNG\r\n\x1a\n", revision="blob-v3")
    assert service.run(image, source_connection_id=cid, verify=True).reused == 0 and image.reads == 1
    # A live run writes only rows without detections; explicit passive runs reuse everything.
    fresh = LazySource(b"another clean note", revision="blob-v4")
    service.run(fresh, source_connection_id=cid, verify=True)
    assert cached(orch, cid, fresh.resource) == []
    assert len(ScanStore(orch.repo).memory["cache"]) == 4
    passive = LazySource(None, revision="blob-v2", forbid_read=True)
    assert service.run(passive, source_connection_id=cid, verify=False).reused == 1


@pytest.mark.parametrize("override", [False, True])
def test_live_candidate_is_checked_with_local_fake_verifier_not_reused_from_passive_cache(monkeypatch, override):
    from cremore.detection import verify

    orch, service, cid, rule = scanner()
    first = LazySource(SYNTHETIC)
    service.run(first, source_connection_id=cid)
    calls = []

    class LocalVerifier:
        def verify(self, **kwargs):
            assert kwargs["secret"].encode() == SYNTHETIC
            calls.append("local synthetic verification")
            return verify.VerificationResult(verify.VerificationState.UNSUPPORTED)

    monkeypatch.setattr(verify, "verifier_for", lambda _catalog_id: LocalVerifier())
    enabled = VerifierConfig(enabled=True)
    if not override:
        orch.engine = Engine(replace(orch.config, verify=enabled), definitions=[rule_definition(rule)])
    live = LazySource(SYNTHETIC)
    result = service.run(live, source_connection_id=cid, verify=True,
                         verify_config=enabled if override else None)
    assert result.reused == 0 and live.reads == 1 and len(calls) == 1
    assert result.detections == 1
    # The durable content cache still contains only the original passive facts.
    raw = cached(orch, cid, live.resource)
    assert len(raw) == 1 and not any(k.startswith("verification_") for k in raw[0]["extra_safe_data"])


@pytest.mark.parametrize("data,complete", [(b"no longer a match", False), (None, True)])
def test_partial_or_failed_read_never_caches_or_retires_prior_exposure(data, complete):
    orch, service, cid, _ = scanner()
    service.run(LazySource(SYNTHETIC), source_connection_id=cid)
    old = next(iter(orch.repo.exposures.values()))
    partial = LazySource(data, revision="blob-v2", complete=complete)
    result = service.run(partial, source_connection_id=cid, reconcile_objects=True)
    assert result.objects_failed == 1 and cached(orch, cid, partial.resource) is None
    assert orch.repo.exposures[old.id].status == "OPEN"
    assert len(ScanStore(orch.repo).memory["cache"]) == 1


def test_detection_cap_never_caches_partial_results_or_retires_unreturned_match():
    orch, service, cid, rule = scanner()
    service.run(LazySource(SYNTHETIC + b"\n" + SECOND), source_connection_id=cid)
    assert len(orch.repo.exposures) == 2
    limited = replace(orch.config, max_detections=1)
    orch.engine = Engine(limited, definitions=[rule_definition(rule)])
    partial = LazySource(SYNTHETIC, revision="blob-v2")
    result = service.run(partial, source_connection_id=cid, reconcile_objects=True)
    assert result.detections == 1 and result.objects_failed == 1
    assert cached(orch, cid, partial.resource) is None
    assert all(e.status == "OPEN" for e in orch.repo.exposures.values())
    assert len(ScanStore(orch.repo).memory["cache"]) == 1


@pytest.mark.parametrize("source", ["s3", "github", "notion"])
def test_root_digest_reuses_adjacent_root_only_and_skips_uncacheable_sources(monkeypatch, source):
    from cremore.scanning import service as service_module

    _orch, service, cid, _ = scanner()
    calls = []
    original = service_module.stable_digest

    def counted(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(service_module, "stable_digest", counted)
    objects = []
    for index, root in enumerate(("first", "first", "second", "second", "first")):
        item = LazySource(b"ordinary notes", source=source, revision=f"version-{index}")
        item.resource.resource = root
        objects.append(item.obj)
    collector = SimpleNamespace(collect=lambda: iter(objects), failed_objects=0)
    for connection in (cid, uuid.uuid4()):
        result = service.run(collector, source_connection_id=connection)
        assert result.objects == 5 and result.reused == result.objects_failed == 0
        expected = [] if source == "notion" else [
            [str(connection), source, root] for root in ("first", "second", "first")]
        assert calls == expected
        calls.clear()


def test_orchestrator_binding_reuses_identity_but_preserves_distinct_repository():
    orch, _service, _cid, _ = scanner()
    orch.learned_fp = SimpleNamespace(repo=orch.repo)
    assert orch.using(orch.repo) is orch
    target = InMemoryRepository()
    bound = orch.using(target)
    assert bound is not orch and bound.repo is target and bound.engine is orch.engine
    assert bound.learned_fp is not orch.learned_fp and bound.learned_fp.repo is target
    assert orch.learned_fp.repo is orch.repo


def test_cache_and_result_writes_keep_the_per_object_repository_boundary():
    orch, service, cid, _ = scanner()
    target = InMemoryRepository()
    entered = []

    @contextmanager
    def write_context():
        entered.append(target)
        yield target

    source = LazySource(SYNTHETIC)
    result = service.run(source, source_connection_id=cid, write_context=write_context,
                         reconcile_objects=True)
    assert result.objects == result.detections == 1 and entered == [target]
    assert not orch.repo.exposures and len(target.exposures) == 1
    assert not ScanStore(orch.repo).memory["cache"]
    assert len(ScanStore(target).memory["cache"]) == 1


@pytest.mark.parametrize("header,counter,reason", [
    (b"%PDF-1.7\n", "skipped_unsupported", "UNSUPPORTED_FORMAT"),
    (b"PK\x03\x04", "skipped_unsupported", "UNSUPPORTED_FORMAT"),
    (b"\x89PNG\r\n\x1a\n", "skipped_media", "MEDIA_FORMAT"),
    (b"\xff\xd8\xff\xe0", "skipped_media", "MEDIA_FORMAT"),
    (b"GIF89a", "skipped_media", "MEDIA_FORMAT"),
])
def test_documents_and_images_are_format_skips_not_failures(header, counter, reason):
    # A token-shaped string inside a PDF or image must not become a finding: the
    # bytes around it are compressed noise, so the object is skipped instead of
    # pattern-matched. Re-reading cannot change that, so it is not a failure.
    _orch, service, cid, _rule = scanner()
    reasons = []

    @contextmanager
    def write_context():
        yield _orch.repo

    result = service.run(LazySource(header + SYNTHETIC, path="docs/report.bin"), source_connection_id=cid,
                         write_context=write_context,
                         object_skipped=lambda repo, resource, why: reasons.append(why))
    assert result.detections == 0 and result.objects_failed == 0
    assert getattr(result, counter) == 1 and result.skipped_unsupported + result.skipped_media == 1
    assert reasons == [reason]


def test_a_format_skip_is_not_a_clean_read_and_keeps_old_exposures():
    # A text file that held a match and is later replaced by a PDF at the same
    # path must not be reconciled as "scanned, nothing found".
    orch, service, cid, _rule = scanner()
    service.run(LazySource(b"note: " + SYNTHETIC, path="docs/report"), source_connection_id=cid, reconcile_objects=True)
    [old] = orch.repo.exposures.values()
    replaced = LazySource(b"%PDF-1.7\n" + SECOND, path="docs/report", revision="blob-v2")
    result = service.run(replaced, source_connection_id=cid, reconcile_objects=True)
    assert result.skipped_unsupported == 1 and result.objects_failed == 0
    assert orch.repo.exposures[old.id].status == "OPEN"


@pytest.mark.parametrize("data,reason", [(None, "UNREADABLE"), (b"%PDF-1.7", "UNSUPPORTED_FORMAT")])
def test_skip_callback_uses_the_same_optional_repository_boundary_as_success(data, reason):
    orch, service, cid, _ = scanner()
    seen = []
    source = LazySource(data)
    service.run(source, source_connection_id=cid,
                object_skipped=lambda repo, resource, why: seen.append((repo, resource, why)))
    assert seen == [(orch.repo, source.resource, reason)]


def test_detection_cap_stays_a_failure_next_to_format_skips():
    # `objects_failed` still counts an object that was read but not fully scanned.
    orch, service, cid, rule = scanner()
    orch.engine = Engine(replace(orch.config, max_detections=1), definitions=[rule_definition(rule)])

    class Two:
        failed_objects = 0

        def collect(self):
            yield LazySource(SYNTHETIC + b"\n" + SECOND, path="src/a.txt").obj
            yield LazySource(b"PK\x03\x04" + SYNTHETIC, path="dist/b.zip", revision="blob-v2").obj

    result = service.run(Two(), source_connection_id=cid, reconcile_objects=True)
    assert result.objects_failed == 1 and result.skipped_unsupported == 1


def test_plain_text_with_the_same_token_is_still_scanned():
    _orch, service, cid, _rule = scanner()
    result = service.run(LazySource(b"note: " + SYNTHETIC, path="docs/report.txt"), source_connection_id=cid)
    assert result.detections == 1 and result.skipped_unsupported == 0


def test_a_format_that_stops_being_scanned_does_not_replay_cached_detections(monkeypatch):
    # The skip decision runs after the cache lookup, so the skip list must be part
    # of the cache key; otherwise a PDF cached before it was listed keeps
    # replaying its old noise.
    import cremore.detection.engine as engine_module

    current, _service, _cid, rule = scanner()
    monkeypatch.setattr(engine_module, "UNSUPPORTED_MAGIC", ())
    before, _service, _cid, _rule = scanner(rule=rule)
    assert before.engine.detection_digest != current.engine.detection_digest


def partial_extraction(monkeypatch, reason, *, data=SYNTHETIC):
    """A document whose fixed format limit leaves part of it unread (extraction is another unit's)."""
    from cremore.scanning import service as module
    from cremore.scanning.extraction import ExtractionResult

    calls = []

    def extract(raw, **_kwargs):
        calls.append(raw)
        return ExtractionResult(data, "pdf", False, reason)

    monkeypatch.setattr(module, "extract", extract)
    return calls


def test_a_fixed_extraction_gap_is_inspected_cached_and_reported_never_a_failure(monkeypatch):
    orch, service, cid, _ = scanner()
    service.run(LazySource(b"note: " + SECOND, path="docs/report.pdf"), source_connection_id=cid, reconcile_objects=True)
    [old] = orch.repo.exposures.values()
    parsed = partial_extraction(monkeypatch, "PDF_GRAPHICS_CONTENT")
    committed = []
    gap = LazySource(b"%PDF-1.7 synthetic", path="docs/report.pdf", revision="blob-v2")
    result = service.run(gap, source_connection_id=cid, reconcile_objects=True,
                         object_committed=lambda _repo, resource, _result, complete: committed.append(complete))
    assert result.objects_failed == 0 and result.partially_inspected == 1 and result.detections == 1
    assert result.extraction_reasons == {"PDF_GRAPHICS_CONTENT": 1} and committed == [True]
    # Part of the document went unread: an earlier match there is not proven gone.
    assert orch.repo.exposures[old.id].status == "OPEN"
    assert entry(orch, cid, gap.resource)["reasons"] == {"PDF_GRAPHICS_CONTENT": 1}
    assert len(ScanStore(orch.repo).memory["cache"]) == 2  # the earlier text row and this one
    again = LazySource(None, path="docs/report.pdf", revision="blob-v2", forbid_read=True)
    reused = service.run(again, source_connection_id=cid, reconcile_objects=True)
    assert len(parsed) == 1 and reused.reused == 1 and reused.partially_inspected == 1
    assert reused.extraction_reasons == {"PDF_GRAPHICS_CONTENT": 1} and reused.objects_failed == 0
    assert again.resource.metadata["document_extraction_status"] == "PDF_GRAPHICS_CONTENT"
    assert len(ScanStore(orch.repo).memory["cache"]) == 2


def test_the_retryable_set_is_the_extraction_contract():
    from cremore.scanning.extraction.contract import RETRYABLE_REASONS

    assert RETRYABLE_EXTRACTION_REASONS == RETRYABLE_REASONS == frozenset({"PARSE_TIMEOUT", "PARSER_UNAVAILABLE"})


@pytest.mark.parametrize("limits,data,reason", [
    (replace(DEFAULT_LIMITS, input_bytes=4), b"ordinary text", "INPUT_LIMIT"),
    (replace(DEFAULT_LIMITS, text_bytes=10), b"note: " + SYNTHETIC, "TEXT_LIMIT"),
])
def test_a_real_fixed_limit_is_a_cached_partial_inspection_not_a_failure(limits, data, reason):
    orch = scanner()[0]
    service = ScanService(orch, extraction_limits=limits)
    cid = uuid.uuid4()
    source = LazySource(data, path="docs/large.txt")
    result = service.run(source, source_connection_id=cid, reconcile_objects=True)
    assert result.objects_failed == 0 and result.partially_inspected == 1
    assert result.extraction_reasons == {reason: 1} and len(ScanStore(orch.repo).memory["cache"]) == 1
    again = service.run(LazySource(None, path="docs/large.txt", forbid_read=True), source_connection_id=cid)
    assert again.reused == again.partially_inspected == 1 and again.objects_failed == 0


@pytest.mark.parametrize("reason", ["PARSER_RESOURCE_LIMIT", "PARSER_FAILURE"])
def test_a_parser_crash_is_no_retry_loop_and_no_cache_row(monkeypatch, reason):
    # Unlike a format's own limits, a crash may not repeat: the next full scan reads it again.
    orch, service, cid, _ = scanner()
    parsed = partial_extraction(monkeypatch, reason, data=b"")
    committed = []
    source = LazySource(b"%PDF-1.7 synthetic", path="docs/report.pdf")
    result = service.run(source, source_connection_id=cid,
                         object_committed=lambda _repo, resource, _result, complete: committed.append(complete))
    assert result.objects_failed == 0 and result.partially_inspected == 1 and committed == [True]
    assert entry(orch, cid, source.resource) is None and not ScanStore(orch.repo).memory["cache"]
    again = LazySource(b"%PDF-1.7 synthetic", path="docs/report.pdf")
    assert service.run(again, source_connection_id=cid).reused == 0 and again.reads == 1 and len(parsed) == 2


def test_live_verification_writes_no_skip_rows(monkeypatch):
    from cremore.detection import verify

    orch, _service, cid, rule = scanner()
    monkeypatch.setattr(verify, "verifier_for", lambda _catalog_id: None)
    orch.engine = Engine(replace(orch.config, verify=VerifierConfig(enabled=True)), definitions=[rule_definition(rule)])
    service = ScanService(orch)
    image = LazySource(b"\x89PNG\r\n\x1a\n", path="img/logo.png")
    result = service.run(image, source_connection_id=cid, verify=True)
    assert result.skipped_media == 1 and not ScanStore(orch.repo).memory["cache"]
    clean = LazySource(b"ordinary words", path="docs/a.txt", revision="blob-v2")
    service.run(clean, source_connection_id=cid, verify=True)
    assert cached(orch, cid, clean.resource) == []


@pytest.mark.parametrize("reason", sorted(RETRYABLE_EXTRACTION_REASONS))
def test_a_retryable_extraction_outcome_stays_a_failure_and_is_never_cached(monkeypatch, reason):
    orch, service, cid, _ = scanner()
    partial_extraction(monkeypatch, reason, data=b"")
    committed = []
    source = LazySource(b"%PDF-1.7 synthetic", path="docs/report.pdf")
    result = service.run(source, source_connection_id=cid,
                         object_committed=lambda _repo, resource, _result, complete: committed.append(complete))
    assert result.objects_failed == 1 and result.partially_inspected == 0 and committed == [False]
    assert entry(orch, cid, source.resource) is None and not ScanStore(orch.repo).memory["cache"]


def test_a_cached_format_skip_is_reported_again_without_reading():
    orch, service, cid, _ = scanner()
    reasons = []
    first = LazySource(b"\x89PNG\r\n\x1a\n" + SYNTHETIC, path="img/logo.png")
    skipped = service.run(first, source_connection_id=cid,
                          object_skipped=lambda _repo, _resource, why: reasons.append(why))
    assert skipped.objects_failed == 0 and skipped.skipped_media == 1
    assert entry(orch, cid, first.resource)["skip"] == "MEDIA_FORMAT"
    assert len(ScanStore(orch.repo).memory["cache"]) == 1
    again = LazySource(None, path="img/logo.png", forbid_read=True)
    result = service.run(again, source_connection_id=cid,
                         object_skipped=lambda _repo, _resource, why: reasons.append(why))
    assert result.reused == result.skipped_media == 1 and result.objects == result.objects_failed == 0
    assert result.extraction_reasons == {"MEDIA_FORMAT": 1} and reasons == ["MEDIA_FORMAT", "MEDIA_FORMAT"]
    assert again.resource.metadata["document_format"] == "image"
    assert len(ScanStore(orch.repo).memory["cache"]) == 1


def test_a_legacy_list_value_still_answers_as_a_complete_text_read():
    orch, service, cid, _ = scanner()
    source = LazySource(b"plain", path="a.txt")
    root = stable_digest([str(cid), "github", "org/repo"])
    digest = cache_digest(orch.engine.detection_digest)
    # A content-addressed subject is the blob id itself; the row holds which revision it read.
    identity = stable_digest([str(cid), root, source.resource.revision, digest])
    ScanStore(orch.repo).memory["cache"][identity] = {"revision": source.resource.revision, "detections": []}
    reused = LazySource(None, path="a.txt", forbid_read=True)
    result = service.run(reused, source_connection_id=cid)
    assert result.reused == result.objects == 1 and result.partially_inspected == 0
    assert "document_format" not in reused.resource.metadata
