"""Small, offline regressions for the detection-to-durable-data boundary."""

from dataclasses import asdict

import pytest

from cremore.detection import DetectorInput, Engine
from cremore.detection.engine import EngineConfig
from cremore.detection.engine_test import B36, GH, routing_definition
from cremore.detection.models import CatalogEntry, Definition, PatternDef
from cremore.detection.verify import VerificationResult, VerificationState, VerifierConfig


@pytest.mark.parametrize("tokens,kind", [
    ((GH, "ghp_" + B36[::-1]), "GITHUB_TOKEN"),
    (((B36 * 3)[:76] + "AZDOaB3d", (B36[::-1] * 3)[:76] + "AZDOeF5g"), "AZURE_DEVOPS_PAT"),
    (("abc1Q~" + B36[:31], "def2Q~" + B36[::-1][:31]), "AZURE_ENTRA_CLIENT_SECRET"),
])
def test_adjacent_synthetic_values_are_both_detected_and_masked(tokens, kind):
    results = Engine().scan(DetectorInput(",".join(tokens).encode()))
    relevant = [item for item in results if item.credential_type == kind]
    assert results.complete and len(relevant) == 2
    assert all(token not in item.redacted_line for item in results for token in tokens)


@pytest.mark.parametrize("limits", [{"max_candidates": 1}, {"max_candidate_bytes": 14}, {"max_match_bytes": 5}])
def test_candidate_budgets_leave_an_incomplete_result_without_unchecked_context(limits):
    engine = Engine(EngineConfig(**limits), definitions=[routing_definition("ITEM", ())])
    results = engine.scan(DetectorInput(b"ITEM_A1B2C3D4 ITEM_B2C3D4E5"))
    assert not results.complete
    assert all("ITEM_" not in item.redacted_line for item in results)
    if limits.get("max_match_bytes") != 5:
        assert len(results) == 1  # Keep already processed findings.


def test_context_is_bounded_without_changing_detection_coordinates():
    engine = Engine(EngineConfig(max_context_bytes=32), definitions=[routing_definition("ITEM", ())])
    results = engine.scan(DetectorInput(b"header\n" + b"plain " * 16 + b"ITEM_A1B2C3D4" + b" suffix" * 16))
    assert results.complete and len(results) == 1 and results[0].line_number == 2
    assert len(results[0].redacted_line) <= 34 and "ITEM_A1B2C3D4" not in results[0].redacted_line
    assert "…" in results[0].redacted_line


@pytest.mark.parametrize("prefix", ["xoxe-", "xoxe.", "xwfp-", "xoxd-", "xoxc-"])
def test_retired_slack_families_are_not_retained_as_nearby_context(prefix):
    retired = prefix + "synthetic-value-for-redaction"
    results = Engine().scan(DetectorInput(f"{GH} {retired}".encode()))
    assert any(item.credential_type == "GITHUB_TOKEN" for item in results)
    assert all(retired not in item.redacted_line for item in results)
    assert all(retired not in str(asdict(item)) for item in results)


def test_multiline_masking_counts_each_prefix_byte_at_most_once():
    class CountedBytes(bytes):
        counted = 0

        def count(self, sub, start=0, end=None):
            end = len(self) if end is None else end
            self.counted += end - start
            return super().count(sub, start, end)

    data = CountedBytes(b"BEGIN\nline one\nITEM_A1B2C3D4\nline three\nEND")
    engine = Engine(definitions=[Definition(
        CatalogEntry(id="multi", name="multi", provider="synthetic", credential_type="MULTI"),
        (PatternDef(r"BEGIN\n[\s\S]+?\nEND"),)), routing_definition("ITEM", ())])
    result = engine.scan(DetectorInput(data))
    assert result.complete and {d.credential_type for d in result} == {"MULTI", "ITEM"}
    assert data.counted <= len(data)
    assert all("line one" not in d.redacted_line and "ITEM_A1B2C3D4" not in d.redacted_line for d in result)


def test_verifier_facts_cannot_reflect_raw_or_other_catalog_credentials(monkeypatch):
    opaque = b"ITEM_A1B2C3D4"
    engine = Engine(definitions=[routing_definition("ITEM", ())])
    monkeypatch.setattr(engine, "_verify", lambda *args: VerificationResult(VerificationState.VERIFIED,
        facts={"name": GH, "login": opaque.decode(), "scopes": "read:inventory"}))
    result = engine.scan(DetectorInput(opaque, verify_config=VerifierConfig(enabled=True)))
    assert result[0].extra_safe_data["verification_scopes"] == "read:inventory"
    assert "verification_name" not in result[0].extra_safe_data and "verification_login" not in result[0].extra_safe_data
    # The raw identifier is deliberately in-memory only; none of these facts are.
    assert GH not in str(asdict(result[0]))


def test_sas_evidence_withholds_the_entire_query_line():
    signature = B36 + "aB3dE5fG="
    text = "private context https://myaccount.blob.core.windows.net/c/file?sv=2022-11-02&sp=r&sig=" + signature
    result = Engine().scan(DetectorInput(text.encode()))
    sas = next(item for item in result if item.credential_type == "AZURE_SAS_TOKEN")
    assert sas.redacted_line == "[Credential material redacted]"
    assert sas.extra_safe_data["azure_sas"]["account"] == "myaccount"
