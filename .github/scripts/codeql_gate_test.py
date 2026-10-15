"""The gate accepts reviewed sinks while refusing new findings in the same file."""

import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("codeql_gate", Path(__file__).with_name("codeql_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def report(rule, path, fingerprint):
    return {"runs": [{
        "tool": {"driver": {"rules": [{"id": rule, "properties": {"security-severity": "7.5"}}]}},
        "results": [{"ruleId": rule, "message": {"text": "Synthetic gate result"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                         "region": {"startLine": 123}}}],
                     "partialFingerprints": {"primaryLocationLineHash": fingerprint}}],
    }]}


@pytest.mark.parametrize("identity", gate.ACCEPTED_SINKS)
def test_only_reviewed_sink_fingerprint_is_accepted(tmp_path, identity):
    rule, path, fingerprint = identity
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps(report(rule, path, fingerprint)), encoding="utf-8")
    assert gate.main(str(tmp_path)) == 0
    for changed in (None, "unreviewed-location:1"):
        sarif.write_text(json.dumps(report(rule, path, changed)), encoding="utf-8")
        assert gate.main(str(tmp_path)) == 1
    for changed_rule, changed_path in (("synthetic/new-security-rule", path), (rule, "unreviewed.py")):
        sarif.write_text(json.dumps(report(changed_rule, changed_path, fingerprint)), encoding="utf-8")
        assert gate.main(str(tmp_path)) == 1


def test_existing_fingerprint_helper_acceptance_is_preserved(tmp_path):
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps(report("py/weak-sensitive-data-hashing", "cremore/detection/fingerprint.py", None)),
                     encoding="utf-8")
    assert gate.main(str(tmp_path)) == 0


def test_missing_sarif_still_fails(tmp_path):
    assert gate.main(str(tmp_path)) == 1
