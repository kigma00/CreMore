"""Fail the job when CodeQL reports a security finding.

Reads every SARIF file CodeQL wrote and fails on any result whose rule carries
a ``security-severity`` score (CodeQL's CVSS-style rating), or on any
``error``-level result. Each finding is printed with its location so the job
log is actionable without a code scanning dashboard. A reviewed finding in
``ACCEPTED`` or ``ACCEPTED_SINKS`` is printed with its reason and does not fail the job.
"""

from __future__ import annotations

import json
import pathlib
import sys

# Reviewed findings: one rule in one file, with the reason it stands. The same
# rule anywhere else still fails the job.
ACCEPTED = {
    ("py/weak-sensitive-data-hashing", "cremore/detection/fingerprint.py"): (
        "finding fingerprints are HMAC-SHA256 under the installation's required FINGERPRINT_KEY "
        "(32+ random bytes) for de-duplication and vault matching, not password storage; a slow "
        "KDF would orphan every stored fingerprint and make bulk matching impractical"
    ),
}

# Query mismatches reviewed from Security run 37110946850 (1b96955). New
# acceptances bind the rule, path and CodeQL primary-location line fingerprint;
# an unrelated sink in the same file, or a changed sink, still fails the gate.
ACCEPTED_SINKS = {
    ("js/clear-text-storage-of-sensitive-data", "web/console/views/integrations/auth-first.tsx", "1a9fa2f1a9cf8ebe:1"): (
        "sessionStorage retains only an onboarding draft UUID and random browser binding, never submitted credentials; "
        "the API requires the original authenticated admin, binding and a 30-minute server expiry"
    ),
}


def accepted_reason(finding):
    _, rule, where, _, fingerprint = finding
    path = where.rsplit(":", 1)[0]
    return ACCEPTED.get((rule, path)) or ACCEPTED_SINKS.get((rule, path, fingerprint))


def rules_by_id(run: dict) -> dict:
    rules = {}
    for component in [run.get("tool", {}).get("driver", {}), *run.get("tool", {}).get("extensions", [])]:
        for rule in component.get("rules", []) or []:
            rules[rule.get("id")] = rule
    return rules


def findings(sarif: dict):
    for run in sarif.get("runs", []):
        rules = rules_by_id(run)
        for result in run.get("results", []) or []:
            rule = rules.get(result.get("ruleId"), {})
            props = rule.get("properties", {}) or {}
            score = props.get("security-severity")
            level = result.get("level") or (rule.get("defaultConfiguration", {}) or {}).get("level", "warning")
            if score is None and level != "error":
                continue
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            path = location.get("artifactLocation", {}).get("uri", "?")
            line = location.get("region", {}).get("startLine", "?")
            fingerprint = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")
            yield score, result.get("ruleId"), f"{path}:{line}", result.get("message", {}).get("text", ""), fingerprint


def main(directory: str) -> int:
    files = sorted(pathlib.Path(directory).glob("*.sarif"))
    if not files:
        print(f"no SARIF output in {directory}", file=sys.stderr)
        return 1
    found = [f for file in files for f in findings(json.loads(file.read_text(encoding="utf-8")))]
    accepted = [f for f in found if accepted_reason(f)]
    failing = [f for f in found if f not in accepted]
    for score, rule, where, message, _fingerprint in sorted(failing, key=lambda f: -float(f[0] or 10)):
        print(f"[{score or 'error'}] {rule} {where}: {message}")
    for finding in accepted:
        print(f"[accepted] {finding[1]} {finding[2]}: {accepted_reason(finding)}")
    print(f"{len(failing)} security finding(s) in {len(files)} SARIF file(s); {len(accepted)} accepted")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "codeql-results"))
