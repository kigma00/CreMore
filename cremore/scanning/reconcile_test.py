"""A complete rescan retires what it no longer sees; a reappearance reopens."""

import uuid

from cremore.collectors.base import CollectedObject
from cremore.collectors.bytes_source import BytesCollector
from cremore.db.repository import InMemoryRepository
from cremore.detection import ResourceRef
from cremore.domain.models import CustomRule
from cremore.scanning import Orchestrator
from cremore.scanning.service import ScanService

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
GH2 = "ghp_" + "zY9xW8vU7tS6rQ5pN4mL3kJ2hG1fE0dC9bA8"


def _collector(files: dict[str, str]):
    return BytesCollector([
        CollectedObject(ResourceRef(source_type="github", resource="org/repo", location=path,
                                    metadata={"exposure": "public"}), text.encode())
        for path, text in files.items()
    ])


def test_complete_rescan_retires_locations_but_requires_credential_retirement():
    repo = InMemoryRepository()
    orch = Orchestrator(repo)
    service = ScanService(orch)
    conn = uuid.uuid4()

    first = service.run(_collector({"a.py": f"t={GH}", "b.py": f"u={GH2}"}), source_connection_id=conn)
    assert first.findings == 2 and len(first.exposure_ids) == 2

    # Second complete run: the first secret is gone from a.py.
    second = service.run(_collector({"a.py": "clean now", "b.py": f"u={GH2}"}), source_connection_id=conn)
    removed = orch.reconcile_connection(conn, second.exposure_ids)
    assert removed == 1
    findings = {repo.get_credential(f.credential_id).fingerprint: f for f in repo.list_findings()}
    resolved = [f for f in findings.values() if f.all_locations_removed]
    assert len(resolved) == 1 and resolved[0].workflow_status == "OPEN"
    events = repo.list_finding_events(resolved[0].id)
    assert events and events[-1].event_type == "ROLLUP_UPDATED"
    assert events[-1].note == "LOCATIONS_REMOVED_KEY_RETIREMENT_UNCONFIRMED"
    # the other finding is untouched
    assert sum(1 for f in findings.values() if f.workflow_status == "OPEN") == 2

    # It comes back: the auto-resolved finding reopens with an audit event.
    third = service.run(_collector({"a.py": f"t={GH}", "b.py": f"u={GH2}"}), source_connection_id=conn)
    orch.reconcile_connection(conn, third.exposure_ids)
    reopened = repo.get_finding(resolved[0].id)
    assert reopened.workflow_status == "OPEN" and reopened.resolution is None
    assert reopened.all_locations_removed is False
    assert repo.list_finding_events(reopened.id)[-1].note == "EXPOSURE_ROLLUP_REPAIRED"


def test_analyst_decisions_are_not_overridden_by_rescans():
    repo = InMemoryRepository()
    orch = Orchestrator(repo)
    service = ScanService(orch)
    conn = uuid.uuid4()
    service.run(_collector({"a.py": f"t={GH}"}), source_connection_id=conn)
    finding = repo.list_findings()[0]
    repo.update_finding_status(finding.id, "FALSE_POSITIVE")
    # gone, then back: a false positive stays a false positive
    empty = service.run(_collector({"a.py": "nothing"}), source_connection_id=conn)
    assert orch.reconcile_connection(conn, empty.exposure_ids) == 1
    assert repo.get_finding(finding.id).workflow_status == "FALSE_POSITIVE"
    back = service.run(_collector({"a.py": f"t={GH}"}), source_connection_id=conn)
    orch.reconcile_connection(conn, back.exposure_ids)
    assert repo.get_finding(finding.id).workflow_status == "FALSE_POSITIVE"


def test_reconcile_only_touches_the_given_connection():
    repo = InMemoryRepository()
    orch = Orchestrator(repo)
    service = ScanService(orch)
    a, b = uuid.uuid4(), uuid.uuid4()
    service.run(_collector({"a.py": f"t={GH}"}), source_connection_id=a)
    service.run(_collector({"b.py": f"u={GH2}"}), source_connection_id=b)
    assert orch.reconcile_connection(a, set()) == 1
    statuses = {repo.get_credential(f.credential_id).fingerprint: f.workflow_status for f in repo.list_findings()}
    assert sorted(statuses.values()) == ["OPEN", "OPEN"]
    assert sum(bool(f.all_locations_removed) for f in repo.list_findings()) == 1


def test_operator_rules_are_compiled_in_and_scoped():
    repo = InMemoryRepository()
    rule = repo.create_rule(CustomRule(name="Internal marker", pattern=r"(?P<secret>ACME_INTERNAL_[A-Z0-9]{6})",
                                       keywords=["acme_internal"], severity="LOW", scope_sources=["github"]))
    orch = Orchestrator(repo, rule_provider=repo.list_rules)
    assert orch.refresh_rules() == 1
    service = ScanService(orch)
    service.run(_collector({"cfg.ini": "key = ACME_IN" "TERNAL_AB12CD"}), source_connection_id=uuid.uuid4())
    findings = repo.list_findings()
    assert len(findings) == 1 and findings[0].severity == "LOW"
    cred = repo.get_credential(findings[0].credential_id)
    assert cred.provider == "custom" and cred.credential_type.startswith("CUSTOM_RULE_")

    # Out of the rule's source scope: nothing.
    inline = BytesCollector.one(b"key = ACME_IN" b"TERNAL_ZZ99YY", source_type="inline", resource="r", location="l")
    other = InMemoryRepository()
    other.create_rule(CustomRule(name="Internal marker", pattern=r"(?P<secret>ACME_INTERNAL_[A-Z0-9]{6})",
                                 keywords=["acme_internal"], scope_sources=["github"]))
    scoped = Orchestrator(other, rule_provider=other.list_rules)
    scoped.refresh_rules()
    assert ScanService(scoped).run(inline).findings == 0

    # Disabling the rule rebuilds the engine without it.
    repo.update_rule(rule.id, enabled=False, revision=2)
    assert orch.refresh_rules() == 0
