"""Provider refinement must precede fenced persistence and preserve failures."""

import threading
import uuid
from contextlib import contextmanager

import pytest
from cremore_notion_provider.collectors.markdown_test import (
    BLOCK,
    PAGE,
    REVISION,
    Client,
    Response,
    collector,
    paragraph,
)

from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.detection import Engine
from cremore.detection.custom import rule_definition
from cremore.domain.models import CustomRule
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import ScanService

MARKER = "SYNTHETIC_NOTION_A1B2C3D4"


def scanner():
    repo = InMemoryRepository()
    rule = CustomRule(id=uuid.uuid4(), name="Synthetic Notion", pattern=r"SYNTHETIC_NOTION_[A-Z0-9]{8}")
    engine = Engine(definitions=[rule_definition(rule)])
    orchestrator = Orchestrator(repo, engine=engine)
    orchestrator._rules = {f"custom-{rule.id}": rule}
    return repo, ScanService(orchestrator), uuid.uuid4()


def test_only_detected_markdown_reads_blocks_and_persists_exact_block():
    repo, service, cid = scanner()
    client = Client(markdown="no candidate")
    assert service.run(collector(client), source_connection_id=cid).detections == 0
    assert not any("/blocks/" in url for url in client.calls)
    client = Client(markdown=MARKER)
    writes = []
    original = client.get

    def get(*args, **kwargs):
        assert not writes
        return original(*args, **kwargs)

    client.get = get

    @contextmanager
    def fenced():
        writes.append(True)
        try:
            yield repo
        finally:
            writes.pop()

    # Use a distinct connection: unchanged revisions intentionally reuse results.
    result = service.run(collector(client), source_connection_id=uuid.uuid4(), write_context=fenced)
    assert result.detections == 1 and result.objects_failed == 0
    assert any("/blocks/" in url for url in client.calls)
    exposure = next(iter(repo.exposures.values()))
    assert exposure.metadata["notion_block_id"] == BLOCK
    assert exposure.metadata["revision"] == REVISION


@pytest.mark.parametrize("failure", ["denied", "changed"])
def test_partial_or_changed_refinement_retains_hit_but_never_caches_or_reconciles(failure):
    repo, service, cid = scanner()

    class Changed(Client):
        refined = False

        def get(self, url, **kwargs):
            if "/blocks/" in url:
                self.refined = True
                if failure == "denied":
                    return Response({}, 403)
            response = super().get(url, **kwargs)
            if self.refined and "/pages/" in url:
                response.data["last_edited_time"] = "2026-10-02T00:00:00Z"
            return response

    committed = []
    source = collector(Changed(markdown=MARKER, blocks=[paragraph(MARKER)]))
    result = service.run(source, source_connection_id=cid, reconcile_objects=True,
                         object_committed=lambda _repo, resource, _result, complete:
                         committed.append((resource.revision, complete)))
    assert result.detections == 1 and result.objects_failed == 1
    assert committed == [("", False)]
    assert source.failed_page_ids == {PAGE}
    assert not ScanStore(repo).memory["cache"]
    assert "notion_block_id" not in next(iter(repo.exposures.values())).metadata


def test_persistence_exception_closes_live_fetch_iterator():
    _repo, service, cid = scanner()
    source = collector(Client(markdown=MARKER))

    def fail():
        raise RuntimeError("synthetic-write-failure")

    with pytest.raises(RuntimeError, match="synthetic-write-failure"):
        service.run(source, source_connection_id=cid, before_write=fail)
    assert source._dispatcher is None
    assert not any(t.name.startswith("notion-fetch") for t in threading.enumerate())
