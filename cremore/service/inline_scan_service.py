"""인라인 스캔과 작업 조회 흐름의 진입점."""

from __future__ import annotations

import uuid

from cremore.engine.scan_engine import ScanEngine, ScanInputTooLarge

__all__ = ["InlineScanService", "ScanInputTooLarge"]


class InlineScanService:
    """인라인 탐지와 작업 조회를 HTTP 계층에서 분리한다."""

    def __init__(self, repo, settings, orchestrator):
        self._engine = ScanEngine(repo, settings, orchestrator)

    def scan(self, *, text: str, source_type: str, resource_name: str,
             location: str, exposure: str):
        return self._engine.scan(
            text=text, source_type=source_type, resource_name=resource_name,
            location=location, exposure=exposure,
        )

    def list_jobs(self, limit: int):
        return self._engine.list_jobs(max(1, min(limit, 500)))

    def get_job(self, job_id: uuid.UUID):
        return self._engine.get_job(job_id)
