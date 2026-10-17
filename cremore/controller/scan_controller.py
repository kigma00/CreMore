"""인라인 스캔과 스캔 작업 HTTP 처리.

1. 입력·권한을 검사한다.
2. 서비스를 호출해 기존 응답 계약으로 변환한다.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from cremore.api.finding_presenters import finding_summary
from cremore.api.source_presenters import scan_job_public
from cremore.service.inline_scan_service import InlineScanService, ScanInputTooLarge


class ScanRequest(BaseModel):
    text: str
    source_type: str = "inline"
    resource_name: str = "inline"
    location: str = "inline"
    exposure: str = "unknown"


class ScanController:
    """스캔 리소스의 라우트를 기존 등록 순서로 생성한다."""

    @staticmethod
    def register(app, service: InlineScanService, require_auth, require_role) -> None:
        router = APIRouter()

        """인라인 스캔 리소스."""
        @router.post("/api/v1/scan", status_code=202)
        def scan(body: ScanRequest, _actor: str = Depends(require_role("analyst"))) -> dict:
            try:
                result, findings = service.scan(
                    text=body.text, source_type=body.source_type,
                    resource_name=body.resource_name, location=body.location,
                    exposure=body.exposure,
                )
            except ScanInputTooLarge as exc:
                raise HTTPException(status_code=413, detail=str(exc)) from exc
            return {
                "detections": result.detections,
                "findings": [finding_summary(finding, credential) for finding, credential in findings],
            }

        """스캔 작업 목록 리소스."""
        @router.get("/api/v1/scan-jobs")
        def list_scan_jobs(_actor: str = Depends(require_auth), limit: int = 100) -> list[dict]:
            return [scan_job_public(job) for job in service.list_jobs(limit)]

        """스캔 작업 상세 리소스."""
        @router.get("/api/v1/scan-jobs/{job_id}")
        def get_scan_job(job_id: uuid.UUID, _actor: str = Depends(require_auth)) -> dict:
            job = service.get_job(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="job not found")
            return scan_job_public(job)

        app.include_router(router)
