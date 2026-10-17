"""연결 조회·수정·스캔 요청 HTTP 처리.

1. 입력·권한을 검사한다.
2. 서비스를 호출해 기존 응답 계약으로 변환한다.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from cremore.api.source_presenters import connection_public
from cremore.service.connection_service import (
    ConnectionDisabled,
    ConnectionService,
    CredentialRefused,
    InvalidConnectionInput,
)


class ConnectionUpdateRequest(BaseModel):
    status: str | None = None
    config: dict | None = None
    secret_ref: str | None = None
    token: str | None = None


class ConnectionController:
    """연결 리소스의 라우트를 기존 등록 순서로 생성한다."""

    @staticmethod
    def register(app, service: ConnectionService, require_auth, require_role) -> None:
        router = APIRouter()

        """연결 상세 리소스."""
        @router.get("/api/v1/connections/{connection_id}")
        def get_connection(connection_id: uuid.UUID, _actor: str = Depends(require_auth)) -> dict:
            conn = service.get(connection_id)
            if conn is None:
                raise HTTPException(status_code=404, detail="connection not found")
            return connection_public(conn)

        """연결 상태·설정 리소스."""
        @router.patch("/api/v1/connections/{connection_id}")
        def update_connection(
            connection_id: uuid.UUID,
            body: ConnectionUpdateRequest,
            _actor: str = Depends(require_role("admin")),
        ) -> dict:
            try:
                conn = service.update(
                    connection_id, status=body.status, config=body.config,
                    secret_ref=body.secret_ref, token=body.token,
                )
            except CredentialRefused as exc:
                raise HTTPException(status_code=409, detail=(
                    "CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION: change it on the provider connection"
                )) from exc
            except InvalidConnectionInput as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if conn is None:
                raise HTTPException(status_code=404, detail="connection not found")
            return connection_public(conn)

        """연결 스캔 작업 리소스."""
        @router.post("/api/v1/connections/{connection_id}/scan", status_code=202)
        def scan_connection(
            connection_id: uuid.UUID, _actor: str = Depends(require_role("analyst"))
        ) -> dict:
            try:
                job = service.enqueue_scan(connection_id)
            except ConnectionDisabled as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if job is None:
                raise HTTPException(status_code=404, detail="connection not found")
            return {"id": str(job.id), "status": job.status}

        app.include_router(router)
