"""AWS 비밀 메타데이터의 읽기 전용 HTTP 응답."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from cremore.api.aws_support import secret_record_public
from cremore.service.aws_inventory_service import (
    AwsInventoryService,
    AwsReadError,
    InventoryUnavailable,
    QueuedAwsRead,
)


class AwsInventoryController:
    """AWS 인벤토리 응답을 기존 JSON 계약으로 변환한다."""

    @staticmethod
    def register(app, service: AwsInventoryService, require_auth) -> None:
        router = APIRouter()

        """AWS Secrets Manager의 비밀 메타데이터 리소스."""
        @router.get("/api/v1/aws/secrets-inventory")
        def secrets_inventory(
            account_id: str | None = None, _actor: str = Depends(require_auth)
        ) -> dict:
            try:
                result = service.collect(account_id, _actor)
            except InventoryUnavailable as exc:
                raise HTTPException(status_code=501, detail=(
                    "SECRETS_INVENTORY_OFF: secret inventory is switched off for this installation"
                )) from exc
            except AwsReadError as exc:
                raise HTTPException(status_code=exc.status, detail=exc.code) from exc
            if isinstance(result, QueuedAwsRead):
                return JSONResponse(
                    {"status": result.status, "request_id": str(result.id),
                     "poll_url": f"/api/v1/aws/requests/{result.id}"},
                    status_code=202,
                )
            session, inv = result
            return {
                "account_id": session.account_id,
                "collected_via": session.via,
                "region": inv.region,
                "collection_status": inv.collection_status,
                "error_code": inv.error_code,
                "total": len(inv.secrets),
                "without_rotation": len(inv.without_rotation),
                "secrets": [secret_record_public(secret) for secret in inv.secrets],
            }

        app.include_router(router)
