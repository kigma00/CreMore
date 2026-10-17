"""기존 API 계약의 미지원 경로 응답."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException


class UnsupportedController:
    """대시보드 경로보다 뒤에 등록해야 하는 최종 경로."""

    @staticmethod
    def register(app, require_auth) -> None:
        router = APIRouter()

        """지원되지 않는 API 경로."""
        @router.api_route(
            "/api/v1/{path:path}",
            methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            include_in_schema=False,
        )
        def not_supported(path: str, _actor: str = Depends(require_auth)):
            raise HTTPException(
                status_code=501,
                detail=f"not supported by this API: /api/v1/{path} "
                "(see docs/ARCHITECTURE.md, dashboard support matrix)",
            )

        app.include_router(router)
