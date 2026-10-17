"""연결 조회·변경·스캔 흐름의 진입점."""

from __future__ import annotations

import uuid

from cremore.engine.connection_engine import (
    ConnectionDisabled,
    ConnectionEngine,
    CredentialRefused,
    InvalidConnectionInput,
)

__all__ = ["ConnectionDisabled", "ConnectionService", "CredentialRefused", "InvalidConnectionInput"]


class ConnectionService:
    """HTTP 표현과 무관하게 연결 작업을 제공한다."""

    def __init__(self, repo):
        self._engine = ConnectionEngine(repo)

    def get(self, connection_id: uuid.UUID):
        return self._engine.get(connection_id)

    def update(self, connection_id: uuid.UUID, *, status: str | None, config: dict | None,
               secret_ref: str | None, token: str | None):
        return self._engine.update(
            connection_id, status=status, config=config, secret_ref=secret_ref, token=token
        )

    def enqueue_scan(self, connection_id: uuid.UUID):
        return self._engine.enqueue_scan(connection_id)
