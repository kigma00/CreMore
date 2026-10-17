"""연결 검증과 저장.

1. 기존 연결과 입력을 검증한다.
2. 변경 또는 스캔 작업을 저장한다.
"""

from __future__ import annotations

import uuid

from cremore.domain.connections import (
    ConnectionError as ConnectionValidationError,
)
from cremore.domain.connections import job_kind_for, job_payload_for, validate_connection
from cremore.domain.models import ConnectionStatus, ScanJob


class InvalidConnectionInput(ValueError):
    """연결 입력이 기존 계약에 맞지 않을 때."""


class CredentialRefused(ValueError):
    """공급자 연결이 소유한 자격증명의 직접 수정을 거절할 때."""


class ConnectionDisabled(ValueError):
    """비활성 연결에서 스캔을 요청했을 때."""


class ConnectionEngine:
    """연결 상태·설정을 검증하고 저장한다."""

    def __init__(self, repo):
        self._repo = repo

    def get(self, connection_id: uuid.UUID):
        """연결을 조회한다.

        Args:
            connection_id: 연결 식별자.

        Returns:
            Connection | None: 저장된 연결 또는 없음.
        """
        return self._repo.get_connection(connection_id)

    def update(self, connection_id: uuid.UUID, *, status: str | None, config: dict | None,
               secret_ref: str | None, token: str | None):
        """기존 검증 규칙을 적용해 연결을 수정한다.

        Args:
            connection_id: 연결 식별자.
            status: 요청된 연결 상태.
            config: 요청된 연결 설정.
            secret_ref: 허용되지 않는 별도 비밀 참조.
            token: 허용되지 않는 별도 토큰.

        Returns:
            Connection | None: 수정된 연결 또는 없음.

        Raises:
            ValueError: 입력이 기존 연결 계약에 맞지 않을 때.
        """
        # 1. 존재하지 않는 연결은 저장하지 않는다.
        conn = self.get(connection_id)
        if conn is None:
            return None
        if secret_ref is not None or token is not None:
            raise CredentialRefused("CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION")
        changes: dict = {}
        if status is not None:
            if status not in (ConnectionStatus.ACTIVE.value, ConnectionStatus.DISABLED.value):
                raise InvalidConnectionInput("status must be ACTIVE or DISABLED")
            changes["status"] = status
        if config is not None:
            candidate = conn.model_copy(update={"config": config})
            try:
                validate_connection(candidate)
            except ConnectionValidationError as exc:
                raise InvalidConnectionInput(str(exc)) from exc
            changes["config"] = config
        # 2. 기존 저장소 메서드를 사용해 DB 동작을 유지한다.
        return self._repo.update_connection(connection_id, **changes)

    def enqueue_scan(self, connection_id: uuid.UUID):
        """활성 연결의 스캔 작업을 등록한다.

        Args:
            connection_id: 연결 식별자.

        Returns:
            ScanJob | None: 등록된 작업 또는 연결 없음.

        Raises:
            ValueError: 연결이 비활성 상태일 때.
        """
        conn = self.get(connection_id)
        if conn is None:
            return None
        if conn.status == ConnectionStatus.DISABLED.value:
            raise ConnectionDisabled("connection is disabled")
        payload = job_payload_for(conn)
        if conn.secret_ref:
            payload["secret_ref"] = conn.secret_ref
        return self._repo.enqueue_job(
            ScanJob(kind=job_kind_for(conn), payload=payload, connection_id=conn.id)
        )
