"""AWS 비밀 메타데이터 조회.

1. 설치와 관리자 스위치를 확인한다.
2. 격리 실행은 작업을 예약하고, 일반 실행은 승인된 계정 세션으로 조회한다.
"""

from __future__ import annotations

from dataclasses import dataclass

from cremore.engine.aws_read_engine import AwsReadEngine


@dataclass(frozen=True)
class QueuedAwsRead:
    """HTTP 경계가 작업 응답을 만들기 위한 최소 정보."""

    id: object
    status: str


class InventoryUnavailable(Exception):
    """설치나 관리자 스위치가 조회를 허용하지 않을 때."""


class AwsInventoryEngine:
    """주입된 기존 AWS 경계 함수를 사용해 조회 정책을 유지한다."""

    def __init__(self, repo, settings, aws_sessions, inventory_factory,
                 enabled, session_factory):
        self._repo = repo
        self._settings = settings
        self._aws_sessions = aws_sessions
        self._inventory_factory = inventory_factory
        self._enabled = enabled
        self._session_factory = session_factory

    def collect(self, account_id: str | None, actor: str):
        """설정된 AWS 계정의 비밀 메타데이터를 조회한다.

        Args:
            account_id: 선택한 AWS 계정 식별자.
            actor: 승인된 요청자 식별자.

        Returns:
            QueuedAwsRead | tuple: 격리 작업 또는 계정 세션과 조회 결과.

        Raises:
            InventoryUnavailable: 조회 기능이 꺼져 있을 때.
        """
        # 1. 설치 설정과 대시보드 스위치를 모두 통과해야 실제 AWS를 읽는다.
        if self._inventory_factory is None or not self._enabled(self._settings, self._repo):
            raise InventoryUnavailable()
        # 2. 격리 배포는 기존 큐 경로를 사용해 API 프로세스의 직접 조회를 막는다.
        if getattr(self._settings, "isolated_deployment", False):
            job = AwsReadEngine.enqueue(
                self._repo, self._settings, "secrets-inventory", actor,
                {"account_id": account_id, "compact": False},
            )
            return QueuedAwsRead(job.id, job.status)
        session = self._session_factory(self._repo, self._settings, self._aws_sessions, account_id)
        return session, self._inventory_factory(session)
