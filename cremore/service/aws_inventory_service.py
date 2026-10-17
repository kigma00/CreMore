"""AWS 비밀 메타데이터 조회 흐름."""

from __future__ import annotations

from cremore.engine.aws_inventory_engine import (
    AwsInventoryEngine,
    InventoryUnavailable,
    QueuedAwsRead,
)
from cremore.engine.aws_read_engine import AwsReadError

__all__ = ["AwsInventoryService", "AwsReadError", "InventoryUnavailable", "QueuedAwsRead"]


class AwsInventoryService:
    """HTTP 경계가 조회 구현의 세부 사항을 알지 않도록 한다."""

    def __init__(self, repo, settings, aws_sessions, inventory_factory,
                 enabled, session_factory):
        self._engine = AwsInventoryEngine(
            repo, settings, aws_sessions, inventory_factory,
            enabled, session_factory,
        )

    def collect(self, account_id: str | None, actor: str):
        return self._engine.collect(account_id, actor)
