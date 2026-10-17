"""데이터베이스 연결 생성.

1. 메모리 SQLite에는 스레드가 공유하는 풀을 적용한다.
2. 파일 SQLite와 그 밖의 DB에는 기존 연결 옵션을 적용한다.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool


class Database:
    """기존 프로세스별 연결 수명과 풀 설정을 보존하는 DB 인프라."""

    @staticmethod
    def make_engine(url: str) -> Engine:
        """설정된 URL로 SQLAlchemy 엔진을 생성한다.

        Args:
            url: SQLAlchemy 데이터베이스 URL.

        Returns:
            Engine: 기존 DB 종류별 풀 옵션이 적용된 엔진.
        """
        # 1. 메모리 DB는 API 스레드 사이에서 동일한 연결을 공유해야 한다.
        if url.startswith("sqlite") and ":memory:" in url:
            return create_engine(
                url, future=True, poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
        # 2. 파일 DB는 작업 스레드의 쓰기 경합 동안 기존 대기 시간을 유지한다.
        if url.startswith("sqlite"):
            return create_engine(url, future=True, pool_pre_ping=True, connect_args={"timeout": 30})
        return create_engine(url, future=True, pool_pre_ping=True)


make_engine = Database.make_engine
