"""격리된 AWS 읽기 작업 등록.

1. 승인된 대상의 읽기 작업을 등록한다.
2. 거절 사유를 HTTP에 독립적인 오류로 전달한다.
"""

from __future__ import annotations

from cremore.collectors.base import CollectorError
from cremore.coverage import aws_requests


class AwsReadError(Exception):
    """기존 AWS 작업 거절 코드와 응답 상태를 보존한다."""

    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code = code
        self.status = status


class AwsReadEngine:
    """HTTP 응답을 만들지 않고 저장소에 AWS 읽기 작업을 등록한다."""

    @staticmethod
    def enqueue(repo, settings, operation, actor, params):
        """승인된 AWS 메타데이터 읽기 작업을 등록한다.

        Args:
            repo: API 저장소.
            settings: 실행 설정.
            operation: 허용된 AWS 읽기 작업 이름.
            actor: 요청자 식별자.
            params: 승인 대상의 식별자.

        Returns:
            ScanJob: 저장된 작업.

        Raises:
            AwsReadError: 대상이나 승인이 기존 계약을 충족하지 않을 때.
        """
        # 1. 기존 등록 함수가 승인·대상·작업 크기 제한을 검사한다.
        try:
            return aws_requests.enqueue(repo, settings, operation, actor, params)
        except CollectorError as exc:
            raise AwsReadError(exc.code, 409) from exc
        except (TypeError, ValueError) as exc:
            raise AwsReadError("AWS_REQUEST_TARGET_INVALID", 422) from exc
