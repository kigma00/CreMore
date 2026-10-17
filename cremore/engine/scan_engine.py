"""인라인 탐지와 스캔 작업 조회.

1. 현재 탐지 규칙과 검증 스위치를 적용한다.
2. 탐지 결과 및 저장된 작업을 읽는다.
"""

from __future__ import annotations

import uuid

from cremore.detection import ResourceRef
from cremore.scanning import scan_switches, verification_switch


class ScanInputTooLarge(ValueError):
    """설정된 요청 크기 상한을 초과했을 때."""


class ScanEngine:
    """HTTP 입력 객체 없이 스캔 엔진과 저장소를 호출한다."""

    def __init__(self, repo, settings, orchestrator):
        self._repo = repo
        self._settings = settings
        self._orchestrator = orchestrator

    def scan(self, *, text: str, source_type: str, resource_name: str,
             location: str, exposure: str):
        """기존 인라인 탐지 흐름을 실행한다.

        Args:
            text: 검사할 문자열.
            source_type: 원본 유형.
            resource_name: 원본 이름.
            location: 원본 위치.
            exposure: 노출 수준.

        Returns:
            tuple: 탐지 결과와 각 finding의 자격증명 쌍.

        Raises:
            ValueError: 설정된 입력 크기를 초과했을 때.
        """
        # 1. 요청마다 현재 규칙과 관리자 검증 스위치를 적용한다.
        self._orchestrator.refresh_rules()
        data = text.encode("utf-8")
        if len(data) > self._settings.max_input_bytes:
            raise ScanInputTooLarge("scan input exceeds MAX_INPUT_BYTES")
        resource = ResourceRef(
            source_type=source_type,
            resource=resource_name,
            location=location,
            metadata={"exposure": exposure},
        )
        verify = None if verification_switch.switch(self._repo)["enabled"] else False
        vconfig = scan_switches.verify_config_for(
            self._orchestrator.config.verify, self._settings, self._repo
        )
        # 2. 기존 저장 순서를 보존하고 응답에 필요한 자격증명만 읽는다.
        result = self._orchestrator.scan_resource(
            data, resource, verify=verify, verify_config=vconfig
        )
        return result, [
            (finding, self._repo.get_credential(finding.credential_id))
            for finding in result.findings
        ]

    def list_jobs(self, limit: int):
        """작업 목록을 조회한다.

        Args:
            limit: 조회 상한.

        Returns:
            list: 저장된 작업 목록.
        """
        return self._repo.list_jobs(limit)

    def get_job(self, job_id: uuid.UUID):
        """작업 하나를 조회한다.

        Args:
            job_id: 작업 식별자.

        Returns:
            ScanJob | None: 저장된 작업 또는 없음.
        """
        return self._repo.get_job(job_id)
