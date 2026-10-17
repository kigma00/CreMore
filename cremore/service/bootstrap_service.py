"""API 시작에 필요한 도메인 구성.

1. 감사 기록의 키를 연결한다.
2. 스캔 구성요소를 만든다.
3. 로그인 그룹의 요청 상태를 게시한다.
"""

from __future__ import annotations

import logging

from cremore.detection.engine import EngineConfig
from cremore.detection.verify import VerifierConfig
from cremore.identity import sign_in_groups
from cremore.operations import audit_integrity
from cremore.scanning import Orchestrator
from cremore.scanning.learned_fp import LearnedFPService


class BootstrapService:
    """HTTP 앱 객체를 다루지 않고 시작 시 필요한 상태를 준비한다."""

    @staticmethod
    def attach_audit(repo, settings) -> None:
        """새 감사 행의 MAC 키를 저장소에 연결한다.

        Args:
            repo: API 저장소.
            settings: 검증된 실행 설정.

        Returns:
            None: 기존 저장소 설정을 완료한다.
        """
        # 1. API가 쓰는 감사 행은 기록 순간에 MAC을 가져야 한다.
        audit_integrity.attach(repo, settings)

    @staticmethod
    def scan_components(repo, settings):
        """기존 스캔 구성과 규칙 제공자를 만든다.

        Args:
            repo: API 저장소.
            settings: 검증된 실행 설정.

        Returns:
            tuple: 학습된 오탐 서비스와 스캔 오케스트레이터.
        """
        # 2. 인라인 API와 worker의 지문·검증 설정을 동일하게 구성한다.
        learned_fp = LearnedFPService(repo, settings)
        orchestrator = Orchestrator(
            repo,
            config=EngineConfig(
                fingerprint_key=settings.fingerprint_key_bytes,
                verify=VerifierConfig(
                    enabled=settings.verification_enabled,
                    known_github_hosts=settings.known_github_hosts,
                ),
            ),
            rule_provider=repo.list_rules,
            learned_fp=learned_fp,
        )
        return learned_fp, orchestrator

    @staticmethod
    def publish_sign_in_groups(repo, settings) -> None:
        """로그인 역할 그룹의 조회 요청을 게시한다.

        Args:
            repo: API 저장소.
            settings: 검증된 실행 설정.

        Returns:
            None: 게시 실패 시에도 기존처럼 API 시작을 계속한다.
        """
        # 3. 그룹 게시 장애는 로그인 역할 조회 작업에 맡기고 API 시작은 유지한다.
        try:
            sign_in_groups.publish_wanted(repo, settings)
        except Exception as exc:  # noqa: BLE001 -- 기존 시작 동작과 비밀값 비노출을 유지한다.
            logging.getLogger("cremore.main").warning(
                "[WARN] could not publish the sign-in role groups: %s", type(exc).__name__
            )
