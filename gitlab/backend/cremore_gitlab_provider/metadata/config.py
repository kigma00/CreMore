"""설정 검증: 명시한 그룹·프로젝트와 수집기 자신의 PAT만 조회한다."""

import hashlib
import json
import math
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from urllib.parse import urlsplit

from .audit import utc_time
from .metadata_policy import POLICY_VERSION


@dataclass(frozen=True)
class Config:
    """비밀값을 제외한 설정. 인증 Token은 환경 변수에서 별도로 읽는다."""

    base_url: str = "https://gitlab.com"
    group_ids: tuple[int, ...] = ()
    project_ids: tuple[int, ...] = ()
    sources: tuple[str, ...] = ()
    include_values: bool = False
    include_self_pat: bool = True
    include_enterprise_pat: bool = True
    include_resource_access_tokens: bool = True
    include_service_accounts: bool = True
    include_graphql: bool = True
    enrich_users: bool = True
    include_audit_events: bool = False
    # 이전 설정의 별칭. true이면 현재 지원하는 모든 토큰 유형의 관련 감사 수집을 활성화한다.
    include_deploy_token_audit: bool = False
    audit_created_after: str | None = None
    # null이면 전체 지정 이력을 조회한다. GitLab의 실제 보존 기간을 추정하는 옵션이 아니다.
    audit_lookback_days: int | None = None
    page_size: int = 100
    requests_per_second: float = 2.0
    user_details_requests_per_second: float = 0.5
    burst: int = 2
    timeout_seconds: float = 30.0
    max_retries: int = 4
    max_pages_per_task: int = 10000
    max_requests_per_run: int = 10000
    max_consecutive_rate_limits: int = 3
    retry_min_seconds: float = 1.0
    max_response_bytes: int = 20 * 1024 * 1024

    @classmethod
    def from_dict(cls, value: dict) -> "Config":
        """JSON 설정을 검증하고 불명확한 옵션·인증값 혼입을 거부한다."""
        if not isinstance(value, dict):
            raise ValueError("설정은 JSON 객체여야 합니다.")  # noqa: TRY004 - preserve the native validation contract
        known = {field.name for field in fields(cls)}
        if set(value) - known:
            raise ValueError("지원하지 않는 설정 키가 있습니다. config.example.json을 확인하세요.")
        data = dict(value)
        sources = data.get("sources", [])
        if not isinstance(sources, (list, tuple)) or any(not isinstance(item, str) for item in sources):
            raise ValueError("sources: 문자열 목록이 필요합니다.")
        data["sources"] = tuple(sorted(set(sources)))
        for key in ("group_ids", "project_ids"):
            ids = data.get(key, [])
            if not isinstance(ids, (list, tuple)) or any(type(i) is not int or i <= 0 for i in ids):
                raise ValueError(f"{key}: 양의 정수 ID 목록을 지정하세요.")
            data[key] = tuple(sorted(set(ids)))
        config = cls(**data)
        if type(config.include_values) is not bool:
            raise ValueError("include_values: true 또는 false가 필요합니다.")
        if not isinstance(config.base_url, str):
            raise ValueError("base_url은 HTTPS URL 문자열이어야 합니다.")  # noqa: TRY004 - preserve the native validation contract
        url = urlsplit(config.base_url)
        # HTTPS 검증을 끄거나 다른 origin에 인증 헤더를 넘기는 옵션은 제공하지 않는다.
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
            raise ValueError("base_url은 경로·계정정보 없는 HTTPS origin이어야 합니다.")
        for key in ("include_self_pat", "include_enterprise_pat", "include_resource_access_tokens", "include_service_accounts", "include_graphql", "enrich_users", "include_audit_events", "include_deploy_token_audit"):
            if type(getattr(config, key)) is not bool:
                raise ValueError(f"{key}: true 또는 false가 필요합니다.")
        if config.audit_created_after is not None:
            utc_time(config.audit_created_after)
        if config.audit_lookback_days is not None and (type(config.audit_lookback_days) is not int or not 1 <= config.audit_lookback_days <= 36500):
            raise ValueError("audit_lookback_days: null 또는 1~36500의 정수가 필요합니다.")
        for key, lower, upper in (("page_size", 1, 100), ("burst", 1, 100), ("max_retries", 0, 10), ("max_pages_per_task", 1, 1000000),
                                  ("max_requests_per_run", 1, 10000000), ("max_consecutive_rate_limits", 1, 100),
                                  ("max_response_bytes", 1024, 1024 * 1024 * 1024)):
            value = getattr(config, key)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"{key}: {lower}~{upper}의 정수가 필요합니다.")
        for key in ("requests_per_second", "user_details_requests_per_second", "timeout_seconds", "retry_min_seconds"):
            value = getattr(config, key)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{key}: 양의 유한수가 필요합니다.")
        if config.user_details_requests_per_second > 0.5:
            raise ValueError("user_details_requests_per_second: 0보다 크고 0.5 이하여야 합니다.")
        if not config.include_self_pat and not config.group_ids and not config.project_ids and not config.sources:
            raise ValueError("자신의 PAT 또는 명시적인 그룹/프로젝트 중 하나를 선택하세요.")
        if config.retry_min_seconds > 60:
            raise ValueError("retry_min_seconds는 60초 이하여야 합니다.")
        return config

    @classmethod
    def load(cls, path: Path) -> "Config":
        """UTF-8 JSON 파일을 읽는다. 구문 오류는 CLI에서 위치와 함께 보고한다."""
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def fingerprint(self) -> str:
        """재개 시 범위·옵션 변경을 감지하는 설정 해시. Credential 해시가 아니다."""
        # 속도·재시도·응답 한도를 조정한 재개는 허용하되 조회 대상/기간/페이지는 고정한다.
        value = {
            key: item for key, item in asdict(self).items() if key not in self.transport_settings()
        }
        if not value["sources"] and not value["include_values"]:
            # Legacy runs keep the exact existing resume contract.
            value.pop("sources")
            value.pop("include_values")
        # 예전 DB의 제외 대상 값이 새 결과에 섞이지 않도록 정책 변경 시 새 경로를 요구한다.
        value["collection_contract_version"] = 4
        value["metadata_selection_policy"] = POLICY_VERSION
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def transport_settings(self) -> dict:
        """재개 때 조정 가능한 운용 값을 범위 해시와 분리해 manifest에 남긴다."""
        keys = ("requests_per_second", "burst", "user_details_requests_per_second", "timeout_seconds", "max_retries", "max_requests_per_run",
                "max_consecutive_rate_limits", "retry_min_seconds", "max_response_bytes")
        return {key: getattr(self, key) for key in keys}

    @property
    def audit_enabled(self) -> bool:
        """새 옵션과 이전 이름의 활성화를 한 곳에서 판정한다."""
        return self.include_audit_events or self.include_deploy_token_audit
