"""식별·원문 분리·JSON 직렬화. API의 사실과 수집기의 추정을 구분한다."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .handlers import METADATA_PRIORITY

# Token 자체와 DSN은 메타데이터가 아니다. 제거한 필드의 경로만 남긴다.
SECRET_KEYS = {
    "token",
    "secret",
    "secret_token",
    "access_token",
    "refresh_token",
    "private_token",
    "client_secret",
    "password",
    "runners_token",
    "runner_token",
    "authentication_token",
    "public_key",
    "sentry_dsn",
    "verification_token",
    "authorization",
    "authorization_key",
}
# P1-4의 개인정보 최소화 정책과 별개로 Credential 원문만 분리한다.
# *_id, 만료·존재 상태 등은 접미사 규칙과 겹치지 않으며 메타데이터로 남긴다.
SAFE_KEY_FIELDS = {"primary_key", "foreign_key", "partition_key", "sort_key"}
SECRET_SUFFIXES = ("_token", "_secret", "_password", "_key")
URL_FIELDS = {"url", "import_url", "mirror_url", "http_url_to_repo", "web_url"}


def secret_field(key: str, value: Any) -> bool:
    """정확한 비밀 필드와 확장 접미사를 판정하되 명시적 존재 여부 불리언은 보존한다."""
    normalized = normalized_key(key)
    if normalized in SECRET_KEYS:
        return True
    if normalized in SAFE_KEY_FIELDS:
        return False
    if type(value) is bool and normalized.startswith(("has_", "is_", "can_")):
        return False
    return normalized.endswith(SECRET_SUFFIXES)


def sanitize_url(value: str) -> tuple[str, bool]:
    """URL userinfo와 명명된 인증 query 값만 지운다. 주소·저장소 경로는 보존한다."""
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value, False  # SCP 경로의 사용자명 등은 HTTP 자격증명으로 추정하지 않는다.
        authority = parts.netloc.rsplit("@", 1)[-1]
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        cleaned = [(key, "[REDACTED]" if secret_field(key, item) else item) for key, item in pairs]
        query = urlencode(cleaned) if cleaned != pairs else parts.query
        changed = authority != parts.netloc or cleaned != pairs
        return (
            (urlunsplit((parts.scheme, authority, parts.path, query, parts.fragment)), True)
            if changed
            else (value, False)
        )
    except ValueError:
        # 파싱할 수 없는 URL에 인증 구분자가 있으면 원문을 반환하지 않는다.
        return ("[REDACTED_INVALID_URL]", True) if "@" in value else (value, False)


def now() -> str:
    """관찰 시각을 UTC ISO 8601 문자열로 반환한다."""
    return datetime.now(UTC).isoformat()


def dumps(value: Any) -> str:
    """비표준 NaN을 거부하는 한 줄 JSON. 한국어 필드를 그대로 보존한다."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def stable_id(value: Any) -> str:
    """공식 식별자·문맥을 로컬 키로 직렬화한다. 비밀 원문은 입력하지 않는다."""
    return hashlib.sha256(dumps(value).encode("utf-8")).hexdigest()


def normalized_key(key: str) -> str:
    """GraphQL camelCase와 REST snake_case 비밀 필드명을 같은 규칙으로 검사한다."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower().replace("-", "_")


def sanitize(value: Any, path: str = "") -> tuple[Any, list[str]]:
    """모든 비밀값 이외의 응답 필드를 보존하고 제거 경로를 반환한다."""
    removed: list[str] = []
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            child = f"{path}.{key}" if path else key
            if secret_field(key, item):
                removed.append(child)
                continue
            if isinstance(item, str) and (
                normalized_key(key) in URL_FIELDS or normalized_key(key).endswith("_url")
            ):
                output[key], changed = sanitize_url(item)
                if changed:
                    removed.append(child + ".<embedded_credentials>")
                continue
            output[key], omitted = sanitize(item, child)
            removed.extend(omitted)
        return output, removed
    if isinstance(value, list):
        output = []
        for index, item in enumerate(value):
            clean, omitted = sanitize(item, f"{path}[{index}]")
            output.append(clean)
            removed.extend(omitted)
        return output, removed
    return value, removed


def native_id(value: Any, graphql_type: str | None = None) -> int:
    """양의 정수 ID만 받는다. GraphQL ID는 명시한 모델의 GlobalID만 변환한다."""
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str) and value.isdecimal() and int(value) > 0:
        return int(value)
    if graphql_type and isinstance(value, str):
        prefix = f"gid://gitlab/{graphql_type}/"
        if value.startswith(prefix):
            return native_id(value[len(prefix) :])
    raise ValueError("응답에서 유효한 공식 ID를 확인하지 못했습니다.")


def identity(base_url: str, family: str, token_id: int, scope: dict) -> dict:
    """이름을 사용하지 않는 결정적 키. 확인된 API 간에만 같은 ID 공간을 사용한다."""
    # PAT 조회 경로(자신/enterprise/service account)는 동일한 개인 PAT ID 공간이다.
    # Group/Project 통합·개별 API는 자산 종류와 ID를 함께 묶어 정확히 대응한다.
    if family in {
        "personal_access_token",
        "group_service_account_pat",
        "project_service_account_pat",
    }:
        namespace, key_scope = "personal_access_token", {}
    elif family in {"group_access_token", "project_access_token"}:
        namespace, key_scope = "resource_access_token", {"kind": scope["kind"], "id": scope["id"]}
    elif family in {"group_deploy_token", "project_deploy_token"}:
        namespace, key_scope = "deploy_token", {"kind": scope["kind"], "id": scope["id"]}
    else:
        namespace, key_scope = family, scope
    return {
        "instance": base_url.rstrip("/"),
        "namespace": namespace,
        "native_id": token_id,
        "scope": key_scope,
    }


def metadata_view(observations: list[dict]) -> tuple[dict, dict]:
    """관찰별 원본을 유지한 채 공통 표시값과 소유자/발급자 근거를 만든다."""
    merged: dict = {}
    # 동일 출처의 최신 관찰은 SQLite가 유지한다. 서로 다른 출처는 고정 권위 순서를 쓴다.
    # owner의 GraphQL 전용 state/webUrl 등도 중첩 병합하여 보존한다.
    for observation in sorted(
        observations,
        key=lambda row: (METADATA_PRIORITY.get(row.get("handler"), 0), row["source_id"]),
    ):
        merged = merge_metadata(merged, observation["metadata"])
    owner = {"status": "not_provided", "id": None, "evidence": None}
    issuer = {"status": "not_provided", "id": None, "evidence": None}
    if merged.get("user_id") is not None:
        owner = {
            "status": "observed",
            "id": merged["user_id"],
            "evidence": "user_id (token owner; not necessarily creator)",
        }
    elif isinstance(merged.get("owner"), dict):
        owner = {
            "status": "observed",
            "id": merged["owner"].get("id"),
            "evidence": "owner",
            "profile": merged["owner"],
        }
    for key in ("created_by_user_id", "createdByUser"):
        if merged.get(key) is not None:
            value = merged[key]
            issuer = {
                "status": "observed",
                "id": value.get("id") if isinstance(value, dict) else value,
                "evidence": key,
            }
            break
    # 공통 요약은 공식 User ID를 int로 통일한다. 출처별 원본 GlobalID는 바꾸지 않는다.
    for person in (owner, issuer):
        if person["id"] is not None:
            try:
                person["id"] = native_id(person["id"], "User")
            except ValueError:
                person["status"] = "invalid_reference"
                person["id"] = None
    # 명시적 null과 필드 미제공을 표시 단계에서도 구분한다.
    if owner["status"] == "not_provided" and any(key in merged for key in ("user_id", "owner")):
        owner["status"] = "null"
    if issuer["status"] == "not_provided" and any(
        key in merged for key in ("created_by_user_id", "createdByUser")
    ):
        issuer["status"] = "null"
    # 이름을 추정하지 않는다: Trigger description을 공식 name 필드로 바꾸지 않는다.
    summary = {
        "name": {
            "value": merged.get("name"),
            "status": "null"
            if "name" in merged and merged["name"] is None
            else "observed"
            if "name" in merged
            else "not_provided",
        },
        "description": merged.get("description"),
        "owner": owner,
        "issuer": issuer,
    }
    return merged, summary


def merge_metadata(base: dict, incoming: dict) -> dict:
    """원천 객체를 수정하지 않는 중첩 병합. 상위 출처의 명시적 null도 사실로 유지한다."""
    result = dict(base)
    for key, value in incoming.items():
        result[key] = (
            merge_metadata(result[key], value)
            if isinstance(result.get(key), dict) and isinstance(value, dict)
            else value
        )
    return result


def observed_scopes(observations: list[dict]) -> list[dict]:
    """표시용 모든 관찰 소속을 결정적 순서로 보존한다. identity.scope와 의미를 구분한다."""
    scopes = {dumps(row.get("context", {}).get("scope", {})) for row in observations}
    return [json.loads(value) for value in sorted(scopes)]
