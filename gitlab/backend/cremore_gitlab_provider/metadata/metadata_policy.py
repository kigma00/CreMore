"""CreMore 목적별 저장 정책. 승인된 제외 필드만 객체 종류에 맞게 제거한다."""

from typing import Any

from .model import normalized_key, sanitize

# 정책을 바꾸면 이 식별자와 수집 계약을 갱신한다. API 미제공과 정책 제외는 다르다.
POLICY_VERSION = "cremore_inventory_v1"
METADATA_POLICY = (
    f"{POLICY_VERSION}; non_secret_fields_except_approved_exclusions; missing_is_not_false"
)

# 사용자 프로필에만 적용한다. 이메일/IP/조직/직무/IdP 연결은 승인된 제외 대상이 아니다.
USER_EXCLUDED = frozenset(
    {
        "twitter",
        "linkedin",
        "discord",
        "github",
        "website_url",
        "bio",
        "bio_html",
        "pronouns",
        "theme_id",
        "color_scheme_id",
        "avatar_url",
        "followers",
        "following",
        "is_followed",
        "location",
        "local_time",
        "preferred_language",
        "commit_email",
        "last_sign_in_at",
        "current_sign_in_at",
        "last_activity_on",
        "confirmed_at",
    }
)
PROJECT_EXCLUDED = frozenset(
    {
        "avatar_url",
        "star_count",
        "forks_count",
        "open_issues_count",
        "merge_commit_template",
        "squash_commit_template",
        "issues_template",
        "merge_requests_template",
        "suggestion_commit_message",
        "show_diff_preview_in_email",
        "printing_merge_request_link_enabled",
        # 이 permissions는 조회자의 프로젝트 접근 문맥이다. 토큰의 granular_scopes는 건드리지 않는다.
        "permissions",
        "can_create_merge_request_in",
    }
)
GROUP_EXCLUDED = frozenset(
    {
        "avatar_url",
        "math_rendering_limits_enabled",
        "lock_math_rendering_limits_enabled",
        "show_diff_preview_in_email",
    }
)
EXCLUDED_BY_KIND = {
    "user": USER_EXCLUDED,
    "project": PROJECT_EXCLUDED,
    "group": GROUP_EXCLUDED,
    "namespace": frozenset({"avatar_url"}),
    # 전체 값 표시 권한을 유출 탐지로 오인하지 않도록 기본 인벤토리에서 제외한다.
    "pipeline_trigger_token": frozenset({"has_token_exposed"}),
}

# 객체 관계가 확인된 경로만 내려간다. 같은 키가 임의 확장 객체에 있다고 지우지 않는다.
CHILD_KINDS = {
    "user": {},
    "group": {"projects": "project", "shared_projects": "project", "parent": "group"},
    "project": {"owner": "user", "namespace": "namespace", "forked_from_project": "project"},
    "agent": {"config_project": "project", "created_by_user": "user"},
    "token": {"owner": "user", "created_by_user": "user"},
    "audit": {"details": "audit_details"},
    "audit_details": {"author": "user", "user": "user", "project": "project", "group": "group"},
}


def select_metadata(value: Any, kind: str, path: str = "") -> tuple[Any, list[str]]:
    """값은 복사하고 제외한 경로만 남긴다. null/false와 알 수 없는 새 필드는 보존한다."""
    if isinstance(value, dict):
        selected, excluded = {}, []
        # token 계열은 같은 사용자 관계를 공유하되 제외 규칙은 정확한 계열에만 적용한다.
        relations = CHILD_KINDS.get(
            kind, CHILD_KINDS["token"] if kind.endswith(("_token", "_pat", "_key")) else {}
        )
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else key
            normalized = normalized_key(key)
            if normalized in EXCLUDED_BY_KIND.get(kind, ()):
                excluded.append(child_path)
                continue
            child_kind = relations.get(normalized, "other")
            selected[key], removed = select_metadata(item, child_kind, child_path)
            excluded.extend(removed)
        return selected, sorted(excluded)
    if isinstance(value, list):
        selected, excluded = [], []
        for index, item in enumerate(value):
            clean, removed = select_metadata(item, kind, f"{path}[{index}]")
            selected.append(clean)
            excluded.extend(removed)
        return selected, sorted(excluded)
    return value, []


def prepare_metadata(value: Any, kind: str) -> tuple[Any, list[str], list[str]]:
    """SQLite/JSON 영속화 전에 목적 선별과 기존 비밀값 분리를 모두 적용한다."""
    selected, excluded_metadata = select_metadata(value, kind)
    clean, excluded_credentials = sanitize(selected)
    return clean, excluded_credentials, excluded_metadata


def policy_description() -> dict:
    """값 없이 정책명·종류별 제외 키만 manifest에 기록해 결과 해석을 돕는다."""
    return {
        "version": POLICY_VERSION,
        "excluded_fields_by_object_kind": {
            kind: sorted(fields) for kind, fields in sorted(EXCLUDED_BY_KIND.items())
        },
        "applied_before_persistence": True,
        "exclusion_paths_field": "excluded_metadata_fields",
        "unknown_fields": "preserved_unless_secret",
        "conditional_metadata": "email_ip_organization_identity_and_security_context_preserved",
    }
