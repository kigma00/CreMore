"""사람이 읽는 JSON의 필드 순서. 식별자 계산·원천 값·목록 순서는 변경하지 않는다."""

from typing import Any

# Token ID부터 읽고 운영에 필요한 정보와 감사 근거로 내려가도록 순서를 고정한다.
INVENTORY_ORDER = (
    "token_id",
    "credential_types",
    "summary",
    "metadata",
    "scope",
    "observed_scopes",
    "audit",
    "first_seen_at_this_run",
    "last_seen_at_this_run",
    "observations",
    "identity",
    "inventory_id",
    "schema_version",
    "metadata_policy",
    "metadata_merge_policy",
)
METADATA_ORDER = (
    "id",
    "name",
    "description",
    "username",
    "user_id",
    "owner",
    "created_by_user_id",
    "createdByUser",
    "resource_type",
    "resource_id",
    "agent_id",
    "scopes",
    "granular",
    "granular_scopes",
    "access_level",
    "active",
    "revoked",
    "expired",
    "status",
    "canAccessProject",
    "created_at",
    "updated_at",
    "expires_at",
    "expiresAt",
    "last_used_at",
    "last_used",
    "lastUsed",
    "last_used_ips",
)
ORDERS = {
    "inventory": INVENTORY_ORDER,
    "metadata": METADATA_ORDER,
    "summary": ("name", "description", "owner", "issuer", "created_at_from_audit"),
    "relation": (
        "id",
        "status",
        "evidence",
        "names_at_event",
        "candidate_ids",
        "profile_status",
        "profile",
        "username",
        "name",
        "state",
        "locked",
        "web_url",
        "webUrl",
    ),
    "profile": (
        "id",
        "username",
        "name",
        "state",
        "locked",
        "bot",
        "external",
        "organization",
        "job_title",
        "work_information",
        "email",
        "public_email",
        "web_url",
        "webUrl",
    ),
    "identity": ("instance", "namespace", "native_id", "scope"),
    "scope": ("kind", "id", "agent_id", "service_account_id"),
    "value_status": ("value", "status", "evidence"),
    "observation": (
        "source_id",
        "endpoint",
        "handler",
        "context",
        "observed_at",
        "metadata",
        "excluded_metadata_fields",
        "excluded_credential_fields",
        "request_url",
    ),
}
CHILD_CONTEXT = {
    "metadata": "metadata",
    "summary": "summary",
    "owner": "relation",
    "issuer": "relation",
    "profile": "profile",
    "identity": "identity",
    "scope": "scope",
    "observed_scopes": "scope",
    "observations": "observation",
    "name": "value_status",
    "created_at_from_audit": "value_status",
}


def order_for_json(value: Any, context: str = "default") -> Any:
    """있는 필드만 고정 순서로 배치하고 새로 추가된 필드는 마지막에 이름순으로 둔다."""
    if isinstance(value, dict):
        priorities = {key: index for index, key in enumerate(ORDERS.get(context, ()))}
        keys = sorted(value, key=lambda key: (priorities.get(key, len(priorities)), key))
        return {key: order_for_json(value[key], CHILD_CONTEXT.get(key, "default")) for key in keys}
    if isinstance(value, list):
        # 배열 순서에는 API 의미가 있을 수 있어 정렬하지 않고 내부 객체 순서만 통일한다.
        return [order_for_json(item, context) for item in value]
    return value
