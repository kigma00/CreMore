"""수집 단계의 공통 분류. 존재하지 않는 핸들러나 서로 다른 병합 순서를 방지한다."""

# 낮은 우선순위부터 병합한다. 수집 시각이나 재개 순서가 대표값을 바꾸지 않는다.
METADATA_PRIORITY = {"graphql_triggers": 10, "resource_list": 20,
                     "token_list": 30, "token_detail": 40}
TOKEN_LIST_HANDLERS = frozenset({"token_list", "resource_list", "graphql_triggers"})
SINGLE_OBJECT_HANDLERS = frozenset({"group", "project", "user", "agent_detail", "token_detail"})

# 실행 순서다. 위 METADATA_PRIORITY(병합 권위)와 달리 숫자가 작을수록 먼저 조회한다.
# 탐색과 목록을 같은 단계의 FIFO로 묶어 전체 조직 탐색이 끝나기 전에도 토큰을 발견한다.
TASK_PRIORITIES = {
    "group": 0, "project": 0, "subgroups": 0, "projects": 0,
    "service_accounts": 0, "agents": 0, "token_list": 0,
    "resource_list": 0, "graphql_triggers": 0,
    "token_detail": 10, "agent_detail": 10,
    "user": 20,
    "audit_plan": 30, "audit_events": 30,
}

# 작업별 제한 분류다. 새 핸들러는 우선순위와 분류를 모두 명시해야 한다.
TASK_RATE_CLASSES = {
    "group": "default", "project": "default", "subgroups": "default", "projects": "default",
    "service_accounts": "default", "agents": "default", "token_list": "default",
    "resource_list": "default", "graphql_triggers": "default",
    "token_detail": "default", "agent_detail": "default",
    "user": "user_details", "audit_plan": "default", "audit_events": "default",
}
RATE_CLASSES = frozenset(TASK_RATE_CLASSES.values())

# These use the same page transaction, global limiter and queue as native
# sources. They are scheduled only by the provider's explicit extensions.
for _handler in ("instance_pat", "instance_deploy_tokens", "instance_ssh_keys", "instance_deploy_keys",
                 "user_ssh_keys", "enterprise_ssh_keys", "project_deploy_keys", "ci_variables"):
    TASK_PRIORITIES[_handler] = 0
    TASK_RATE_CLASSES[_handler] = "default"
TASK_PRIORITIES["instance_ssh_keys"] = 10


def task_priority(handler: str) -> int:
    """새 핸들러에 실행 순서가 지정되지 않았으면 조용히 잘못 정렬하지 않고 거부한다."""
    if handler not in TASK_PRIORITIES:
        raise ValueError("작업 핸들러의 우선순위가 정의되지 않았습니다.")
    return TASK_PRIORITIES[handler]


def task_rate_class(handler: str) -> str:
    """알 수 없는 핸들러를 제한 없는 기본 작업으로 잘못 처리하지 않는다."""
    if handler not in TASK_RATE_CLASSES:
        raise ValueError("작업 핸들러의 속도 제한 분류가 정의되지 않았습니다.")
    return TASK_RATE_CLASSES[handler]


def task_scheduling_policy() -> dict:
    """재개 이관 여부와 실행 당시 순서를 설명할 고정 정책을 반환한다."""
    return {"version": "inventory_before_enrichment_v2", "order_by": ["priority", "seq"],
            "handler_priorities": dict(TASK_PRIORITIES), "handler_rate_classes": dict(TASK_RATE_CLASSES),
            "readiness": "endpoint_bucket_only_without_consuming_permits",
            "selection": "first_non_deferred_after_head_or_original_head",
            "recheck": "after_each_page_or_local_task", "retry_backoff_interleaving": False,
            "single_worker": True}
