"""1번 분류 Token의 기존 발급 목록만 발견하는 API 어댑터와 BFS 실행기."""

import logging
import re
import traceback
from dataclasses import asdict
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from .audit import audit_reference, audit_windows, is_token_related, utc_time
from .config import Config
from .handlers import SINGLE_OBJECT_HANDLERS
from .http import Client, CollectionError, next_page
from .model import identity, native_id, now, stable_id
from .provenance import code_provenance
from .storage import Store

LOG = logging.getLogger(__name__)

# 문서화된 Trigger 메타데이터만 명시한다. 비밀값인 token 필드는 요청하지 않는다.
# Experiment 필드가 현재 SaaS에 없으면 errors/coverage에 남기고 REST 결과는 보존한다.
TRIGGER_QUERY = """query TriggerMetadata($fullPath: ID!, $after: String, $first: Int!) {
  project(fullPath: $fullPath) {
    pipelineTriggers(first: $first, after: $after) {
      nodes { id description canAccessProject expiresAt lastUsed
              owner { id username name state webUrl } }
      pageInfo { hasNextPage endCursor }
    }
  }
}"""


def graphql_diagnostics(errors: list) -> dict:
    """서버 오류 전문 대신 스키마 이름·query 줄/열만 남겨 보강 실패를 진단한다."""
    result = []
    for error in errors:
        if not isinstance(error, dict):
            continue
        info = {}
        for key in ("code", "typeName", "fieldName"):
            value = (error.get("extensions") or {}).get(key)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,100}", value):
                info[key] = value
        info["locations"] = [
            {key: place[key] for key in ("line", "column") if type(place.get(key)) is int}
            for place in error.get("locations", [])
            if isinstance(place, dict)
        ]
        result.append(info)
    return {"graphql_errors": result, "query_definition": "collector.py:TRIGGER_QUERY"}


class Collector:
    """자산 발견 → 페이지 수집 → 정확한 식별 → 저장·보강 작업을 순서대로 실행한다."""

    def __init__(self, config: Config, client: Client, store: Store, extensions=None):
        """전송 계층을 주입받아 실제 계정 없이 같은 수집 로직을 검증할 수 있다."""
        self.config, self.client, self.store = config, client, store
        self.principal_id = None
        self.extensions = extensions

    def initialize(self):
        """수집용 인증의 사용자와 명시한 범위를 기록한다. 재개 계정 변경은 거부한다."""
        user = self.client.request(self.client.rest_url("/user")).body
        if not isinstance(user, dict):
            raise CollectionError("INVALID_AUTH_RESPONSE", "/user 응답이 객체가 아닙니다.")
        self.principal_id = native_id(user.get("id"))
        saved = self.store.get_setting("principal_id")
        if saved is not None and saved != self.principal_id:
            raise CollectionError(
                "PRINCIPAL_CHANGED", "재개 계정이 이전 계정과 다릅니다. 새 출력 경로를 사용하세요."
            )
        if self.extensions:
            self.extensions.verify_principal(user)
        with self.store.db:
            self.store.set_setting("principal_id", self.principal_id)
            self.store.set_setting("base_url", self.config.base_url.rstrip("/"))
            self.store.set_setting("config", asdict(self.config))
            self.store.save_asset("user", self.principal_id, user, "/user")
            self.store.set_setting("fatal_error", None)
            for feature in (
                "include_self_pat",
                "include_enterprise_pat",
                "include_resource_access_tokens",
                "include_service_accounts",
                "include_graphql",
                "enrich_users",
            ):
                if not getattr(self.config, feature):
                    self.store.note("DISABLED_BY_CONFIG", {"feature": feature})
            if not self.config.audit_enabled:
                self.store.note("DISABLED_BY_CONFIG", {"feature": "include_audit_events"})
            elif self.config.include_deploy_token_audit:
                self.store.note(
                    "LEGACY_AUDIT_OPTION",
                    {
                        "replacement": "include_audit_events",
                        "collection_scope": "token_related_group_project_events",
                    },
                )
            if self.config.include_self_pat:
                # 관리자 권한이 있어도 자동으로 모든 사용자의 PAT를 훑지 않는다.
                self.add_list(
                    "/personal_access_tokens",
                    "personal_access_token",
                    {"kind": "user", "id": self.principal_id},
                    {"user_id": self.principal_id},
                )
            for group_id in self.config.group_ids:
                self.store.add_task("group", f"/groups/{group_id}", {})
            for project_id in self.config.project_ids:
                self.store.add_task("project", f"/projects/{project_id}", {})
            if self.extensions:
                self.extensions.initialize(self)

    def add_list(self, path: str, family: str, scope: dict, params=None):
        """Token 목록 작업을 등록한다. state=active 같은 임의의 필터를 추가하지 않는다."""
        return self.store.add_task("token_list", path, {"family": family, "scope": scope}, params)

    def add_user(self, value):
        """Token의 소유·발급 참조에 등장한 사용자만 조회한다."""
        if not self.config.enrich_users or value is None:
            return
        try:
            uid = native_id(value, "User")
        except ValueError:
            return  # 잘못된 참조를 추정 사용자 ID로 변환하지 않는다.
        self.store.add_task("user", f"/users/{uid}", {"user_id": uid})

    def token(self, item: dict, task: dict, url: str, detail: bool = False):
        """공식 토큰 ID와 관계를 확인하고 저장 계층에서 승인된 메타데이터 선별을 적용한다."""
        context = task["spec"]["context"]
        family, scope = context["family"], context["scope"]
        token_id = native_id(
            item.get("id"), "Ci::Trigger" if task["spec"]["handler"] == "graphql_triggers" else None
        )
        key = identity(self.config.base_url, family, token_id, scope)
        self.store.save_record(key, family, scope, item, task, url)
        self.add_user(item.get("user_id"))
        self.add_user(item.get("created_by_user_id"))
        if isinstance(item.get("owner"), dict):
            self.add_user(item["owner"].get("id"))
        # GraphQL의 실험 필드는 REST와 별도 출처로 저장한다. 추가 상세 작업은 REST 목록에서만 생성한다.
        if detail or task["spec"]["handler"] == "graphql_triggers":
            return
        path = task["spec"]["path"]
        if family == "personal_access_token":
            # 조직 Owner 인증으로 다른 사용자 PAT 상세를 읽을 수 있다고 가정하지 않는다.
            if item.get("user_id") == self.principal_id:
                self.store.add_task("token_detail", f"/personal_access_tokens/{token_id}", context)
        elif family not in {
            "group_service_account_pat",
            "project_service_account_pat",
            "error_tracking_client_key",
        }:
            self.store.add_task("token_detail", f"{path}/{token_id}", context)

    def handle(self, task: dict, body, url: str) -> int:
        """각 공식 응답의 구조를 확인하고 후속 작업을 등록한다. 숫자는 관찰한 레코드 수다."""
        spec = task["spec"]
        handler, context, path = spec["handler"], spec["context"], spec["path"]
        if self.extensions:
            from .extensions import PATHS
            if handler in PATHS:
                return self.extensions.handle(self, task, body)
        if handler in SINGLE_OBJECT_HANDLERS:
            if not isinstance(body, dict):
                raise CollectionError(
                    "INVALID_RESPONSE_SHAPE", "단건 조회에서 JSON 객체가 필요합니다."
                )
            if handler == "token_detail":
                if native_id(body.get("id")) != int(path.rsplit("/", 1)[1]):
                    raise CollectionError(
                        "RESPONSE_ID_MISMATCH", "상세 응답의 ID가 요청 대상과 다릅니다."
                    )
                self.token(body, task, url, detail=True)
                return 1
            object_id = native_id(body.get("id"))
            if object_id != int(path.rsplit("/", 1)[1]):
                raise CollectionError(
                    "RESPONSE_ID_MISMATCH", "자산 응답의 ID가 요청 대상과 다릅니다."
                )
            self.store.save_asset(
                "agent" if handler == "agent_detail" else handler, object_id, body, path
            )
            if handler == "group":
                self.group_tasks(object_id, body)
            elif handler == "project":
                self.project_tasks(object_id, body)
            return 1
        if not isinstance(body, list) or any(not isinstance(item, dict) for item in body):
            raise CollectionError(
                "INVALID_RESPONSE_SHAPE", "목록 조회에서 JSON 객체 배열이 필요합니다."
            )
        audit_retained = 0
        for item in body:
            item_id = native_id(item.get("id"))
            if handler == "audit_events":
                # 토큰 관련 기록만 저장한다. 보존 여부와 특정 토큰 매핑 성공 여부는 별개다.
                if not is_token_related(item):
                    self.store.save_filtered_audit_event(item, task)
                    continue
                audit_retained += 1
                interpretation = audit_reference(item, context["scope"])
                self.store.save_audit_event(item, interpretation, task, url)
                if interpretation["status"] == "identified":
                    self.add_user(interpretation["actor_id"])
            elif handler in {"subgroups", "projects"}:
                kind = "group" if handler == "subgroups" else "project"
                self.store.save_asset(kind, item_id, item, path)
                self.store.add_task(kind, f"/{kind}s/{item_id}", {})
            elif handler == "service_accounts":
                self.store.save_asset("user", item_id, item, path)
                scope = context["scope"]
                family = f"{scope['kind']}_service_account_pat"
                self.add_list(
                    f"{path}/{item_id}/personal_access_tokens",
                    family,
                    {**scope, "service_account_id": item_id},
                )
                self.add_user(item_id)
            elif handler == "agents":
                self.store.save_asset("agent", item_id, item, path)
                scope = {"kind": "project", "id": context["project_id"], "agent_id": item_id}
                self.store.add_task("agent_detail", f"{path}/{item_id}", {"scope": scope})
                self.add_list(f"{path}/{item_id}/tokens", "kubernetes_agent_token", scope)
            elif handler == "resource_list":
                # 통합 API의 resource_type/resource_id를 사용해 단독 API와 같은 키를 만든다.
                kind = item.get("resource_type")
                if kind not in ("group", "project"):
                    raise CollectionError(
                        "UNKNOWN_RESOURCE_TYPE",
                        "통합 Token 응답에 알려지지 않은 resource_type이 있습니다.",
                    )
                resource_id = native_id(item.get("resource_id"))
                scope = {"kind": kind, "id": resource_id}
                synthetic = {
                    **task,
                    "spec": {**spec, "context": {"family": f"{kind}_access_token", "scope": scope}},
                }
                self.token(item, synthetic, url, detail=True)
                self.store.add_task(
                    "token_detail",
                    f"/{kind}s/{resource_id}/access_tokens/{item_id}",
                    synthetic["spec"]["context"],
                )
            elif handler == "token_list":
                self.token(item, task, url)
            else:
                raise CollectionError("UNKNOWN_HANDLER", "정의되지 않은 수집 단계입니다.")
        if handler == "audit_events":
            self.store.count_audit_page(task["id"], len(body), audit_retained)
        return len(body)

    def group_tasks(self, group_id: int, metadata: dict):
        """지정 그룹의 직접 하위 자산을 순회한다. 공유받은 외부 프로젝트는 제외한다."""
        scope = {"kind": "group", "id": group_id}
        base = f"/groups/{group_id}"
        if self.config.audit_enabled:
            self.store.add_task("audit_plan", base + "/audit_events", {"scope": scope})
        self.store.add_task("subgroups", base + "/subgroups", {})
        self.store.add_task(
            "projects",
            base + "/projects",
            {},
            {"with_shared": "false", "include_subgroups": "false"},
        )
        self.add_list(base + "/access_tokens", "group_access_token", scope)
        self.add_list(base + "/deploy_tokens", "group_deploy_token", scope)
        if self.config.include_service_accounts:
            self.store.add_task("service_accounts", base + "/service_accounts", {"scope": scope})
        # parent_id가 미반환이면 최상위 그룹이라고 임의 추론하지 않는다.
        if "parent_id" in metadata and metadata["parent_id"] is None:
            if self.config.include_enterprise_pat:
                self.add_list(
                    base + "/manage/personal_access_tokens", "personal_access_token", scope
                )
            if self.config.include_resource_access_tokens:
                self.store.add_task(
                    "resource_list", base + "/manage/resource_access_tokens", {"scope": scope}
                )
        elif "parent_id" not in metadata:
            self.store.note("TOP_LEVEL_GROUP_UNCONFIRMED", scope)
        if self.extensions:
            self.extensions.group(self, group_id, metadata)

    def project_tasks(self, project_id: int, metadata: dict):
        """1번에 포함된 프로젝트 Token들과 보강에 필요한 Agent/서비스 계정을 조회한다."""
        scope = {"kind": "project", "id": project_id}
        base = f"/projects/{project_id}"
        if self.config.audit_enabled:
            self.store.add_task("audit_plan", base + "/audit_events", {"scope": scope})
        for suffix, family in (
            ("access_tokens", "project_access_token"),
            ("deploy_tokens", "project_deploy_token"),
            ("triggers", "pipeline_trigger_token"),
            ("error_tracking/client_keys", "error_tracking_client_key"),
        ):
            self.add_list(base + "/" + suffix, family, scope)
        self.store.add_task("agents", base + "/cluster_agents", {"project_id": project_id})
        if self.config.include_service_accounts:
            self.store.add_task("service_accounts", base + "/service_accounts", {"scope": scope})
        if self.config.include_graphql:
            context = {
                "family": "pipeline_trigger_token",
                "scope": scope,
                "full_path": metadata.get("path_with_namespace"),
            }
            self.store.add_task("graphql_triggers", "/api/graphql", context)

    def graphql_page(self, task: dict) -> tuple[list, str | None, dict | None]:
        """REST에서 부족한 Trigger 필드를 보강하며 null·부분 오류를 성공한 빈 목록과 구별한다."""
        context = task["spec"]["context"]
        if not context.get("full_path"):
            raise CollectionError(
                "MISSING_PROJECT_PATH", "GraphQL 보강에 필요한 프로젝트 경로를 확인하지 못했습니다."
            )
        variables = {
            "fullPath": context["full_path"],
            "after": task["cursor"],
            "first": self.config.page_size,
        }
        body = self.client.request("/api/graphql", TRIGGER_QUERY, variables).body
        if not isinstance(body, dict):
            raise CollectionError("INVALID_GRAPHQL_RESPONSE", "GraphQL 응답이 객체가 아닙니다.")
        partial = bool(body.get("errors"))
        diagnostic = graphql_diagnostics(body["errors"]) if partial else None
        data = body.get("data")
        if data is not None and not isinstance(data, dict):
            raise CollectionError("INVALID_GRAPHQL_RESPONSE", "GraphQL data가 객체가 아닙니다.")
        project = (data or {}).get("project")
        connection = project.get("pipelineTriggers") if isinstance(project, dict) else None
        if connection is None:
            raise CollectionError(
                "GRAPHQL_ERROR" if partial else "GRAPHQL_VISIBILITY_UNKNOWN",
                "GraphQL Token 목록을 조회하지 못했습니다. 스키마·기능·권한을 확인하세요.",
                details=diagnostic,
            )
        if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list):
            raise CollectionError(
                "INVALID_GRAPHQL_RESPONSE", "GraphQL 연결 응답의 nodes가 배열이 아닙니다."
            )
        info = connection.get("pageInfo")
        if not isinstance(info, dict) or type(info.get("hasNextPage")) is not bool:
            raise CollectionError("INVALID_PAGINATION", "GraphQL pageInfo를 확인하지 못했습니다.")
        cursor = info.get("endCursor") if info["hasNextPage"] else None
        if info["hasNextPage"] and (
            not isinstance(cursor, str) or not cursor or cursor == task["cursor"]
        ):
            raise CollectionError("INVALID_PAGINATION", "GraphQL 다음 cursor가 없거나 반복됩니다.")
        return connection["nodes"], cursor, diagnostic

    def process(self, task: dict):
        """HTTP 요청은 DB 트랜잭션 밖에서, 페이지 저장·후속 큐·체크포인트는 안에서 수행한다."""
        spec = task["spec"]
        if self.extensions:
            from .extensions import PATHS
            if spec["handler"] in PATHS:
                self.extensions.check_task(task)
        if task["pages"] >= self.config.max_pages_per_task:
            raise CollectionError(
                "PAGE_LIMIT_REACHED",
                "설정한 페이지 한도에 도달했습니다. 완전 수집으로 표시하지 않습니다.",
            )
        if spec["handler"] == "audit_plan":
            scope = spec["context"]["scope"]
            metadata = self.store.asset_metadata(scope["kind"], scope["id"]) or {}
            start = self.config.audit_created_after or metadata.get("created_at")
            end = self.store.get_setting("started_at")
            horizon = None
            if self.config.audit_lookback_days is not None:
                horizon = utc_time(end) - timedelta(days=self.config.audit_lookback_days)
                if start is None or utc_time(start) < horizon:
                    # 정책으로 조회를 줄인 사실을 기록하며 GitLab 보존 만료로 표시하지 않는다.
                    with self.store.db:
                        self.store.note(
                            "AUDIT_HISTORY_LIMITED_BY_CONFIG",
                            {
                                **scope,
                                "requested_start": start,
                                "effective_start": horizon.isoformat(),
                                "lookback_days": self.config.audit_lookback_days,
                                "provider_retention_assumed": False,
                            },
                        )
                    start = horizon.isoformat()
            if start is None:
                raise CollectionError(
                    "AUDIT_START_UNKNOWN",
                    "자산 생성 시각이 없습니다. audit_created_after를 지정한 새 실행으로 조회하세요.",
                )
            # 실행 시작 시각을 고정해 재개 때 조회 기간·작업 ID가 바뀌지 않게 한다.
            with self.store.db:
                for window in audit_windows(start, end):
                    params = {**window, "pagination": "keyset", "order_by": "id", "sort": "desc"}
                    self.store.add_task("audit_events", spec["path"], spec["context"], params)
                self.store.page_done(task, task["id"], 0)
            return
        if spec["handler"] == "graphql_triggers":
            page_key = stable_id({"cursor": task["cursor"]})
            if self.store.has_page(task["id"], page_key):
                raise CollectionError("PAGINATION_LOOP", "GraphQL cursor 순환이 감지되었습니다.")
            nodes, cursor, partial = self.graphql_page(task)
            with self.store.db:
                for node in nodes:
                    if not isinstance(node, dict):
                        raise CollectionError(
                            "PARTIAL_GRAPHQL_NODE", "GraphQL 목록에 null/비정상 노드가 있습니다."
                        )
                    self.token(node, task, "/api/graphql", detail=True)
                if partial:
                    # 유효한 일부 관찰은 저장하되 cursor를 전진시켜 누락을 숨기지 않는다.
                    self.store.error(
                        task,
                        "GRAPHQL_PARTIAL",
                        "부분 GraphQL 오류: 수집한 관찰을 보존하고 재개 위치를 유지합니다.",
                        location="collector.py:TRIGGER_QUERY",
                        details=partial,
                    )
                else:
                    self.store.page_done(task, page_key, len(nodes), cursor=cursor)
            return
        is_list = spec["handler"] not in SINGLE_OBJECT_HANDLERS
        params = {**spec["params"], **({"per_page": self.config.page_size} if is_list else {})}
        if is_list and params.get("pagination") != "keyset":
            params["page"] = 1
        url = task["next_url"] or self.client.rest_url(spec["path"], params)
        if self.store.has_page(task["id"], url):
            raise CollectionError("PAGINATION_LOOP", "REST 다음 페이지가 이미 처리한 페이지입니다.")
        response = self.client.request(url)
        following = (
            next_page(self.client, url, response.headers, len(response.body), self.config.page_size)
            if is_list and isinstance(response.body, list)
            else None
        )
        if following and urlsplit(following).path != urlsplit(url).path:
            raise CollectionError(
                "PAGINATION_SCOPE_CHANGED", "다음 페이지가 다른 API 경로를 가리킵니다."
            )
        if following:
            before, after = parse_qs(urlsplit(url).query), parse_qs(urlsplit(following).query)
            if any(before.get(key) != after.get(key) for key in spec["params"]):
                raise CollectionError(
                    "PAGINATION_SCOPE_CHANGED", "다음 페이지가 고정 조회 범위를 변경했습니다."
                )
        with self.store.db:
            count = self.handle(task, response.body, url)
            self.store.page_done(task, url, count, next_url=following)

    def run(self):
        """실행 코드·운용 설정을 기록하고 중단 후에도 진단 가능한 요청 통계를 보존한다."""
        provenance = code_provenance()
        entry = {
            "started_at": now(),
            "code_provenance": provenance,
            "transport_settings": self.config.transport_settings(),
            "scope_fingerprint": self.config.fingerprint(),
        }
        before_requests, before_retries = self.client.requests, self.client.retries
        with self.store.db:
            self.store.set_setting("code_provenance", provenance)
        try:
            self.initialize()
            self.run_tasks()
        finally:
            entry.update(
                finished_at=now(),
                requests=self.client.requests - before_requests,
                retries=self.client.retries - before_retries,
            )
            with self.store.db:
                history = self.store.get_setting("execution_history") or []
                self.store.set_setting("execution_history", [*history, entry])

    def run_tasks(self):
        """범위별 실패는 계속 수집하되 인증·전역 제한은 남은 작업을 보존하고 중단한다."""
        while task := self.store.next_task():
            spec = task["spec"]
            LOG.info(
                "stage=%s task=%s path=%s page=%s",
                spec["handler"],
                task["id"][:12],
                spec["path"],
                task["pages"] + 1,
            )
            try:
                self.process(task)
            except (CollectionError, ValueError, KeyError, TypeError) as exc:
                code = exc.code if isinstance(exc, CollectionError) else "RESPONSE_SCHEMA_ERROR"
                message = (
                    str(exc)
                    if isinstance(exc, CollectionError)
                    else "응답 필드·타입을 처리하지 못했습니다. code_location을 확인하세요."
                )
                trace = traceback.extract_tb(exc.__traceback__)[-1]
                location = f"{trace.filename}:{trace.lineno} ({trace.name})"
                with self.store.db:
                    self.store.error(
                        task,
                        code,
                        message,
                        getattr(exc, "status", None),
                        location,
                        getattr(exc, "details", None),
                    )
                LOG.error(
                    "stage=%s code=%s path=%s location=%s",
                    spec["handler"],
                    code,
                    spec["path"],
                    location,
                )
                if code in {
                    "AUTHENTICATION_FAILED",
                    "REQUEST_BUDGET_EXCEEDED",
                    "RATE_LIMIT_CIRCUIT_OPEN",
                    "RETRY_LATER",
                }:
                    with self.store.db:
                        self.store.note(
                            "COLLECTION_STOPPED",
                            {"reason": code, "remaining_tasks_preserved": True},
                        )
                    break
