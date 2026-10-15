"""토큰 관련 감사 기록을 선별하고, 명시적인 토큰 참조와 생성자 근거를 해석한다."""

import re
from datetime import UTC, datetime, timedelta

from .model import native_id

CREATION_TYPES = {"group": "group_deploy_token_created", "project": "deploy_token_created"}
# 구조화된 이벤트 유형이 없는 응답은 확인된 생성 메시지 전체 형식으로만 판별한다.
# 이름에 숫자나 'token_id'가 들어가도 마지막의 고정 접미부에서 ID를 읽는다.
CREATION_MESSAGE = re.compile(
    r"Created (?P<kind>project|group) deploy token with name: .*"
    r" with token_id: (?P<id>[1-9][0-9]*) with scopes: "
    r"\[(?::[a-z_]+(?:,\s*:[a-z_]+)*)?\]\.\Z",
    re.DOTALL,
)
AGENT_CREATION_MESSAGE = re.compile(
    r"Created cluster agent token '.*' with id (?P<id>[1-9][0-9]*)\Z", re.DOTALL
)

# event_name/event_type은 행동의 의미를, target_type/ID는 대상 개체를 식별한다.
# 알려지지 않은 토큰 관련 이벤트도 저장하며, 알 수 없는 행동을 임의로 '생성'으로 바꾸지 않는다.
EVENT_RULES = {
    "personal_access_token_created": ("personal_access_token", None, "created"),
    "personal_access_token_revoked": ("personal_access_token", None, "revoked"),
    "cluster_agent_token_created": ("kubernetes_agent_token", "project", "created"),
    "cluster_agent_token_revoked": ("kubernetes_agent_token", "project", "revoked"),
}
for _kind in ("group", "project"):
    for _suffix, _action in (
        ("created", "created"),
        ("deleted", "deleted"),
        ("creation_failed", "creation_failed"),
        ("deletion_failed", "deletion_failed"),
    ):
        EVENT_RULES[f"{_kind}_access_token_{_suffix}"] = ("resource_access_token", _kind, _action)
    for _suffix in ("created", "revoked", "destroyed", "creation_failed"):
        _prefix = "group_deploy_token" if _kind == "group" else "deploy_token"
        EVENT_RULES[f"{_prefix}_{_suffix}"] = ("deploy_token", _kind, _suffix)

# Ruby 모델의 명시적 대상 참조만 받는다. 서비스 계정 PAT도 PersonalAccessToken이다.
# PersonalAccessToken은 resource access token에도 사용될 수 있어 후보를 하나로 추정하지 않는다.
TARGET_NAMESPACES = {
    "PersonalAccessToken": {"personal_access_token", "resource_access_token"},
    "DeployToken": {"deploy_token"},
    "Ci::Trigger": {"pipeline_trigger_token"},
    "Clusters::AgentToken": {"kubernetes_agent_token"},
    "ErrorTracking::ClientKey": {"error_tracking_client_key"},
}


def event_types(event: dict) -> set[str]:
    """REST event_name과 event_type의 최상위·details 변형을 함께 읽고 모순을 숨기지 않는다."""
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    return {
        container[key]
        for container in (event, details)
        for key in ("event_name", "event_type")
        if isinstance(container.get(key), str) and container[key]
    }


def is_token_related(event: dict) -> bool:
    """구조화된 유형·대상 또는 알려진 토큰 메시지로 선별한다. 이름의 token 문자열은 쓰지 않는다."""
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    if any(re.search(r"(?:^|_)tokens?(?:_|$)", value) for value in event_types(event)):
        return True
    for container in (event, details):
        target_type = container.get("target_type")
        if isinstance(target_type, str) and (
            target_type in TARGET_NAMESPACES or target_type.endswith("Token")
        ):
            return True
    message = details.get("custom_message")
    if not isinstance(message, str):
        return False
    # 구조화된 토큰 참조가 없는 구형 응답을 위한 좁은 형식 검사다.
    return bool(
        re.match(
            r"^(?:Created|Revoked|Deleted|Rotated) (?:personal access|group access|project access|"
            r"group deploy|project deploy|cluster agent|pipeline trigger) token(?:\b|:)",
            message,
        )
    )


def token_audit_scopes(scope: dict, observations: list[dict]) -> set[tuple[str, int]]:
    """토큰이 실제 관찰된 Group/Project/User 문맥을 모아 API 간 중복 조회도 추적한다."""
    scopes = set()
    for value in [scope] + [o.get("context", {}).get("scope", {}) for o in observations]:
        identifier = positive_id(value.get("id"))
        if value.get("kind") in ("group", "project", "user") and identifier is not None:
            scopes.add((value["kind"], identifier))
    for observation in observations:
        owner = positive_id(observation.get("metadata", {}).get("user_id"))
        if owner is not None:
            scopes.add(("user", owner))
    return scopes


def utc_time(value: str) -> datetime:
    """시간대가 명시된 ISO 8601만 받아 UTC로 바꾼다. 임의의 로컬 시간은 추정하지 않는다."""
    if not isinstance(value, str):
        raise ValueError("감사 조회 시각은 시간대가 있는 ISO 8601 문자열이어야 합니다.")  # noqa: TRY004 - preserve the native validation contract
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("감사 조회 시각에 Z 또는 +09:00 같은 시간대를 지정하세요.")
    return result.astimezone(UTC)


def audit_windows(start: str, end: str):
    """최대 30일 조회 제한을 지키며 전체 지정 기간을 나눈다. 경계 중복은 event ID로 제거한다."""
    left = utc_time(start).replace(microsecond=0)
    stop = utc_time(end).replace(microsecond=0)
    if left > stop:
        raise ValueError("감사 조회 시작 시각이 이번 실행 시작 시각보다 늦습니다.")
    while True:
        right = min(left + timedelta(days=30), stop)
        yield {"created_after": left.isoformat(), "created_before": right.isoformat()}
        if right == stop:
            return
        # 두 API 경계가 모두 inclusive이므로 같은 경계 시각을 사용해 누락을 막는다.
        left = right


def positive_id(value):
    """감사 시스템의 -1·null 같은 가상 행위자 ID를 실제 사용자로 바꾸지 않는다."""
    try:
        return native_id(value)
    except ValueError:
        return None


def deploy_creation(event: dict, scope: dict) -> dict | None:
    """생성 이벤트만 해석한다. 이름만 있는 기록·상이한 소속·모순되는 ID는 결합하지 않는다."""
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    types = event_types(event)
    message = details.get("custom_message", "")
    match = CREATION_MESSAGE.fullmatch(message) if isinstance(message, str) else None
    expected = CREATION_TYPES[scope["kind"]]
    if types:
        if expected not in types:
            return None  # 폐기·삭제·생성 실패를 발급자 근거로 사용하지 않는다.
    elif match is None:
        return None
    result = {
        "token_id": None,
        "status": "unresolved",
        "reason": None,
        "issuer_id": None,
        "issuer_name": None,
        "created_at": None,
    }
    if types and types != {expected}:
        result["reason"] = "conflicting_event_types"
        return result
    if (
        event.get("entity_type") != scope["kind"].title()
        or positive_id(event.get("entity_id")) != scope["id"]
    ):
        result["reason"] = "scope_mismatch"
        return result
    ids = set()
    if match:
        if match["kind"] != scope["kind"]:
            result["reason"] = "scope_mismatch"
            return result
        ids.add(int(match["id"]))
    # target_id는 다른 자산의 ID일 수도 있다. DeployToken이라는 유형이 함께 있을 때만 쓴다.
    for container in (event, details):
        if container.get("target_type") == "DeployToken":
            target = positive_id(container.get("target_id"))
            if target is None:
                result["reason"] = "invalid_target_id"
                return result
            ids.add(target)
        elif container.get("target_type") is not None:
            result["reason"] = "unexpected_target_type"
            return result
        if "token_id" in container:
            token_id = positive_id(container["token_id"])
            if token_id is None:
                result["reason"] = "invalid_token_id"
                return result
            ids.add(token_id)
    if len(ids) != 1:
        result["reason"] = "conflicting_token_ids" if ids else "token_id_not_provided"
        return result
    result.update(token_id=ids.pop(), status="identified", reason=None)
    # 이름은 당시 감사 기록의 값이며, 현재 사용자 프로필과 구분해 보존한다.
    author_class = details.get("author_class", event.get("author_class"))
    if author_class in (None, "User"):
        result["issuer_id"] = positive_id(event.get("author_id"))
        name = event.get("author_name", details.get("author_name"))
        result["issuer_name"] = name if isinstance(name, str) else None
    try:
        result["created_at"] = utc_time(event.get("created_at")).isoformat()
    except (ValueError, TypeError):
        pass  # 이벤트 원본은 남기되 시각을 추정하지 않는다.
    return result


def audit_reference(event: dict, scope: dict) -> dict:
    """선별된 이벤트에 해석 상태를 붙인다. 개별 토큰 식별 실패는 저장 제외 조건이 아니다."""
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    result = {
        "status": "unresolved",
        "reason": "no_token_reference",
        "token_id": None,
        "namespaces": [],
        "action": "unknown",
        "issuer_id": None,
        "issuer_name": None,
        "actor_id": None,
        "actor_name": None,
        "created_at": None,
        "agent_id": None,
    }
    # 이벤트의 actor와 발생 시각은 모든 행동에 보존하되 생성 요약에는 created만 사용한다.
    if details.get("author_class", event.get("author_class")) in (None, "User"):
        result["actor_id"] = positive_id(event.get("author_id"))
        name = event.get("author_name", details.get("author_name"))
        result["actor_name"] = name if isinstance(name, str) else None
    try:
        result["created_at"] = utc_time(event.get("created_at")).isoformat()
    except (ValueError, TypeError):
        pass
    if (
        event.get("entity_type") != scope["kind"].title()
        or positive_id(event.get("entity_id")) != scope["id"]
    ):
        result["reason"] = "scope_mismatch"
        return result
    types = event_types(event)
    if len(types) > 1:
        result["reason"] = "conflicting_event_types"
        return result
    event_type = next(iter(types), None)
    rule = EVENT_RULES.get(event_type)
    if rule:
        namespace, kind, action = rule
        result.update(namespaces=[namespace], action=action)
        if action == "created":
            result.update(issuer_id=result["actor_id"], issuer_name=result["actor_name"])
        if kind is not None and kind != scope["kind"]:
            result["reason"] = "scope_mismatch"
            return result
    # UI에서 실제 확인한 Deploy 메시지의 엄격한 해석도 공통 수집 흐름 안에서 유지한다.
    if scope["kind"] in CREATION_TYPES:
        deploy = deploy_creation(event, scope)
        if deploy is not None:
            return {**result, **deploy, "namespaces": ["deploy_token"], "action": "created"}
    target_types = {
        str(c["target_type"]) for c in (event, details) if c.get("target_type") is not None
    }
    if len(target_types) > 1:
        result["reason"] = "conflicting_target_types"
        return result
    target_type = next(iter(target_types), None)
    namespaces = TARGET_NAMESPACES.get(target_type, set())
    ids = set()
    agent_ids = {positive_id(c["agent_id"]) for c in (event, details) if "agent_id" in c}
    if target_type == "Clusters::Agent":
        # Agent ID를 token ID로 오인하지 않는다. 정확한 생성 메시지의 마지막 ID만 읽는다.
        if rule and rule[0] != "kubernetes_agent_token":
            result["reason"] = "event_target_type_mismatch"
            return result
        agent_ids.update(positive_id(c["target_id"]) for c in (event, details) if "target_id" in c)
        if not agent_ids:
            result["reason"] = "agent_id_not_provided"
            return result
        message = details.get("custom_message")
        match = AGENT_CREATION_MESSAGE.fullmatch(message) if isinstance(message, str) else None
        if (
            match
            and (not types or types == {"cluster_agent_token_created"})
            and scope["kind"] == "project"
        ):
            ids.add(int(match["id"]))
            result.update(
                namespaces=["kubernetes_agent_token"],
                action="created",
                issuer_id=result["actor_id"],
                issuer_name=result["actor_name"],
            )
    if namespaces:
        if rule and rule[0] not in namespaces:
            result["reason"] = "event_target_type_mismatch"
            return result
        if not rule:
            result["namespaces"] = sorted(namespaces)
        for container in (event, details):
            if container.get("target_id") is not None:
                target_id = positive_id(container["target_id"])
                if target_id is None:
                    result["reason"] = "invalid_target_id"
                    return result
                ids.add(target_id)
    # User target_id는 bot 계정 ID일 수 있다. 알려진 토큰 이벤트의 별도 token_id만 사용한다.
    if rule:
        for container in (event, details):
            if "token_id" in container:
                token_id = positive_id(container["token_id"])
                if token_id is None:
                    result["reason"] = "invalid_token_id"
                    return result
                ids.add(token_id)
    if len(ids) != 1 or not result["namespaces"]:
        result["reason"] = (
            "conflicting_token_ids" if len(ids) > 1 else "token_id_or_type_not_provided"
        )
        return result
    result.update(token_id=ids.pop(), status="identified", reason=None)
    if agent_ids:
        if None in agent_ids or len(agent_ids) != 1:
            result.update(status="unresolved", reason="invalid_or_conflicting_agent_id")
        else:
            result["agent_id"] = agent_ids.pop()
    return result


class TokenAuditIndex:
    """정확한 ID 해시 조회 후 소속을 대조한다. 이름·사용자 ID만으로 토큰을 추정하지 않는다."""

    def __init__(self, records):
        """한 번의 수집 결과로 인덱스를 만든다. 감사가 먼저 도착해도 최종 목록과 대조한다."""
        self.by_id = {}
        for record in records:
            key = record["identity"]
            self.by_id.setdefault((key["namespace"], key["native_id"]), []).append(record)

    def match(self, reference: dict, scope: dict) -> tuple[list[str], str]:
        """같은 숫자의 다른 유형·소속을 제외하고 모호한 후보는 모두 미확정으로 남긴다."""
        if reference["status"] != "identified":
            return [], reference["reason"]
        matches = set()
        for namespace in reference["namespaces"]:
            for record in self.by_id.get((namespace, reference["token_id"]), []):
                if namespace == "personal_access_token":
                    # PAT는 전역 ID지만 수집한 소속/소유자 문맥이 확인된 경우에만 대응시킨다.
                    if (scope["kind"], scope["id"]) not in record["audit_scopes"]:
                        continue
                else:
                    key_scope = record["identity"]["scope"]
                    if (key_scope.get("kind"), key_scope.get("id")) != (scope["kind"], scope["id"]):
                        continue
                    if (
                        reference.get("agent_id") is not None
                        and key_scope.get("agent_id") != reference["agent_id"]
                    ):
                        continue
                matches.add(record["inventory_id"])
        ids = sorted(matches)
        return ids, "matched" if len(
            ids
        ) == 1 else "ambiguous_token_reference" if ids else "token_not_observed_in_scope"


def enrich_from_audit(summary: dict, evidence: list[dict]):
    """감사 근거를 공통 요약에 보강하고, 서로 다른 생성자·시각은 모순 상태로 표시한다."""
    # 폐기·변경·알 수 없는 이벤트의 actor는 해당 토큰의 생성자로 사용하지 않는다.
    evidence = [event for event in evidence if event["interpretation"].get("action") == "created"]
    if not evidence:
        return
    references = [{"event_id": e["event_id"], "scope": e["scope"]} for e in evidence]
    actors = {
        e["interpretation"]["issuer_id"]
        for e in evidence
        if e["interpretation"]["issuer_id"] is not None
    }
    times = {
        e["interpretation"]["created_at"]
        for e in evidence
        if e["interpretation"]["created_at"] is not None
    }
    if summary["issuer"]["status"] in ("not_provided", "null"):
        if len(actors) == 1:
            uid = next(iter(actors))
            names = sorted(
                {
                    e["interpretation"]["issuer_name"]
                    for e in evidence
                    if e["interpretation"]["issuer_id"] == uid
                    and e["interpretation"]["issuer_name"]
                }
            )
            summary["issuer"] = {
                "status": "observed_in_audit",
                "id": uid,
                "names_at_event": names,
                "evidence": references,
            }
        elif len(actors) > 1:
            summary["issuer"] = {
                "status": "conflicting_audit_evidence",
                "id": None,
                "candidate_ids": sorted(actors),
                "evidence": references,
            }
    summary["created_at_from_audit"] = {
        "status": "observed_in_audit"
        if len(times) == 1
        else "conflicting_audit_evidence"
        if times
        else "not_provided",
        "value": next(iter(times)) if len(times) == 1 else None,
        "evidence": references,
    }
