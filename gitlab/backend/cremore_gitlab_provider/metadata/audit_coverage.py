"""감사 질의 완료와 토큰 생성 근거의 검색 범위를 구분한다. 조회 기간은 변경하지 않는다."""

from .audit import utc_time


def merge_ranges(ranges: list[tuple]) -> list[tuple]:
    """맞닿거나 중복된 완료 창만 합치고 실패한 중간 기간을 채우지 않는다."""
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def query_status(tasks: list[dict]) -> str:
    """예약 작업의 완료 상태를 반환한다. 생성 이벤트 발견 여부는 별도로 판단한다."""
    states = {task["status"] for task in tasks}
    return ("failed" if "failed" in states else "pending" if "pending" in states else
            "complete" if any(task["handler"] == "audit_events" for task in tasks) else "not_scheduled")


def creation_time(metadata: dict) -> tuple:
    """토큰 API의 생성일만 사용한다. 감사로 복원한 날짜를 API 제공값으로 바꾸지 않는다."""
    if "created_at" not in metadata:
        return None, "not_provided"
    if metadata["created_at"] is None:
        return None, "null"
    try:
        return utc_time(metadata["created_at"]), "known"
    except (ValueError, TypeError, OverflowError):
        return None, "invalid"


class CreationCoverageIndex:
    """조회 창을 소속마다 한 번 합쳐 여러 토큰에 재사용하고 토큰별 생성시각을 대조한다."""

    def __init__(self, tasks_by_scope: dict, config: dict, notes: list[dict]):
        """완료한 창만 검색 완료 범위로 인정한다. 일부 페이지만 받은 창은 포함하지 않는다."""
        self.enabled = bool(config.get("include_audit_events") or config.get("include_deploy_token_audit"))
        self.config = config
        self.scopes = {}
        limits = {(note["scope"].get("kind"), note["scope"].get("id")): note["scope"]
                  for note in notes if note["code"] == "AUDIT_HISTORY_LIMITED_BY_CONFIG"}
        self.global_stop = next((note["scope"].get("reason") for note in reversed(notes)
                                 if note["code"] == "COLLECTION_STOPPED"), None)
        for key, tasks in tasks_by_scope.items():
            complete, planned = [], []
            incomplete = 0
            for task in tasks:
                if task["handler"] != "audit_events":
                    continue
                try:
                    period = (utc_time(task["params"]["created_after"]), utc_time(task["params"]["created_before"]))
                    if period[0] > period[1]:
                        raise ValueError("잘못된 감사 기간")
                except (KeyError, ValueError, TypeError, OverflowError):
                    incomplete += 1
                    continue
                planned.append(period)
                if task["status"] == "complete":
                    complete.append(period)
                else:
                    incomplete += 1
            status = query_status(tasks)
            reasons = []
            if status in {"failed", "pending"}:
                errors = [task.get("error", {}).get("code") for task in tasks if task.get("error")]
                reason = self.global_stop if status == "pending" else next(iter(errors), None)
                reasons.append(self.stop_reason(reason) if reason else "query_incomplete")
            if key in limits:
                reasons.append("lookback_days")
            if config.get("audit_created_after"):
                reasons.append("configured_start")
            self.scopes[key] = {"scope": {"kind": key[0], "id": key[1]}, "query_status": status,
                                "planned": merge_ranges(planned), "completed": merge_ranges(complete),
                                "incomplete_windows": incomplete, "stop_reasons": list(dict.fromkeys(reasons))}

    @staticmethod
    def stop_reason(code: str | None) -> str:
        """운용 오류를 제한 사유로 표시하되 미조회 구간을 조회 완료로 바꾸지 않는다."""
        return {"REQUEST_BUDGET_EXCEEDED": "request_budget", "RATE_LIMIT_CIRCUIT_OPEN": "rate_limit",
                "RETRY_LATER": "retry_later", "AUTHENTICATION_FAILED": "authentication_failed"}.get(code, "query_failed")

    def describe(self, metadata: dict, scopes: set[tuple], evidence: list[dict]) -> dict:
        """생성 이벤트 발견·기간 미포함·미확인을 구분한다. 단순 미발견을 부재로 해석하지 않는다."""
        created, date_status = creation_time(metadata)
        # 유형별 제공 가능성을 추정하지 않고 현재 수집기가 조회하는 Group/Project만 평가한다.
        # User/Instance는 바깥의 unqueried_scopes 및 query_scope로 별도 표시한다.
        relevant = {scope for scope in scopes if scope[0] in {"group", "project"}}
        reports, completed, point_coverage = [], [], []
        for key in sorted(relevant):
            value = self.scopes.get(key)
            if value is None:
                reason = "audit_disabled" if not self.enabled else (
                    self.stop_reason(self.global_stop) if self.global_stop else "scope_not_scheduled")
                value = {"scope": {"kind": key[0], "id": key[1]}, "query_status": "not_scheduled",
                         "planned": [], "completed": [], "incomplete_windows": 0, "stop_reasons": [reason]}
            ranges = value["completed"]
            # 완료한 범위가 없으면 미확인이다. any([])로 미조회를 범위 밖(false)으로 바꾸지 않는다.
            covered = any(start <= created <= end for start, end in ranges) if created is not None and ranges else None
            point_coverage.append(covered)
            completed.extend(ranges)
            reports.append({"scope": value["scope"], "query_status": value["query_status"],
                            "completed_ranges": [{"start": start.isoformat(), "end": end.isoformat()} for start, end in ranges],
                            "planned_ranges": [{"start": start.isoformat(), "end": end.isoformat()} for start, end in value["planned"]],
                            "incomplete_windows": value["incomplete_windows"], "token_creation_time_covered": covered,
                            "stop_reasons": value["stop_reasons"]})
        creation_found = any(event["interpretation"].get("action") == "created" for event in evidence)
        # 소속별 미확인도 보존한다. all([None])은 미확인을 false로 바꾸므로 그대로 사용하지 않는다.
        if any(value is False for value in point_coverage):
            covered = False  # 완료한 범위가 생성시각을 포함하지 않는 소속이 확인됐다.
        elif point_coverage and all(value is True for value in point_coverage):
            covered = True
        else:
            covered = None  # 판정할 소속이 없거나, 미포함 근거 없이 미확인 소속이 남아 있다.
        searched = bool(completed)
        incomplete = any(report["query_status"] in {"failed", "pending"} or report["incomplete_windows"] for report in reports)
        unscheduled = any(report["query_status"] == "not_scheduled" for report in reports)
        if creation_found:
            status, reason = "found", "matched_creation_event"
        elif not self.enabled:
            status, reason = "not_searched", "audit_disabled"
        elif incomplete or (searched and unscheduled):
            status, reason = "search_incomplete", "selected_scope_or_window_incomplete"
        elif not searched:
            status, reason = "not_searched", "no_completed_group_project_window"
        elif created is not None and covered is not True:
            status, reason = "search_range_did_not_cover", "creation_time_outside_completed_ranges"
        elif created is None:
            # 생성일이 없는 경우 상태값만 읽는 소비자도 범위 포함 여부 미확인을 구분한다.
            status, reason = "searched_not_found_range_unverifiable", "creation_time_unavailable_for_selected_ranges"
        else:
            status, reason = "searched_not_found", "no_matching_creation_event_in_selected_ranges"
        reasons = list(dict.fromkeys(reason for report in reports for reason in report["stop_reasons"]))
        if not self.enabled and "audit_disabled" not in reasons:
            reasons.append("audit_disabled")
        # 생성 근거를 찾았으면 토큰 수준 미확인 사유는 없다. 조회 제한·실패 사실은
        # scope_coverage와 바깥 audit.query_status에 남아 있어 전체 이력 완주로 오인하지 않는다.
        if creation_found:
            reasons = []
        # 중단 사유가 여러 개면 운용 중단을 우선 표기하고 전체 목록도 보존한다.
        priority = ("request_budget", "rate_limit", "retry_later", "authentication_failed", "query_failed", "query_incomplete",
                    "audit_disabled", "scope_not_collected", "scope_not_scheduled", "lookback_days", "configured_start")
        return {"status": status, "reason": reason, "evaluation_scope": "group_project_queries_only",
                "token_created_at_known": created is not None, "token_created_at_status": date_status,
                "token_created_at": created.isoformat() if created else None,
                "token_creation_time_covered": covered,
                "oldest_window_searched": min((start for start, _ in completed), default=None).isoformat() if completed else None,
                "newest_window_searched": max((end for _, end in completed), default=None).isoformat() if completed else None,
                "stop_reason": next((reason for reason in priority if reason in reasons), None),
                "stop_reasons": reasons, "scope_coverage": reports}
