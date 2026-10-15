"""토큰별 감사 검색 사실을 검증한다. 이벤트 부재나 유형별 제공 가능성은 추정하지 않는다."""

import unittest

from ..audit_coverage import CreationCoverageIndex

SCOPE = ("project", 100)


def window(start, end, status="complete", code=None, pages=1):
    """실제 coverage 형식으로 완료/실패/대기 창을 재현한다."""
    return {"handler": "audit_events", "status": status, "pages_completed": pages,
            "params": {"created_after": start, "created_before": end},
            "error": {"code": code} if code else None}


def index(tasks, notes=None, **config):
    """다른 소속을 섞지 않는 독립적인 검색 범위 인덱스를 만든다."""
    return CreationCoverageIndex({SCOPE: tasks}, {"include_audit_events": True, **config}, notes or [])


class CreationEvidenceTests(unittest.TestCase):
    """발견·선택 범위 미발견·범위 미포함·미조회·중단을 각각 검사한다."""

    def setUp(self):
        """기본 fixture는 9월 1~20일 감사 질의 한 개를 완주한 경우다."""
        self.tasks = [window("2026-09-01T00:00:00Z", "2026-09-20T00:00:00Z")]
        self.metadata = {"created_at": "2026-09-10T00:00:00Z"}

    def test_matching_creation_found_even_with_partial_query_and_unknown_api_date(self):
        """발급 기록을 발견했으면 일부 창 실패가 있어도 발견 사실과 미완주를 함께 남긴다."""
        tasks = [window("2026-09-01T00:00:00Z", "2026-09-20T00:00:00Z", "failed", "REQUEST_BUDGET_EXCEEDED")]
        result = index(tasks).describe({}, {SCOPE}, [{"interpretation": {"action": "created"}}])
        self.assertEqual(result["status"], "found")
        self.assertFalse(result["token_created_at_known"])
        self.assertIsNone(result["token_creation_time_covered"])
        self.assertIsNone(result["oldest_window_searched"])
        self.assertIsNone(result["stop_reason"])
        self.assertEqual(result["stop_reasons"], [])
        self.assertEqual(result["scope_coverage"][0]["stop_reasons"], ["request_budget"])
        self.assertEqual(result["scope_coverage"][0]["incomplete_windows"], 1)

    def test_known_date_in_completed_range_is_searched_not_found(self):
        """미발견은 지정한 API/기간에만 해당하며 전체 GitLab의 기록 부재를 뜻하지 않는다."""
        result = index(self.tasks).describe(self.metadata, {SCOPE}, [])
        self.assertEqual(result["status"], "searched_not_found")
        self.assertTrue(result["token_creation_time_covered"])
        self.assertEqual(result["evaluation_scope"], "group_project_queries_only")

    def test_found_has_no_token_stop_reason_but_keeps_scope_policy_limits(self):
        """발견 성공과 이력 범위 제한을 분리하되 소속의 제한 사실을 지우지 않는다."""
        notes = [{"code": "AUDIT_HISTORY_LIMITED_BY_CONFIG", "scope": {"kind": "project", "id": 100}}]
        event = [{"interpretation": {"action": "created"}}]
        for metadata in (self.metadata, {}, {"created_at": "2024-01-01T00:00:00Z"}):
            result = index(self.tasks, notes).describe(metadata, {SCOPE}, event)
            self.assertEqual(result["status"], "found")
            self.assertIsNone(result["stop_reason"])
            self.assertEqual(result["stop_reasons"], [])
            self.assertEqual(result["scope_coverage"][0]["stop_reasons"], ["lookback_days"])

    def test_no_match_distinguishes_known_covered_date_from_unknown_date_in_status(self):
        """status 하나로도 생성시각 포함 확인과 포함 여부 미확인을 구분할 수 있다."""
        coverage = index(self.tasks)
        known = coverage.describe(self.metadata, {SCOPE}, [])
        unknown = coverage.describe({}, {SCOPE}, [])
        self.assertEqual(known["status"], "searched_not_found")
        self.assertTrue(known["token_creation_time_covered"])
        self.assertEqual(unknown["status"], "searched_not_found_range_unverifiable")
        self.assertIsNone(unknown["token_creation_time_covered"])

    def test_known_date_before_completed_range_is_not_covered(self):
        """오래된 생성일은 질의 완주와 별개로 선택 기간에 포함되지 않았음을 드러낸다."""
        result = index(self.tasks).describe({"created_at": "2024-01-01T00:00:00Z"}, {SCOPE}, [])
        self.assertEqual(result["status"], "search_range_did_not_cover")
        self.assertFalse(result["token_creation_time_covered"])

    def test_missing_null_invalid_date_never_becomes_false_coverage_claim(self):
        """생성일을 모르면 선택 범위 미발견과 포함 여부 미확인(null)을 동시에 보존한다."""
        for metadata, expected in (({}, "not_provided"), ({"created_at": None}, "null"),
                                   ({"created_at": "invalid"}, "invalid"), ({"created_at": "2026-09-10"}, "invalid")):
            result = index(self.tasks).describe(metadata, {SCOPE}, [])
            self.assertEqual(result["status"], "searched_not_found_range_unverifiable")
            self.assertEqual(result["token_created_at_status"], expected)
            self.assertFalse(result["token_created_at_known"])
            self.assertIsNone(result["token_creation_time_covered"])

    def test_gap_between_completed_windows_is_not_filled(self):
        """최초·최종 날짜 사이에 실패 창이 있으면 그 구간을 검색 완료로 합치지 않는다."""
        tasks = [window("2026-09-01T00:00:00Z", "2026-09-05T00:00:00Z"),
                 window("2026-09-05T00:00:00Z", "2026-09-15T00:00:00Z", "failed", "FORBIDDEN"),
                 window("2026-09-15T00:00:00Z", "2026-09-20T00:00:00Z")]
        result = index(tasks).describe(self.metadata, {SCOPE}, [])
        self.assertEqual(result["status"], "search_incomplete")
        self.assertFalse(result["token_creation_time_covered"])
        self.assertEqual(len(result["scope_coverage"][0]["completed_ranges"]), 2)
        self.assertEqual(result["stop_reason"], "query_failed")

    def test_partial_page_does_not_complete_its_entire_window(self):
        """한 창에서 이미 받은 페이지가 있어도 다음 페이지 대기는 완주로 세지 않는다."""
        tasks = [window("2026-09-01T00:00:00Z", "2026-09-20T00:00:00Z", "pending", pages=2)]
        notes = [{"code": "COLLECTION_STOPPED", "scope": {"reason": "REQUEST_BUDGET_EXCEEDED"}}]
        result = index(tasks, notes).describe(self.metadata, {SCOPE}, [])
        self.assertEqual(result["status"], "search_incomplete")
        self.assertEqual(result["stop_reason"], "request_budget")
        self.assertEqual(result["scope_coverage"][0]["completed_ranges"], [])
        self.assertIsNone(result["token_creation_time_covered"])
        self.assertIsNone(result["scope_coverage"][0]["token_creation_time_covered"])

    def test_adjacent_windows_merge_and_include_exact_boundary(self):
        """기간 경계의 포함 조건과 중복 범위 병합을 확인한다."""
        tasks = [window("2026-09-01T00:00:00Z", "2026-09-10T00:00:00Z"),
                 window("2026-09-10T00:00:00Z", "2026-09-20T00:00:00Z")]
        result = index(tasks).describe(self.metadata, {SCOPE}, [])
        self.assertTrue(result["token_creation_time_covered"])
        self.assertEqual(len(result["scope_coverage"][0]["completed_ranges"]), 1)

    def test_different_scopes_do_not_cover_each_others_missing_ranges(self):
        """그룹 완료 구간으로 프로젝트의 미조회 생성시각을 채워 넣지 않는다."""
        scopes = {SCOPE, ("group", 10)}
        values = {SCOPE: [window("2026-09-15T00:00:00Z", "2026-09-20T00:00:00Z")], ("group", 10): self.tasks}
        result = CreationCoverageIndex(values, {"include_audit_events": True}, []).describe(self.metadata, scopes, [])
        self.assertEqual(result["status"], "search_range_did_not_cover")
        self.assertFalse(result["token_creation_time_covered"])

    def test_lookback_reason_is_per_scope_and_resume_drops_old_stop_for_completed_scope(self):
        """실행 전체의 과거 중단 기록을 이제 완주한 소속의 중단 사유로 잘못 복사하지 않는다."""
        notes = [{"code": "COLLECTION_STOPPED", "scope": {"reason": "REQUEST_BUDGET_EXCEEDED"}},
                 {"code": "AUDIT_HISTORY_LIMITED_BY_CONFIG", "scope": {"kind": "project", "id": 100}}]
        result = index(self.tasks, notes).describe({}, {SCOPE}, [])
        self.assertEqual(result["stop_reasons"], ["lookback_days"])
        other = index(self.tasks, notes).describe({}, {("group", 10)}, [])
        self.assertNotIn("lookback_days", other["stop_reasons"])

    def test_disabled_and_user_only_are_not_searched(self):
        """감사 비활성화와 현재 지원하지 않는 User 감사 문맥을 미발견 검색과 구분한다."""
        disabled = index([], include_audit_events=False).describe(self.metadata, {SCOPE}, [])
        self.assertEqual((disabled["status"], disabled["stop_reason"]), ("not_searched", "audit_disabled"))
        self.assertIsNone(disabled["token_creation_time_covered"])
        self.assertIsNone(disabled["scope_coverage"][0]["token_creation_time_covered"])
        user = index(self.tasks).describe(self.metadata, {("user", 1)}, [])
        self.assertEqual(user["status"], "not_searched")
        self.assertEqual(user["scope_coverage"], [])
        self.assertIsNone(user["token_creation_time_covered"])

    def test_no_completed_ranges_leave_coverage_unknown(self):
        """미예약·실패·잘못된 창을 실제 범위 밖 판정으로 바꾸지 않는다."""
        cases = (
            ({}, "not_searched"),
            ({SCOPE: []}, "not_searched"),
            ({SCOPE: [window("2026-09-01T00:00:00Z", "2026-09-20T00:00:00Z", "failed", "FORBIDDEN")]}, "search_incomplete"),
            ({SCOPE: [window("invalid", "2026-09-20T00:00:00Z")]}, "search_incomplete"),
        )
        for tasks, expected_status in cases:
            with self.subTest(tasks=tasks):
                result = CreationCoverageIndex(tasks, {"include_audit_events": True}, []).describe(self.metadata, {SCOPE}, [])
                self.assertEqual(result["status"], expected_status)
                self.assertIsNone(result["token_creation_time_covered"])
                self.assertIsNone(result["scope_coverage"][0]["token_creation_time_covered"])
                self.assertIsNone(result["oldest_window_searched"])

    def test_mixed_scopes_preserve_unknown_and_confirmed_exclusion(self):
        """미조회 소속은 false가 아니며 다른 소속의 확인된 포함·미포함과 구분한다."""
        group = ("group", 10)
        outside = [window("2026-09-15T00:00:00Z", "2026-09-20T00:00:00Z")]
        for project_tasks, group_tasks, expected in (
            ([], [], None), (self.tasks, [], None), (outside, [], False),
            (self.tasks, self.tasks, True), (self.tasks, outside, False),
        ):
            with self.subTest(project=project_tasks, group=group_tasks):
                tasks = {SCOPE: project_tasks, group: group_tasks}
                result = CreationCoverageIndex(tasks, {"include_audit_events": True}, []).describe(self.metadata, {SCOPE, group}, [])
                self.assertIs(result["token_creation_time_covered"], expected)
                for scope in result["scope_coverage"]:
                    if not scope["completed_ranges"]:
                        self.assertIsNone(scope["token_creation_time_covered"])

    def test_revocation_is_not_creation_evidence(self):
        """관측된 폐기 기록이나 소유자 user_id를 생성 이벤트로 대신하지 않는다."""
        result = index(self.tasks).describe({**self.metadata, "user_id": 1}, {SCOPE}, [{"interpretation": {"action": "revoked"}}])
        self.assertEqual(result["status"], "searched_not_found")

