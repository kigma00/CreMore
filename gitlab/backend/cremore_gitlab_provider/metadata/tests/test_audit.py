"""감사 API의 발급자 보강·오결합 방지·기간/페이지/재개를 합성 응답으로 검증한다."""

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from cremore_gitlab_provider.metadata.audit import (
    TokenAuditIndex,
    audit_reference,
    audit_windows,
    deploy_creation,
    is_token_related,
    utc_time,
)
from cremore_gitlab_provider.metadata.collector import Collector
from cremore_gitlab_provider.metadata.config import Config
from cremore_gitlab_provider.metadata.http import CollectionError, Response
from cremore_gitlab_provider.metadata.model import identity, stable_id

from ._qa_storage import Store
from ._responses import FakeClient, inventory_client


def creation(event_id=9001, token_id=302, author_id=2, kind="project", scope_id=100):
    """실계정과 무관한 ID로 공식 감사 필드와 UI에서 확인한 생성 메시지 형식을 재현한다."""
    return {
        "id": event_id,
        "entity_type": kind.title(),
        "entity_id": scope_id,
        "author_id": author_id,
        "created_at": "2026-09-10T01:02:03Z",
        "details": {
            "author_name": f"Demo Issuer {author_id}",
            "author_class": "User",
            "target_type": "DeployToken",
            "target_id": token_id,
            "target_details": "same-name",
            "custom_message": f"Created {kind} deploy token with name: same-name with token_id: {token_id} with scopes: [:read_repository].",
            "new_metadata": {"preserved": True},
            "token": "SYNTHETIC_DO_NOT_PERSIST_AUDIT",
        },
    }


def typed_event(event_id, target_type, token_id, kind="project", scope_id=100, event_type=None):
    """매핑 계약을 시험할 합성 참조다. 실제 SaaS가 모든 유형의 이벤트를 준다는 뜻은 아니다."""
    event = creation(event_id, token_id, kind=kind, scope_id=scope_id)
    event["details"]["target_type"] = target_type
    del event["details"]["custom_message"]
    if event_type:
        event["event_type"] = event_type
    return event


class AuditClient(FakeClient):
    """감사 응답을 날짜·id_before로 페이지 처리하는 테스트 client."""

    def __init__(self, config):
        """생성 이벤트 두 종류와 소속의 생성일을 준비한다."""
        base = inventory_client(config)
        super().__init__(config, base.routes)
        self.graphql_body = base.graphql_body
        for path in ("/groups/10", "/groups/20", "/projects/100"):
            self.routes[path]["created_at"] = "2026-09-01T00:00:00Z"
        self.events = {
            "/groups/10/audit_events": [creation(8001, 301, 1, "group", 10)],
            "/projects/100/audit_events": [creation()],
        }
        self.audit_failures = {}

    def request(self, url, query=None, variables=None):
        """다음 Link 외의 offset 헤더를 제공하지 않아 실제 keyset 처리 경로를 검증한다."""
        parts = urlsplit(url)
        path = parts.path.removeprefix("/api/v4")
        if not path.endswith("/audit_events"):
            return super().request(url, query, variables)
        self.checked_url(url)
        self.requests += 1
        self.calls.append(url)
        params = {key: values[0] for key, values in parse_qs(parts.query).items()}
        cursor = params.get("id_before")
        if (path, cursor) in self.audit_failures:
            raise CollectionError("FORBIDDEN", "합성 감사 API 403", 403)
        start, end = utc_time(params["created_after"]), utc_time(params["created_before"])
        values = sorted(deepcopy(self.events.get(path, [])), key=lambda e: e["id"], reverse=True)
        values = [
            e
            for e in values
            if start <= utc_time(e["created_at"]) <= end
            and (cursor is None or e["id"] < int(cursor))
        ]
        size = int(params["per_page"])
        current = values[:size]
        headers = {}
        if len(values) > size:
            following = {**params, "id_before": current[-1]["id"]}
            link = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(following), ""))
            headers["link"] = f'<{link}>; rel="next"'
        return Response(current, headers)


class AuditTests(unittest.TestCase):
    """토큰 API 응답을 변경하지 않고 감사 근거로 요약을 보강하는 전체 경로를 시험한다."""

    def setUp(self):
        """각 시험은 독립 SQLite와 고정 실행 시각을 사용한다."""
        self.temp = tempfile.TemporaryDirectory()
        self.config = Config.from_dict(
            {
                "base_url": "https://gitlab.example",
                "group_ids": [10],
                "page_size": 2,
                "include_audit_events": True,
            }
        )
        self.directory = Path(self.temp.name) / "run"
        self.store = Store(self.directory, self.config.fingerprint())
        with self.store.db:
            self.store.set_setting("started_at", "2026-09-20T00:00:00Z")
        self.client = AuditClient(self.config)

    def tearDown(self):
        """사용자 결과 대신 임시 데이터만 정리한다."""
        self.store.close()
        self.temp.cleanup()

    def collect(self):
        """CLI와 같은 수집·내보내기 경로를 실행한다."""
        Collector(self.config, self.client, self.store).run()
        self.manifest = self.store.export()
        return {row["identity"]["native_id"]: row for row in self.store.inventory()}

    def evidence_for(self, row):
        """인벤토리 참조가 별도 파일의 전체 감사 메타데이터로 연결되는지 검증한다."""
        events = {event["audit_event_id"]: event for event in self.store.audit_events()}
        return [events[ref["audit_event_id"]] for ref in row["audit"]["event_refs"]]

    def test_group_and_project_creation_enrich_without_changing_token_metadata(self):
        """목록의 발급자 미제공은 유지하고 감사 생성자·시각·원본 필드는 별도 경로로 보강한다."""
        rows = self.collect()
        for token_id, author_id in ((301, 1), (302, 2)):
            row = rows[token_id]
            self.assertEqual(row["summary"]["issuer"]["id"], author_id)
            self.assertEqual(row["summary"]["issuer"]["status"], "observed_in_audit")
            self.assertEqual(row["summary"]["issuer"]["profile"]["id"], author_id)
            self.assertEqual(
                row["summary"]["created_at_from_audit"]["value"], "2026-09-10T01:02:03+00:00"
            )
            self.assertNotIn("created_at", row["metadata"])
            self.assertNotIn("author_id", row["metadata"])
            self.assertEqual(row["summary"]["owner"]["status"], "not_provided")
            self.assertEqual(row["audit"]["query_status"], "complete")
            self.assertTrue(
                self.evidence_for(row)[0]["metadata"]["details"]["new_metadata"]["preserved"]
            )
        self.assertTrue(self.manifest["all_scheduled_tasks_complete"])
        self.assertEqual(self.manifest["audit_enrichment"]["creation_events"], 2)
        self.assertEqual(len(rows), 12)
        for path in self.directory.iterdir():
            if path.is_file():
                self.assertNotIn(b"SYNTHETIC_DO_NOT_PERSIST", path.read_bytes())

    def test_unrelated_revocation_and_failed_creation_are_not_issuers(self):
        """재발급·폐기 등 다른 행동의 author를 원래 생성자로 오인하지 않는다."""
        events = []
        for index, event_type in enumerate(
            (
                "deploy_token_revoked",
                "deploy_token_destroyed",
                "deploy_token_creation_failed",
                "project_created",
            )
        ):
            event = creation(9000 + index)
            event["event_type"] = event_type
            events.append(event)
        self.client.events["/projects/100/audit_events"] = events
        row = self.collect()[302]
        self.assertEqual(row["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(row["audit"]["matching_creation_events"], 0)

    def test_scope_and_structured_id_conflicts_cannot_match(self):
        """같은 토큰 이름·숫자라도 소속 또는 명시적 ID가 모순되면 근거만 남기고 보강하지 않는다."""
        wrong_scope, wrong_id, name_only = creation(9001), creation(9002), creation(9003)
        wrong_scope["entity_id"] = 999
        wrong_id["details"]["target_id"] = 999
        name_only["event_type"] = "deploy_token_created"
        name_only["details"] = {
            "target_details": "project-deploy",
            "custom_message": "Created deploy token",
        }
        self.client.events["/projects/100/audit_events"] = [wrong_scope, wrong_id, name_only]
        row = self.collect()[302]
        self.assertEqual(row["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(row["audit"]["matching_creation_events"], 0)
        unmatched = [
            e
            for e in json.loads((self.directory / "audit_events.json").read_text())
            if e["inventory_match_status"] == "not_matched"
        ]
        self.assertEqual(len(unmatched), 3)

    def test_structured_creation_event_works_without_message(self):
        """공식 유형·DeployToken 대상 ID가 있으면 자유문 메시지를 해석하지 않아도 된다."""
        event = creation()
        event["event_type"] = "deploy_token_created"
        del event["details"]["custom_message"]
        self.client.events["/projects/100/audit_events"] = [event]
        self.assertEqual(self.collect()[302]["summary"]["issuer"]["id"], 2)

    def test_message_only_rest_variant_and_token_name_do_not_confuse_ids(self):
        """구형 REST 메시지에서 이름 안의 token_id가 아닌 실제 접미부 ID를 읽는다."""
        event = creation()
        del event["details"]["target_id"], event["details"]["target_type"]
        event["details"]["custom_message"] = (
            "Created project deploy token with name: name with token_id: 999 with scopes: [:read_api]. with token_id: 302 with scopes: [:read_repository]."
        )
        self.assertEqual(deploy_creation(event, {"kind": "project", "id": 100})["token_id"], 302)

    def test_conflicting_creators_are_explicitly_unknown(self):
        """여러 생성 기록의 author가 모순될 때 마지막 응답자를 임의 선택하지 않는다."""
        self.client.events["/projects/100/audit_events"] = [
            creation(9001, author_id=1),
            creation(9002, author_id=2),
        ]
        issuer = self.collect()[302]["summary"]["issuer"]
        self.assertEqual(issuer["status"], "conflicting_audit_evidence")
        self.assertIsNone(issuer["id"])
        self.assertEqual(issuer["candidate_ids"], [1, 2])

    def test_non_user_actor_does_not_trigger_user_lookup(self):
        """시스템 행위자를 실제 사람 계정으로 해석하지 않는다."""
        event = creation(author_id=999)
        event["details"]["author_class"] = "Gitlab::Audit::SystemAuthor"
        self.client.events["/projects/100/audit_events"] = [event]
        row = self.collect()[302]
        self.assertEqual(row["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(row["audit"]["matching_creation_events"], 1)
        self.assertFalse(any("/users/999" in url for url in self.client.calls))

    def test_audit_failure_preserves_existing_tokens_and_other_scopes(self):
        """감사 403을 토큰 목록 실패로 확대하지 않고 범위별 상태를 보존한다."""
        self.client.audit_failures[("/projects/100/audit_events", None)] = 403
        rows = self.collect()
        self.assertEqual(len(rows), 12)
        self.assertEqual(rows[302]["audit"]["query_status"], "failed")
        self.assertEqual(rows[302]["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(rows[301]["summary"]["issuer"]["id"], 1)
        self.assertFalse(self.manifest["all_scheduled_tasks_complete"])

    def test_keyset_second_page_failure_resumes_and_does_not_duplicate(self):
        """첫 감사 페이지를 보존하고 재개 시 server Link부터 읽어 중복 없이 끝낸다."""
        self.client.events["/projects/100/audit_events"] = [
            creation(9001),
            creation(9002),
            creation(9003),
        ]
        self.client.audit_failures[("/projects/100/audit_events", "9002")] = 403
        row = self.collect()[302]
        self.assertEqual(row["audit"]["matching_creation_events"], 2)
        self.assertEqual(row["audit"]["query_status"], "failed")
        self.store.close()
        self.store = Store(self.directory, self.config.fingerprint(), resume=True)
        self.client.calls.clear()
        self.client.audit_failures.clear()
        row = self.collect()[302]
        self.assertEqual(row["audit"]["matching_creation_events"], 3)
        self.assertEqual(row["audit"]["query_status"], "complete")
        audit_calls = [url for url in self.client.calls if "/audit_events" in url]
        self.assertEqual(len(audit_calls), 1)
        self.assertIn("id_before=9002", audit_calls[0])
        self.assertNotIn("&page=", audit_calls[0])
        self.collect()
        self.assertEqual(self.manifest["audit_enrichment"]["creation_events"], 4)
        self.assertEqual(
            self.manifest["audit_enrichment"]["page_event_observations"],
            {"received": 4, "retained": 4, "filtered_out": 0},
        )

    def test_date_windows_cover_history_and_deduplicate_inclusive_boundary(self):
        """30일을 넘는 기간을 빠짐없이 나누고 중복 경계 이벤트를 하나로 유지한다."""
        self.client.routes["/projects/100"]["created_at"] = "2026-08-01T00:00:00Z"
        event = creation()
        event["created_at"] = "2026-08-31T00:00:00Z"
        self.client.events["/projects/100/audit_events"] = [event]
        row = self.collect()[302]
        self.assertEqual(row["audit"]["matching_creation_events"], 1)
        self.assertEqual(len(self.evidence_for(row)[0]["sources"]), 2)
        tasks = [
            t
            for t in self.store.coverage()
            if t["handler"] == "audit_events" and t["context"]["scope"]["kind"] == "project"
        ]
        self.assertEqual(len(tasks), 2)
        for task in tasks:
            self.assertLessEqual(
                utc_time(task["params"]["created_before"])
                - utc_time(task["params"]["created_after"]),
                timedelta(days=30),
            )

    def test_unknown_start_does_not_silently_use_recent_month(self):
        """자산 생성일 미제공을 기존 발급 이력 전체 조회 성공으로 위장하지 않는다."""
        del self.client.routes["/projects/100"]["created_at"]
        row = self.collect()[302]
        self.assertEqual(row["audit"]["query_status"], "failed")
        self.assertTrue(
            any(
                t["error"] and t["error"]["code"] == "AUDIT_START_UNKNOWN"
                for t in self.store.coverage()
            )
        )

    def test_audit_changes_compare_with_previous_inventory(self):
        """토큰 메타데이터가 같아도 새로 확인한 발급자 정보 변화는 별도로 표시한다."""
        rows = self.collect()
        previous = self.directory / "previous.json"
        prior = deepcopy(list(rows.values()))
        for row in prior:
            if row.get("audit", {}).get("matching_creation_events"):
                del row["audit"]
                row["summary"]["issuer"] = {"status": "not_provided", "id": None}
                row["summary"].pop("created_at_from_audit", None)
        previous.write_text(json.dumps(prior))
        self.store.export(previous)
        changes = json.loads((self.directory / "changes.json").read_text())
        self.assertEqual(len(changes), 2)
        self.assertTrue(all(c["change"] == "audit_enrichment_changed" for c in changes))

    def test_audit_events_do_not_create_inventory_for_absent_token(self):
        """삭제됐거나 목록에서 보이지 않는 토큰의 옛 감사 기록을 현재 토큰으로 만들어내지 않는다."""
        self.client.events["/projects/100/audit_events"].append(creation(9002, token_id=999))
        rows = self.collect()
        self.assertNotIn(999, rows)
        event = next(e for e in self.store.audit_events() if e["event_id"] == 9002)
        self.assertEqual(event["inventory_match_status"], "not_matched")

    def test_config_compatibility_and_date_validation(self):
        """이전 감사 계약과의 잘못된 재개를 막고 별칭·시간대 검증을 유지한다."""
        config = Config.from_dict({})
        old = asdict(config)
        del (
            old["include_audit_events"],
            old["include_deploy_token_audit"],
            old["audit_created_after"],
        )
        self.assertNotEqual(
            config.fingerprint(),
            hashlib.sha256(json.dumps(old, sort_keys=True).encode()).hexdigest(),
        )
        for value in ("2026-09-20", "2026-09-20T12:00:00", True, "invalid"):
            with self.assertRaises(ValueError):
                Config.from_dict({"audit_created_after": value})
        with self.assertRaises(ValueError):
            list(audit_windows("2026-09-21T00:00:00Z", "2026-09-20T00:00:00Z"))
        legacy = Config.from_dict({"include_deploy_token_audit": True})
        self.assertTrue(legacy.audit_enabled)
        before = asdict(legacy)
        del before["include_audit_events"]
        self.assertNotEqual(
            legacy.fingerprint(),
            hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        )

    def test_all_ten_families_can_receive_explicit_token_references(self):
        """10개 계열의 매핑 경로를 검사한다. PAT/Trigger/ClientKey의 실제 감사 제공은 별도 검증이다."""
        group_events = [
            typed_event(8001, "PersonalAccessToken", 101, "group", 10),
            typed_event(8002, "PersonalAccessToken", 401, "group", 10),
            typed_event(
                8003, "PersonalAccessToken", 201, "group", 10, "group_access_token_created"
            ),
            creation(8004, 301, kind="group", scope_id=10),
        ]
        project_events = [
            typed_event(9001, "PersonalAccessToken", 402),
            typed_event(
                9002, "PersonalAccessToken", 203, event_type="project_access_token_created"
            ),
            creation(9003),
            typed_event(9004, "Ci::Trigger", 501),
            typed_event(
                9005, "Clusters::AgentToken", 601, event_type="cluster_agent_token_created"
            ),
            typed_event(9006, "ErrorTracking::ClientKey", 701),
        ]
        self.client.events = {
            "/groups/10/audit_events": group_events,
            "/projects/100/audit_events": project_events,
        }
        rows = self.collect()
        matched_types = set()
        for row in rows.values():
            self.assertIn("audit", row)
            if row["audit"]["matching_events"]:
                matched_types.update(row["credential_types"])
                self.assertEqual(row["audit"]["matching_events"], 1)
                self.assertTrue(
                    self.evidence_for(row)[0]["metadata"]["details"]["new_metadata"]["preserved"]
                )
        self.assertEqual(
            matched_types, set(self.manifest["audit_enrichment"]["matching_credential_types"])
        )
        self.assertEqual(self.manifest["audit_enrichment"]["matched_events"], 10)
        self.assertEqual(rows[203]["summary"]["issuer"]["id"], 2)
        # 종류 미확인 행동의 actor를 생성자로 단정하지 않는다.
        self.assertEqual(rows[501]["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(rows[102]["audit"]["query_status"], "not_scheduled")
        self.assertEqual(
            rows[102]["audit"]["unqueried_scopes"],
            [{"kind": "user", "id": 1, "reason": "user_audit_api_not_collected"}],
        )

    def test_non_token_activity_is_filtered_before_persistence(self):
        """이름에 token이 있는 일반 활동은 버리고, 식별 불가능한 토큰 설정 이벤트는 보존한다."""
        ordinary = typed_event(9002, "Project", 100, event_type="project_created")
        ordinary["details"].update(
            target_details="token-project", custom_message="UNRELATED_ACTIVITY_MUST_NOT_PERSIST"
        )
        flow = typed_event(9003, "Ai::FlowTrigger", 55, event_type="flow_trigger_created")
        policy = typed_event(9004, "Project", 100, event_type="future_token_policy_changed")
        self.client.events["/projects/100/audit_events"] = [creation(), ordinary, flow, policy]
        rows = self.collect()
        self.assertEqual(rows[302]["audit"]["matching_events"], 1)
        self.assertEqual(
            self.manifest["audit_enrichment"]["page_event_observations"],
            {"received": 5, "retained": 3, "filtered_out": 2},
        )
        events = list(self.store.audit_events())
        self.assertEqual({e["event_id"] for e in events}, {8001, 9001, 9004})
        self.assertEqual(
            next(e for e in events if e["event_id"] == 9004)["inventory_match_status"],
            "not_matched",
        )
        for path in self.directory.iterdir():
            if path.is_file():
                self.assertNotIn(b"UNRELATED_ACTIVITY_MUST_NOT_PERSIST", path.read_bytes())

    def test_no_deploy_tokens_still_collects_token_audits(self):
        """Deploy 발견 여부와 관계없이 확인된 Group/Project의 토큰 감사 조회를 예약한다."""
        self.client.routes["/groups/10/deploy_tokens"] = []
        self.client.routes["/projects/100/deploy_tokens"] = []
        self.client.events["/projects/100/audit_events"] = [
            typed_event(9001, "PersonalAccessToken", 203, event_type="project_access_token_created")
        ]
        rows = self.collect()
        self.assertNotIn(301, rows)
        self.assertNotIn(302, rows)
        self.assertEqual(rows[203]["summary"]["issuer"]["id"], 2)
        self.assertTrue(any("/projects/100/audit_events" in url for url in self.client.calls))
        self.assertEqual(self.manifest["audit_enrichment"]["unmatched_events"], 1)

    def test_revoker_is_kept_as_actor_not_creator(self):
        """생성자와 다른 폐기자의 ID·시각·추가 필드는 해당 토큰의 감사 근거에만 보존한다."""
        revoked = typed_event(9002, "DeployToken", 302, event_type="deploy_token_revoked")
        revoked["author_id"] = 1
        self.client.events["/projects/100/audit_events"] = [creation(), revoked]
        row = self.collect()[302]
        self.assertEqual(row["summary"]["issuer"]["id"], 2)
        self.assertEqual(row["audit"]["matching_creation_events"], 1)
        self.assertEqual(row["audit"]["matching_events"], 2)
        evidence = next(e for e in self.evidence_for(row) if e["event_id"] == 9002)
        self.assertEqual(evidence["interpretation"]["actor_id"], 1)
        self.assertIsNone(evidence["interpretation"]["issuer_id"])
        self.assertFalse(
            row["metadata"]["revoked"]
        )  # 감사 기록으로 현재 API 상태를 덮어쓰지 않는다.

    def test_bot_user_id_is_not_a_token_id(self):
        """Resource access token 이벤트가 User를 가리키면 token_id 없는 기록은 미매핑이다."""
        event = typed_event(9001, "User", 203, event_type="project_access_token_created")
        self.client.events["/projects/100/audit_events"] = [event]
        row = self.collect()[203]
        self.assertEqual(row["audit"]["matching_events"], 0)
        self.assertEqual(row["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(
            next(e for e in self.store.audit_events() if e["event_id"] == 9001)[
                "inventory_match_reason"
            ],
            "token_id_or_type_not_provided",
        )
        event["details"]["token_id"] = 203
        self.assertEqual(audit_reference(event, {"kind": "project", "id": 100})["token_id"], 203)

    def test_audit_before_inventory_is_remapped_after_token_arrives(self):
        """감사가 먼저 도착해도 미매핑을 고정하지 않고 최종 인벤토리가 들어온 뒤 다시 대조한다."""
        scope = {"kind": "project", "id": 100}
        task = {
            "id": "audit",
            "spec": {
                "path": "/projects/100/audit_events",
                "handler": "audit_events",
                "context": {"scope": scope},
            },
        }
        with self.store.db:
            self.store.save_audit_event(
                creation(),
                audit_reference(creation(), scope),
                task,
                "https://gitlab.example/api/v4/projects/100/audit_events",
            )
        self.assertEqual(
            next(iter(self.store.audit_events()))["inventory_match_status"], "not_matched"
        )
        token_task = {
            "id": "list",
            "spec": {
                "path": "/projects/100/deploy_tokens",
                "handler": "token_list",
                "context": {"scope": scope},
            },
        }
        with self.store.db:
            self.store.save_record(
                identity(self.config.base_url, "project_deploy_token", 302, scope),
                "project_deploy_token",
                scope,
                {"id": 302},
                token_task,
                "https://gitlab.example/api/v4/projects/100/deploy_tokens",
            )
        self.assertEqual(next(iter(self.store.audit_events()))["inventory_match_status"], "matched")

    def test_ambiguous_namespace_and_agent_reference_stays_unmatched(self):
        """같은 숫자의 PAT/Resource 또는 Agent 간 후보가 여러 개면 유형·소속 근거를 요구한다."""

        def descriptor(family, token_id, scope):
            """인벤토리 식별 규칙 그대로 충돌 시험 후보를 만든다."""
            key = identity(self.config.base_url, family, token_id, scope)
            return {
                "inventory_id": stable_id(key),
                "identity": key,
                "audit_scopes": {(scope["kind"], scope["id"])},
            }

        scope = {"kind": "group", "id": 10}
        index = TokenAuditIndex(
            [
                descriptor("personal_access_token", 201, scope),
                descriptor("group_access_token", 201, scope),
            ]
        )
        event = typed_event(8001, "PersonalAccessToken", 201, "group", 10)
        candidates, reason = index.match(audit_reference(event, scope), scope)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(reason, "ambiguous_token_reference")
        event["event_type"] = "group_access_token_created"
        self.assertEqual(index.match(audit_reference(event, scope), scope)[1], "matched")
        # 같은 ID라도 그룹이 다르면 후보가 아니다.
        other = {**event, "entity_id": 99}
        self.assertEqual(
            index.match(
                audit_reference(other, {"kind": "group", "id": 99}), {"kind": "group", "id": 99}
            )[0],
            [],
        )
        project = {"kind": "project", "id": 100}
        agents = TokenAuditIndex(
            [
                descriptor("kubernetes_agent_token", 601, {**project, "agent_id": agent_id})
                for agent_id in (50, 51)
            ]
        )
        event = typed_event(
            9001, "Clusters::AgentToken", 601, event_type="cluster_agent_token_created"
        )
        self.assertEqual(
            agents.match(audit_reference(event, project), project)[1], "ambiguous_token_reference"
        )
        event["details"]["agent_id"] = 50
        self.assertEqual(agents.match(audit_reference(event, project), project)[1], "matched")

    def test_filter_and_reference_reject_conflicting_metadata(self):
        """필터 통과와 식별 성공을 분리하고, 명시적 ID·타입 모순은 미확정으로 남긴다."""
        scope = {"kind": "project", "id": 100}
        event = creation()
        event["details"]["token_id"] = 999
        self.assertTrue(is_token_related(event))
        self.assertEqual(audit_reference(event, scope)["reason"], "conflicting_token_ids")
        event = typed_event(9001, "DeployToken", 203, event_type="project_access_token_created")
        self.assertEqual(audit_reference(event, scope)["reason"], "event_target_type_mismatch")
        event = typed_event(
            9001, "PersonalAccessToken", 203, event_type="project_access_token_created"
        )
        event["details"]["event_type"] = "project_access_token_deleted"
        self.assertEqual(audit_reference(event, scope)["reason"], "conflicting_event_types")


if __name__ == "__main__":
    unittest.main()
