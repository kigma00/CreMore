"""실응답 형식의 회귀·순서 독립성·저장 경계·전송 중단을 네트워크 없이 검증한다."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from cremore_gitlab_provider.metadata.audit import (
    TokenAuditIndex,
    audit_reference,
    is_token_related,
)
from cremore_gitlab_provider.metadata.collector import Collector
from cremore_gitlab_provider.metadata.config import Config
from cremore_gitlab_provider.metadata.http import Client, CollectionError, rate_limit_reset
from cremore_gitlab_provider.metadata.model import identity, metadata_view, sanitize, stable_id

from ._qa_storage import Store
from ._responses import inventory_client
from .test_audit import AuditClient, typed_event


@contextmanager
def audit_environment(**overrides):
    """실제 계정 대신 독립 임시 DB와 고정 시각의 합성 감사 환경을 제공한다."""
    config = Config.from_dict(
        {
            "base_url": "https://gitlab.example",
            "group_ids": [10],
            "page_size": 2,
            "include_audit_events": True,
            **overrides,
        }
    )
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "run", config.fingerprint())
        try:
            with store.db:
                store.set_setting("started_at", "2026-09-20T00:00:00Z")
            yield config, store, AuditClient(config)
        finally:
            store.close()


def observation(source, handler, metadata, scope=None, at="2026-09-01T00:00:00Z"):
    """API 수집 순서와 독립인 출처별 관찰 fixture를 만든다."""
    return {
        "source_id": source,
        "handler": handler,
        "metadata": deepcopy(metadata),
        "observed_at": at,
        "context": {"scope": scope or {"kind": "project", "id": 100}},
    }


class AuditRegressionTests(unittest.TestCase):
    """event_name 변형과 Agent/Token ID 구분, 제외 근거의 최소 저장을 검증한다."""

    def test_event_name_at_both_levels_and_conflicting_aliases(self):
        """이름 필드의 위치가 달라도 같은 생성으로 해석하고 상충하는 별칭은 거부한다."""
        for key in ("event_name", "event_type"):
            for nested in (False, True):
                event = typed_event(9001, "PersonalAccessToken", 203)
                (event["details"] if nested else event)[key] = "project_access_token_created"
                reference = audit_reference(event, {"kind": "project", "id": 100})
                self.assertEqual(
                    (reference["status"], reference["action"], reference["issuer_id"]),
                    ("identified", "created", 2),
                )
        event["event_name"] = "project_access_token_deleted"
        self.assertEqual(
            audit_reference(event, {"kind": "project", "id": 100})["reason"],
            "conflicting_event_types",
        )

    def test_structured_name_filter_does_not_depend_on_english_message(self):
        """표시 문구가 달라져도 명시적 token 이벤트 유형을 선별한다."""
        event = {
            "event_name": "cluster_agent_token_created",
            "details": {"target_type": "Clusters::Agent", "custom_message": "문구 변경"},
        }
        self.assertTrue(is_token_related(event))
        event["event_name"] = "project_created"
        self.assertFalse(is_token_related(event))

    def test_agent_message_uses_token_id_and_requires_correct_agent(self):
        """Agent 대상 ID와 메시지의 토큰 ID를 모두 대조하고 잘못된 결합을 차단한다."""
        scope = {"kind": "project", "id": 100}
        event = typed_event(9001, "Clusters::Agent", 50)
        event["event_name"] = "cluster_agent_token_created"
        event["details"]["custom_message"] = (
            "Created cluster agent token 'name with id 999' with id 601"
        )
        key = identity(
            "https://gitlab.example", "kubernetes_agent_token", 601, {**scope, "agent_id": 50}
        )
        index = TokenAuditIndex(
            [{"identity": key, "inventory_id": stable_id(key), "audit_scopes": {("project", 100)}}]
        )
        reference = audit_reference(event, scope)
        self.assertEqual((reference["token_id"], reference["agent_id"]), (601, 50))
        self.assertEqual(index.match(reference, scope)[1], "matched")
        for target_id in (51, None):
            changed = deepcopy(event)
            changed["details"]["target_id"] = target_id
            self.assertEqual(index.match(audit_reference(changed, scope), scope)[0], [])
        changed = deepcopy(event)
        changed["details"]["token_id"] = 602
        self.assertEqual(audit_reference(changed, scope)["reason"], "conflicting_token_ids")
        changed = deepcopy(event)
        del changed["details"]["target_id"]
        self.assertEqual(audit_reference(changed, scope)["reason"], "agent_id_not_provided")
        event["details"]["custom_message"] += " unrelated suffix"
        self.assertEqual(audit_reference(event, scope)["status"], "unresolved")

    def test_agent_revocation_message_cannot_supply_creation_evidence(self):
        """명시적 폐기 유형을 생성 문구가 덮어쓰지 못하게 한다."""
        event = typed_event(9001, "Clusters::Agent", 50, event_type="cluster_agent_token_revoked")
        event["details"].update(
            custom_message="Created cluster agent token 'x' with id 601", token_id=601
        )
        reference = audit_reference(event, {"kind": "project", "id": 100})
        self.assertEqual(reference["action"], "revoked")
        self.assertIsNone(reference["issuer_id"])

    def test_rest_shapes_enrich_project_access_and_link_agent(self):
        """실제 관찰한 형태를 가짜 ID로 재현하여 전체 수집·참조 출력까지 검증한다."""
        with audit_environment() as (config, store, client):
            access = typed_event(9001, "PersonalAccessToken", 203)
            access["details"]["event_name"] = "project_access_token_created"
            agent = typed_event(9002, "Clusters::Agent", 50)
            agent["event_name"] = "cluster_agent_token_created"
            agent["details"]["custom_message"] = "Created cluster agent token 'demo' with id 601"
            client.events["/projects/100/audit_events"] = [access, agent]
            Collector(config, client, store).run()
            store.export()
            rows = {row["identity"]["native_id"]: row for row in store.inventory()}
            self.assertEqual(rows[203]["summary"]["issuer"]["status"], "observed_in_audit")
            self.assertEqual(rows[203]["summary"]["issuer"]["id"], 2)
            self.assertEqual(rows[601]["summary"]["issuer"]["status"], "observed")
            self.assertEqual(rows[601]["audit"]["matching_creation_events"], 1)
            events = {event["audit_event_id"]: event for event in store.audit_events()}
            for row in rows.values():
                self.assertNotIn("events", row["audit"])
                for ref in row["audit"]["event_refs"]:
                    self.assertEqual(
                        events[ref["audit_event_id"]]["inventory_id"], row["inventory_id"]
                    )

    def test_filtered_identifiers_deduplicate_without_payload_or_pii(self):
        """기간 경계에서 중복된 제외 이벤트도 한 번 보존하고 민감한 일반 활동 본문은 버린다."""
        with audit_environment() as (config, store, client):
            event = typed_event(9001, "Project", 100, event_type="project_created")
            event.update(created_at="2026-08-31T00:00:00Z", author_email="DO_NOT_STORE_AUTHOR")
            event["details"].update(
                custom_message="DO_NOT_STORE_MESSAGE", ip_address="DO_NOT_STORE_IP"
            )
            client.routes["/projects/100"]["created_at"] = "2026-08-01T00:00:00Z"
            client.events["/projects/100/audit_events"] = [event]
            Collector(config, client, store).run()
            manifest = store.export()
            rows = json.loads((store.directory / "filtered_audit_events.json").read_text())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_id"], 9001)
            self.assertEqual(rows[0]["event_name"], "project_created")
            self.assertEqual(len(rows[0]["source_ids"]), 2)
            self.assertEqual(manifest["audit_enrichment"]["filtered_event_identifiers"], 1)
            for path in store.directory.iterdir():
                if path.is_file():
                    self.assertNotIn(b"DO_NOT_STORE_", path.read_bytes())

    def test_filtered_page_failure_rolls_back_identifiers_and_counts(self):
        """페이지 체크포인트 실패 시 제외 ID와 카운터도 같이 롤백한다."""
        with audit_environment() as (config, store, client):
            task_id = store.add_task(
                "audit_events",
                "/projects/100/audit_events",
                {"scope": {"kind": "project", "id": 100}},
                {
                    "created_after": "2026-09-01T00:00:00Z",
                    "created_before": "2026-09-20T00:00:00Z",
                    "pagination": "keyset",
                },
            )
            store.db.commit()
            client.events["/projects/100/audit_events"] = [
                typed_event(9001, "Project", 100, event_type="project_created")
            ]
            with (
                patch.object(store, "page_done", side_effect=RuntimeError("checkpoint")),
                self.assertRaises(RuntimeError),
            ):
                Collector(config, client, store).process(store.next_task())
            self.assertEqual(
                store.db.execute("SELECT count(*) FROM filtered_audit_events").fetchone()[0], 0
            )
            self.assertIsNone(store.get_setting("audit_counts:" + task_id))

    def test_lookback_is_explicit_and_not_provider_retention(self):
        """전체 이력 기본값을 유지하고 선택한 조회 기간 제한만 커버리지에 표시한다."""
        with audit_environment(audit_lookback_days=7) as (config, store, client):
            Collector(config, client, store).run()
            manifest = store.export()
            tasks = [task for task in store.coverage() if task["handler"] == "audit_events"]
            self.assertTrue(
                all(
                    task["params"]["created_after"] == "2026-09-13T00:00:00+00:00" for task in tasks
                )
            )
            notes = [
                note
                for note in manifest["coverage_notes"]
                if note["code"] == "AUDIT_HISTORY_LIMITED_BY_CONFIG"
            ]
            self.assertTrue(notes)
            self.assertFalse(notes[0]["scope"]["provider_retention_assumed"])
            self.assertEqual(Config.from_dict({}).audit_lookback_days, None)


class MetadataRegressionTests(unittest.TestCase):
    """관찰 순서·공식 ID·범위를 안정화하고 비밀값과 메타데이터 정책을 구분한다."""

    def test_merge_is_order_independent_and_preserves_nested_extras(self):
        """REST 대표값과 GraphQL 추가 필드가 순서·시각 변경에도 동일하게 유지된다."""
        rest = observation("rest", "token_detail", {"id": 501, "owner": {"id": 1, "name": "Rest"}})
        graph = observation(
            "graph",
            "graphql_triggers",
            {
                "id": "gid://gitlab/Ci::Trigger/501",
                "owner": {
                    "id": "gid://gitlab/User/1",
                    "name": "Graph",
                    "state": "active",
                    "webUrl": "https://gitlab.example/demo",
                },
            },
        )
        expected = metadata_view([rest, graph])
        rest["observed_at"], graph["observed_at"] = "2099-01-01", "2000-01-01"
        self.assertEqual(metadata_view([graph, rest]), expected)
        self.assertEqual(expected[0]["id"], 501)
        self.assertEqual(expected[0]["owner"]["state"], "active")
        self.assertEqual(expected[1]["owner"]["id"], 1)
        self.assertEqual(graph["metadata"]["owner"]["id"], "gid://gitlab/User/1")

    def test_graphql_only_summary_id_is_integer_and_null_is_authoritative(self):
        """요약의 사용자 ID 타입은 안정화하고 권위 있는 출처의 명시적 null을 보존한다."""
        graph = observation("g", "graphql_triggers", {"owner": {"id": "gid://gitlab/User/1"}})
        self.assertEqual(metadata_view([graph])[1]["owner"]["id"], 1)
        rest = observation("r", "token_detail", {"owner": None})
        self.assertEqual(metadata_view([graph, rest])[1]["owner"]["status"], "null")

    def test_scope_is_identity_scope_with_all_observed_contexts(self):
        """동일 PAT의 사용자·그룹·서비스 계정 관찰 순서를 바꿔도 대표 소속이 같아야 한다."""
        scopes = [
            {"kind": "user", "id": 1},
            {"kind": "group", "id": 10},
            {"kind": "group", "id": 10, "service_account_id": 1},
        ]
        with tempfile.TemporaryDirectory() as directory:
            rows = []
            for index, order in enumerate((scopes, list(reversed(scopes)))):
                store = Store(Path(directory) / str(index), "fixture")
                try:
                    for scope in order:
                        key = identity(
                            "https://gitlab.example", "personal_access_token", 101, scope
                        )
                        task = {
                            "id": stable_id(scope),
                            "spec": {
                                "path": "/personal_access_tokens",
                                "handler": "token_list",
                                "context": {"scope": scope},
                            },
                        }
                        with store.db:
                            store.save_record(
                                key,
                                "personal_access_token",
                                scope,
                                {"id": 101, "user_id": 1},
                                task,
                                "/api/v4/personal_access_tokens",
                            )
                    rows.append(next(iter(store.inventory())))
                finally:
                    store.close()
            self.assertEqual(rows[0]["inventory_id"], rows[1]["inventory_id"])
            self.assertEqual(rows[0]["scope"], {})
            self.assertEqual(rows[0]["observed_scopes"], rows[1]["observed_scopes"])
            self.assertEqual(len(rows[0]["observed_scopes"]), 3)

    def test_missing_person_id_does_not_attempt_profile_lookup(self):
        """발급자 자체가 미제공인 경우와 사용자 프로필 조회 미성공을 구분한다."""
        with audit_environment(include_audit_events=False) as (config, store, client):
            Collector(config, client, store).run()
            row = next(row for row in store.inventory() if row["identity"]["native_id"] == 301)
            self.assertEqual(row["summary"]["owner"]["profile_status"], "not_applicable")
            self.assertEqual(row["summary"]["issuer"]["profile_status"], "not_applicable")

    def test_suffix_and_url_secrets_removed_but_pii_and_metadata_remain(self):
        """비밀값 sanitizer 자체는 목적별 필드 제외를 하지 않는다. 별도 정책에서 처리한다."""
        value = {
            "customToken": "CREDENTIAL",
            "nested": {"mirror_password": "CREDENTIAL", "new_api_key": "CREDENTIAL"},
            "token_id": 42,
            "runners_token_expires_at": None,
            "has_token_exposed": True,
            "signing_token_present": True,
            "has_runner_token": True,
            "primary_key": "id",
            "author_email": "test@example.invalid",
            "ip_address": "192.0.2.1",
            "identities": [{"provider": "demo", "extern_uid": "sample"}],
            "pronouns": "demo",
            "import_url": "https://user:CREDENTIAL@example.invalid/repo.git?access_token=CREDENTIAL&ref=main",
        }
        clean, removed = sanitize(value)
        self.assertNotIn("CREDENTIAL", json.dumps(clean))
        for key in (
            "token_id",
            "runners_token_expires_at",
            "has_token_exposed",
            "signing_token_present",
            "has_runner_token",
            "primary_key",
            "author_email",
            "ip_address",
            "identities",
            "pronouns",
        ):
            self.assertEqual(clean[key], value[key])
        self.assertIn("example.invalid/repo.git", clean["import_url"])
        self.assertIn("ref=main", clean["import_url"])
        self.assertIn("import_url.<embedded_credentials>", removed)

    def test_url_secret_values_never_reach_sqlite_or_json(self):
        """URL 안의 비밀값도 SQLite 저널·JSON에 저장되기 전에 분리한다."""
        with audit_environment(include_audit_events=False) as (config, store, client):
            client.routes["/projects/100"]["import_url"] = (
                "https://user:URL_SECRET_MARKER@example.invalid/repo.git"
            )
            client.routes["/projects/100"]["future_auth_token"] = "URL_SECRET_MARKER"
            Collector(config, client, store).run()
            store.export()
            for path in store.directory.iterdir():
                if path.is_file():
                    self.assertNotIn(b"URL_SECRET_MARKER", path.read_bytes())

    def test_transport_changes_can_resume_but_scope_changes_cannot(self):
        """속도·재시도 조절은 재개를 허용하고 조회 범위 변경은 새 실행을 요구한다."""
        base = Config.from_dict({"group_ids": [10]})
        changed = Config.from_dict(
            {
                "group_ids": [10],
                "requests_per_second": 0.5,
                "timeout_seconds": 80,
                "max_retries": 1,
                "max_response_bytes": 2048,
                "max_requests_per_run": 20,
            }
        )
        self.assertEqual(base.fingerprint(), changed.fingerprint())
        for override in (
            {"group_ids": [11]},
            {"page_size": 2},
            {"audit_lookback_days": 7},
            {"include_audit_events": True},
        ):
            self.assertNotEqual(
                base.fingerprint(), Config.from_dict({"group_ids": [10], **override}).fingerprint()
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run"
            Store(path, base.fingerprint()).close()
            Store(path, changed.fingerprint(), resume=True).close()

    def test_rejected_legacy_resume_does_not_modify_database(self):
        """호환되지 않는 예전 실행을 열어도 스키마 생성 전 거부해 DB 바이트를 보존한다."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            database = path / "state.sqlite3"
            connection = sqlite3.connect(database)
            with connection:
                connection.execute(
                    "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO settings VALUES (?, ?)",
                    ("config_hash", json.dumps("old-contract")),
                )
            connection.close()
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                Store(path, Config.from_dict({}).fingerprint(), resume=True)
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_manifest_identifies_code_and_runtime_settings(self):
        """커밋 여부와 무관하게 실행 코드 해시·버전·범위·전송 설정을 증거로 남긴다."""
        with audit_environment() as (config, store, client):
            Collector(config, client, store).run()
            manifest = store.export()
            provenance = manifest["code_provenance"]
            self.assertEqual(provenance["collector_version"], "0.11.1")
            self.assertEqual(len(provenance["source_digest"]), 64)
            self.assertIn("audit.py", provenance["source_files_sha256"])
            self.assertEqual(
                manifest["execution_history"][0]["transport_settings"], config.transport_settings()
            )

    def test_previous_time_merge_does_not_create_false_metadata_change(self):
        """구버전의 GraphQL 최종 병합값을 비교할 때 병합 정책 교체를 토큰 변화로 오인하지 않는다."""
        with audit_environment(include_audit_events=False) as (config, store, client):
            Collector(config, client, store).run()
            prior = list(store.inventory())
            trigger = next(row for row in prior if row["identity"]["native_id"] == 501)
            trigger["schema_version"] = "1.0"
            trigger["metadata"]["id"] = "gid://gitlab/Ci::Trigger/501"
            trigger["metadata"]["owner"]["id"] = "gid://gitlab/User/1"
            previous = store.directory / "previous.json"
            previous.write_text(json.dumps(prior))
            self.assertEqual(list(store.compare(previous, list(store.coverage()))), [])

    def test_graphql_resume_does_not_flip_owner_or_emit_false_changes(self):
        """완주 실행과 GraphQL만 나중에 재개한 실행이 동일한 메타데이터를 내보내야 한다."""
        with audit_environment(include_audit_events=False) as (config, baseline, client):
            Collector(config, client, baseline).run()
            baseline.export()
            directory = baseline.directory.parent / "resumed"
            store = Store(directory, config.fingerprint())
            try:
                failed_client = inventory_client(config)
                failed_client.graphql_body = {"data": {"project": {"pipelineTriggers": None}}}
                Collector(config, failed_client, store).run()
                self.assertTrue(any(task["status"] == "failed" for task in store.coverage()))
            finally:
                store.close()
            store = Store(directory, config.fingerprint(), resume=True)
            try:
                Collector(config, inventory_client(config), store).run()
                row = next(row for row in store.inventory() if row["identity"]["native_id"] == 501)
                self.assertIs(type(row["summary"]["owner"]["id"]), int)
                self.assertIs(type(row["metadata"]["id"]), int)
                self.assertEqual(
                    list(
                        store.compare(baseline.directory / "inventory.json", list(store.coverage()))
                    ),
                    [],
                )
            finally:
                store.close()

    def test_conditional_pii_remains_while_approved_profile_fields_are_excluded(self):
        """제외 승인된 거주지는 빼되 연락처·직무·감사 IP는 그대로 보존한다."""
        with audit_environment() as (config, store, client):
            client.routes["/user"].update(
                email="sample@example.invalid", location="sample", job_title="sample"
            )
            client.events["/projects/100/audit_events"][0]["details"].update(
                author_email="actor@example.invalid", ip_address="192.0.2.10"
            )
            Collector(config, client, store).run()
            store.export()
            profile = store.asset_metadata("user", 1)
            self.assertEqual(profile["email"], "sample@example.invalid")
            self.assertNotIn("location", profile)
            self.assertEqual(profile["job_title"], "sample")
            event = next(event for event in store.audit_events() if event["event_id"] == 9001)
            self.assertEqual(event["metadata"]["details"]["author_email"], "actor@example.invalid")
            self.assertEqual(event["metadata"]["details"]["ip_address"], "192.0.2.10")

    def test_only_list_completion_can_prove_not_observed(self):
        """다른 토큰의 상세 조회 완주만으로 목록 미발견을 선언하지 않는다."""
        with audit_environment(include_audit_events=False) as (config, baseline, client):
            Collector(config, client, baseline).run()
            prior = next(row for row in baseline.inventory() if row["identity"]["native_id"] == 501)
            source = next(
                row["source_id"]
                for row in prior["observations"]
                if row["handler"] == "token_detail"
            )
            previous = baseline.directory / "one.json"
            previous.write_text(json.dumps([prior]))
            empty = Store(baseline.directory.parent / "empty", config.fingerprint())
            try:
                changes = list(
                    empty.compare(
                        previous,
                        [{"source_id": source, "status": "complete", "handler": "token_detail"}],
                    )
                )
                self.assertEqual(changes[0]["change"], "observation_unknown")
            finally:
                empty.close()


class FakeResponse(BytesIO):
    """urllib 응답의 최소 인터페이스로 읽은 바이트 수를 시험한다."""

    def __init__(self, body=b"[]", headers=None):
        """실제 네트워크를 열지 않는 응답 본문과 헤더를 준비한다."""
        super().__init__(body)
        self.headers = headers or {}


class SequenceOpener:
    """지정한 HTTP 오류·응답을 순서대로 제공하고 실제 요청 수를 센다."""

    def __init__(self, responses):
        """응답 목록과 호출 기록을 독립적으로 보관한다."""
        self.responses = iter(responses)
        self.calls = 0

    def open(self, request, timeout):
        """가짜 응답을 반환하거나 지정한 예외를 전송한다."""
        self.calls += 1
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


def limited_error(headers=None):
    """인증값을 담지 않은 합성 HTTP 429를 만든다."""
    return HTTPError(
        "https://gitlab.example/api/v4/user", 429, "limited", headers or {}, BytesIO(b"discard")
    )


class TransportRegressionTests(unittest.TestCase):
    """전역 요청 상한·지속 429·응답 크기·재시도 최소 대기를 검증한다."""

    def client(self, responses, **settings):
        """토큰 버킷 때문에 실제 대기하지 않도록 작은 합성 요청 묶음을 구성한다."""
        config = Config.from_dict({"base_url": "https://gitlab.example", "burst": 100, **settings})
        opener = SequenceOpener(responses)
        delays = []
        return Client(config, "SYNTHETIC_AUTH", opener=opener, sleep=delays.append), opener, delays

    def test_request_budget_counts_retries_and_stops_before_send(self):
        """재시도도 전체 예산에 포함하고 한도 밖 요청은 전송하지 않는다."""
        client, opener, _ = self.client([limited_error(), FakeResponse()], max_requests_per_run=1)
        with self.assertRaises(CollectionError) as raised:
            client.request(client.rest_url("/user"))
        self.assertEqual(raised.exception.code, "REQUEST_BUDGET_EXCEEDED")
        self.assertEqual(opener.calls, 1)

    def test_consecutive_429_breaker_spans_tasks(self):
        """개별 작업의 재시도가 없어도 연속 429를 작업 사이에서 누적한다."""
        # 세 번째 요청은 전송 전에 차단되므로 사용되지 않을 HTTPError 스트림은 만들지 않는다.
        client, opener, _ = self.client(
            [limited_error(), limited_error()], max_retries=0, max_consecutive_rate_limits=2
        )
        codes = []
        for _ in range(3):
            with self.assertRaises(CollectionError) as raised:
                client.request(client.rest_url("/user"))
            codes.append(raised.exception.code)
        self.assertEqual(
            codes, ["RATE_LIMITED", "RATE_LIMIT_CIRCUIT_OPEN", "RATE_LIMIT_CIRCUIT_OPEN"]
        )
        self.assertEqual(opener.calls, 2)

    def test_reset_header_and_minimum_backoff(self):
        """GitLab reset 시각과 최소 대기 하한을 지키고 긴 요구는 다음 작업까지 멈춘다."""
        self.assertEqual(rate_limit_reset("110", wall_time=lambda: 100), 10)
        for value in (None, "invalid", "nan", "inf"):
            self.assertEqual(rate_limit_reset(value), 0)
        client, _, delays = self.client([limited_error(), FakeResponse()], retry_min_seconds=2)
        client.request(client.rest_url("/user"))
        self.assertGreaterEqual(delays[0], 2)
        client, opener, delays = self.client([limited_error({"RateLimit-Reset": "9999999999"})])
        with self.assertRaises(CollectionError) as raised:
            client.request(client.rest_url("/user"))
        self.assertEqual(raised.exception.code, "RETRY_LATER")
        self.assertEqual(opener.calls, 1)
        self.assertEqual(delays, [])

    def test_success_resets_429_streak(self):
        """성공 응답 뒤의 429를 이전 제한과 연속으로 집계하지 않는다."""
        client, _, _ = self.client(
            [limited_error(), FakeResponse(), limited_error()],
            max_retries=0,
            max_consecutive_rate_limits=2,
        )
        with self.assertRaises(CollectionError):
            client.request(client.rest_url("/user"))
        client.request(client.rest_url("/user"))
        with self.assertRaises(CollectionError) as raised:
            client.request(client.rest_url("/user"))
        self.assertEqual(raised.exception.code, "RATE_LIMITED")

    def test_response_size_limit_with_and_without_content_length(self):
        """Content-Length 없는 응답도 최대 크기+1까지만 읽고 실패로 표시한다."""
        for headers in ({}, {"Content-Length": "2048"}, {"Content-Length": "3"}):
            client, _, _ = self.client(
                [FakeResponse(b" " * 2048, headers)], max_response_bytes=1024
            )
            with self.assertRaises(CollectionError) as raised:
                client.request(client.rest_url("/user"))
            self.assertEqual(raised.exception.code, "RESPONSE_TOO_LARGE")

    def test_collector_stops_globally_and_keeps_pending_tasks(self):
        """전역 제한 후 나머지 API를 반복 호출하지 않고 재개용 대기 작업을 남긴다."""
        for code in ("REQUEST_BUDGET_EXCEEDED", "RATE_LIMIT_CIRCUIT_OPEN", "RETRY_LATER"):
            with audit_environment() as (config, store, client):
                collector = Collector(config, client, store)
                with patch.object(
                    collector, "process", side_effect=CollectionError(code, "synthetic stop", 429)
                ) as process:
                    collector.run()
                manifest = store.export()
                self.assertEqual(process.call_count, 1)
                self.assertGreater(manifest["tasks"]["pending"], 0)
                self.assertFalse(manifest["all_scheduled_tasks_complete"])


if __name__ == "__main__":
    unittest.main()
