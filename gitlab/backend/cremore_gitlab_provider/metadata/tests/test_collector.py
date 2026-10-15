"""계정 없는 회귀 검증: 범위·중복·미확인·실패 재개·비밀값 분리를 시험한다."""

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch
from urllib.error import HTTPError

from cremore_gitlab_provider.metadata.collector import Collector
from cremore_gitlab_provider.metadata.config import Config
from cremore_gitlab_provider.metadata.http import (
    Client,
    CollectionError,
    next_page,
    retry_after,
)
from cremore_gitlab_provider.metadata.model import identity, metadata_view, sanitize, stable_id

from ._qa_cli import main
from ._qa_storage import Store, write_json_array
from ._responses import inventory_client


class CollectorTests(unittest.TestCase):
    """네트워크를 사용하지 않고 실제 수집기·SQLite·JSON 전체 경로를 검증한다."""

    def setUp(self):
        """시험마다 독립 저장소와 합성 그룹 범위를 준비한다."""
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "run"
        self.config = Config.from_dict(
            {"base_url": "https://gitlab.example", "group_ids": [10], "page_size": 2}
        )
        self.client = inventory_client(self.config)
        self.store = Store(self.directory, self.config.fingerprint())

    def tearDown(self):
        """실제 사용자 파일에 영향을 주지 않도록 임시 DB와 디렉터리를 정리한다."""
        self.store.close()
        self.temp.cleanup()

    def collect(self):
        """동일한 실행기를 완료하고 검증하기 쉬운 ID 기준 결과를 반환한다."""
        Collector(self.config, self.client, self.store).run()
        self.manifest = self.store.export()
        return {r["identity"]["native_id"]: r for r in self.store.inventory()}

    def test_all_class_one_types_and_unknown_fields(self):
        """10개 family, 신규 메타데이터 필드, fine-grained 권한을 누락 없이 보존한다."""
        self.client.routes["/personal_access_tokens"][0]["future_metadata_field"] = {"preserved": True}
        self.client.routes["/personal_access_tokens"][2]["granular_scopes"] = [{"project_id": 100}]
        self.client.routes["/projects/100/access_tokens"][0]["last_used_ips"] = ["192.0.2.1"]
        rows = self.collect()
        self.assertTrue(self.manifest["all_scheduled_tasks_complete"])
        kinds = {kind for row in rows.values() for kind in row["credential_types"]}
        self.assertEqual(
            kinds,
            {
                "personal_access_token",
                "group_service_account_pat",
                "project_service_account_pat",
                "group_access_token",
                "project_access_token",
                "group_deploy_token",
                "project_deploy_token",
                "pipeline_trigger_token",
                "kubernetes_agent_token",
                "error_tracking_client_key",
            },
        )
        self.assertEqual(len(rows), 12)
        self.assertEqual(rows[103]["metadata"]["granular_scopes"][0]["project_id"], 100)
        self.assertTrue(rows[101]["metadata"]["future_metadata_field"]["preserved"])
        self.assertIn("last_used_ips", rows[203]["metadata"])

    def test_duplicate_sources_merge_but_same_name_does_not(self):
        """조직 통합/단독 조회는 합치고 이름이 같은 다른 ID는 별도로 보존한다."""
        rows = self.collect()
        self.assertGreaterEqual(len(rows[201]["observations"]), 3)
        self.assertGreaterEqual(len(rows[101]["observations"]), 3)
        self.assertNotEqual(rows[101]["inventory_id"], rows[102]["inventory_id"])
        self.assertEqual(
            rows[101]["summary"]["name"]["value"], rows[102]["summary"]["name"]["value"]
        )

    def test_owner_is_not_issuer_and_agent_detail_is_collected(self):
        """소유 계정을 발급자로 오인하지 않고 Agent의 명시적 생성자·상세 사용 시각을 수집한다."""
        self.client.routes["/projects/100/cluster_agents/50/tokens/601"]["last_used_at"] = "2026-09-03T00:00:00Z"
        rows = self.collect()
        self.assertTrue(any("/cluster_agents/50/tokens/601" in url for url in self.client.calls))
        self.assertEqual(rows[201]["summary"]["owner"]["id"], 10)
        self.assertEqual(rows[201]["summary"]["issuer"]["status"], "not_provided")
        self.assertEqual(rows[601]["summary"]["issuer"]["id"], 2)
        self.assertEqual(rows[601]["summary"]["issuer"]["profile"]["id"], 2)
        self.assertEqual(rows[601]["metadata"]["last_used_at"], "2026-09-03T00:00:00Z")
        self.assertEqual(rows[501]["summary"]["name"]["status"], "not_provided")
        self.assertIn("canAccessProject", rows[501]["metadata"])

    def test_no_secret_values_persist(self):
        """REST에 같이 오는 원문은 JSON뿐 아니라 SQLite에도 저장되지 않아야 한다."""
        self.client.routes["/groups/10"]["runners_token"] = "SYNTHETIC_DO_NOT_PERSIST_RUNNER"
        self.client.routes["/projects/100/error_tracking/client_keys"][0]["sentry_dsn"] = "SYNTHETIC_DO_NOT_PERSIST_DSN"
        rows = self.collect()
        for path in self.directory.iterdir():
            if path.is_file():
                self.assertNotIn(b"SYNTHETIC_DO_NOT_PERSIST", path.read_bytes(), path.name)
        self.assertNotIn("token", rows[501]["metadata"])
        self.assertEqual(rows[701]["metadata"], {"id": 701, "active": True})
        self.assertTrue(
            any("token" in o["excluded_credential_fields"] for o in rows[501]["observations"])
        )

    def test_failed_second_page_resumes_without_losing_first(self):
        """두 번째 페이지 403 후 첫 페이지는 남고 재개는 실패 페이지부터 진행한다."""
        self.client.failures[("/personal_access_tokens", 2)] = 403
        self.collect()
        self.assertFalse(self.manifest["all_scheduled_tasks_complete"])
        task = next(t for t in self.store.coverage() if t["path"] == "/personal_access_tokens")
        self.assertEqual((task["status"], task["pages_completed"]), ("failed", 1))
        self.store.close()
        self.store = Store(self.directory, self.config.fingerprint(), resume=True)
        self.client = inventory_client(self.config)
        rows = self.collect()
        self.assertTrue(self.manifest["all_scheduled_tasks_complete"])
        self.assertIn(103, rows)
        self.assertFalse(
            any("/personal_access_tokens?" in url and "page=1" in url for url in self.client.calls)
        )

    def test_graphql_null_is_not_empty_success(self):
        """HTTP 성공과 별개로 null 연결 목록은 미확인 상태로 남긴다."""
        self.client.graphql_body = {"data": {"project": {"pipelineTriggers": None}}}
        rows = self.collect()
        self.assertIn(501, rows)
        failed = [t for t in self.store.coverage() if t["status"] == "failed"]
        self.assertEqual(failed[0]["error"]["code"], "GRAPHQL_VISIBILITY_UNKNOWN")

    def test_graphql_partial_preserves_data_without_advancing(self):
        """부분 응답은 유효 관찰을 보존하되 성공 페이지로 확정하지 않는다."""
        self.client.graphql_body["errors"] = [{"message": "SYNTHETIC_DO_NOT_PERSIST_ERROR"}]
        rows = self.collect()
        self.assertIn("canAccessProject", rows[501]["metadata"])
        self.assertNotIn("hasTokenExposed", rows[501]["metadata"])
        task = next(t for t in self.store.coverage() if t["handler"] == "graphql_triggers")
        self.assertEqual((task["status"], task["pages_completed"]), ("failed", 0))
        self.assertNotIn(
            "SYNTHETIC_DO_NOT_PERSIST_ERROR", (self.directory / "errors.json").read_text()
        )

    def test_repeated_run_is_idempotent(self):
        """같은 완료 실행을 다시 구동해도 토큰 개체·작업 수가 증가하지 않는다."""
        self.collect()
        before = len(list(self.store.inventory())), len(list(self.store.coverage()))
        self.collect()
        self.assertEqual(
            before, (len(list(self.store.inventory())), len(list(self.store.coverage())))
        )

    def test_changed_principal_cannot_resume(self):
        """다른 수집 계정의 관찰을 같은 실행으로 합치지 않는다."""
        self.collect()
        self.client.routes["/user"]["id"] = 99
        with self.assertRaisesRegex(CollectionError, "이전 계정"):
            Collector(self.config, self.client, self.store).initialize()

    def test_page_limit_reports_incomplete(self):
        """안전 한도를 완주로 위장하지 않는다."""
        limited = Config.from_dict(
            {
                "base_url": "https://gitlab.example",
                "group_ids": [10],
                "page_size": 2,
                "max_pages_per_task": 1,
            }
        )
        Collector(limited, inventory_client(limited), self.store).run()
        self.assertTrue(
            any(
                t["error"] and t["error"]["code"] == "PAGE_LIMIT_REACHED"
                for t in self.store.coverage()
            )
        )

    def test_missing_token_is_not_revoked(self):
        """두 수집 결과의 집합 차이는 미관찰로 표현하며 폐기를 추정하지 않는다."""
        self.collect()
        previous = self.directory / "inventory.json"
        other = Store(Path(self.temp.name) / "second", self.config.fingerprint())
        try:
            client = inventory_client(self.config)
            client.routes["/projects/100/deploy_tokens"] = []
            Collector(self.config, client, other).run()
            other.export(previous)
            changes = json.loads((other.directory / "changes.json").read_text())
            absent = [c for c in changes if c["change"] == "not_observed"]
            self.assertEqual(len(absent), 1)
            self.assertIs(absent[0]["revocation_inferred"], False)
        finally:
            other.close()

    def test_page_write_and_checkpoint_are_atomic(self):
        """페이지 저장 직후 예외가 나도 관찰·하위 작업·체크포인트가 함께 롤백된다."""
        collector = Collector(self.config, self.client, self.store)
        collector.initialize()
        task = self.store.next_task()
        before_tasks = len(list(self.store.coverage()))
        with (
            patch.object(self.store, "page_done", side_effect=RuntimeError("synthetic crash")),
            self.assertRaises(RuntimeError),
        ):
            collector.process(task)
        self.assertEqual(list(self.store.inventory()), [])
        self.assertEqual(len(list(self.store.coverage())), before_tasks)
        self.assertEqual(self.store.next_task()["pages"], 0)
        collector.process(self.store.next_task())
        self.assertEqual(len(list(self.store.inventory())), 2)

    def test_graphql_schema_error_includes_safe_field_location(self):
        """응답 오류에 비밀 문자열이 있어도 필드명·위치만 진단 결과로 보존한다."""
        self.client.graphql_body = {
            "errors": [
                {
                    "message": "SYNTHETIC_DO_NOT_PERSIST_ERROR",
                    "locations": [{"line": 4, "column": 7}],
                    "extensions": {
                        "code": "undefinedField",
                        "typeName": "PipelineTrigger",
                        "fieldName": "expiresAt",
                    },
                }
            ]
        }
        self.collect()
        error = next(
            t["error"] for t in self.store.coverage() if t["handler"] == "graphql_triggers"
        )
        self.assertEqual(error["diagnostics"]["graphql_errors"][0]["fieldName"], "expiresAt")
        self.assertNotIn(
            "SYNTHETIC_DO_NOT_PERSIST_ERROR", (self.directory / "errors.json").read_text()
        )

    def test_legacy_jsonl_and_json_produce_same_changes(self):
        """첫 실계정 JSONL을 버리지 않고 새 JSON과 같은 의미로 변경 비교한다."""
        self.collect()
        previous = self.directory / "inventory.json"
        legacy = self.directory / "inventory.jsonl"
        legacy.write_text(
            "\n".join(json.dumps(row) for row in json.loads(previous.read_text())) + "\n",
            encoding="utf-8",
        )
        other = Store(Path(self.temp.name) / "second", self.config.fingerprint())
        try:
            client = inventory_client(self.config)
            client.routes["/projects/100/deploy_tokens"] = []
            Collector(self.config, client, other).run()
            coverage = list(other.coverage())
            expected = list(other.compare(previous, coverage))
            self.assertTrue(expected)
            self.assertEqual(list(other.compare(legacy, coverage)), expected)
        finally:
            other.close()

    def test_resume_keeps_legacy_export_and_writes_json(self):
        """기존 실행을 재개하면 새 JSON을 만들고 과거 JSONL은 삭제·덮어쓰기하지 않는다."""
        self.collect()
        legacy = self.directory / "inventory.jsonl"
        legacy.write_text(
            "\n".join(json.dumps(row) for row in self.store.inventory()) + "\n", encoding="utf-8"
        )
        original = legacy.read_bytes()
        (self.directory / "inventory.json").unlink()
        self.store.close()
        self.store = Store(self.directory, self.config.fingerprint(), resume=True)
        self.collect()
        self.assertEqual(legacy.read_bytes(), original)
        self.assertEqual(len(json.loads((self.directory / "inventory.json").read_text())), 12)
        self.assertEqual(self.manifest["output_format"], "json")

    def test_compare_reads_previous_before_replacing_same_path(self):
        """재내보내기 시 이전 파일을 먼저 덮어써 실제 변경이 사라지는 회귀를 막는다."""
        self.collect()
        previous = self.directory / "inventory.json"
        old_rows = json.loads(previous.read_text())
        old_rows[0]["metadata"]["historical_field"] = "previous value"
        write_json_array(previous, old_rows)
        self.store.export(previous)
        changes = json.loads((self.directory / "changes.json").read_text())
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["change"], "metadata_changed")
        self.assertEqual(changes[0]["fields"], ["historical_field"])

    def test_compare_rejects_invalid_inventory_shape(self):
        """잘못된 JSON 파일을 빈 인벤토리나 정상 비교로 해석하지 않는다."""
        self.collect()
        previous = self.directory / "invalid.json"
        for document in ({}, [None], [{"schema_version": "1.0", "inventory_id": "x"}]):
            with self.subTest(document=document):
                previous.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(ValueError):
                    list(self.store.compare(previous, list(self.store.coverage())))


class TransportAndModelTests(unittest.TestCase):
    """외부 네트워크 없이 전송 실패와 보존 규칙의 경계 조건을 검증한다."""

    def test_secret_removal_preserves_unknown_and_null(self):
        """키를 선택적으로 삭제하면서 미반환과 null의 구별을 보존한다."""
        clean, removed = sanitize(
            {"new_field": None, "nested": {"secretToken": "hidden", "expires_at": None}}
        )
        self.assertEqual(clean, {"new_field": None, "nested": {"expires_at": None}})
        self.assertEqual(removed, ["nested.secretToken"])

    def test_explicit_null_owner_is_not_missing_field(self):
        """공통 요약에서도 API의 명시적 null과 미제공 필드를 구분한다."""
        _, summary = metadata_view(
            [
                {
                    "metadata": {"owner": None, "created_by_user_id": None},
                    "observed_at": "2026-09-20",
                    "source_id": "fixture",
                }
            ]
        )
        self.assertEqual(summary["owner"]["status"], "null")
        self.assertEqual(summary["issuer"]["status"], "null")

    def test_scoped_ids_cannot_collide_across_types(self):
        """다른 Token 유형·자산에서 숫자 ID가 같다고 병합하지 않는다."""
        a = identity("https://gitlab.com", "group_access_token", 1, {"kind": "group", "id": 10})
        b = identity("https://gitlab.com", "project_access_token", 1, {"kind": "project", "id": 10})
        self.assertNotEqual(stable_id(a), stable_id(b))

    def test_cross_origin_pagination_rejected(self):
        """페이지 Link가 인증 범위를 벗어날 때 전송 전에 거부한다."""
        client = inventory_client(Config.from_dict({}))
        with self.assertRaises(CollectionError):
            next_page(
                client,
                "https://gitlab.com/api/v4/personal_access_tokens",
                {"link": '<https://other.example/api/v4/tokens>; rel="next"'},
                100,
                100,
            )

    def test_missing_total_headers_does_not_stop_at_full_page(self):
        """총 건수·다음 페이지 헤더가 없는 가득 찬 페이지는 다음 offset을 확인한다."""
        client = inventory_client(Config.from_dict({}))
        url = next_page(
            client, "https://gitlab.com/api/v4/personal_access_tokens?page=1", {}, 100, 100
        )
        self.assertIn("page=2", url)
        self.assertIsNone(next_page(client, url, {}, 0, 100))

    def test_http_429_honors_retry_after(self):
        """가짜 HTTP opener로 Retry-After 대기를 지키며 GET을 재시도하는지 확인한다."""

        class Stream(BytesIO):
            """urllib 응답의 JSON 스트림·헤더를 재현한다."""

            headers: ClassVar[dict] = {}

        class Opener:
            """첫 요청은 429, 다음 요청은 정상 JSON을 반환한다."""

            calls = 0

            def open(self, request, timeout):
                """인증값 출력 없이 HTTPError를 합성한다."""
                self.calls += 1
                if self.calls == 1:
                    raise HTTPError(
                        request.full_url, 429, "limited", {"Retry-After": "2"}, BytesIO()
                    )
                return Stream(b"[]")

        waits = []
        client = Client(
            Config.from_dict({"burst": 10}), "TEST_ONLY_AUTH", opener=Opener(), sleep=waits.append
        )
        response = client.request("/api/v4/personal_access_tokens")
        self.assertEqual(response.body, [])
        self.assertEqual(waits, [2.0])
        self.assertEqual(client.retries, 1)

    def test_retry_after_http_date(self):
        """Retry-After 날짜는 초로 해석하고 비정상 무한·NaN 대기값은 거부한다."""
        self.assertEqual(retry_after("Thu, 01 Jan 1970 00:01:00 GMT", wall_time=lambda: 50), 10)
        self.assertEqual(retry_after("inf"), 0)
        self.assertEqual(retry_after("nan"), 0)

    @unittest.skipUnless(os.name == "posix", "Native CLI QA requires POSIX flock")
    def test_emergency_export_keeps_exclusive_lock(self):
        """내부 오류 후 결과를 내보내는 동안에도 다른 실행의 쓰기를 차단한다."""
        import fcntl

        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            output = Path(directory) / "failed"
            config = Path(directory) / "config.json"
            config.write_text("{}", encoding="utf-8")

            def verify_locked(store, code):
                """긴급 출력 시점에서 별도 파일 핸들로 경쟁 잠금을 시도한다."""
                with (
                    (output / ".collector.lock").open("a+") as contender,
                    self.assertRaises(BlockingIOError),
                ):
                    fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            with (
                patch.dict(os.environ, {"GITLAB_QA_TOKEN": "SYNTHETIC_AUTH"}),
                patch(
                    "cremore_gitlab_provider.metadata.tests._qa_cli.Collector.run",
                    side_effect=CollectionError("TEST_FAILURE", "합성 실패"),
                ),
                patch(
                    "cremore_gitlab_provider.metadata.tests._qa_cli.export_failure",
                    side_effect=verify_locked,
                ) as export,
            ):
                self.assertEqual(main(["collect", "--config", str(config), "--token-env",
                                       "GITLAB_QA_TOKEN", "--output", str(output)]), 1)
                export.assert_called_once()
            with (output / ".collector.lock").open("a+") as contender:
                fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_config_rejects_unknown_and_insecure_settings(self):
        """잘못된 범위·비밀 설정을 조용히 무시하지 않는다."""
        for value in (
            {"token": "not_allowed"},
            {"base_url": "http://gitlab.com"},
            {"group_ids": [True]},
            {"page_size": 0},
        ):
            with self.assertRaises(ValueError):
                Config.from_dict(value)

    @unittest.skipUnless(os.name == "posix", "Native CLI QA requires POSIX flock")
    def test_cli_collect_emits_parseable_json_arrays(self):
        """빈 목록 응답만 주입해 QA 명령의 결과 형식·완주를 확인한다."""
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            from ._responses import FakeClient

            output = Path(directory) / "run"
            config = Path(directory) / "config.json"
            config.write_text("{}", encoding="utf-8")
            with (
                patch.dict(os.environ, {"GITLAB_QA_TOKEN": "SYNTHETIC_AUTH"}),
                patch("cremore_gitlab_provider.metadata.tests._qa_cli.Client",
                      side_effect=lambda config, token: FakeClient(config)),
            ):
                result = main(["collect", "--config", str(config), "--token-env",
                               "GITLAB_QA_TOKEN", "--output", str(output)])
            self.assertEqual(result, 0)
            documents = {}
            for name in ("inventory", "assets", "coverage", "errors"):
                documents[name] = json.loads((output / f"{name}.json").read_text())
                self.assertIsInstance(documents[name], list)
            self.assertEqual(documents["inventory"], [])
            self.assertEqual(documents["errors"], [])
            self.assertEqual(
                json.loads((output / "manifest.json").read_text())["output_format"], "json"
            )
            self.assertEqual(list(output.glob("*.jsonl")), [])

    def test_json_writer_preserves_unicode_nested_fields_and_empty_array(self):
        """JSON 배열의 빈 목록·한국어·null·불리언·중첩 필드와 파일 권한을 검증한다."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "inventory.json"
            write_json_array(output, iter(()))
            self.assertEqual(json.loads(output.read_text()), [])
            rows = [
                {
                    "name": "수집 검증",
                    "metadata": {"unknown": None, "active": False, "scopes": ["read_api"]},
                }
            ]
            write_json_array(output, iter(rows))
            self.assertEqual(json.loads(output.read_text()), rows)
            self.assertIn("수집 검증", output.read_text())
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_failed_json_serialization_preserves_previous_file(self):
        """배열 중간에서 잘못된 값이 나와도 기존 JSON과 접근 권한을 손상시키지 않는다."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "inventory.json"
            write_json_array(output, [{"name": "previous"}])
            original = output.read_bytes()
            for invalid in (float("nan"), object()):
                with self.subTest(invalid_type=type(invalid).__name__):
                    with self.assertRaises((ValueError, TypeError)):
                        write_json_array(output, iter([{"name": "new"}, {"invalid": invalid}]))
                    self.assertEqual(output.read_bytes(), original)
                    self.assertEqual(list(Path(directory).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
