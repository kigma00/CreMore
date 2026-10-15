"""목적별 제외·JSON 표시 순서가 토큰 권한·감사 근거·재개·비교를 훼손하지 않는지 확인한다."""

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

from cremore_gitlab_provider.metadata.collector import TRIGGER_QUERY, Collector
from cremore_gitlab_provider.metadata.config import Config
from cremore_gitlab_provider.metadata.metadata_policy import (
    GROUP_EXCLUDED,
    PROJECT_EXCLUDED,
    USER_EXCLUDED,
    prepare_metadata,
)
from cremore_gitlab_provider.metadata.model import stable_id
from cremore_gitlab_provider.metadata.presentation import order_for_json

from ._qa_storage import Store
from .test_hardening import audit_environment


class SelectionTests(unittest.TestCase):
    """같은 필드명이라도 객체 종류에 따라 다른 의미를 보존하는 회귀 검사."""

    def test_nested_user_fields_are_removed_without_dropping_token_permissions(self):
        """사용자 프로필만 줄이고 Fine-grained 권한·null·새 확장 필드는 보존한다."""
        payload = {
            "id": 1,
            "name": "token",
            "bio": "unknown token metadata",
            "active": False,
            "last_used_at": None,
            "last_used_ips": ["192.0.2.1"],
            "granular_scopes": [{"permissions": ["read_project"], "project_id": 100}],
            "owner": {
                "id": 2,
                "avatarUrl": "DROP_ME",
                "bioHtml": "DROP_ME",
                "lastSignInAt": "DROP_ME",
                "email": "owner@example.invalid",
                "organization": "Demo",
                "job_title": "Engineer",
                "identities": [{"provider": "saml", "extern_uid": "demo"}],
            },
            "future_field": {"permissions": ["custom"], "location": "preserve unknown meaning"},
        }
        before = deepcopy(payload)
        clean, secrets, excluded = prepare_metadata(payload, "personal_access_token")
        self.assertEqual(payload, before)
        self.assertNotIn("DROP_ME", json.dumps(clean))
        self.assertEqual(clean["granular_scopes"], payload["granular_scopes"])
        self.assertEqual(clean["future_field"], payload["future_field"])
        self.assertEqual(clean["owner"]["identities"], payload["owner"]["identities"])
        self.assertEqual(clean["last_used_ips"], payload["last_used_ips"])
        self.assertIsNone(clean["last_used_at"])
        self.assertIs(clean["active"], False)
        self.assertEqual(set(excluded), {"owner.avatarUrl", "owner.bioHtml", "owner.lastSignInAt"})
        self.assertEqual(secrets, [])

    def test_nested_asset_copies_keep_discovery_fields_and_security_context(self):
        """그룹 내 프로젝트·namespace에도 적용하되 수집에 쓰이는 경로/날짜/상위 ID는 남긴다."""
        payload = {
            "id": 10,
            "parent_id": None,
            "created_at": "2026-09-01T00:00:00Z",
            "service_access_tokens_expiration_enforced": True,
            "avatar_url": "DROP_ME",
            "projects": [
                {
                    "id": 100,
                    "path_with_namespace": "demo/project",
                    "permissions": {"group_access": "DROP_ME"},
                    "star_count": 3,
                    "visibility": "private",
                    "default_branch": "main",
                    "namespace": {"id": 10, "avatar_url": "DROP_ME"},
                    "owner": {"id": 2, "theme_id": 1, "state": "active"},
                }
            ],
        }
        clean, _, excluded = prepare_metadata(payload, "group")
        project = clean["projects"][0]
        self.assertNotIn("DROP_ME", json.dumps(clean))
        self.assertEqual(project["path_with_namespace"], "demo/project")
        self.assertEqual(project["visibility"], "private")
        self.assertEqual(clean["created_at"], payload["created_at"])
        self.assertIn("parent_id", clean)
        self.assertIn("service_access_tokens_expiration_enforced", clean)
        self.assertIn("projects[0].permissions", excluded)
        self.assertNotIn("star_count", project)
        self.assertNotIn("theme_id", project["owner"])

    def test_every_approved_group_is_excluded_before_sqlite_and_export(self):
        """고유 표식을 넣어 전체 JSON·SQLite에 제외 값이 남지 않고 감사/연락처가 유지됨을 검사한다."""
        with audit_environment() as (config, store, client):
            # 타입 검증에 쓰이지 않는 제외 필드에만 고유 표식을 심어 저장 전 제거를 검증한다.
            for path, body in client.routes.items():
                if path == "/user" or path.startswith("/users/"):
                    body.update({key: f"APPROVED_DROP_{key}" for key in USER_EXCLUDED})
                    body.update(
                        email="keep@example.invalid", job_title="Engineer", organization="Demo"
                    )
            for path in ("/groups/10", "/groups/20"):
                client.routes[path].update({key: f"APPROVED_DROP_{key}" for key in GROUP_EXCLUDED})
            client.routes["/projects/100"].update(
                {key: f"APPROVED_DROP_{key}" for key in PROJECT_EXCLUDED}
            )
            trigger = client.routes["/projects/100/triggers"][0]
            client.routes["/projects/100/access_tokens"][0]["last_used_ips"] = ["192.0.2.1"]
            client.routes["/personal_access_tokens"][2]["granular_scopes"] = [
                {"project_id": 100, "permissions": ["read_repository"]}
            ]
            trigger["owner"] = {
                "id": 1,
                "username": "demo",
                "avatar_url": "APPROVED_DROP_INLINE_PROFILE",
            }
            client.events["/projects/100/audit_events"][0]["details"].update(
                author_email="actor@example.invalid",
                ip_address="192.0.2.10",
                user_agent="retained-agent",
                author={"id": 2, "bio": "APPROVED_DROP_AUDIT_PROFILE"},
            )
            Collector(config, client, store).run()
            manifest = store.export()
            self.assertTrue(manifest["all_scheduled_tasks_complete"])
            self.assertEqual(manifest["audit_enrichment"]["matched_events"], 2)
            self.assertEqual(
                manifest["metadata_selection_policy"]["version"], "cremore_inventory_v1"
            )
            for path in store.directory.iterdir():
                if path.is_file():
                    self.assertNotIn(b"APPROVED_DROP_", path.read_bytes(), path.name)
            rows = {r["token_id"]: r for r in store.inventory()}
            self.assertEqual(
                rows[302]["summary"]["issuer"]["profile"]["email"], "keep@example.invalid"
            )
            self.assertEqual(rows[203]["metadata"]["last_used_ips"], ["192.0.2.1"])
            self.assertEqual(
                rows[103]["metadata"]["granular_scopes"][0]["permissions"], ["read_repository"]
            )
            event = next(e for e in store.audit_events() if e["event_id"] == 9001)
            self.assertEqual(event["metadata"]["details"]["author_email"], "actor@example.invalid")
            self.assertEqual(event["metadata"]["details"]["ip_address"], "192.0.2.10")
            self.assertEqual(event["metadata"]["details"]["user_agent"], "retained-agent")
            self.assertIn("custom_message", event["metadata"]["details"])
            assets = json.loads((store.directory / "assets.json").read_text())
            user = next(a for a in assets if a["kind"] == "user" and a["id"] == 1)
            self.assertIn("bio", user["excluded_metadata_fields"])
            self.assertNotIn("hasTokenExposed", rows[501]["metadata"])
            self.assertIn("canAccessProject", rows[501]["metadata"])
            self.assertNotIn("hasTokenExposed", TRIGGER_QUERY)

    def test_exclusion_paths_survive_sparse_asset_refresh(self):
        """후속 상세 응답에 해당 키가 없어도 정책으로 제외한 필드라는 기록은 보존한다."""
        with audit_environment(include_audit_events=False) as (_, store, _):
            with store.db:
                store.save_asset(
                    "user", 1, {"id": 1, "bio": "drop", "email": "keep@example.invalid"}, "/user"
                )
                store.save_asset("user", 1, {"id": 1, "username": "demo"}, "/users/1")
            row = json.loads(
                store.db.execute(
                    "SELECT value FROM assets WHERE kind='user' AND id='1'"
                ).fetchone()[0]
            )
            self.assertEqual(row["excluded_metadata_fields"], ["bio"])
            self.assertEqual(row["metadata"]["email"], "keep@example.invalid")

    def test_old_contract_resume_is_rejected_without_writing_old_database(self):
        """v0.5의 전체 메타데이터가 새 선별 결과에 섞이지 않도록 재개 전에 거부한다."""
        config = Config.from_dict({})
        old_config = {
            k: v for k, v in asdict(config).items() if k not in config.transport_settings()
        }
        old_config["collection_contract_version"] = 3
        old_hash = hashlib.sha256(json.dumps(old_config, sort_keys=True).encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            Store(path, old_hash).close()
            before = (path / "state.sqlite3").read_bytes()
            with self.assertRaises(ValueError):
                Store(path, config.fingerprint(), resume=True)
            self.assertEqual((path / "state.sqlite3").read_bytes(), before)

    def test_old_inventory_comparison_ignores_policy_removal_but_detects_permission_change(self):
        """선별 변경은 오탐에서 빼되 실제 권한 변경은 계속 검출하고 예전 파일은 수정하지 않는다."""
        with audit_environment(include_audit_events=False) as (config, store, client):
            client.routes["/personal_access_tokens"][2]["granular_scopes"] = [
                {"project_id": 100, "permissions": ["read_repository"]}
            ]
            Collector(config, client, store).run()
            previous = list(store.inventory())
            for row in previous:
                row["schema_version"] = "1.1"
                row.pop("token_id")
            trigger = next(r for r in previous if r["identity"]["native_id"] == 501)
            trigger["metadata"]["hasTokenExposed"] = True
            trigger["metadata"]["owner"]["avatar_url"] = "old-avatar"
            path = store.directory / "previous.json"
            path.write_text(json.dumps(previous))
            before = path.read_bytes()
            coverage = list(store.coverage())
            self.assertEqual(list(store.compare(path, coverage)), [])
            self.assertEqual(path.read_bytes(), before)
            fine = next(r for r in previous if r["identity"]["native_id"] == 103)
            fine["metadata"]["granular_scopes"][0]["permissions"] = ["read_user"]
            path.write_text(json.dumps(previous))
            changes = list(store.compare(path, coverage))
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0]["fields"], ["granular_scopes"])


class PresentationTests(unittest.TestCase):
    """JSON 필드 순서를 바꿔도 데이터의 의미·식별자·타입이 변하지 않아야 한다."""

    def test_output_begins_with_native_token_id_and_common_field_order_is_consistent(self):
        """실제 내보내기에서 토큰 ID·종류·관계가 먼저 나오고 공통 메타데이터 순서가 같음을 확인한다."""
        with audit_environment(include_audit_events=False) as (config, store, client):
            Collector(config, client, store).run()
            store.export()
            rows = json.loads((store.directory / "inventory.json").read_text())
            common = {"id", "name", "scopes", "active", "created_at", "expires_at", "last_used_at"}
            for row in rows:
                self.assertEqual(
                    list(row)[:4], ["token_id", "credential_types", "summary", "metadata"]
                )
                self.assertEqual(row["token_id"], row["identity"]["native_id"])
                self.assertEqual(row["inventory_id"], stable_id(row["identity"]))
                self.assertEqual(
                    list(row["summary"])[:4], ["name", "description", "owner", "issuer"]
                )
                metadata = row["metadata"]
                if common <= metadata.keys():
                    self.assertEqual(
                        [k for k in metadata if k in common],
                        [
                            "id",
                            "name",
                            "scopes",
                            "active",
                            "created_at",
                            "expires_at",
                            "last_used_at",
                        ],
                    )
            missing_name = next(r for r in rows if r["token_id"] == 501)
            self.assertNotIn("name", missing_name["metadata"])
            self.assertEqual(missing_name["summary"]["name"]["status"], "not_provided")

    def test_ordering_is_deterministic_without_inserting_fields_or_changing_arrays(self):
        """알 수 없는 키는 뒤에 이름순으로 두되 누락을 null로 채우거나 배열 값을 정렬하지 않는다."""
        row = {
            "metadata": {
                "z_extra": 1,
                "expires_at": None,
                "active": False,
                "scopes": ["write", "read"],
                "name": "demo",
                "id": 9,
                "a_extra": {"z": 2, "a": 1},
            },
            "token_id": 9,
            "credential_types": ["personal_access_token"],
            "summary": {},
        }
        before = deepcopy(row)
        ordered = order_for_json(row, "inventory")
        reverse = {k: row[k] for k in reversed(row)}
        reverse["metadata"] = {k: row["metadata"][k] for k in reversed(row["metadata"])}
        self.assertEqual(json.dumps(order_for_json(reverse, "inventory")), json.dumps(ordered))
        self.assertEqual(ordered, before)
        self.assertEqual(row, before)
        self.assertEqual(list(ordered["metadata"])[-2:], ["a_extra", "z_extra"])
        self.assertNotIn("description", ordered["metadata"])
        self.assertEqual(ordered["metadata"]["scopes"], ["write", "read"])
