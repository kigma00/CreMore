# Native QA only, preserved from GitLab 744c48c. The deployed worker never imports this module.
"""SQLite 작업 상태와 JSON 출력. 페이지 저장·체크포인트를 같은 트랜잭션으로 묶는다."""

import json
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path

from ..audit import TokenAuditIndex, enrich_from_audit, event_types, token_audit_scopes
from ..handlers import TOKEN_LIST_HANDLERS
from ..metadata_policy import METADATA_POLICY, policy_description, prepare_metadata
from ..model import dumps, metadata_view, native_id, now, observed_scopes, sanitize, stable_id
from ..presentation import order_for_json

SCHEMA_VERSION = "1.2"


@contextmanager
def atomic_json_file(destination: Path):
    """권한 0600의 임시 파일을 완전히 기록한 뒤 교체하고 실패 시 기존 파일을 보존한다."""
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        # 같은 디렉터리 안에서 교체하므로 독자는 완성된 JSON만 읽는다.
        temporary.replace(destination)
    finally:
        # 직렬화나 디스크 쓰기가 실패해도 이번에 만든 임시 파일만 정리한다.
        temporary.unlink(missing_ok=True)


def write_json_array(destination: Path, rows, context: str = "default"):
    """전체 목록을 메모리에 쌓지 않고 레코드별로 들여쓴 UTF-8 JSON 배열을 기록한다."""
    with atomic_json_file(destination) as stream:
        stream.write("[")
        first = True
        for row in rows:
            # 표준 JSON이 아닌 NaN·Infinity는 거부하고 null·불리언·중첩 필드는 그대로 둔다.
            # 해시용 dumps의 키 정렬과 별개로, 사용자 JSON은 업무 순서대로 표시한다.
            encoded = json.dumps(
                order_for_json(row, context), ensure_ascii=False, indent=2, allow_nan=False
            )
            stream.write("\n" if first else ",\n")
            stream.write("  " + encoded.replace("\n", "\n  "))
            first = False
        stream.write("\n]\n" if not first else "]\n")


def read_previous_inventory(previous: Path):
    """현재 JSON 배열과 이전 JSONL을 모두 읽어 기존 실검증 결과와의 비교를 지원한다."""
    with previous.open(encoding="utf-8") as stream:
        if previous.suffix.lower() == ".jsonl":
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"이전 JSONL 구문 오류: line={line_number}, column={exc.colno}"
                    ) from exc
        else:
            document = json.load(stream)
            if not isinstance(document, list):
                raise ValueError("이전 inventory.json의 최상위 값은 토큰 목록 배열이어야 합니다.")
            yield from document


class Store:
    """사용자 결과는 JSON 배열, 내부 재개·중복 제어는 SQLite로 담당한다."""

    def __init__(self, directory: Path, config_hash: str, resume: bool = False):
        """다른 실행을 덮어쓰지 않고, 재개 시 동일 설정인지 확인한다."""
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory = directory
        database = directory / "state.sqlite3"
        if database.exists() != resume:
            raise ValueError("새 출력 경로를 사용하거나 기존 실행에 --resume을 지정하세요.")
        self.db = sqlite3.connect(database)
        self.db.row_factory = sqlite3.Row
        # 감사와 목록 응답의 도착 순서와 무관하게, 내보내기 직전에 최종 ID를 대조한다.
        self._audit_dirty = True
        self.db.execute("PRAGMA foreign_keys=ON")
        # 재개 계약을 DDL보다 먼저 검사한다. 거부될 구버전 DB에 새 테이블조차 만들지 않는다.
        if resume:
            try:
                saved = self.get_setting("config_hash")
            except sqlite3.DatabaseError:
                self.db.close()
                raise ValueError(
                    "재개할 수집기 설정을 읽을 수 없습니다. 새 출력 경로를 사용하세요."
                ) from None
            if saved != config_hash:
                self.db.close()
                raise ValueError(
                    "재개 시 조회 범위나 수집 계약이 달라졌습니다. 새 출력 경로를 사용하세요."
                )
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
                spec TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                next_url TEXT, cursor TEXT, pages INTEGER NOT NULL DEFAULT 0,
                records_seen INTEGER NOT NULL DEFAULT 0, error TEXT, completed_at TEXT);
            CREATE TABLE IF NOT EXISTS pages (task_id TEXT, page_key TEXT, PRIMARY KEY(task_id,page_key));
            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY, identity_json TEXT NOT NULL, families TEXT NOT NULL,
                scope TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS observations (
                record_id TEXT, source_id TEXT, value TEXT NOT NULL,
                PRIMARY KEY(record_id,source_id), FOREIGN KEY(record_id) REFERENCES records(id));
            CREATE TABLE IF NOT EXISTS assets (kind TEXT, id TEXT, value TEXT, PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, record_id TEXT, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS filtered_audit_events (id TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS audit_record_index ON audit_events(record_id);
            CREATE TABLE IF NOT EXISTS errors (seq INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);
        """)
        saved = self.get_setting("config_hash")
        if saved is not None and saved != config_hash:
            self.db.close()
            raise ValueError(
                "재개 시 설정이 달라졌습니다. 같은 설정 또는 새 출력 경로를 사용하세요."
            )
        with self.db:
            self.set_setting("config_hash", config_hash)
            if self.get_setting("started_at") is None:
                self.set_setting("started_at", now())
            if resume:
                # 완료 페이지·관찰은 유지하고 실패한 작업의 현 위치에서 재시도한다.
                self.db.execute(
                    "UPDATE tasks SET status='pending',error=NULL WHERE status='failed'"
                )
        os.chmod(database, 0o600)

    def close(self):
        """CLI 종료 시 SQLite 핸들을 닫는다."""
        self.db.close()

    def note(self, code: str, scope: dict):
        """실패와 별개인 설정 제외·범위 미확인 사유를 실행 설명에 보존한다."""
        notes = self.get_setting("coverage_notes") or []
        value = {"code": code, "scope": scope}
        if value not in notes:
            notes.append(value)
            self.set_setting("coverage_notes", notes)

    def get_setting(self, key: str):
        """JSON 인코딩된 실행 설정 한 개를 읽는다."""
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_setting(self, key: str, value):
        """인증 원문을 제외한 실행 식별·범위를 저장한다."""
        self.db.execute(
            "INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, dumps(value)),
        )

    def add_task(self, handler: str, path: str, context: dict, params: dict | None = None) -> str:
        """동일한 공식 API 작업을 한 번만 큐에 넣는다. 순서는 BFS 작업 큐로 사용한다."""
        spec = {"handler": handler, "path": path, "context": context, "params": params or {}}
        task_id = stable_id(spec)
        self.db.execute("INSERT OR IGNORE INTO tasks(id,spec) VALUES (?,?)", (task_id, dumps(spec)))
        return task_id

    def next_task(self):
        """가장 먼저 등록한 미완료 작업을 반환한다."""
        row = self.db.execute(
            "SELECT * FROM tasks WHERE status='pending' ORDER BY seq LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        task = dict(row)
        task["spec"] = json.loads(task["spec"])
        return task

    def save_asset(self, kind: str, asset_id: int, metadata: dict, source: str):
        """연결 자산·소유자 메타데이터를 저장하되 token 발급자라는 의미는 부여하지 않는다."""
        clean, removed, excluded = prepare_metadata(metadata, kind)
        old = self.db.execute(
            "SELECT value FROM assets WHERE kind=? AND id=?", (kind, str(asset_id))
        ).fetchone()
        previous = json.loads(old[0]) if old else {}
        merged = previous.get("metadata", {})
        merged.update(clean)
        # 상세 API가 목록에 있던 제외 필드를 반환하지 않아도 앞서 제외한 사실은 남긴다.
        excluded = sorted(set(previous.get("excluded_metadata_fields", [])) | set(excluded))
        value = {
            "kind": kind,
            "id": asset_id,
            "metadata": merged,
            "source": source,
            "observed_at": now(),
            "excluded_credential_fields": removed,
            "excluded_metadata_fields": excluded,
        }
        self.db.execute(
            "INSERT INTO assets VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET value=excluded.value",
            (kind, str(asset_id), dumps(value)),
        )

    def save_record(
        self, identity: dict, family: str, scope: dict, metadata: dict, task: dict, page_url: str
    ):
        """A01a의 키를 A01c UPSERT에 사용하고 정책을 통과한 메타데이터를 출처별로 보존한다."""
        record_id = stable_id(identity)
        timestamp = now()
        previous = self.db.execute(
            "SELECT families FROM records WHERE id=?", (record_id,)
        ).fetchone()
        families = set(json.loads(previous[0])) if previous else set()
        families.add(family)
        self.db.execute(
            """INSERT INTO records VALUES (?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET families=excluded.families,scope=excluded.scope,last_seen=excluded.last_seen""",
            (
                record_id,
                dumps(identity),
                dumps(sorted(families)),
                dumps(identity["scope"]),
                timestamp,
                timestamp,
            ),
        )
        clean, removed, excluded = prepare_metadata(metadata, family)
        observation = {
            "source_id": task["id"],
            "endpoint": task["spec"]["path"],
            "handler": task["spec"]["handler"],
            "request_url": page_url,
            "context": task["spec"]["context"],
            "observed_at": timestamp,
            "metadata": clean,
            "excluded_credential_fields": removed,
            "excluded_metadata_fields": excluded,
        }
        self.db.execute(
            "INSERT INTO observations VALUES (?,?,?) ON CONFLICT(record_id,source_id) DO UPDATE SET value=excluded.value",
            (record_id, task["id"], dumps(observation)),
        )
        self._audit_dirty = True
        return record_id

    def asset_metadata(self, kind: str, asset_id: int):
        """감사 기간과 사용자 표시 정보에 필요한 연결 자산의 실제 응답을 읽는다."""
        row = self.db.execute(
            "SELECT value FROM assets WHERE kind=? AND id=?", (kind, str(asset_id))
        ).fetchone()
        return json.loads(row[0])["metadata"] if row else None

    def save_audit_event(self, event: dict, interpretation: dict, task: dict, page_url: str):
        """선별한 토큰 관련 기록만 저장한다. 감사 기록으로 현재 토큰 목록을 만들어내지 않는다."""
        scope = task["spec"]["context"]["scope"]
        event_id = native_id(event.get("id"))
        key = stable_id({"scope": scope, "event_id": event_id})
        old = self.db.execute("SELECT value FROM audit_events WHERE id=?", (key,)).fetchone()
        sources = {s["source_id"]: s for s in json.loads(old[0])["sources"]} if old else {}
        sources[task["id"]] = {
            "source_id": task["id"],
            "endpoint": task["spec"]["path"],
            "request_url": page_url,
            "observed_at": now(),
        }
        clean, removed, excluded = prepare_metadata(event, "audit")
        value = {
            "audit_event_id": key,
            "event_id": event_id,
            "scope": scope,
            "interpretation": interpretation,
            "metadata": clean,
            "sources": [sources[key] for key in sorted(sources)],
            "excluded_credential_fields": removed,
            "excluded_metadata_fields": excluded,
        }
        self.db.execute(
            "INSERT INTO audit_events VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET record_id=excluded.record_id,value=excluded.value",
            (key, None, dumps(value)),
        )
        self._audit_dirty = True

    def save_filtered_audit_event(self, event: dict, task: dict):
        """선별 제외 근거로 ID·유형·조회 소속만 남긴다. 본문·이름·IP·행위자는 저장하지 않는다."""
        scope = task["spec"]["context"]["scope"]
        event_id = native_id(event.get("id"))
        key = stable_id({"scope": scope, "event_id": event_id})
        row = self.db.execute(
            "SELECT value FROM filtered_audit_events WHERE id=?", (key,)
        ).fetchone()
        previous = json.loads(row[0]) if row else {}
        # 공식 이벤트 유형 식별자 형식만 남겨 임의의 자유문이 진단 파일에 들어오는 것을 막는다.
        names = sorted(
            value for value in event_types(event) if re.fullmatch(r"[a-z][a-z0-9_]{0,199}", value)
        )
        value = {
            "event_id": event_id,
            "event_name": names[0] if len(names) == 1 else None,
            "event_types": names,
            "scope": scope,
            "reason": "not_token_related",
            "source_ids": sorted(set(previous.get("source_ids", [])) | {task["id"]}),
        }
        self.db.execute(
            "INSERT INTO filtered_audit_events VALUES (?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
            (key, dumps(value)),
        )

    def count_audit_page(self, task_id: str, received: int, retained: int):
        """같은 페이지 트랜잭션 안에서 건수를 누적한다. 일반 활동의 본문은 저장하지 않는다."""
        key = f"audit_counts:{task_id}"
        counts = self.get_setting(key) or {"received": 0, "retained": 0, "filtered_out": 0}
        counts["received"] += received
        counts["retained"] += retained
        counts["filtered_out"] += received - retained
        self.set_setting(key, counts)

    def reconcile_audit_events(self):
        """모든 토큰 유형을 ID 해시 인덱스로 대조하고 유일한 후보만 연결한다."""
        if not self._audit_dirty:
            return

        def descriptors():
            """메타데이터 원문 전체 대신 식별·관찰 소속만 메모리 인덱스에 올린다."""
            for row in self.db.execute("SELECT id,identity_json,scope FROM records"):
                observations = [
                    json.loads(o[0])
                    for o in self.db.execute(
                        "SELECT value FROM observations WHERE record_id=?", (row["id"],)
                    )
                ]
                yield {
                    "inventory_id": row["id"],
                    "identity": json.loads(row["identity_json"]),
                    "audit_scopes": token_audit_scopes(json.loads(row["scope"]), observations),
                }

        index = TokenAuditIndex(descriptors())
        with self.db:
            # 같은 테이블을 읽는 cursor의 방문 순서가 UPDATE의 영향을 받지 않게 고정한다.
            rows = self.db.execute("SELECT id,value FROM audit_events ORDER BY id").fetchall()
            for row in rows:
                value = json.loads(row["value"])
                matches, reason = index.match(value["interpretation"], value["scope"])
                record_id = matches[0] if len(matches) == 1 else None
                value.update(
                    candidate_inventory_id=record_id,
                    candidate_inventory_ids=matches,
                    inventory_match_reason=reason,
                )
                self.db.execute(
                    "UPDATE audit_events SET record_id=?,value=? WHERE id=?",
                    (record_id, dumps(value), row["id"]),
                )
        self._audit_dirty = False

    def audit_events(self):
        """관련 이벤트의 미매핑 사유도 내보낸다. 미발견을 폐기로 판단하지 않는다."""
        self.reconcile_audit_events()
        for row in self.db.execute(
            "SELECT a.value, r.id FROM audit_events a LEFT JOIN records r ON r.id=a.record_id ORDER BY a.id"
        ):
            value = json.loads(row[0])
            yield {
                **value,
                "inventory_id": row[1],
                "inventory_match_status": "matched" if row[1] else "not_matched",
            }

    def error(
        self,
        task: dict,
        code: str,
        message: str,
        status=None,
        location: str | None = None,
        details: dict | None = None,
    ):
        """오류 발생 단계·API·코드 위치를 기록하고 빈 목록으로 위장하지 않는다."""
        event = {
            "at": now(),
            "task_id": task["id"],
            "stage": task["spec"]["handler"],
            "endpoint": task["spec"]["path"],
            "context": task["spec"]["context"],
            "code": code,
            "message": message,
            "http_status": status,
            "code_location": location,
        }
        event["diagnostics"] = details or {}
        self.db.execute("INSERT INTO errors(value) VALUES (?)", (dumps(event),))
        self.db.execute(
            "UPDATE tasks SET status='failed',error=? WHERE id=?", (dumps(event), task["id"])
        )

    def page_done(self, task: dict, page_key: str, count: int, next_url=None, cursor=None):
        """관찰·하위 작업 저장과 같은 트랜잭션에서만 다음 위치를 확정한다."""
        self.db.execute("INSERT INTO pages VALUES (?,?)", (task["id"], page_key))
        done = next_url is None and cursor is None
        self.db.execute(
            "UPDATE tasks SET status=?,next_url=?,cursor=?,pages=pages+1,records_seen=records_seen+?,completed_at=? WHERE id=?",
            (
                "complete" if done else "pending",
                next_url,
                cursor,
                count,
                now() if done else None,
                task["id"],
            ),
        )

    def has_page(self, task_id: str, page_key: str) -> bool:
        """순환 페이지 링크·같은 cursor 반복을 탐지한다."""
        return (
            self.db.execute(
                "SELECT 1 FROM pages WHERE task_id=? AND page_key=?", (task_id, page_key)
            ).fetchone()
            is not None
        )

    def coverage(self):
        """페이지 완주 여부와 실패를 포함한 작업별 관찰 범위를 반환한다."""
        for row in self.db.execute("SELECT * FROM tasks ORDER BY seq"):
            spec = json.loads(row["spec"])
            extra = {}
            if spec["handler"] == "audit_events":
                extra["audit_event_counts"] = self.get_setting(f"audit_counts:{row['id']}") or {
                    "received": 0,
                    "retained": 0,
                    "filtered_out": 0,
                }
            yield {
                "source_id": row["id"],
                **spec,
                "status": row["status"],
                "pages_completed": row["pages"],
                "records_seen": row["records_seen"],
                "completed_at": row["completed_at"],
                "error": json.loads(row["error"]) if row["error"] else None,
                **extra,
            }

    def inventory(self):
        """한 Token당 한 행을 구성하고 소유자·발급자 조회 결과를 보강한다."""
        self.reconcile_audit_events()
        config = self.get_setting("config") or {}
        audit_enabled = config.get("include_audit_events") or config.get(
            "include_deploy_token_audit"
        )
        audit_tasks = {}
        for task in self.coverage():
            if task["handler"] in {"audit_plan", "audit_events"}:
                scope = task["context"]["scope"]
                audit_tasks.setdefault((scope["kind"], scope["id"]), []).append(task)
        for row in self.db.execute("SELECT * FROM records ORDER BY id"):
            observations = [
                json.loads(o[0])
                for o in self.db.execute(
                    "SELECT value FROM observations WHERE record_id=? ORDER BY source_id",
                    (row["id"],),
                )
            ]
            metadata, summary = metadata_view(observations)
            extra = {}
            if audit_enabled:
                evidence = [
                    json.loads(r[0])
                    for r in self.db.execute(
                        "SELECT value FROM audit_events WHERE record_id=? ORDER BY id", (row["id"],)
                    )
                ]
                enrich_from_audit(summary, evidence)
                scopes = token_audit_scopes(json.loads(row["scope"]), observations)
                tasks = [task for scope in sorted(scopes) for task in audit_tasks.get(scope, [])]
                states = {t["status"] for t in tasks}
                query_status = (
                    "failed"
                    if "failed" in states
                    else "pending"
                    if "pending" in states
                    else "complete"
                    if any(t["handler"] == "audit_events" for t in tasks)
                    else "not_scheduled"
                )
                extra["audit"] = {
                    "query_status": query_status,
                    "source_ids": [t["source_id"] for t in tasks],
                    "query_scope": "group_project_only",
                    "unqueried_scopes": [
                        {
                            "kind": kind,
                            "id": scope_id,
                            "reason": "user_audit_api_not_collected"
                            if kind == "user"
                            else "scope_not_scheduled",
                        }
                        for kind, scope_id in sorted(scopes)
                        if (kind, scope_id) not in audit_tasks
                    ],
                    "matching_events": len(evidence),
                    "matching_creation_events": sum(
                        e["interpretation"].get("action") == "created" for e in evidence
                    ),
                    "event_refs": [
                        {key: event[key] for key in ("audit_event_id", "event_id", "scope")}
                        for event in evidence
                    ],
                    "event_details_file": "audit_events.json",
                }
            for relation in ("owner", "issuer"):
                person = summary[relation]
                if person["id"] is None:
                    person["profile_status"] = "not_applicable"
                    continue
                # REST user ID와 이미 확인된 GraphQL User GlobalID만 사용자 조회에 대응한다.
                uid = str(person["id"]).removeprefix("gid://gitlab/User/")
                asset = self.db.execute(
                    "SELECT value FROM assets WHERE kind='user' AND id=?", (uid,)
                ).fetchone()
                if asset:
                    person["profile"] = json.loads(asset[0])["metadata"]
                    person["profile_status"] = "observed"
                else:
                    person["profile_status"] = "not_observed"
            key = json.loads(row["identity_json"])
            yield {
                "token_id": key["native_id"],
                "schema_version": SCHEMA_VERSION,
                "inventory_id": row["id"],
                "identity": key,
                "credential_types": json.loads(row["families"]),
                "scope": key["scope"],
                "observed_scopes": observed_scopes(observations),
                "first_seen_at_this_run": row["first_seen"],
                "last_seen_at_this_run": row["last_seen"],
                "summary": summary,
                "metadata": metadata,
                "observations": observations,
                **extra,
                "metadata_merge_policy": "handler_priority_deep_merge_v1",
                "metadata_policy": METADATA_POLICY,
            }

    def export(self, previous: Path | None = None) -> dict:
        """현재 관찰·오류·범위를 JSON으로 내보낸다. 이전 실행의 누락을 폐기로 바꾸지 않는다."""
        coverage = list(self.coverage())
        if previous:
            # 같은 출력 폴더의 이전 JSON을 지정해도 교체 전에 읽어 비교 기준을 보존한다.
            write_json_array(self.directory / "changes.json", self.compare(previous, coverage))
        write_json_array(self.directory / "inventory.json", self.inventory(), context="inventory")
        write_json_array(self.directory / "coverage.json", coverage)
        write_json_array(
            self.directory / "assets.json",
            (
                json.loads(row[0])
                for row in self.db.execute("SELECT value FROM assets ORDER BY kind,id")
            ),
        )
        write_json_array(
            self.directory / "errors.json",
            (
                json.loads(row[0])
                for row in self.db.execute("SELECT value FROM errors ORDER BY seq")
            ),
        )
        write_json_array(self.directory / "audit_events.json", self.audit_events())
        write_json_array(
            self.directory / "filtered_audit_events.json",
            (
                json.loads(row[0])
                for row in self.db.execute("SELECT value FROM filtered_audit_events ORDER BY id")
            ),
        )
        counts = {
            state: sum(item["status"] == state for item in coverage)
            for state in ("complete", "pending", "failed")
        }
        manifest = {
            "schema_version": "1.0",
            "started_at": self.get_setting("started_at"),
            "exported_at": now(),
            "provider_instance": self.get_setting("base_url"),
            "collector_user_id": self.get_setting("principal_id"),
            "config": self.get_setting("config"),
            "inventory_records": self.db.execute("SELECT count(*) FROM records").fetchone()[0],
            "tasks": counts,
            "all_scheduled_tasks_complete": not counts["failed"] and not counts["pending"],
            "historical_error_events": self.db.execute("SELECT count(*) FROM errors").fetchone()[0],
            "limitations": [
                "Completion covers scheduled authorized API queries, not every organizational credential.",
                "Token issuer is unknown unless explicitly returned.",
                "Missing records are not proof of revocation; API retention and visibility apply.",
                "Runtime/connection credentials in classes 2 and 3 are outside this collector.",
                "Secret values, public_key and sentry_dsn are removed before persistence.",
                "PAT and resource-token identity spaces are kept separate unless an explicit API mapping is available.",
            ],
        }
        manifest["provider"] = "gitlab"
        manifest["collection_mode"] = self.get_setting("collection_mode")
        manifest["schema_scope"] = "GitLab collector_v1 only; not the CreMore shared schema"
        manifest["coverage_notes"] = self.get_setting("coverage_notes") or []
        manifest["fatal_error"] = self.get_setting("fatal_error")
        manifest["output_format"] = "json"
        manifest["schema_version"] = SCHEMA_VERSION
        manifest["code_provenance"] = self.get_setting("code_provenance")
        manifest["execution_history"] = self.get_setting("execution_history") or []
        manifest["metadata_merge_policy"] = "handler_priority_deep_merge_v1"
        manifest["metadata_selection_policy"] = policy_description()
        config = self.get_setting("config") or {}
        audit_counts = {
            key: sum(task.get("audit_event_counts", {}).get(key, 0) for task in coverage)
            for key in ("received", "retained", "filtered_out")
        }
        event_counts = {"token_related_events": 0, "matched_events": 0, "creation_events": 0}
        for event in self.audit_events():
            event_counts["token_related_events"] += 1
            event_counts["matched_events"] += event["inventory_match_status"] == "matched"
            event_counts["creation_events"] += event["interpretation"].get("action") == "created"
        event_counts["unmatched_events"] = (
            event_counts["token_related_events"] - event_counts["matched_events"]
        )
        manifest["audit_enrichment"] = {
            "enabled": bool(
                config.get("include_audit_events") or config.get("include_deploy_token_audit")
            ),
            "collection_scope": "token_related_group_project_events",
            # 매핑 처리 대상과 GitLab이 각 유형의 이벤트를 실제 제공하는지는 구분한다.
            "matching_credential_types": [
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
            ],
            "page_event_observations": audit_counts,
            **event_counts,
        }
        manifest["audit_enrichment"]["filtered_event_identifiers"] = self.db.execute(
            "SELECT count(*) FROM filtered_audit_events"
        ).fetchone()[0]
        manifest["audit_enrichment"]["event_details_file"] = "audit_events.json"
        manifest["audit_enrichment"]["filtered_details_recoverable"] = False
        manifest["limitations"][1] = (
            "Issuer requires an explicit API field or an unambiguous matching creation audit event; audit availability and actor identity are not guaranteed."
        )
        manifest["limitations"].append(
            "Audit collection covers authorized Group/Project queries only; User/Instance and streaming-only events are not collected. A completed query does not guarantee per-token audit evidence."
        )
        if manifest["fatal_error"] or self.get_setting("principal_id") is None:
            manifest["all_scheduled_tasks_complete"] = False
        # 실행 요약만 단일 객체이며, 목록 파일과 같은 원자적 교체·권한 규칙을 적용한다.
        with atomic_json_file(self.directory / "manifest.json") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
        return manifest

    def compare(self, previous: Path, coverage: list[dict]):
        """A03 집합 대조. 설정·권한 차이는 coverage와 함께 해석하고 폐기는 추정하지 않는다."""
        old = {}
        for item in read_previous_inventory(previous):
            if (
                not isinstance(item, dict)
                or item.get("schema_version") not in ("1.0", "1.1", SCHEMA_VERSION)
                or not isinstance(item.get("inventory_id"), str)
                or not isinstance(item.get("metadata"), dict)
            ):
                raise ValueError(
                    "이 수집기의 schema_version=1.0/1.1/1.2 inventory.json 또는 이전 inventory.jsonl이 필요합니다."
                )
            # 과거 시각순 병합 결과를 그대로 비교하면 정책 수정 자체를 토큰 변경으로 오인한다.
            # 원천 관찰이 있는 파일은 같은 병합·비밀값 정책으로 양쪽을 대조한다.
            if item.get("schema_version") == "1.0" and item.get("observations"):
                item["metadata"] = sanitize(metadata_view(item["observations"])[0])[0]
            # 과거 파일은 수정하지 않고 메모리에서만 같은 선별 정책을 적용한다.
            # 필드 제거 자체가 token 변경으로 기록되거나 changes.json에 되살아나지 않게 한다.
            family = (
                "pipeline_trigger_token"
                if "pipeline_trigger_token" in item.get("credential_types", [])
                else "token"
            )
            item["metadata"] = prepare_metadata(item["metadata"], family)[0]
            old[item["inventory_id"]] = item
        complete_sources = {row["source_id"] for row in coverage if row["status"] == "complete"}
        seen = set()
        for item in self.inventory():
            key = item["inventory_id"]
            seen.add(key)
            if key not in old:
                yield {
                    "inventory_id": key,
                    "change": "newly_observed",
                    "not_necessarily_newly_issued": True,
                }
            elif item["metadata"] != old[key]["metadata"]:
                # 직접 필드 비교로 차이를 설명한다. 비밀 원문 fingerprint는 만들지 않는다.
                before, after = old[key]["metadata"], item["metadata"]
                changed = sorted(
                    k
                    for k in before.keys() | after.keys()
                    if (k in before, before.get(k)) != (k in after, after.get(k))
                )
                yield {"inventory_id": key, "change": "metadata_changed", "fields": changed}
            if key in old and ("audit" in item or "audit" in old[key]):
                # 조회 시각·현재 프로필 변동이 아니라 생성자·생성 시각 근거의 의미 변화만 비교한다.
                def audit_summary(record):
                    """v0.2에 없던 감사 보강 필드도 이전 미관찰 상태와 비교할 수 있게 한다."""
                    summary = record.get("summary", {})
                    issuer = summary.get("issuer", {})
                    created = summary.get("created_at_from_audit", {})
                    return {
                        "issuer": {
                            k: issuer.get(k)
                            for k in ("status", "id", "names_at_event", "candidate_ids")
                        },
                        "created_at_from_audit": {k: created.get(k) for k in ("status", "value")},
                    }

                if audit_summary(item) != audit_summary(old[key]):
                    yield {
                        "inventory_id": key,
                        "change": "audit_enrichment_changed",
                        "before": audit_summary(old[key]),
                        "after": audit_summary(item),
                    }
        for key in sorted(old.keys() - seen):
            # 단건 조회 성공은 다른 토큰의 부재를 증명하지 않는다. 목록 출처만 사용한다.
            sources = {
                o["source_id"]
                for o in old[key].get("observations", [])
                if o["handler"] in TOKEN_LIST_HANDLERS
            }
            yield {
                "inventory_id": key,
                "change": "not_observed" if sources & complete_sources else "observation_unknown",
                "revocation_inferred": False,
                "reason": "Completed matching source did not return record"
                if sources & complete_sources
                else "Matching source not completed or not scheduled",
            }
