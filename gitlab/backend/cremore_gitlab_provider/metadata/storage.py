"""Replayable GitLab view; durable writes belong to the shared coverage worker.

The native collector's page transaction semantics remain intact. This view has
no database or state file: committed typed records rebuild it after a restart,
and the worker commits each emitted page and its checkpoint under its lease.
"""

from __future__ import annotations

import heapq
import json
from copy import deepcopy
from pathlib import Path

from .audit import (
    TokenAuditIndex,
    enrich_from_audit,  # noqa: F401 - compatibility export
    event_types,
    token_audit_scopes,
)
from .audit_coverage import CreationCoverageIndex  # noqa: F401 - compatibility export
from .handlers import RATE_CLASSES, TOKEN_LIST_HANDLERS, task_priority, task_rate_class
from .metadata_policy import (
    METADATA_POLICY,  # noqa: F401 - compatibility export
    prepare_metadata,
)
from .model import (
    metadata_view,
    native_id,
    now,
    observed_scopes,  # noqa: F401 - compatibility export
    stable_id,
)

SCHEMA_VERSION = "1.4"


def read_previous_inventory(previous):
    """Read explicit legacy JSON/JSONL exports, or an already decoded inventory."""
    if not isinstance(previous, (str, Path)):
        yield from previous
        return
    previous = Path(previous)
    with previous.open(encoding="utf-8") as stream:
        if previous.suffix.lower() == ".jsonl":
            for line in stream:
                if line.strip():
                    yield json.loads(line)
        else:
            document = json.load(stream)
            if not isinstance(document, list):
                raise ValueError("GITLAB_PREVIOUS_INVENTORY_ARRAY_REQUIRED")
            yield from document


class _PageTransaction:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        if self.store.transaction is not None:
            raise RuntimeError("GITLAB_NESTED_PAGE_TRANSACTION")
        self.before = {}
        self.pending = len(self.store.pending)
        self.errors = len(self.store.state["errors"])
        self.store.transaction = self
        return self

    def __exit__(self, kind, value, trace):
        if kind is not None:
            for (bucket, key), (present, previous) in self.before.items():
                if present:
                    self.store.state[bucket][key] = previous
                else:
                    self.store.state[bucket].pop(key, None)
            del self.store.pending[self.pending :]
            del self.store.state["errors"][self.errors :]
            self.store._task_heaps = None
        self.store.transaction = None
        return False


class Store:
    """Native collector view with replay and a compact cursor checkpoint."""

    def __init__(self, config_hash, checkpoint=None):
        self.state = {
            "settings": {},
            "notes": {},
            "tasks": {},
            "pages": {},
            "records": {},
            "assets": {},
            "audit_events": {},
            "filtered_audit_events": {},
            "errors": [],
        }
        self._task_heaps = None
        self.pending = []
        self.transaction = None
        checkpoint = deepcopy(checkpoint or {})
        saved = checkpoint.get("settings", {}).get("config_hash")
        if saved is not None and saved != config_hash:
            raise ValueError("GITLAB_RESUME_CONTRACT_CHANGED")
        self.state["settings"] = checkpoint.get("settings", {})
        for note in self.state["settings"].pop("coverage_notes", []):
            self.state["notes"][stable_id(note)] = note
        self.state["tasks"] = checkpoint.get("tasks", {})
        self.state["pages"] = checkpoint.get("pages", {})
        self.resume_tasks = set(self.state["tasks"])
        self.set_setting("config_hash", config_hash)
        if self.get_setting("started_at") is None:
            self.set_setting("started_at", now())
        for task in self.state["tasks"].values():
            if task["status"] == "failed" and checkpoint.get("phase", "collect") == "collect":
                task.update(status="pending", error=None)

    @property
    def db(self):
        return _PageTransaction(self)

    def close(self):
        """This view owns no file handles or database connections."""

    def _put(self, bucket, key, value):
        if self.transaction is not None:
            previous = self.state[bucket].get(key)
            self.transaction.before.setdefault((bucket, key), (key in self.state[bucket], previous))
        is_new_task = bucket == "tasks" and key not in self.state["tasks"]
        self.state[bucket][key] = value
        if is_new_task and self._task_heaps is not None:
            self._index_task(key, value, len(self.state["tasks"]) - 1)

    def get_setting(self, key):
        if key == "coverage_notes":
            return deepcopy(list(self.state["notes"].values()))
        return deepcopy(self.state["settings"].get(key))

    def set_setting(self, key, value):
        if key == "coverage_notes":
            # Replay appends deduplicated facts. Notes are never replaced mid-page.
            for note in value or []:
                self._put("notes", stable_id(note), deepcopy(note))
            return
        self._put("settings", key, deepcopy(value))

    def note(self, code, scope):
        """Hash-index notes instead of copying the full list on every insertion."""
        value = {"code": code, "scope": deepcopy(scope)}
        key = stable_id(value)
        if key not in self.state["notes"]:
            self._put("notes", key, value)

    def add_task(self, handler, path, context, params=None):
        spec = {"handler": handler, "path": path, "context": context, "params": params or {}}
        task_id = stable_id(spec)
        if task_id not in self.state["tasks"]:
            self._put(
                "tasks",
                task_id,
                {
                    "id": task_id,
                    "spec": deepcopy(spec),
                    "status": "pending",
                    "next_url": None,
                    "cursor": None,
                    "pages": 0,
                    "records_seen": 0,
                    "error": None,
                    "completed_at": None,
                },
            )
        return task_id

    def _index_task(self, key, value, seq):
        """Index only executable tasks; priority never comes from submitted facts."""
        if value["status"] == "pending":
            handler = value["spec"]["handler"]
            heapq.heappush(self._task_heaps[task_rate_class(handler)],
                           (task_priority(handler), seq, key))

    def next_task(self, deferred_rate_classes=frozenset()):
        """Two priority heaps avoid rescanning the whole queue for each page.

        Deferred user lookups yield to ready work; if nothing else is ready,
        return the original head and let the transport enforce its wait.
        """
        if deferred_rate_classes - RATE_CLASSES:
            raise ValueError("UNKNOWN_RATE_CLASS")
        if self._task_heaps is None:
            self._task_heaps = {name: [] for name in RATE_CLASSES}
            for seq, (key, value) in enumerate(self.state["tasks"].items()):
                self._index_task(key, value, seq)
        heads = []
        for name, heap in self._task_heaps.items():
            while heap and self.state["tasks"][heap[0][2]]["status"] != "pending":
                heapq.heappop(heap)
            if heap:
                heads.append((heap[0], name))
        if not heads:
            return None
        head = min(heads)
        if head[1] in deferred_rate_classes:
            head = min((item for item in heads if item[1] not in deferred_rate_classes), default=head)
        return deepcopy(self.state["tasks"][head[0][2]])

    def save_asset(self, kind, asset_id, metadata, source):
        clean, removed, excluded = prepare_metadata(metadata, kind)
        key = f"{kind}:{asset_id}"
        old = self.state["assets"].get(key, {})
        if source == "/user" and old.get("source") == f"/users/{asset_id}":
            # Reauthentication confirms identity; it must not replace an already
            # committed profile from the explicit detail endpoint on restart.
            return
        value = {
            "kind": kind,
            "id": asset_id,
            "metadata": {**old.get("metadata", {}), **clean},
            "source": source,
            "observed_at": now(),
            "excluded_credential_fields": sorted(
                set(old.get("excluded_credential_fields", [])) | set(removed)
            ),
            "excluded_metadata_fields": sorted(
                set(old.get("excluded_metadata_fields", [])) | set(excluded)
            ),
        }
        self._put("assets", key, value)
        self.pending.append(("asset", deepcopy(value)))

    def asset_metadata(self, kind, asset_id):
        value = self.state["assets"].get(f"{kind}:{asset_id}")
        return deepcopy(value["metadata"]) if value else None

    def save_record(self, identity, family, scope, metadata, task, page_url):
        record_id = stable_id(identity)
        timestamp = now()
        old = self.state["records"].get(
            record_id,
            {
                "identity": deepcopy(identity),
                "families": [],
                "observations": {},
                "first_seen": timestamp,
                "last_seen": timestamp,
            },
        )
        value = {**old, "observations": dict(old["observations"])}
        value["families"] = sorted(set(value["families"]) | {family})
        value["last_seen"] = timestamp
        clean, removed, excluded = prepare_metadata(metadata, family)
        observation = {
            "source_id": task["id"],
            "endpoint": task["spec"]["path"],
            "handler": task["spec"]["handler"],
            "request_url": page_url,
            "context": deepcopy(task["spec"]["context"]),
            "observed_at": timestamp,
            "metadata": clean,
            "excluded_credential_fields": removed,
            "excluded_metadata_fields": excluded,
        }
        value["observations"][task["id"]] = observation
        self._put("records", record_id, value)
        self.pending.append(
            (
                "observation",
                {
                    "inventory_id": record_id,
                    "identity": deepcopy(identity),
                    "family": family,
                    "first_seen": value["first_seen"],
                    "last_seen": timestamp,
                    "observation": deepcopy(observation),
                },
            )
        )
        return record_id

    def save_audit_event(self, event, interpretation, task, page_url):
        scope = task["spec"]["context"]["scope"]
        event_id = native_id(event.get("id"))
        key = stable_id({"scope": scope, "event_id": event_id})
        old = self.state["audit_events"].get(key, {})
        sources = {source["source_id"]: source for source in old.get("sources", [])}
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
            "scope": deepcopy(scope),
            "interpretation": deepcopy(interpretation),
            "metadata": clean,
            "sources": [sources[source] for source in sorted(sources)],
            "excluded_credential_fields": removed,
            "excluded_metadata_fields": excluded,
        }
        self._put("audit_events", key, value)
        self.pending.append(("audit", deepcopy(value)))

    def save_filtered_audit_event(self, event, task):
        import re

        scope = task["spec"]["context"]["scope"]
        event_id = native_id(event.get("id"))
        key = stable_id({"scope": scope, "event_id": event_id})
        previous = self.state["filtered_audit_events"].get(key, {})
        names = sorted(
            value for value in event_types(event) if re.fullmatch(r"[a-z][a-z0-9_]{0,199}", value)
        )
        value = {
            "event_id": event_id,
            "event_name": names[0] if len(names) == 1 else None,
            "event_types": names,
            "scope": deepcopy(scope),
            "reason": "not_token_related",
            "source_ids": sorted(set(previous.get("source_ids", [])) | {task["id"]}),
        }
        self._put("filtered_audit_events", key, value)
        self.pending.append(("filtered_audit", deepcopy(value)))

    def count_audit_page(self, task_id, received, retained):
        task = deepcopy(self.state["tasks"][task_id])
        counts = task.setdefault(
            "audit_event_counts", {"received": 0, "retained": 0, "filtered_out": 0}
        )
        counts["received"] += received
        counts["retained"] += retained
        counts["filtered_out"] += received - retained
        self._put("tasks", task_id, task)

    def error(self, task, code, message, status=None, location=None, details=None):
        event = {
            "at": now(),
            "task_id": task["id"],
            "stage": task["spec"]["handler"],
            "endpoint": task["spec"]["path"],
            "context": deepcopy(task["spec"]["context"]),
            "code": code,
            "message": message,
            "http_status": status,
            "code_location": location,
            "diagnostics": details or {},
        }
        self.state["errors"].append(event)
        self._put(
            "tasks",
            task["id"],
            {**self.state["tasks"][task["id"]], "status": "failed", "error": event},
        )
        self.pending.append(("source", deepcopy(self.state["tasks"][task["id"]])))

    def page_done(self, task, page_key, count, next_url=None, cursor=None):
        pages = list(self.state["pages"].get(task["id"], []))
        key = stable_id(page_key)
        if key in pages:
            raise ValueError("GITLAB_PAGE_ALREADY_COMMITTED")
        pages.append(key)
        self._put("pages", task["id"], pages)
        value = dict(self.state["tasks"][task["id"]])
        done = next_url is None and cursor is None
        value.update(
            status="complete" if done else "pending",
            next_url=next_url,
            cursor=cursor,
            pages=value["pages"] + 1,
            records_seen=value["records_seen"] + count,
            completed_at=now() if done else None,
        )
        self._put("tasks", task["id"], value)
        self.pending.append(("source", deepcopy(value)))

    def has_page(self, task_id, page_key):
        return stable_id(page_key) in self.state["pages"].get(task_id, [])

    def coverage(self):
        for task in self.state["tasks"].values():
            extra = {}
            if task["spec"]["handler"] == "audit_events":
                extra["audit_event_counts"] = task.get(
                    "audit_event_counts", {"received": 0, "retained": 0, "filtered_out": 0}
                )
            yield {
                "source_id": task["id"],
                **deepcopy(task["spec"]),
                "status": task["status"],
                "pages_completed": task["pages"],
                "records_seen": task["records_seen"],
                "completed_at": task["completed_at"],
                "error": deepcopy(task["error"]),
                **extra,
            }

    def audit_events(self):
        descriptors = [
            {
                "inventory_id": key,
                "identity": value["identity"],
                "audit_scopes": token_audit_scopes(
                    value["identity"]["scope"], list(value["observations"].values())
                ),
            }
            for key, value in self.state["records"].items()
        ]
        index = TokenAuditIndex(descriptors)
        for key in sorted(self.state["audit_events"]):
            event = deepcopy(self.state["audit_events"][key])
            matches, reason = index.match(event["interpretation"], event["scope"])
            matched = matches[0] if len(matches) == 1 else None
            yield {
                **event,
                "candidate_inventory_id": matched,
                "candidate_inventory_ids": matches,
                "inventory_match_reason": reason,
                "inventory_id": matched,
                "inventory_match_status": "matched" if matched else "not_matched",
            }

    def inventory(self):
        """Project committed metadata; raw provider values never enter this view."""
        from .inventory_view import inventory_rows
        yield from inventory_rows(self)

    def checkpoint(self):
        """Only pending work and cursor hashes persist; facts replay from batches."""
        pending = {
            key: deepcopy(value)
            for key, value in self.state["tasks"].items()
            if value["status"] != "complete"
        }
        settings = {
            key: deepcopy(value)
            for key, value in self.state["settings"].items()
            if key in {"config_hash", "principal_id", "base_url", "started_at", "coverage_notes", "gitlab_value_contract"}
        }
        settings["coverage_notes"] = self.get_setting("coverage_notes")
        return {
            "settings": settings,
            "tasks": pending,
            "pages": {
                key: list(value) for key, value in self.state["pages"].items() if key in pending
            },
        }

    def replay(self, kind, value):
        """Apply only normalized committed records supplied by the owning worker."""
        value = deepcopy(value)
        if kind == "observation":
            key = value["inventory_id"]
            row = self.state["records"].setdefault(
                key,
                {
                    "identity": value["identity"],
                    "families": [],
                    "observations": {},
                    "first_seen": value["first_seen"],
                    "last_seen": value["last_seen"],
                },
            )
            row["families"] = sorted(set(row["families"]) | {value["family"]})
            row["observations"][value["observation"]["source_id"]] = value["observation"]
            row["first_seen"] = min(row["first_seen"], value["first_seen"])
            row["last_seen"] = max(row["last_seen"], value["last_seen"])
        elif kind == "asset":
            self.state["assets"][f"{value['kind']}:{value['id']}"] = value
            if value["kind"] == "user" and value["source"] == "/user":
                self.state["settings"].setdefault("principal_id", value["id"])
        elif kind == "audit":
            self.state["audit_events"][value["audit_event_id"]] = value
        elif kind == "filtered_audit":
            key = stable_id({"scope": value["scope"], "event_id": value["event_id"]})
            self.state["filtered_audit_events"][key] = value
        elif kind == "source":
            self._task_heaps = None
            # A resume checkpoint owns incomplete tasks; replay supplies completed history.
            if value["id"] not in self.resume_tasks:
                self.state["tasks"][value["id"]] = value
            if value.get("error") and value["error"] not in self.state["errors"]:
                self.state["errors"].append(deepcopy(value["error"]))

    def compare(self, previous):
        """Preserve native missing/changed semantics without importing values."""
        from .normalization import FactWriter, unpack_facts

        def selected(value, family="token"):
            value = prepare_metadata(value, family)[0]
            return unpack_facts([fact.model_dump() for fact in FactWriter().facts(value)])

        def audit_summary(row):
            summary = selected(row.get("summary", {}))
            issuer = summary.get("issuer", {})
            created = summary.get("created_at_from_audit", {})
            return {
                "issuer": {
                    key: issuer.get(key)
                    for key in ("status", "id", "names_at_event", "candidate_ids")
                },
                "created_at_from_audit": {key: created.get(key) for key in ("status", "value")},
            }

        old = {}
        for original in read_previous_inventory(previous):
            if (
                not isinstance(original, dict)
                or original.get("schema_version") not in {"1.0", "1.1", "1.2", "1.3", SCHEMA_VERSION}
                or not isinstance(original.get("inventory_id"), str)
                or not isinstance(original.get("metadata"), dict)
            ):
                raise ValueError("GITLAB_PREVIOUS_INVENTORY_SCHEMA_REQUIRED")
            row = deepcopy(original)
            if row["schema_version"] == "1.0" and row.get("observations"):
                row["metadata"] = metadata_view(row["observations"])[0]
            family = (
                "pipeline_trigger_token"
                if "pipeline_trigger_token" in row.get("credential_types", [])
                else "token"
            )
            row["metadata"] = selected(row["metadata"], family)
            old[row["inventory_id"]] = row
        complete = {row["source_id"] for row in self.coverage() if row["status"] == "complete"}
        seen = set()
        for row in self.inventory():
            key = row["inventory_id"]
            seen.add(key)
            family = (
                "pipeline_trigger_token"
                if "pipeline_trigger_token" in row["credential_types"]
                else "token"
            )
            row["metadata"] = selected(row["metadata"], family)
            if key not in old:
                yield {
                    "inventory_id": key,
                    "change": "newly_observed",
                    "not_necessarily_newly_issued": True,
                }
            elif row["metadata"] != old[key]["metadata"]:
                before, after = old[key]["metadata"], row["metadata"]
                fields = sorted(
                    name
                    for name in before.keys() | after.keys()
                    if (name in before, before.get(name)) != (name in after, after.get(name))
                )
                yield {"inventory_id": key, "change": "metadata_changed", "fields": fields}
            if (
                key in old
                and ("audit" in row or "audit" in old[key])
                and audit_summary(row) != audit_summary(old[key])
            ):
                yield {
                    "inventory_id": key,
                    "change": "audit_enrichment_changed",
                    "before": audit_summary(old[key]),
                    "after": audit_summary(row),
                }
        for key in sorted(old.keys() - seen):
            sources = {
                item["source_id"]
                for item in old[key].get("observations", [])
                if item["handler"] in TOKEN_LIST_HANDLERS
            }
            yield {
                "inventory_id": key,
                "change": "not_observed" if sources & complete else "observation_unknown",
                "revocation_inferred": False,
                "reason": "Completed matching source did not return record"
                if sources & complete
                else "Matching source not completed or not scheduled",
            }

    def export(self):
        """Return the native JSON-array artifact shape; no state files are created."""
        from .metadata_policy import policy_description

        coverage = list(self.coverage())
        inventory = list(self.inventory())
        audit = list(self.audit_events())
        counts = {
            state: sum(row["status"] == state for row in coverage)
            for state in ("complete", "pending", "failed")
        }
        config = self.get_setting("config") or {}
        policy = policy_description()
        policy["unknown_fields"] = "omitted_with_explicit_shared_schema_reason"
        audit_counts = {
            key: sum(task.get("audit_event_counts", {}).get(key, 0) for task in coverage)
            for key in ("received", "retained", "filtered_out")
        }
        matched = sum(event["inventory_match_status"] == "matched" for event in audit)
        return {
            "inventory": inventory,
            "assets": list(deepcopy(self.state["assets"]).values()),
            "coverage": coverage,
            "errors": deepcopy(self.state["errors"]),
            "audit_events": audit,
            "filtered_audit_events": list(deepcopy(self.state["filtered_audit_events"]).values()),
            "manifest": {
                "schema_version": SCHEMA_VERSION,
                "provider": "gitlab",
                "output_format": "json",
                "schema_scope": "GitLab native projection of CreMore shared metadata schema 2",
                "started_at": self.get_setting("started_at"),
                "exported_at": now(),
                "provider_instance": self.get_setting("base_url"),
                "collector_user_id": self.get_setting("principal_id"),
                "config": config,
                "collection_mode": "shared_metadata",
                "fatal_error": self.get_setting("fatal_error"),
                "inventory_records": len(inventory),
                "tasks": counts,
                "all_scheduled_tasks_complete": bool(self.get_setting("principal_id"))
                and not counts["failed"]
                and not counts["pending"]
                and not self.get_setting("fatal_error")
                and self.get_setting("run_status") == "COMPLETE",
                "historical_error_events": len(self.state["errors"]),
                "metadata_selection_policy": policy,
                "metadata_merge_policy": "handler_priority_deep_merge_v1",
                "code_provenance": self.get_setting("code_provenance"),
                "execution_history": self.get_setting("execution_history") or [],
                "coverage_notes": self.get_setting("coverage_notes") or [],
                "audit_enrichment": {
                    "enabled": bool(
                        config.get("include_audit_events")
                        or config.get("include_deploy_token_audit")
                    ),
                    "collection_scope": "token_related_group_project_events",
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
                    "token_related_events": len(audit),
                    "matched_events": matched,
                    "unmatched_events": len(audit) - matched,
                    "creation_events": sum(
                        event["interpretation"].get("action") == "created" for event in audit
                    ),
                    "filtered_event_identifiers": len(self.state["filtered_audit_events"]),
                    "event_details_file": "audit_events.json",
                    "filtered_details_recoverable": False,
                },
                "limitations": [
                    "Completion covers scheduled authorized API queries, not every organizational credential.",
                    "Issuer requires an explicit API field or unambiguous matching creation audit event.",
                    "Missing records are not proof of revocation; API visibility and active-only endpoints apply.",
                    "Runtime credentials, repository content, User/Instance audit and streaming-only events are not collected.",
                    "Secret values, public_key and sentry_dsn are removed before persistence; unapproved shared metadata is omitted explicitly.",
                    "PAT and resource-token identity spaces remain separate without explicit API mapping.",
                    "A completed Group/Project audit query does not guarantee per-token audit evidence.",
                ],
            },
        }
