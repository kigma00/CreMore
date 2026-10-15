# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/recollect.py).
"""Rerun selected incomplete metadata reads from page one, never from saved URLs."""

import argparse
import json
import re
import uuid
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .bitbucket import (
    BRANCH_OPERATIONS,
    CORE_OPERATIONS,
    OPERATIONS,
    RUNNER_OPERATIONS,
    valid_target,
)
from .compare import canonical, load_snapshot, scope
from .discovery import collect_operation
from .http import Limits
from .jobs import DEFAULT_DIRECTORY, check, create_client, validate_job
from .metadata import utc_now
from .read_operations import (
    ACCOUNT_COUNT_OPERATIONS,
    ACCOUNT_DETAIL_OPERATIONS,
    READ_OPERATIONS,
    operation_url,
    valid_identifier,
)
from .specs import SOURCES
from .storage import load_private, output_digest, save_private


def validate_task(operation, report, specs, org_id=None):
    spec = specs[operation]
    target = report.get("target_id")
    body = report.get("requested_account_ids")
    if specs is READ_OPERATIONS:
        operation_url(operation, org_id, target)
        if operation in ACCOUNT_COUNT_OPERATIONS:
            check(
                type(body) is list
                and 1 <= len(body) <= 100
                and all(valid_identifier(value, 100) for value in body)
                and len(body) == len(set(body))
            )
        else:
            check(body is None)
    else:
        check(body is None)
        if "{key_id}" in spec["path"]:
            check(
                type(target) in (tuple, list)
                and len(target) == 2
                and all(valid_target(value) for value in target)
            )
            target = list(target)
        elif "{target}" in spec["path"]:
            check(valid_target(target))
        else:
            check(target is None)
    check(report.get("method", spec.get("method", "GET")) == spec.get("method", "GET"))
    return {"operation": operation, "target_id": target, "requested_account_ids": body}


def build_plan(
    snapshot, *, include_unverified=False, operations=None, max_tasks=200, directory=None
):
    check(type(include_unverified) is bool and type(max_tasks) is int and 1 <= max_tasks <= 1000)
    recollection = snapshot.get("report_type") == "metadata_recollection"
    if recollection:
        check(
            type(snapshot.get("schema_version")) is int
            and snapshot["schema_version"] == 1
            and type(snapshot.get("source_scope")) is dict
        )
        previous_scope = snapshot["source_scope"]
        shell = {
            "provider": "atlassian",
            "schema_version": previous_scope["schema_version"],
            "report_type": previous_scope["report_type"],
            "environment": previous_scope["environment"],
            "connection_profile": previous_scope["connection_profile"],
            "collection_mode": previous_scope["collection_mode"],
            "started_at": snapshot["started_at"],
            "finished_at": snapshot.get("finished_at", snapshot["started_at"]),
            "workspace": previous_scope["scope_id"],
            "queried_org_id": previous_scope["scope_id"],
        }
        source = scope(shell)
        check(source == previous_scope)
    else:
        source = scope(snapshot)
    kind, mode = source["report_type"], source["collection_mode"]
    if kind == "inventory":
        job_mode, allowed, specs = "cloud-inventory", set(SOURCES), READ_OPERATIONS
    elif kind == "metadata_discovery":
        job_mode, allowed, specs = "cloud-discovery", set(READ_OPERATIONS), READ_OPERATIONS
    elif kind == "managed_account_metadata_discovery":
        job_mode, allowed, specs = (
            "cloud-accounts",
            {"managed-accounts", *ACCOUNT_DETAIL_OPERATIONS},
            READ_OPERATIONS,
        )
    else:
        job_mode = {
            "core": "bitbucket-core",
            "runners": "bitbucket-runners",
            "branch_restrictions": "bitbucket-branches",
        }[mode]
        allowed = set(
            CORE_OPERATIONS
            if mode == "core"
            else ("repositories",) + (RUNNER_OPERATIONS if mode == "runners" else BRANCH_OPERATIONS)
        )
        specs = OPERATIONS
    job = validate_job(
        {
            "name": "recollection",
            "mode": job_mode,
            "profile": source["connection_profile"],
            "expected_scope": source["scope_id"],
        }
    )
    if operations is not None:
        check(
            type(operations) is list
            and bool(operations)
            and all(type(op) is str and op in allowed for op in operations)
            and len(operations) == len(set(operations))
        )
    reports = snapshot.get("collections")
    if recollection:
        if snapshot.get("checkpoint_kind") == "references":
            check(reports == [] and type(snapshot.get("collection_refs")) is list)
            reports = []
            for reference in snapshot["collection_refs"]:
                check(directory is not None and type(reference) is dict)
                filename = reference.get("file")
                check(
                    type(filename) is str
                    and re.fullmatch(r"recollection-part-[0-9a-f]{32}\.json", filename)
                )
                part, digest = load_private(directory, filename)
                check(
                    digest == reference["sha256"]
                    and part.get("report_type") == "metadata_recollection_part"
                    and type(part.get("schema_version")) is int
                    and part["schema_version"] == 1
                    and part.get("run_id") == snapshot.get("run_id")
                    and part.get("source_scope") == source
                )
                # Planning needs task identity/status, not every saved response.
                # Keep one part in memory at a time and hash its exact opened FD.
                report = part["collection"]
                check(type(report) is dict)
                reports.append(
                    {
                        key: report[key]
                        for key in (
                            "operation",
                            "method",
                            "target_id",
                            "requested_account_ids",
                            "coverage",
                            "recollection_task_index",
                        )
                        if key in report
                    }
                )
                del part, report
        previous_plan = snapshot.get("plan")
        check(type(previous_plan) is dict and type(previous_plan.get("tasks")) is list)
        previous_tasks = previous_plan["tasks"]
        check(1 <= len(previous_tasks) <= 1002 and type(reports) is list)
        completed = {}
        for report_index, report in enumerate(reports):
            check(type(report) is dict)
            index = report.get("recollection_task_index")
            check(
                type(index) is int and 0 <= index < len(previous_tasks) and index not in completed
            )
            task = previous_tasks[index]
            check(
                type(task) is dict
                and type(task.get("operation")) is str
                and task["operation"] in allowed
            )
            check(
                validate_task(task["operation"], task, specs, source["scope_id"])
                == validate_task(report["operation"], report, specs, source["scope_id"])
            )
            completed[index] = (report, report_index)
        reports = []
        for index, task in enumerate(previous_tasks):
            check(
                type(task) is dict
                and type(task.get("operation")) is str
                and task["operation"] in allowed
            )
            validated = validate_task(task["operation"], task, specs, source["scope_id"])
            saved = completed.get(index)
            if saved is None:
                # A checkpoint written during interruption leaves pending tasks explicit.
                report = dict(validated, coverage="failed")
                ref = "/plan/tasks/" + str(index)
            else:
                report, report_index = saved
                ref = (
                    "/collection_refs/"
                    if snapshot.get("checkpoint_kind") == "references"
                    else "/collections/"
                ) + str(report_index)
            reports.append((ref, report))
    elif kind == "inventory":
        check(type(reports) is dict)
        reports = [
            ("/collections/" + op, dict(report, operation=op)) for op, report in reports.items()
        ]
    else:
        check(type(reports) is list)
        reports = [("/collections/" + str(index), report) for index, report in enumerate(reports)]
    coverages = {"failed", "partial", "unverified"} if include_unverified else {"failed", "partial"}
    tasks, seen = [], set()
    for ref, report in reports:
        check(
            type(report) is dict
            and type(report.get("operation")) is str
            and report["operation"] in allowed
        )
        check(
            report.get("coverage")
            in ("complete", "failed", "partial", "unverified", "not_requested")
        )
        if report["coverage"] not in coverages or (
            operations is not None and report["operation"] not in operations
        ):
            continue
        task = validate_task(report["operation"], report, specs, source["scope_id"])
        encoded = canonical(task)
        check(encoded not in seen)
        seen.add(encoded)
        task.update(source_ref=ref, previous_coverage=report["coverage"], role="selected")
        tasks.append(task)
    check(len(tasks) <= max_tasks)
    prerequisites = []
    names = {task["operation"] for task in tasks}
    # Runner UUID mappings must be established by fresh public resource reads.
    if (
        specs is OPERATIONS
        and names & {"workspace-runners", "repository-runners"}
        and "repositories" not in names
    ):
        # Reuse the Runner collector's repository-read permission; do not add a
        # workspace-read permission requirement just for recovery.
        prerequisites.append(
            {
                "operation": "repositories",
                "target_id": None,
                "requested_account_ids": None,
                "role": "prerequisite",
            }
        )
    tasks.sort(key=lambda task: 0 if task["operation"] in ("workspace", "repositories") else 1)
    return {
        "schema_version": 1,
        "report_type": "metadata_recollection_plan",
        "job": job,
        "source_scope": source,
        "tasks": prerequisites + tasks,
        "selected_count": len(tasks),
        "prerequisite_count": len(prerequisites),
        "include_unverified": include_unverified,
        "page_policy": "restart_at_first_page",
        "fanout_policy": "selected_targets_only",
    }


def execute_plan(
    plan, directory, limits=None, *, input_sha256=None, client_factory=None, now=utc_now
):
    # Plans are built in memory from the validated source, not accepted as external executable files.
    check(plan.get("report_type") == "metadata_recollection_plan")
    job = validate_job(plan["job"])
    specs = READ_OPERATIONS if job["mode"].startswith("cloud-") else OPERATIONS
    for task in plan["tasks"]:
        check(task["operation"] in specs)
        validate_task(task["operation"], task, specs, job["expected_scope"])
    check(bool(plan["tasks"]))
    limits = limits or Limits()
    result = {
        "schema_version": 1,
        "report_type": "metadata_recollection",
        "provider": "atlassian",
        "run_id": uuid.uuid4().hex,
        "source_scope": plan["source_scope"],
        "connection_profile": job["profile"],
        "started_at": now(),
        "run_status": "running",
        "inventory_complete": False,
        "input_sha256": input_sha256,
        "limits": asdict(limits),
        "plan": plan,
        "collections": [],
        "collection_refs": [],
        "requests": 0,
        "not_executed": [],
        "limitations": [
            "selected_reads_only",
            "new_observation_window",
            "source_snapshot_unchanged",
            "fresh_pagination",
            "no_new_target_fanout",
        ],
    }
    latest = save_private(directory, result, prefix="recollection")
    client = (client_factory or create_client)(job, directory, limits)
    interrupted = False
    for index, task in enumerate(plan["tasks"]):
        if interrupted:
            result["not_executed"].append({"task_index": index, "reason": "interrupted"})
            continue
        try:
            report = collect_operation(
                client,
                task["operation"],
                identifier=task["target_id"],
                body=task["requested_account_ids"],
                specs=specs,
                now=now,
            )
            report["recollection_task_index"] = index
            result["collections"].append(report)
            part = {
                "schema_version": 1,
                "report_type": "metadata_recollection_part",
                "run_id": result["run_id"],
                "source_scope": result["source_scope"],
                "collection": report,
            }
            filename = save_private(directory, part, prefix="recollection-part")
            result["collection_refs"].append(
                {"file": filename, "sha256": output_digest(directory, filename)}
            )
        except KeyboardInterrupt:
            interrupted = True
            result["not_executed"].append({"task_index": index, "reason": "interrupted"})
        result["requests"] = client.requests
        result["previous_checkpoint"] = latest
        checkpoint = dict(result, collections=[], checkpoint_kind="references")
        latest = save_private(directory, checkpoint, prefix="recollection")
    states = [report["coverage"] for report in result["collections"]]
    result["run_status"] = (
        "interrupted"
        if interrupted
        else "complete"
        if all(state == "complete" for state in states)
        else "partial"
    )
    result["finished_at"] = now()
    result["previous_checkpoint"] = latest
    latest = save_private(directory, result, prefix="recollection")
    return result, latest


def main(argv=None, *, directory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        help="Original collector snapshot; explicit connection profile required in the snapshot.",
    )
    parser.add_argument(
        "--operation", action="append", help="Restrict to an operation (repeatable)."
    )
    parser.add_argument(
        "--include-unverified",
        action="store_true",
        help="Explicitly include unverified reads, including unresolved provider contracts.",
    )
    parser.add_argument("--max-tasks", type=int, default=200)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan without loading credentials, requesting APIs or writing files.",
    )
    for name in Limits.__dataclass_fields__:
        parser.add_argument(
            "--" + name.replace("_", "-"),
            type=int if name in ("max_pages", "max_records", "max_requests", "retries") else float,
            default=getattr(Limits(), name),
        )
    args = parser.parse_args(argv)
    try:
        snapshot, digest = load_snapshot(args.input)
        limits = Limits(**{name: getattr(args, name) for name in Limits.__dataclass_fields__})
        plan = build_plan(
            snapshot,
            include_unverified=args.include_unverified,
            operations=args.operation,
            max_tasks=args.max_tasks,
            directory=Path(args.input).parent,
        )
        if args.dry_run or not plan["selected_count"]:
            print(
                json.dumps(
                    {
                        "status": "planned" if plan["selected_count"] else "nothing_to_retry",
                        "selected": plan["selected_count"],
                        "prerequisites": plan["prerequisite_count"],
                        "operations": dict(Counter(task["operation"] for task in plan["tasks"])),
                        "page_policy": plan["page_policy"],
                    },
                    indent=2,
                )
            )
            return 0
        result, filename = execute_plan(
            plan,
            Path(directory) if directory is not None else DEFAULT_DIRECTORY,
            limits,
            input_sha256=digest,
        )
    except KeyboardInterrupt:
        parser.exit(
            130, "Recollection interrupted. Existing private checkpoints remain available.\n"
        )
    except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
        parser.exit(
            2,
            "Recollection input, connection or private output invalid. Details suppressed; source snapshot unchanged.\n",
        )
    print(
        json.dumps(
            {
                "status": result["run_status"],
                "requests": result["requests"],
                "coverage_counts": dict(
                    Counter(report["coverage"] for report in result["collections"])
                ),
                "not_executed": len(result["not_executed"]),
                "output_file": filename,
            },
            indent=2,
        )
    )
    return (
        130
        if result["run_status"] == "interrupted"
        else 0
        if result["run_status"] == "complete"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
