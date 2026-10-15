# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/jobs.py).
"""Run bounded Atlassian collection jobs with private, durable progress manifests."""

import argparse
import hashlib
import json
import time
import uuid
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path

from .bitbucket import OPERATIONS, BitbucketClient, iter_bitbucket
from .collector import iter_collect
from .connections import load_bitbucket, load_cloud, profile_argument, valid_workspace
from .discovery import iter_accounts, iter_discovery
from .http import CloudClient, Limits
from .jsonio import canonical
from .jsonio import load_json as load_snapshot
from .metadata import utc_now
from .specs import SOURCES
from .steps import consume
from .storage import output_digest, save_private

MODES = (
    "cloud-inventory",
    "cloud-discovery",
    "cloud-accounts",
    "bitbucket-core",
    "bitbucket-runners",
    "bitbucket-branches",
)
DEFAULT_DIRECTORY = Path.cwd() / ".local"


def check(condition):
    if not condition:
        raise ValueError("Invalid collection job configuration")


def validate_job(value):
    check(
        type(value) is dict
        and not set(value)
        - {
            "name",
            "mode",
            "profile",
            "expected_scope",
            "limits",
            "max_targets",
            "page_size",
            "sources",
            "include_account_reads",
        }
    )
    job = dict(value)
    for key in ("name", "profile"):
        check(type(job.get(key)) is str)
        profile_argument(job[key])
    check(job.get("mode") in MODES)
    target = job.get("expected_scope")
    check(type(target) is str)
    if job["mode"].startswith("cloud-"):
        check(str(uuid.UUID(target)) == target)
    else:
        check(valid_workspace(target))
    limits = job.get("limits", {})
    check(type(limits) is dict and not set(limits) - set(Limits.__dataclass_fields__))
    job["limits"] = asdict(Limits(**limits))
    job.setdefault("max_targets", 50)
    check(type(job["max_targets"]) is int and 1 <= job["max_targets"] <= 500)
    job.setdefault("page_size", 20)
    max_page_size = 1000 if job["mode"] == "cloud-discovery" else 100
    check(type(job["page_size"]) is int and 1 <= job["page_size"] <= max_page_size)
    if job["mode"] in ("cloud-inventory", "cloud-accounts"):
        check(job["page_size"] == 20)
    if "include_account_reads" in job:
        check(job["mode"] == "cloud-discovery" and type(job["include_account_reads"]) is bool)
    if "sources" in job:
        sources = job["sources"]
        check(job["mode"] == "cloud-inventory" and type(sources) is list and bool(sources))
        check(
            all(type(source) is str and source in SOURCES for source in sources)
            and len(sources) == len(set(sources))
        )
    return job


def validate_config(value):
    check(
        type(value) is dict
        and not set(value) - {"schema_version", "jobs", "max_requests", "max_seconds"}
    )
    check(type(value.get("schema_version")) is int and value["schema_version"] == 1)
    check(type(value.get("jobs")) is list and 1 <= len(value["jobs"]) <= 20)
    config = dict(value)
    config["jobs"] = [validate_job(job) for job in value["jobs"]]
    check(len({job["name"] for job in config["jobs"]}) == len(config["jobs"]))
    config.setdefault("max_requests", 300)
    config.setdefault("max_seconds", 600)
    # Use the same validated upper bounds as individual collectors.
    Limits(max_requests=config["max_requests"], max_seconds=config["max_seconds"])
    return config


def create_client(job, directory, limits):
    """Connect only after validating the expected organization/workspace."""
    if job["mode"].startswith("cloud-"):
        target, key = load_cloud(Path(directory), job["profile"])
        check(target == job["expected_scope"])
        return CloudClient(target, key, limits, token_page_size=job["page_size"])
    target, key = load_bitbucket(Path(directory), job["profile"])
    check(target == job["expected_scope"])
    return BitbucketClient(target, key, limits, page_size=job["page_size"])


def collect_job(job, client, *, now=utc_now):
    """Integration entry point: native collector result, without saving or printing."""
    return consume(iter_job(job, client, now=now))


def iter_job(job, client, *, now=utc_now):
    """Yield each redacted page before making the next request; return native result."""
    job = validate_job(job)
    mode = job["mode"]
    target = client.org_id if mode.startswith("cloud-") else client.workspace
    check(target == job["expected_scope"])
    if mode == "cloud-inventory":
        result = yield from iter_collect(client, job.get("sources"), now=now)
    elif mode == "cloud-discovery":
        result = yield from iter_discovery(
            client,
            max_targets=job["max_targets"],
            include_account_reads=job.get("include_account_reads", True),
            now=now,
        )
    elif mode == "cloud-accounts":
        result = yield from iter_accounts(client, max_targets=job["max_targets"], now=now)
    else:
        result = yield from iter_bitbucket(
            client,
            job["max_targets"],
            now=now,
            runners_only=mode == "bitbucket-runners",
            branch_restrictions_only=mode == "bitbucket-branches",
        )
    result["connection_profile"] = job["profile"]
    return result


def diagnostic_outcome(report):
    status, reason = report.get("last_http_status"), report.get("reason")
    if reason in ("request_limit", "time_limit"):
        return "budget_exhausted"
    if status == 401:
        return "authentication_rejected"
    if status == 403:
        return "access_denied"
    if status == 404:
        return "not_found_or_hidden"
    if status == 429:
        return "rate_limited"
    if status == 400:
        return "request_rejected"
    if type(status) is int and status >= 500:
        return "provider_error"
    if reason == "retry_wait_exceeds_limit":
        return "retry_deferred"
    if reason == "transport_error":
        return "transport_error"
    if status == 200 and reason in (None, "page_limit", "record_limit"):
        return "readable_sample"
    return "unverified_response"


def diagnostics(result, job):
    reports = result["collections"]
    if type(reports) is dict:
        reports = [
            dict(report, operation=operation)
            for operation, report in reports.items()
            if report["coverage"] != "not_requested"
        ]
    checks = []
    for report in reports:
        operation = report["operation"]
        checks.append(
            {
                "operation": operation,
                "http_status": report.get("last_http_status"),
                "outcome": diagnostic_outcome(report),
                "coverage": report["coverage"],
                "requests": report["requests"],
                "authentication_sent": not (
                    job["mode"].startswith("bitbucket-")
                    and OPERATIONS[operation].get("public", False)
                ),
                "observed_records": report.get("saved_records", report.get("accepted_records", 0)),
            }
        )
    readable = bool(checks) and all(check["outcome"] == "readable_sample" for check in checks)
    return {
        "schema_version": 1,
        "report_type": "metadata_read_diagnostics",
        "mode": job["mode"],
        "connection_profile": job["profile"],
        "expected_scope": job["expected_scope"],
        "started_at": result["started_at"],
        "finished_at": result["finished_at"],
        "run_status": "complete" if readable else "unverified",
        "inventory_complete": False,
        "source_run_status": result["run_status"],
        "checks": checks,
        "outcome_counts": dict(Counter(check["outcome"] for check in checks)),
        "limitations": [
            "sample_reads_only",
            "effective_permissions_not_verified",
            "404_cause_not_determined",
            "unobserved_targets_not_checked",
        ],
    }


def config_digest(config):
    return hashlib.sha256(canonical(config).encode()).hexdigest()


def resume_jobs(value, manifest, directory, *, diagnose=False):
    """Select unfinished jobs; verify completed output references before skipping."""
    config = validate_config(value)
    check(
        type(manifest) is dict
        and manifest.get("report_type") == "atlassian_job_manifest"
        and type(manifest.get("schema_version")) is int
        and manifest["schema_version"] == 1
    )
    check(manifest.get("config_sha256") == config_digest(config))
    check(manifest.get("action") == ("diagnose" if diagnose else "collect"))
    selected = manifest.get("selected_jobs")
    names = {job["name"] for job in config["jobs"]}
    check(
        type(selected) is list
        and bool(selected)
        and all(type(name) is str and name in names for name in selected)
        and len(selected) == len(set(selected))
    )
    check(type(manifest.get("jobs")) is list)
    completed = set()
    seen = set()
    configs = {job["name"]: job for job in config["jobs"]}
    for entry in manifest["jobs"]:
        check(type(entry) is dict and entry.get("name") in selected and entry["name"] not in seen)
        seen.add(entry["name"])
        check(
            all(
                entry.get(key) == configs[entry["name"]][key]
                for key in ("mode", "profile", "expected_scope")
            )
        )
        if entry.get("state") == "collected" and entry.get("run_status") == "complete":
            try:
                valid = output_digest(directory, entry.get("output_file")) == entry.get(
                    "output_sha256"
                )
            except (OSError, ValueError):
                valid = False
            if valid:
                completed.add(entry["name"])
    return [name for name in selected if name not in completed]


def run_jobs(
    value,
    directory,
    *,
    diagnose=False,
    selected_jobs=None,
    resumed_from_sha256=None,
    client_factory=None,
    clock=time.monotonic,
    now=utc_now,
):
    """Sequential jobs share a total request/time budget; each output stays native."""
    config = validate_config(value)
    check(type(diagnose) is bool)
    names = {job["name"] for job in config["jobs"]}
    if selected_jobs is not None:
        check(
            type(selected_jobs) is list
            and bool(selected_jobs)
            and all(type(name) is str and name in names for name in selected_jobs)
            and len(selected_jobs) == len(set(selected_jobs))
        )
    scheduled = [
        job for job in config["jobs"] if selected_jobs is None or job["name"] in selected_jobs
    ]
    factory = client_factory or create_client
    deadline = clock() + config["max_seconds"]
    manifest = {
        "schema_version": 1,
        "report_type": "atlassian_job_manifest",
        "run_id": uuid.uuid4().hex,
        "action": "diagnose" if diagnose else "collect",
        "started_at": now(),
        "status": "running",
        "inventory_complete": False,
        "config_sha256": config_digest(config),
        "selected_jobs": [job["name"] for job in scheduled],
        "resumed_from_sha256": resumed_from_sha256,
        "budget": {key: config[key] for key in ("max_requests", "max_seconds")},
        "requests": 0,
        "jobs": [],
    }
    latest = save_private(directory, manifest, prefix="manifest")
    interrupted = False
    for original in scheduled:
        job = dict(original)
        entry = {
            "name": job["name"],
            "mode": job["mode"],
            "profile": job["profile"],
            "expected_scope": job["expected_scope"],
            "started_at": now(),
            "requests": 0,
        }
        remaining_time, remaining_requests = (
            deadline - clock(),
            config["max_requests"] - manifest["requests"],
        )
        client = None
        result = None
        if interrupted:
            entry["state"] = "skipped_after_interrupt"
        elif remaining_time < 1 or remaining_requests < 1:
            entry["state"] = "skipped_budget"
        else:
            limits = Limits(**job["limits"])
            if diagnose:
                job["max_targets"] = 1
                limits = replace(
                    limits, max_pages=1, retries=0, max_requests=min(limits.max_requests, 20)
                )
            limits = replace(
                limits,
                max_seconds=min(limits.max_seconds, remaining_time),
                max_requests=min(limits.max_requests, remaining_requests),
            )
            entry["effective_limits"] = asdict(limits)
            # Persist a running checkpoint before loading credentials or making requests.
            entry["state"] = "running"
            manifest["jobs"].append(entry)
            manifest["previous_manifest"] = latest
            latest = save_private(directory, manifest, prefix="manifest")
            try:
                client = factory(job, directory, limits)
                remaining_time = deadline - clock()
                if remaining_time <= 0:
                    entry["state"] = "skipped_budget"
                else:
                    client.restrict_time(remaining_time)
                    result = collect_job(job, client, now=now)
                    if diagnose:
                        result = diagnostics(result, job)
                    entry["state"], entry["run_status"] = "collected", result["run_status"]
            except KeyboardInterrupt:
                interrupted, entry["state"] = True, "interrupted"
            except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
                entry["state"] = "configuration_error" if client is None else "execution_error"
            finally:
                entry["requests"] = client.requests if client is not None else 0
                manifest["requests"] += entry["requests"]
            if result is not None and entry["state"] == "collected":
                # Output failures abort the batch; never continue work that cannot be preserved.
                entry["output_file"] = save_private(
                    directory, result, prefix="diagnostic" if diagnose else "inventory"
                )
                entry["output_sha256"] = output_digest(directory, entry["output_file"])
        if not manifest["jobs"] or manifest["jobs"][-1] is not entry:
            manifest["jobs"].append(entry)
        entry["finished_at"] = now()
        manifest["previous_manifest"] = latest
        latest = save_private(directory, manifest, prefix="manifest")
    manifest["finished_at"] = now()
    manifest["status"] = (
        "interrupted"
        if interrupted
        else "complete"
        if all(
            entry["state"] == "collected" and entry["run_status"] == "complete"
            for entry in manifest["jobs"]
        )
        else "partial"
    )
    manifest["previous_manifest"] = latest
    latest = save_private(directory, manifest, prefix="manifest")
    return manifest, latest


def manifest_summary(manifest, filename):
    return {
        "status": manifest["status"],
        "requests": manifest["requests"],
        "job_states": dict(Counter(job["state"] for job in manifest["jobs"])),
        "collection_statuses": dict(
            Counter(job["run_status"] for job in manifest["jobs"] if "run_status" in job)
        ),
        "output_file": filename,
    }


def main(argv=None, *, directory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        required=True,
        help="JSON job configuration containing profile references, never credentials.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration only; no credentials, network or output files.",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Bounded first-page sample reads; save counts/status instead of response metadata.",
    )
    parser.add_argument(
        "--resume-manifest",
        help="Rerun unfinished jobs from a matching prior manifest/checkpoint. New budgets and observation windows apply.",
    )
    args = parser.parse_args(argv)
    try:
        value, _ = load_snapshot(args.config)
        config = validate_config(value)
        private_dir = Path(directory) if directory is not None else DEFAULT_DIRECTORY
        selected, previous_digest = None, None
        if args.resume_manifest:
            previous, previous_digest = load_snapshot(args.resume_manifest)
            selected = resume_jobs(config, previous, private_dir, diagnose=args.diagnose)
            if not selected:
                print(json.dumps({"status": "nothing_to_resume", "jobs": 0}))
                return 0
        if args.dry_run:
            planned = [job for job in config["jobs"] if selected is None or job["name"] in selected]
            print(
                json.dumps(
                    {
                        "status": "valid_plan",
                        "jobs": len(planned),
                        "modes": dict(Counter(job["mode"] for job in planned)),
                        "action": "diagnose" if args.diagnose else "collect",
                        "max_requests": config["max_requests"],
                        "max_seconds": config["max_seconds"],
                    },
                    indent=2,
                )
            )
            return 0
        manifest, filename = run_jobs(
            config,
            private_dir,
            diagnose=args.diagnose,
            selected_jobs=selected,
            resumed_from_sha256=previous_digest,
        )
    except KeyboardInterrupt:
        parser.exit(130, "Batch interrupted. Existing private checkpoints remain available.\n")
    except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
        parser.exit(
            2,
            "Invalid job configuration or private output failure. Details suppressed; inspect existing private checkpoints.\n",
        )
    print(json.dumps(manifest_summary(manifest, filename), indent=2))
    return (
        130 if manifest["status"] == "interrupted" else 0 if manifest["status"] == "complete" else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
