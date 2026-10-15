"""Read-only scheduling eligibility, using the same clocks as the worker."""

import uuid
from datetime import UTC, datetime

from cremore.coverage import JOB_KIND, METADATA_JOB_KIND, aws_scheduling, scheduling
from cremore.coverage.models import ConnectionSpec, worker_collected
from cremore.coverage.store import CoverageStore, utc
from cremore.scanning import scope, trigger_settings, triggers


def for_job(repo, settings, job, *, now=None):
    now = utc(now or datetime.now(UTC))
    enabled, minutes, due = False, 0, None
    if job.kind == "scope" and job.payload.get("profile_id"):
        profile = repo.get_scope_profile(uuid.UUID(job.payload["profile_id"]))
        if profile is None:
            return None
        # A scope without a full-scan cadence of its own follows the installation default, in slots from its start.
        default, start = trigger_settings.full_scan(settings, repo)
        intervals = [value for value in (profile.schedule_minutes, triggers.full_scan_cadence(profile, default)) if value]
        minutes = min(intervals) if intervals else 0
        enabled = bool(minutes and trigger_settings.schedules_on(settings, repo))
        if enabled:
            try:
                triggers.prepare_trigger_plan(repo, settings, profile.id, "SCHEDULE", now=now)
            except scope.ScopeError:
                enabled = False
        if enabled:
            # A full-scan slot ends when the next is due (its start plus the scope's spread): the time shown.
            origin = trigger_settings.schedule_origin(repo, now)
            due = min(slot.ends if slot.answered else now
                      for slot in triggers.slot_states(repo, profile, now, (default, start), origin))
    elif job.kind in (JOB_KIND, METADATA_JOB_KIND) and job.payload.get("coverage_connection_id"):
        cid = uuid.UUID(job.payload["coverage_connection_id"])
        row = CoverageStore(repo).get(cid)
        if row is None:
            return None
        spec = row["spec"]
        minutes = spec.get("schedule_minutes", 0)
        revision = row["revision"]
        enabled = bool(row["enabled"] and settings.scan_schedules_allowed)
        if spec.get("schema_version") == 2:
            prefix, latest = "metadata-schedule:", scheduling.connection_job(repo, cid)
        else:
            typed = ConnectionSpec.model_validate(spec)
            if not worker_collected(typed):
                return None
            latest = aws_scheduling.connection_job(repo, cid)
            if typed.provider.startswith("aws_"):
                from cremore_aws_provider import aws_inventory_settings

                prefix, revision = "aws-inventory-schedule:", None
                minutes = minutes or (aws_inventory_settings.config(settings, repo)["interval_minutes"]
                                      if typed.schedule_source == "installation" else 0)
                enabled = enabled and not aws_scheduling.scheduled_refusal(repo, settings, typed)
            else:
                prefix = "vault-collection-schedule:"
        enabled = bool(enabled and minutes)
        if enabled:
            due = scheduling.next_collection_at(repo, prefix + str(cid), latest, minutes, revision=revision, now=now)
            if spec.get("schema_version") == 2:
                from cremore.coverage.github_exports import next_create_at
                export_due = next_create_at(repo, spec)
                if export_due is not None:
                    due = max(due, export_due)
    else:
        return None
    return {"minutes": minutes, "enabled": enabled, "next_due_at": due.isoformat() if due else None}
