"""Scan worker: claim queued jobs and run them.

Polls the repository for a queued job, builds its collector, scans every object
through the orchestrator, and records the outcome. One failing job never stops
the worker; it is marked FAILED with a safe error code and the loop continues.

Two job kinds exist besides content scans: ``credential-check`` runs a read-only
identity call for a connection's own credential, and a complete connection scan
retires the exposures it no longer sees.
"""

from __future__ import annotations

import datetime as _dt
import logging
import signal
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager, nullcontext

from cremore_aws_provider.aws_identity import (
    APPROVED_IDENTITY_KEY,
    ROLE_CHECK_JOB,
    WORKER_IDENTITY_KEY,
    AwsLoginRequired,
)

from cremore.collectors.base import Collector, CollectorError, guard_requests
from cremore.coverage import METADATA_JOB_KIND
from cremore.db.repository import Repository
from cremore.db.scan_store import ScanStore
from cremore.domain.models import ConnectionCheckEvent, ConnectionStatus, ScanJob
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.scope import FAILURE_BASIS
from cremore.scanning.service import ScanService
from cremore.worker.factory import build_collector

logger = logging.getLogger("cremore.worker")

CollectorFactory = Callable[[ScanJob], Collector]
CredentialChecker = Callable[
    [ScanJob], object
]  # -> cremore.collectors.credential_check.CredentialCheck
CatalogLister = Callable[[ScanJob], tuple[list[dict], str]]  # -> (resources, completeness)
CREDENTIAL_CHECK = "credential-check"
# The connection wizard's permission check (cremore.onboarding.check).
PROVIDER_CHECK = "provider-check"
FINDING_CONTEXT = "finding-context"  # cremore.governance.ownership.JOB_KIND
# An approved plan on another provider's credential (cremore.remediation.provider_actions.JOB_KIND).
PROVIDER_ACTION = "provider-credential-action"


def _default_http_client(**kwargs):
    import httpx

    return httpx.Client(timeout=30.0, follow_redirects=False, **kwargs)
SECRET_SCANNING = "github-secret-scanning"
CATALOG_REFRESH = "catalog-refresh"
SCOPE = "scope"
AWS_ROLE_CHECK = ROLE_CHECK_JOB
AWS_WORKER_IDENTITY = WORKER_IDENTITY_KEY
AWS_APPROVED_IDENTITY = APPROVED_IDENTITY_KEY
_IDENTITY_TTL = 60.0
# Where Slack alerts go out (cremore.alerts.delivery), about every second on a thread of their own: the mixed worker's
# control loop, and the control process of a split deployment, which alone holds the control sealing key that opens
# the webhook and the bot token, and the grants on the delivery rows (cremore.db.privileges). Collector and remediator
# processes never send.
ALERT_ROLES = ("mixed", "control")
ALERT_SECONDS = 1.0
# How long a stop waits for the alert pass in hand. Told to stop, a pass sends no new message and puts what it claimed
# back at once, so this covers the message in flight: a wait for the shared slot and one Slack answer
# (cremore.alerts.delivery MAX_WAIT_SECONDS + TIMEOUT), inside the 30 s stop period Compose and Helm give.
ALERT_GRACE_SECONDS = 15.0


def _needs_aws(job: ScanJob) -> bool:
    p = job.payload or {}
    return bool(job.kind in ("s3", AWS_ROLE_CHECK) or p.get("scanner_role_arn") or p.get("source_type") == "s3"
                or "aws" in (p.get("connection_kind"), p.get("kind"), p.get("provider")))


class JobWorker:
    def __init__(
        self,
        repo: Repository,
        orchestrator: Orchestrator | None = None,
        collector_factory: CollectorFactory | None = None,
        *,
        verify: bool | None = None,
        credential_checker: CredentialChecker | None = None,
        secret_scanning_reader: Callable[[ScanJob], dict] | None = None,
        catalog_lister: CatalogLister | None = None,
        settings=None,
        sqs_client_factory=None,
        aws_identity_probe: Callable[[], dict] | None = None,
        aws_role_checker: Callable[[object], object] | None = None,
        org_client_factory: Callable[[], object] | None = None,
        control_tower_client_factory: Callable[[str, str], object] | None = None,
        lifecycle_sqs_client_factory: Callable[[str], object] | None = None,
        # Returns (sso client, access token) for one sweep; built per call so a
        # token refreshed by a new `aws sso login` is picked up without a restart.
        sso_session_factory: Callable[[], tuple] | None = None,
        aws_sessions=None,
        aws_content_sessions=None,
        metadata_secret_resolver=None,
        # (payload, roots, states, request budget) -> {resource_id: Changes | error}, with
        # the connection's credential resolved the way a scan resolves it.
        change_reader: Callable[..., object] | None = None,
        # Queue kind ("pubsub", "servicebus") -> open(address) returning the queue
        # cremore.scanning.triggers.poll_queue reads; SQS keeps sqs_client_factory.
        queue_openers: dict[str, Callable[[str], object]] | None = None,
        # A plain HTTP client for provider permission checks (cremore.onboarding.check).
        http_client_factory: Callable[[], object] | None = None,
        action_clients=None,
        # (job, read, roots, request budget) -> what ``read(payload, roots, http_client=, request_budget=)`` returns
        # for a run's plan (a Notion run's page headers, cremore.worker.runtime.ScanRuntime.plan), with the job
        # connection's credential resolved the way a scan resolves it.
        plan_reader: Callable[..., dict] | None = None,
    ) -> None:
        self.repo = repo
        from cremore.worker.isolation import execution_role
        self.execution_role = execution_role(settings)
        self.action_clients = action_clients
        from cremore.operations import audit_integrity

        audit_integrity.attach(repo, settings)  # audit rows this worker writes carry its entry MAC
        self.orchestrator = orchestrator or Orchestrator(repo)
        self.service = ScanService(self.orchestrator)
        self.collector_factory = collector_factory or (lambda job: build_collector(job))
        self._verify = verify
        self.credential_checker = credential_checker
        self.secret_scanning_reader = secret_scanning_reader
        self.catalog_lister = catalog_lister
        self.settings = settings
        self.sqs_client_factory = sqs_client_factory
        # Both run in this process, so they see the credentials scans really use.
        self.aws_identity_probe = aws_identity_probe
        self.aws_role_checker = aws_role_checker
        # Opt-in: lists the organization's accounts (read-only) so new ones are
        # registered without being added by hand. None when discovery is off.
        self.org_client_factory = org_client_factory
        self.control_tower_client_factory = control_tower_client_factory
        self.lifecycle_sqs_client_factory = lifecycle_sqs_client_factory
        self.sso_session_factory = sso_session_factory
        self.aws_sessions = aws_sessions
        self.aws_content_sessions = aws_content_sessions
        self.metadata_secret_resolver = metadata_secret_resolver
        self.change_reader = change_reader
        self.queue_openers = dict(queue_openers or {})
        self.http_client_factory = http_client_factory or _default_http_client
        self.plan_reader = plan_reader
        self._identity: tuple[float, dict] | None = None
        # Whether aws_identity records what it sees for the dashboard; a supervised task runner leaves that to
        # its control loop, so one report stands for the worker however many runners probe.
        self.reports_identity = True
        self._scan_slot_ready = False
        self._last_trigger_poll = 0.0
        self._last_maintenance = 0.0
        self._audit_thread: threading.Thread | None = None
        # Names this process in its database liveness record (operations.heartbeat).
        self.worker_id = str(uuid.uuid4())
        self.started_at = _dt.datetime.now(_dt.UTC)
        self._last_org_discovery = 0.0
        self._last_org_event_attempt = (None, 0.0)
        self._last_sso_discovery = 0.0
        self._policy_cursor = None
        from cremore.worker.runtime import ScanRuntime

        self.runtime = ScanRuntime(self)

    @property
    def verify(self) -> bool | None:
        """Installation ceiling AND the dashboard switch, read when each job runs."""
        if not self._verify:
            return self._verify
        from cremore.scanning import verification_switch

        return verification_switch.switch(self.repo)["enabled"]

    def verify_config(self):
        """The engine's verify config with the live probe/cross-host switches."""
        base = self.orchestrator.config.verify
        if self.settings is None:
            return base
        from cremore.scanning import scan_switches
        return scan_switches.verify_config_for(base, self.settings, self.repo)

    def aws_identity(self, *, refresh: bool = False, state: dict | None = None) -> dict | None:
        """The AWS identity of this worker process, reported for the API to compare."""
        if self.aws_identity_probe is None:
            return None
        now = time.monotonic()
        if state is None and not refresh and self._identity and now - self._identity[0] < _IDENTITY_TTL:
            return self._identity[1]
        if state is None:
            try:
                state = self.aws_identity_probe()
            except Exception as exc:  # noqa: BLE001 -- a missing SDK or config is a reported state
                from cremore_aws_provider.aws_identity import error_code

                state = {"state": "ERROR", "error_code": error_code(exc)}
        self._identity = (now, state)
        from cremore_aws_provider.roles_anywhere import diagnostic

        renewal = diagnostic(state)
        if renewal:
            state["renewal_health"] = renewal
        if not self.reports_identity:
            return state
        report = {k: state.get(k) for k in ("state", "kind", "account_id", "match_key", "principal_arn",
                                            "permission_set", "sso_region", "sso_start_url", "requires",
                                            "caller_arn", "trust", "partition", "error_code", "credential_source", "renewal_health")}
        report["checked_at"] = _dt.datetime.now(_dt.UTC).isoformat()
        try:
            self.repo.put_setting("aws_identity:remediator" if self.execution_role == "remediator" else AWS_WORKER_IDENTITY, report, "worker")
        except Exception as exc:  # noqa: BLE001 -- reporting never stops scanning
            logger.warning("could not record worker AWS identity: %s", type(exc).__name__)
        return state

    def aws_hold(self, job: ScanJob) -> str | None:
        """Why AWS work for this job must wait: an expired sign-in or an unapproved identity change."""
        if self.aws_identity_probe is None or not _needs_aws(job):
            return None
        approved = (self.repo.get_setting(AWS_APPROVED_IDENTITY) or {}).get("value")
        uses_role = bool(approved or (job.payload or {}).get("scanner_role_arn") or job.kind == AWS_ROLE_CHECK)
        current = self.aws_identity() or {}
        renewal = current.get("renewal_health") or {}
        if uses_role and renewal.get("state") == "ERROR":
            return renewal.get("error_code") or "AWS_ROLES_ANYWHERE_RENEWAL_FAILED"
        if current.get("state") in ("LOGIN_REQUIRED", "NO_CREDENTIALS") and uses_role:
            return "AWS_LOGIN_REQUIRED"
        if approved and current.get("state") == "READY" and current.get("match_key") != approved.get("match_key"):
            return "AWS_SCANNER_IDENTITY_CHANGED"
        return None

    def share_budget(self, task, keys, code: str) -> bool:
        """Top up an exhausted root from siblings' unused shares, or wait for them. True = deferred."""
        from cremore.db.task_store import LeaseLost

        if task.get("kind") == "PLAN":
            return False
        try:
            granted, pending = self.runtime.tasks.top_up_budget(task["id"], task["token"], keys)
            if not granted and pending is None:
                return False
            # Waiting drops below the unfinished siblings so they (often on the same
            # bucket lock) run first and free their unused share. ``budget_wait`` tells
            # the siblings this root has no budget to run with until one finishes.
            # ponytail: a sibling finishing after this root gave up does not reopen it.
            self.runtime.tasks.defer(task["id"], task["token"], code, delay_seconds=1 if granted else 10,
                                     priority=None if granted else pending - 1,
                                     checkpoint={"budget_wait": not granted})
        except LeaseLost:
            return False
        logger.info("root task %s %s budget", task["id"], "received sibling" if granted else "waits for sibling")
        return True

    def shared_pacing(self):
        """Notion calls outside a scan (catalog, credential and permission checks, finding context) share the database
        pacing a scan of the connection uses, so the worker's processes together keep to its rate; a scan sets its own.
        The remediator has no grant on that table, and its Notion calls pace themselves."""
        if self.execution_role == "remediator":
            return nullcontext()
        return guard_requests(None, pacing=ScanStore(self.repo))

    def _defer(self, task, code: str) -> None:
        # Not inside the fenced context: it rejects a task that is no longer RUNNING on exit.
        self.runtime.tasks.defer(task["id"], task["token"], code, delay_seconds=60)
        logger.info("AWS task %s waiting: %s", task["id"], code)

    def process_next(self, poll: bool = True) -> bool:
        """Claim and run one job. Returns False when the queue is empty.

        ``poll=False`` is a supervised task runner's (cremore.worker.supervisor): its control loop polls the
        triggers, so they keep running while this process scans.
        """

        if poll:
            self.poll_triggers()
        tasks = self.runtime.tasks
        if self.execution_role == "control":
            return False
        seeded = tasks.seed_next_job(execution_role=self.execution_role)
        task = tasks.claim(execution_role=self.execution_role)
        if task is None:
            return bool(tasks.finalize_runs(execution_role=self.execution_role) or seeded)
        job = self.repo.get_job(task["run_id"])
        context = lambda: tasks.fenced(task["id"], task["token"])
        try:
            from cremore.worker.isolation import accepts
            if not accepts(self.repo, job, self.execution_role):
                raise CollectorError("WORKER_AUTHORITY_MISMATCH")
            self.orchestrator.refresh_rules()
            hold = self.aws_hold(job) if self.execution_role != "remediator" else None
            if hold:
                self._defer(task, hold)
                return True
            with self.runtime.keep_lease(task), self.shared_pacing():
                from cremore.coverage import JOB_KIND as COVERAGE_JOB
                if job.kind == COVERAGE_JOB:
                    from cremore.coverage.job import run as run_coverage
                    run_coverage(self, job, task, context)
                elif job.kind == METADATA_JOB_KIND:
                    from cremore.coverage.metadata_job import run as run_metadata
                    run_metadata(self, job, task, context)
                elif job.kind == "credential-usage":
                    from cremore.coverage.credential_usage import run as run_usage

                    run_usage(self, job, task, context)
                elif job.kind == AWS_ROLE_CHECK:
                    self._run_aws_role_check(job, write_context=context)
                    with context() as repo:
                        from cremore.db.task_store import TaskStore

                        TaskStore(repo).finish(task["id"], task["token"], {})
                elif job.kind == SCOPE:
                    if task["kind"] == "PLAN":
                        self.runtime.plan(job, task)
                    else:
                        self.runtime.run_root(job, task)
                elif job.kind == CREDENTIAL_CHECK:
                    self._run_credential_check(job, write_context=context)
                    with context() as repo:
                        from cremore.db.task_store import TaskStore

                        TaskStore(repo).finish(task["id"], task["token"], {})
                elif job.kind == SECRET_SCANNING:
                    self._run_secret_scanning(job, write_context=context)
                    with context() as repo:
                        from cremore.db.task_store import TaskStore

                        TaskStore(repo).finish(task["id"], task["token"], {})
                elif job.kind == CATALOG_REFRESH:
                    self._run_catalog_refresh(job, write_context=context)
                    with context() as repo:
                        from cremore.db.task_store import TaskStore

                        TaskStore(repo).finish(task["id"], task["token"], {})
                elif job.kind == "aws-api-read":
                    from cremore.coverage import aws_requests
                    aws_requests.run(self, job, task, context)
                elif job.kind == "machine-identity-check":
                    from cremore.db.task_store import TaskStore
                    from cremore.identity import machine

                    revision = (job.payload or {}).get("revision")
                    if machine.revision_of(self.repo.get_setting(machine.KEY)) != revision:
                        raise CollectorError("MACHINE_IDENTITY_CHANGED")
                    try:
                        result = machine.Keeper(self.repo, self.settings, "test").test()
                    except Exception:  # noqa: BLE001 -- token endpoints may include secrets in errors
                        with context() as repo:
                            if machine.revision_of(repo.get_setting(machine.KEY)) == revision:
                                repo.put_setting(machine.TEST_KEY, {"revision": revision, "tokens": {},
                                    "tested_by": str((job.payload or {}).get("actor") or "worker"),
                                    "state": "FAILED", "safe_error_code": "MACHINE_IDENTITY_CHECK_FAILED",
                                    "checked_at": _dt.datetime.now(_dt.UTC).isoformat(), "job_id": str(job.id)}, "worker")
                        raise CollectorError("MACHINE_IDENTITY_CHECK_FAILED") from None
                    with context() as repo:
                        if machine.revision_of(repo.get_setting(machine.KEY)) != revision:
                            raise CollectorError("MACHINE_IDENTITY_CHANGED")
                        repo.put_setting(machine.TEST_KEY, {"revision": revision, "tokens": result, "state": "COMPLETED",
                            "tested_by": str((job.payload or {}).get("actor") or "worker"),
                            "checked_at": _dt.datetime.now(_dt.UTC).isoformat(), "job_id": str(job.id)},
                            str((job.payload or {}).get("actor") or "worker"))
                        repo.complete_job(job.id, objects=0, findings=0)
                        TaskStore(repo).finish(task["id"], task["token"], {})
                elif job.kind == PROVIDER_CHECK:
                    from cremore.onboarding.check import run as run_provider_check

                    run_provider_check(self, job, write_context=context)
                    with context() as repo:
                        from cremore.db.task_store import TaskStore

                        TaskStore(repo).finish(task["id"], task["token"], {})
                elif job.kind == FINDING_CONTEXT:
                    from cremore.governance.ownership import run as run_finding_context

                    run_finding_context(self, job, task, write_context=context)
                elif job.kind == PROVIDER_ACTION:
                    from cremore.remediation.provider_actions import run as run_provider_action

                    run_provider_action(self, job, write_context=context)
                    with context() as repo:
                        from cremore.db.task_store import TaskStore

                        TaskStore(repo).finish(task["id"], task["token"], {})
                else:
                    started = time.monotonic()

                    def before_request():
                        from cremore.db.task_store import LeaseLost

                        if time.monotonic() - started >= 3600:
                            raise CollectorError("BUDGET_SECONDS")
                        self.runtime.validate(job)
                        try:
                            with context():
                                pass  # Checks cancellation and lease before provider I/O.
                        except LeaseLost as exc:
                            if str(exc) == "RUN_CANCELLED":
                                raise CollectorError("RUN_CANCELLED") from None
                            raise

                    with guard_requests(before_request, pacing=ScanStore(self.repo)):
                        self.runtime.validate(job)
                        self._run_legacy_scan(job, task, context)
        except Exception as exc:  # noqa: BLE001 -- each failed job is recorded without disclosing exception text
            from cremore.db.task_store import LeaseLost

            if isinstance(exc, LeaseLost) or getattr(exc, "code", None) == "RUN_CANCELLED":
                if str(exc) == "RUN_CANCELLED":
                    # A stop was requested: end this task now so the run can be
                    # finalized as CANCELLED without waiting out the lease.
                    tasks.release_cancelled(task["id"], task["token"])
                    tasks.finalize_runs(execution_role=self.execution_role)
                    logger.info("job %s stopped on request", job.id)
                    return True
                logger.warning("job %s lost execution lease; result discarded", job.id)
                return True
            from cremore_aws_provider.aws_identity import is_login_required

            if is_login_required(exc) and _needs_aws(job):
                # The sign-in expired mid-run: pause (checkpoints kept), show it, resume after login.
                self.aws_identity(state={"state": "LOGIN_REQUIRED", "error_code": "AWS_LOGIN_REQUIRED"})
                try:
                    self._defer(task, "AWS_LOGIN_REQUIRED")
                except LeaseLost:
                    logger.warning("job %s lost lease before AWS wait was recorded", job.id)
                return True
            code = getattr(exc, "code", "TASK_EXECUTION_FAILED")
            if job.kind == METADATA_JOB_KIND:
                from cremore.coverage.metadata_stream import safe_error_code
                code = safe_error_code(exc)
            budget_key = {"BUDGET_REQUESTS": "requests", "BUDGET_BYTES": "bytes", "BUDGET_SECONDS": "seconds"}.get(code)
            if budget_key and job.kind == SCOPE and self.share_budget(task, [budget_key], code):
                return True
            try:
                with context() as repo:
                    from cremore.db.task_store import TaskStore

                    if budget_key and job.kind == SCOPE:
                        self.runtime.finish_budget_stop(job, task, repo, code)
                        logger.info("root task %s stopped on %s", task["id"], code)
                        return True
                    TaskStore(repo).fail(task["id"], task["token"], code)
                    # Metadata finalization closes its persisted run and parent
                    # together, including failures before collection resumes.
                    # Preserve the other jobs' legacy public error contract.
                    if job.kind not in (SCOPE, METADATA_JOB_KIND):
                        repo.fail_job(
                            job.id,
                            str(exc) if isinstance(exc, CollectorError) else type(exc).__name__,
                        )
            except LeaseLost:
                logger.warning("job %s lost lease before failure was recorded", job.id)
                return True
            logger.warning("job %s failed: %s", job.id, type(exc).__name__)
        finally:
            if self.aws_content_sessions is not None:
                self.aws_content_sessions.release(job)
        tasks.finalize_runs(execution_role=self.execution_role)
        return True

    def poll_triggers(self):
        if self.settings is None or time.monotonic() - self._last_trigger_poll < 5:
            return
        self._last_trigger_poll = time.monotonic()
        if self.execution_role in ("control", "remediator"):
            self._poll_dedicated()
            return
        from cremore.coverage.aws_scheduling import poll_aws_inventory_schedules
        from cremore.coverage.scheduling import poll_metadata_schedules
        from cremore.scanning.changes import poll_change_feeds
        from cremore.scanning.rescore import RescoreService
        from cremore.scanning.triggers import poll_queue, poll_resumable, poll_schedules, poll_sqs

        for poll in (
            lambda: poll_schedules(self.repo, self.settings),
            lambda: poll_metadata_schedules(self.repo, self.settings),
            lambda: poll_resumable(self.repo, self.settings),
            lambda: (
                poll_sqs(self.repo, self.settings, self.sqs_client_factory)
                if self.sqs_client_factory is not None
                else None
            ),
            *(
                lambda kind=kind, opener=opener: poll_queue(self.repo, self.settings, kind, opener)
                for kind, opener in self.queue_openers.items()
            ),
            lambda: (
                poll_change_feeds(self.repo, self.settings, self.change_reader)
                if self.change_reader is not None
                else None
            ),
            lambda: RescoreService(self.orchestrator).run_batch(),
        ):
            try:
                poll()
            except Exception as exc:  # noqa: BLE001 -- an optional trigger cannot stop queued scans
                logger.warning("scan trigger poll failed: %s", type(exc).__name__)
        if time.monotonic() - self._last_maintenance >= 60:
            self._last_maintenance = time.monotonic()
            self.aws_identity(refresh=True)
            try:
                self.queue_stale_validations()
            except Exception as exc:  # noqa: BLE001 -- retried on the next maintenance tick
                logger.warning("could not queue AWS revalidation: %s", type(exc).__name__)
            try:
                from cremore.operations.evaluator import publish

                publish(self.repo, self.settings)
            except Exception as exc:  # noqa: BLE001 -- health events are re-derived on the next tick
                logger.warning("connection health evaluation failed: %s", type(exc).__name__)
            try:
                from cremore.operations import coverage_verdicts

                coverage_verdicts.publish(self.repo, self.settings, self.orchestrator)
            except Exception as exc:  # noqa: BLE001 -- verdicts are compared again in the next slot
                logger.warning("coverage verdict evaluation failed: %s", type(exc).__name__)
            try:
                from cremore.identity import leavers

                result = leavers.publish(self.repo, self.settings, self.orchestrator)
                if result and result.get("status") == "PARTIAL":
                    logger.warning("departed-owner check incomplete: %s", ",".join(result["reasons"]))
            except Exception as exc:  # noqa: BLE001 -- the next slot evaluates again
                logger.warning("departed-owner check failed: %s", type(exc).__name__)
            try:
                from cremore.governance import ownership

                ownership.sweep(self.repo)
            except Exception as exc:  # noqa: BLE001 -- the next slot queues them again
                logger.warning("finding context sweep failed: %s", type(exc).__name__)
            try:
                from cremore.identity import sign_in_groups

                # Who is in the groups that give console roles to people who sign in with Google, every few minutes.
                sign_in_groups.sweep(self.repo, self.settings, self.metadata_secret_resolver, self.http_client_factory)
            except Exception as exc:  # noqa: BLE001 -- read again on a later tick
                logger.warning("sign-in group read failed: %s", type(exc).__name__)
            try:
                from cremore.onboarding import github_enterprise

                # CreMore's GitHub App on the enterprise's other organizations: a few installed and connected a tick.
                github_enterprise.sweep(self.repo, self.settings, self.http_client_factory)
            except Exception as exc:  # noqa: BLE001 -- the organizations stay queued for the next tick
                logger.warning("GitHub enterprise installation sweep failed: %s", type(exc).__name__)
            try:
                from cremore.ticketing import sweep as ticket_sweep

                # The owners' answers to the approvals asked in the company's ticket system, read once a minute.
                if self.execution_role == "mixed":
                    ticket_sweep.sweep(self.repo, self.settings, self.http_client_factory, orchestrator=self.orchestrator)
            except Exception as exc:  # noqa: BLE001 -- read again on the next tick
                logger.warning("ticket approval sweep failed: %s", type(exc).__name__)
            try:
                from cremore.governance import response

                response.sweep(self.repo, self.settings, self.orchestrator)
            except Exception as exc:  # noqa: BLE001 -- stored proof stays unconfirmed; retry next tick
                logger.warning("response evidence sweep failed: %s", type(exc).__name__)
            try:
                from cremore.governance import response_threads

                # Progress replies in exposure-response threads, where Slack alerts go out (ALERT_ROLES).
                if self.execution_role == "mixed":
                    response_threads.sweep(self.repo, self.settings)
            except Exception as exc:  # noqa: BLE001 -- the cursor holds what is owed; the next minute posts it
                logger.warning("response thread progress failed: %s", type(exc).__name__)
            try:
                from cremore.remediation import provider_actions

                # A provider plan whose run ended without settling it is not left waiting or executing.
                if self.execution_role == "mixed":
                    provider_actions.settle(self.repo, self.settings)
            except Exception as exc:  # noqa: BLE001 -- the next tick looks again
                logger.warning("provider plan settle sweep failed: %s", type(exc).__name__)
            try:
                from cremore.onboarding import check as onboarding_check

                # Integrations checked before checks kept credential marks are checked once more, a few a tick.
                onboarding_check.backfill_marks(self.repo, _dt.datetime.now(_dt.UTC))
            except Exception as exc:  # noqa: BLE001 -- the next tick looks again
                logger.warning("credential mark backfill failed: %s", type(exc).__name__)
            try:
                from cremore.operations import heartbeat

                heartbeat.beat(self.repo, self.worker_id, self.started_at)
                heartbeat.publish(self.repo, self.settings)
            except Exception as exc:  # noqa: BLE001 -- the next maintenance tick beats again
                logger.warning("worker heartbeat failed: %s", type(exc).__name__)
            try:
                from cremore.operations import retention

                retention.prune(self.repo, self.settings)
            except Exception as exc:  # noqa: BLE001 -- pruning resumes in a later hour
                logger.warning("SIEM outbox retention failed: %s", type(exc).__name__)
            # The chain's first seal and the hourly full walk can outlast a liveness probe: on PostgreSQL their own
            # thread, one at a time, while this loop keeps beating. SQLite has one write lock (and in memory one
            # shared connection), so there they run here.
            engine = getattr(self.repo, "engine", None)
            if engine is None or engine.dialect.name != "postgresql":
                self._audit_tick()
            elif self._audit_thread is None or not self._audit_thread.is_alive():
                self._audit_thread = threading.Thread(target=self._audit_tick, name="audit-chain", daemon=True)
                self._audit_thread.start()
            try:
                from cremore.scanning.triggers import cleanup_trigger_receipts, poll_policy_sweeps

                # An upgraded installation may have had several scans active; the
                # one-active-scan index is created as soon as they have finished.
                if (not getattr(self.settings, "isolated_deployment", False)
                        and not self._scan_slot_ready and hasattr(self.repo, "ensure_scan_slot")):
                    self._scan_slot_ready = self.repo.ensure_scan_slot()
                self.orchestrator.refresh_rules()
                polled = poll_policy_sweeps(
                    self.repo, self.settings, self.orchestrator, cursor=self._policy_cursor
                )
                self._policy_cursor = polled["next_cursor"]
                cleanup_trigger_receipts(self.repo)
                ScanStore(self.repo).prune_cache()
            except Exception as exc:  # noqa: BLE001 -- retry bounded maintenance on the next poll
                logger.warning("scan maintenance failed: %s", type(exc).__name__)
        self._maybe_discover_org_accounts()
        self._maybe_discover_sso_accounts()
        try:
            # Accounts the sweeps just registered join the connections that take them in.
            from cremore.onboarding.adoption import adopt

            adopt(self.repo, self.settings)
        except Exception as exc:  # noqa: BLE001 -- adoption is retried on the next poll
            logger.warning("provider connection adoption failed: %s", type(exc).__name__)
        try:
            poll_aws_inventory_schedules(self.repo, self.settings, self.aws_sessions)
        except Exception as exc:  # noqa: BLE001 -- one optional inventory poll must not stop the worker
            logger.warning("AWS inventory schedule failed: %s", type(exc).__name__)

    def _maybe_discover_org_accounts(self):
        s = self.settings
        if s is None or self.org_client_factory is None:
            return
        from cremore_aws_provider import aws_controltower, aws_org_settings

        # Allowed by configuration, switched on by an Admin, and an ExternalId
        # set: re-read every poll, so the dashboard can stop the next sweep.
        if not aws_org_settings.effective(s, self.repo):
            return
        if self.lifecycle_sqs_client_factory is not None:
            try:
                aws_controltower.poll_lifecycle_events(self.repo, s, self.lifecycle_sqs_client_factory)
            except Exception as exc:  # noqa: BLE001 -- periodic discovery still runs when events are unavailable
                logger.warning("Control Tower event poll failed: %s", type(exc).__name__)
        pending = aws_controltower.rediscovery_pending(self.repo)
        interval = max(1, s.aws_org_discovery_interval_minutes) * 60
        now = time.monotonic()
        event_due = bool(pending and (pending["id"] != self._last_org_event_attempt[0]
                                    or now - self._last_org_event_attempt[1] >= 60))
        if self._last_org_discovery and now - self._last_org_discovery < interval and not event_due:
            return
        self._last_org_discovery = now
        if pending:
            self._last_org_event_attempt = (pending["id"], now)
        try:
            from cremore_aws_provider.aws_org_discovery import reconcile_org_accounts

            config = aws_org_settings.config(s, self.repo)
            validator = self._discovery_validator() if config["auto_validate"] else None
            org_client = self.org_client_factory()
            reconcile_org_accounts(self.repo, s, org_client, config, queue_validation=validator)
            if config["control_tower_enabled"] and self.control_tower_client_factory is not None:
                from cremore_aws_provider.aws_org_context import SUMMARY_KEY
                organization = (self.repo.get_setting(SUMMARY_KEY) or {}).get("value") or {}
                try:
                    ct_client = self.control_tower_client_factory(organization.get("management_account_id"),
                                                                 config["control_tower_region"])
                    aws_controltower.collect_context(self.repo, org_client, ct_client)
                except Exception as exc:  # noqa: BLE001 -- management context is optional, IAM work continues
                    aws_controltower.unavailable_context(self.repo, exc)
            if pending:
                aws_controltower.complete_rediscovery(self.repo, pending["id"])
        except Exception as exc:  # noqa: BLE001 -- account discovery is optional
            logger.warning("org account discovery failed: %s", type(exc).__name__)

    def _maybe_discover_sso_accounts(self):
        s = self.settings
        if s is None or self.sso_session_factory is None:
            return
        from cremore_aws_provider import aws_sso_settings

        # Allowed by configuration, switched on by an Admin, and a permission set
        # chosen: all three are re-read every poll, so turning the switch off in
        # the dashboard stops the next sweep without restarting the worker.
        if not aws_sso_settings.discovery_effective(s, self.repo):
            return
        interval = max(1, getattr(s, "aws_sso_discovery_interval_minutes", 60)) * 60
        if self._last_sso_discovery and time.monotonic() - self._last_sso_discovery < interval:
            return
        self._last_sso_discovery = time.monotonic()
        try:
            from cremore_aws_provider.aws_sso_discovery import reconcile_sso_accounts

            sso, token = self.sso_session_factory()
            # An Identity Center account has no stack to wait for, so it is
            # always proved at once; there is nothing here worth a knob.
            reconcile_sso_accounts(self.repo, s, sso, token,
                                   aws_sso_settings.permission_set(s, self.repo)["name"],
                                   queue_validation=self._discovery_validator())
        except AwsLoginRequired:
            # The sign-in this sweep needs is exactly the one that expired; the
            # next poll retries once the operator has run `aws sso login` again.
            logger.info("sso account discovery waiting for a new AWS sign-in")
        except Exception as exc:  # noqa: BLE001 -- account discovery is optional
            logger.warning("sso account discovery failed: %s", type(exc).__name__)

    def _discovery_validator(self):
        """Queues a newly discovered account's scanner check at once, so it goes
        READY without waiting for the maintenance sweep. Shared by both discovery
        sources. None until the AWS identity is approved."""
        from cremore_aws_provider import aws_access

        approved = aws_access.approval(self.repo, aws_access.SCANNER, self.settings)
        if approved is None:
            return None

        def queue(account):
            aws_access.queue_validation(self.repo, account, aws_access.SCANNER, approved["revision"])

        return queue

    def _run_legacy_scan(self, job, task, context):
        from cremore.db.task_store import TaskStore

        @contextmanager
        def authorized_write():
            with context() as repo:
                self.runtime.validate(job, repo)
                yield repo

        collector = self.collector_factory(
            job.model_copy(update={"payload": {**(job.payload or {}), "_lazy": True}})
        )
        # A scoped run may ask for provider verification; it only happens
        # where the deployment enabled verification in the first place.
        requested = (job.payload or {}).get("verify")
        verify = self.verify if requested is None else (bool(requested) and bool(self.verify))
        # The policy this run actually scans with, recorded so a later rule change
        # can be shown as needing a rescan of the whole connection.
        evidence = self.orchestrator.detection_evidence
        summary = self.service.run(
            collector,
            source_connection_id=job.connection_id,
            scan_id=job.id,
            verify=verify,
            verify_config=self.verify_config(),
            reconcile_objects=True,
            write_context=authorized_write,
            progress=lambda: self.runtime.validate(job),
            watched_locations={
                (e.source_type, e.resource_name, e.location)
                for e in self.repo.exposures_for_connection(job.connection_id)
            }
            if job.connection_id
            else (),
        )
        # Only a complete run of the connection's whole scope (listed, every
        # scannable object read) may retire exposures it no longer sees; a
        # partial run or a scoped subset proves nothing absent. Format skips are
        # not failures, and their listed locations are kept as seen.
        coverage = getattr(collector, "coverage", None) or {}
        authoritative = bool(getattr(collector, "authoritative_listing", False))
        with context() as repo:
            self.runtime.validate(job, repo)
            if (
                job.connection_id is not None
                and summary.objects_failed == 0
                and not coverage.get("skipped")
                and not coverage.get("stopped_reason")
                and authoritative
            ):
                self.orchestrator.using(repo).reconcile_connection(
                    job.connection_id,
                    summary.exposure_ids,
                    seen_locations=summary.existing_locations_seen,
                    scan_id=job.id, scan_started_at=job.started_at or job.created_at,
                )
            repo.complete_job(
                job.id,
                summary.objects,
                summary.findings,
                objects_failed=summary.objects_failed,
                coverage={
                    **coverage,
                    "timings": summary.timings,
                    "skipped_unsupported": summary.skipped_unsupported,
                    "skipped_media": summary.skipped_media,
                    "extraction_reasons": summary.extraction_reasons,
                    "failure_basis": FAILURE_BASIS,
                    **evidence,
                    "authoritative_listing": authoritative,
                },
            )
            TaskStore(repo).finish(task["id"], task["token"], {})
        logger.info(
            "job %s done: %d objects (%d unreadable), %d findings",
            job.id,
            summary.objects,
            summary.objects_failed,
            summary.findings,
        )

    def _ledger(self, job: ScanJob, conn, **fields) -> None:
        """A check's audit evidence is required, never best-effort."""
        self.repo.record_check_event(self._check_event(job, conn, **fields))

    @staticmethod
    def _check_event(job, conn, **fields):
        requester = (job.payload or {}).get("requested_by")
        return ConnectionCheckEvent(
            connection_id=conn.id,
            job_id=job.id,
            source_type={"aws": "s3"}.get(conn.provider, conn.provider),
            requested_by=uuid.UUID(str(requester)) if requester else None,
            requested_at=job.created_at,
            **fields,
        )

    def _run_aws_role_check(self, job: ScanJob, *, write_context=None) -> None:
        """Prove, from the process that scans, that this account is usable for scanning.

        The result is stored only under the revisions the job was queued with;
        a check that became stale while queued or running is discarded.
        """

        from cremore_aws_provider import aws_access
        from cremore_aws_provider.aws_identity import AwsLoginRequired

        payload = job.payload or {}
        account = self.repo.get_aws_account(uuid.UUID(str(payload.get("aws_account_id"))))
        if account is None:
            raise ValueError("aws role check has no account")
        purpose = "remediation" if self.execution_role == "remediator" else "scanner"
        approved = aws_access.approval(self.repo, purpose, self.settings)
        current = (aws_access.access_revision(account, purpose), (approved or {}).get("revision"))
        wanted = (payload.get("access_revision"), payload.get("approval_revision"))
        stored = False
        # The worker validates only the identity purpose assigned to this process.
        if (payload.get("purpose", aws_access.SCANNER) == purpose and wanted == current
                and aws_access.validation_refusal(account, purpose, approved) is None):
            if self.aws_role_checker is None:
                status, code = "INVALID", "WORKER_AWS_NOT_CONFIGURED"
            else:
                result = self.aws_role_checker(account)
                status = result.status
                code = result.code or ("SCANNER_ROLE_ASSUMED" if result.status == "VALID" else "ASSUME_ROLE_DENIED")
                if code == "AWS_LOGIN_REQUIRED":
                    # Not a fact about the account: wait for the sign-in instead of recording it.
                    self.aws_identity(state={"state": "LOGIN_REQUIRED", "error_code": code})
                    raise AwsLoginRequired()
            with write_context() if write_context else nullcontext(self.repo) as repo:
                latest = aws_access.approval(repo, purpose, self.settings)
                stored = aws_access.record_validation(
                    repo, account, purpose, access_revision=wanted[0], approval_revision=wanted[1],
                    current_approval_revision=(latest or {}).get("revision"), status=status, detail=code)
                repo.complete_job(job.id, objects=0, findings=0)
        else:
            with write_context() if write_context else nullcontext(self.repo) as repo:
                repo.complete_job(job.id, objects=0, findings=0)
        if not stored:
            logger.info("aws role check %s discarded: revisions changed", job.id)

    def queue_stale_validations(self) -> int:
        """Re-prove accounts whose scanner result predates the current revisions (e.g. after an upgrade)."""

        from cremore_aws_provider import aws_access

        purpose = "remediation" if self.execution_role == "remediator" else "scanner"
        approved = aws_access.approval(self.repo, purpose, self.settings)
        if approved is None or self.aws_identity_probe is None:
            return 0
        queued, pending = 0, aws_access.pending_validations(self.repo)
        for account in self.repo.list_aws_accounts():
            if (account.enabled and aws_access.validation_refusal(account, purpose, approved) is None
                    and getattr(account, "remediation_validation_key" if purpose == "remediation" else "validation_key", None) != aws_access.validation_key(account, purpose, approved["revision"])):
                aws_access.queue_validation(self.repo, account, purpose, approved["revision"], pending)
                queued += 1
        return queued

    def _run_catalog_refresh(self, job: ScanJob, *, write_context=None) -> None:
        """Metadata-only listing into the connection's resource catalog."""

        from cremore.db.catalog_store import CatalogStore
        from cremore.domain.models import ScopeCatalog
        from cremore.scanning.scope import new_snapshot_id

        if self.catalog_lister is None:
            raise ValueError("catalog refresh requires a catalog lister")
        p = job.payload or {}
        kind, cid = p["connection_kind"], uuid.UUID(str(p["connection_id"]))
        if self.aws_content_sessions is not None:
            self.aws_content_sessions.require_current(job)
        listed, completeness = self.catalog_lister(job)
        existing = CatalogStore(self.repo).header(kind, cid)
        narrow = bool(p.get("reference") or p.get("query"))
        if narrow and existing and existing.completeness == "COMPLETE" and existing.snapshot_id:
            completeness = "COMPLETE"
        with write_context() if write_context else nullcontext(self.repo) as repo:
            if self.aws_content_sessions is not None:
                self.aws_content_sessions.require_current(job, repo)
            CatalogStore(repo).refresh(
                ScopeCatalog(
                    kind=kind,
                    connection_id=cid,
                    snapshot_id=new_snapshot_id(),
                    auth_revision=str(p.get("auth_revision", "")),
                    completeness=completeness,
                    reason_code=None,
                    refresh_job_id=job.id,
                    refreshed_at=_dt.datetime.now(_dt.UTC),
                ),
                listed,
                replace=not narrow,
            )
            repo.complete_job(job.id, objects=len(listed), findings=0)
        logger.info(
            "catalog refresh for %s/%s: %d listed (%s)", kind, cid, len(listed), completeness
        )

    def _run_credential_check(self, job: ScanJob, *, write_context=None) -> None:
        if self.credential_checker is None:
            raise ValueError("credential check requires a credential checker")
        conn = self.repo.get_connection(job.connection_id) if job.connection_id else None
        if conn is None:
            raise ValueError("credential check job has no connection")
        context = write_context or (lambda: nullcontext(self.repo))
        with context() as repo:
            repo.record_check_event(
                self._check_event(job, conn, stage="CLAIMED_FOR_CHECK", job_status="RUNNING")
            )
        try:
            if self.aws_content_sessions is not None:
                self.aws_content_sessions.require_current(job)
            result = self.credential_checker(job)
        except Exception as exc:  # noqa: BLE001 -- persist terminal credential-check failure atomically
            with context() as repo:
                repo.finish_credential_check(
                    job,
                    {},
                    self._check_event(
                        job,
                        conn,
                        stage="TERMINAL",
                        job_status="FAILED",
                        outcome="UNCERTAIN",
                        reason_code="JOB_FAILED",
                    ),
                    error=type(exc).__name__,
                )
            return
        now = _dt.datetime.now(_dt.UTC)
        changes: dict = {
            "credential_evidence": result.as_evidence(now.isoformat()),
            "last_error": None if result.status == "ACTIVE" else (result.error or result.status),
        }
        if result.status == "ACTIVE":
            changes["last_verified_at"] = now
            if conn.status in (ConnectionStatus.PENDING.value, ConnectionStatus.ERROR.value):
                changes["status"] = ConnectionStatus.ACTIVE.value
        elif result.status == "REJECTED" and conn.status != ConnectionStatus.DISABLED.value:
            changes["status"] = ConnectionStatus.ERROR.value
        with context() as repo:
            if self.aws_content_sessions is not None:
                self.aws_content_sessions.require_current(job, repo)
            repo.finish_credential_check(
                job,
                changes,
                self._check_event(
                    job,
                    conn,
                    stage="TERMINAL",
                    job_status="COMPLETED",
                    outcome=result.status
                    if result.status in ("ACTIVE", "REJECTED", "INDETERMINATE")
                    else "UNCERTAIN",
                    reason_code="CHECK_RESULT",
                ),
            )
        logger.info("credential check for %s: %s", conn.id, result.status)

    def _run_secret_scanning(self, job: ScanJob, *, write_context=None) -> None:
        """Store the provider's own alerts for a connection we own.

        A refusal is recorded with its reason. It must never be stored as an
        empty alert list, because secret scanning needs Advanced Security on
        private repositories and can be switched off, and both answer the same
        way as a repository that genuinely has no alert.
        """

        if self.secret_scanning_reader is None:
            raise ValueError("secret-scanning read requires a reader")
        conn = self.repo.get_connection(job.connection_id) if job.connection_id else None
        if conn is None:
            raise ValueError("secret-scanning job has no connection")
        context = write_context or (lambda: nullcontext(self.repo))
        self.runtime.validate(job)
        try:
            result = self.secret_scanning_reader(job)
        except Exception as exc:  # noqa: BLE001 -- a failure is recorded as a safe code, never provider text
            result = {"collection_status": "FAILED", "reason_code": type(exc).__name__[:64],
                      "alerts": [], "counts": {"alerts": 0}, "truncated": False,
                      "collected_at": _dt.datetime.now(_dt.UTC).isoformat()}
        with context() as repo:
            self.runtime.validate(job, repo)
            repo.update_connection(conn.id, secret_scanning=result)
        logger.info("secret-scanning read completed; consult the connection report for status")

    def _poll_dedicated(self):
        """Dedicated processes have no collector schedules or unrelated secrets."""
        if time.monotonic() - self._last_maintenance < 60:
            return
        self._last_maintenance = time.monotonic()
        from cremore.operations import heartbeat
        calls = [lambda: heartbeat.beat(self.repo, self.worker_id, self.started_at)]
        if self.execution_role == "control":
            from cremore.governance import response_threads
            from cremore.ticketing import sweep as ticket_sweep
            calls.append(lambda: ticket_sweep.sweep(self.repo, self.settings, self.http_client_factory,
                                                     orchestrator=self.orchestrator))
            calls.append(lambda: response_threads.sweep(self.repo, self.settings))
        else:
            from cremore.remediation import provider_actions
            calls.extend((lambda: self.aws_identity(refresh=True),
                          lambda: self.queue_stale_validations(),
                          lambda: provider_actions.settle(self.repo, self.settings)))
        for call in calls:
            try:
                call()
            except Exception as exc:  # noqa: BLE001 -- bounded maintenance retries on the next tick
                logger.warning("dedicated worker maintenance failed: %s", type(exc).__name__)

    def _audit_tick(self) -> None:
        from cremore.operations import audit_integrity

        try:
            audit_integrity.seal(self.repo, self.settings)
            audit_integrity.publish(self.repo, self.settings)
        except Exception as exc:  # noqa: BLE001 -- unsealed rows wait for the next tick, the anchor for the next hour
            logger.warning("audit chain sealing failed: %s", type(exc).__name__)

    @staticmethod
    def beat(path: str | None) -> None:
        """Touch the heartbeat file so a liveness probe can see the loop is alive."""

        if not path:
            return
        try:
            with open(path, "a"):
                pass
            import os

            os.utime(path, None)
        except OSError:  # a missing/readonly path must never kill the worker
            logger.warning("heartbeat file %s not writable", path)

    def deliver_alerts(self, stop=None) -> None:
        """One Slack alert pass (cremore.alerts.delivery); where this role sends, it runs about every second. ``stop``
        (true once the process is stopping) ends the pass after the message in hand."""
        from cremore.alerts.delivery import deliver_pending

        deliver_pending(self.repo, self.settings, stop=stop)

    def run_forever(self, poll_interval: float = 2.0, heartbeat_path: str | None = None) -> None:
        """The dedicated roles' single loop (cremore.cli.worker.serve). The control process sends Slack alerts on a
        thread of its own (ALERT_ROLES); there SIGTERM and SIGINT end the loop, and the pass in hand sends no new
        message and finishes the one in flight, so a message Slack accepted is acknowledged rather than sent again and
        what it had claimed goes back for the next process at once."""
        logger.info("worker ready")
        stopping, previous, alerts = [], {}, None
        if self.execution_role in ALERT_ROLES:
            from cremore.worker.supervisor import Repeater

            # The signal's flag too: the loop may be inside a long pass (a ticket sweep) before its finally stops this.
            alerts = Repeater("slack-alerts", ALERT_SECONDS,
                              lambda: self.deliver_alerts(stop=lambda: bool(stopping) or alerts.stopped.is_set()),
                              grace=ALERT_GRACE_SECONDS)
            if threading.current_thread() is threading.main_thread():
                # A flag, not an Event: a handler taking a lock the interrupted loop may hold could deadlock.
                for signum in (signal.SIGTERM, signal.SIGINT):
                    previous[signum] = signal.signal(signum, lambda *_: stopping.append(True))
            alerts.start()
        try:
            while not stopping:
                self.beat(heartbeat_path)
                if not self.process_next():
                    time.sleep(poll_interval)
        finally:
            if alerts is not None:
                alerts.stop()
            for signum, handler in previous.items():
                signal.signal(signum, signal.SIG_DFL if handler is None else handler)
