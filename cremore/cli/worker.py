"""`cremore-worker` entrypoint: process queued scan jobs from the SQL repository."""

from __future__ import annotations

import logging


def build_worker(settings, repo):
    """Wire the worker's optional services for one installation.

    Separate from :func:`main` so the wiring can be exercised without a database:
    a service handed over in the wrong shape fails inside a poll loop that
    swallows every trigger exception, which is silence rather than a crash.
    """
    from cremore.worker.isolation import execution_role
    role = execution_role(settings)
    if getattr(settings, "isolated_deployment", False):
        from cremore.secretstore.isolation import validate_process_keys
        validate_process_keys(settings, role)
        if role == "remediator" and settings.action_execution_enabled:
            from cremore.remediation.authorization import verifier
            verifier(settings)
    if role in ("remediator", "control"):
        return build_dedicated_worker(settings, repo, role)
    from cremore_aws_provider.aws_readonly import readonly_client

    from cremore.scanning.orchestrator import Orchestrator
    from cremore.worker import JobWorker
    from cremore.worker.factory import build_collector

    def scanner_client(service, **kwargs):
        import boto3
        return readonly_client(boto3.client(service, **kwargs), service)
    # Opt-in: score a discovered AWS principal's privilege from its curated IAM
    # potential-access. Read-only, but calls IAM with the scanner's credentials.
    from cremore_aws_provider.aws_sessions import AccountSessions, boto3_client_factory

    worker_ref: dict = {}

    def worker_identity(purpose, fresh):
        # The worker only scans: its scanner identity is the one it reports and holds on.
        worker = worker_ref.get("worker")
        if purpose != "scanner" or worker is None:
            return {"state": "ERROR", "error_code": "PURPOSE_NOT_AVAILABLE_IN_WORKER"}
        return worker.aws_identity(refresh=fresh) or {"state": "ERROR"}

    aws_sessions = AccountSessions(repo, settings, client_factory=boto3_client_factory(settings), identity=worker_identity)
    from cremore_aws_provider.worker_session import ContentSessions

    from cremore.coverage.job import require_current_access

    aws_content_sessions = ContentSessions(aws_sessions, require_current_access)
    provider = None
    if settings.iam_potential_access_allowed:
        from cremore_aws_provider.investigation import investigation_switches
        from cremore_aws_provider.investigation.potential_access import provider_from_sessions

        # Each principal is evaluated in its own account, never with the worker's
        # identity, and only while an Admin has the investigation switched on.
        provider = investigation_switches.switched_potential_access(
            provider_from_sessions(aws_sessions, settings.aws_region), settings, repo)
        logging.getLogger("cremore.worker").info("IAM potential-access scoring available (switched in the dashboard)")

    # Supply the SDK/HTTP clients the collectors need, created lazily per job so
    # the worker starts without boto3/httpx when only inline jobs are queued.
    def s3_client_factory(job):
        p = job.payload or {}
        region = p.get("region") or settings.aws_region
        return aws_content_sessions.client(job, "s3", region)

    def s3_partition_factory(job):
        from cremore_aws_provider import aws_access

        aws_content_sessions.require_current(job)
        code, _account, approved = aws_sessions.refusal((job.payload or {}).get("account_id"), aws_access.SCANNER)
        partition = approved.get("partition") if isinstance(approved, dict) else None
        if code or partition not in ("aws", "aws-cn", "aws-us-gov", "aws-eusc"):
            raise aws_access.AccessBlocked(code or "AWS_PARTITION_UNAVAILABLE")
        return partition

    def http_client_factory():
        import httpx

        return httpx.Client(timeout=30.0)

    # Resolves a connection's secret_ref at scan time: tokens sealed by CreMore
    # always, vault:// references when a secret store is configured. The
    # plaintext is never persisted on the job or connection.
    from cremore.secretstore.resolver import SecretResolver

    kv = None
    if settings.secret_store_enabled:
        from cremore.secretstore.vault import kv_from_settings

        kv = kv_from_settings(settings)
        logging.getLogger("cremore.worker").info("secret store wired for secret_ref resolution")
    secret_resolver = SecretResolver(kv, sealing_key=settings.credential_sealing_keys
                                     if getattr(settings, "isolated_deployment", False) else settings.sealing_keys)

    def resolver_for(job):
        if not getattr(settings, "isolated_deployment", False):
            return secret_resolver
        from cremore.onboarding.credential_access import resolver_for_child
        return resolver_for_child(repo, "content", job.connection_id, secret_resolver,
                                  payload=job.payload, settings=settings, job_kind=job.kind)

    def collector_factory(job):
        return build_collector(
            job,
            s3_client_factory=s3_client_factory,
            s3_partition_factory=s3_partition_factory,
            http_client_factory=http_client_factory,
            secret_resolver=resolver_for(job),
            max_object_bytes=settings.max_object_size_mb * 1024 * 1024,
        )

    # Read-only identity check of a connection's own credential (job kind
    # credential-check); the token is resolved here and never persisted.
    def credential_checker(job):
        from cremore.collectors.credential_check import run_credential_check

        return run_credential_check(
            job.payload or {},
            http_client_factory=http_client_factory,
            # The check hands the payload to the factory; the scan factory takes the job.
            s3_client_factory=lambda _payload: s3_client_factory(job),
            sts_client_factory=lambda: aws_content_sessions.client(job, "sts", settings.aws_region),
            secret_resolver=resolver_for(job),
        )

    # GitHub's own secret-scanning alerts for a connection we own (job kind
    # github-secret-scanning). Alert metadata only: the provider returns the raw
    # secret and the reader drops it before anything is stored. The platform
    # resolves the connection's secret reference here, as catalog_lister does;
    # the GitHub library only reads with the resolved credential (review 2026-09-26).
    def secret_scanning_reader(job):
        from cremore_github_provider.collectors.github_secret_scanning import run as read_alerts
        from cremore_github_provider.collectors.github_secret_scanning import unavailable

        from cremore.secretstore.resolver import SecretRefError, inject_secret

        try:
            payload = inject_secret("github", job.payload or {}, resolver_for(job),
                                    github_client_factory=http_client_factory)
        except SecretRefError:
            return unavailable(job.payload or {})
        return read_alerts(payload, http_client_factory=http_client_factory)

    # What changed in an approved repository or space since the last look (change
    # feeds, cremore.scanning.changes): the credential is resolved here, as for a scan.
    def change_reader(payload, roots, states, request_budget):
        from cremore.collectors.base import guard_requests
        from cremore.db.scan_store import ScanStore
        from cremore.scanning.changes import read_changes
        from cremore.secretstore.resolver import inject_secret

        resolved_for_change = secret_resolver
        if getattr(settings, "isolated_deployment", False):
            from cremore.onboarding.credential_access import resolver_for_child
            resolved_for_change = resolver_for_child(repo, "content", payload.get("connection_id"),
                                                     secret_resolver, payload=payload, settings=settings, job_kind="scope")
        resolved = inject_secret("scope", payload, resolved_for_change, github_client_factory=http_client_factory)
        # Paced through the database with the connection's scans (Notion's 2.5 requests a second, its Retry-After).
        with guard_requests(None, pacing=ScanStore(repo)):
            return read_changes(resolved, roots, states, http_client=http_client_factory, request_budget=request_budget)

    # A Notion run's plan reads its approved pages' headers in one search walk (cremore.worker.runtime): the
    # credential is resolved here, as for a scan, and the runtime paces the walk through the database.
    def plan_reader(job, read, roots, request_budget):
        from cremore.secretstore.resolver import inject_secret

        payload = inject_secret(job.kind, job.payload or {}, resolver_for(job), github_client_factory=http_client_factory)
        with http_client_factory() as client:
            return read(payload, roots, http_client=client, request_budget=request_budget)

    # Metadata-only resource listing for the dashboard's scan-scope catalog
    # (job kind catalog-refresh): buckets, repositories, pages — never content.
    def catalog_lister(job):
        from cremore.scanning.catalog import list_resources
        from cremore.secretstore.resolver import inject_secret

        payload = inject_secret(
            "catalog-refresh",
            job.payload or {},
            resolver_for(job),
            github_client_factory=http_client_factory,
        )
        if payload.get("provider") == "aws":
            from datetime import UTC, datetime

            from cremore_aws_provider.source import list_resources as aws_resources

            from cremore.collectors.base import RequestBudget

            return aws_resources(
                payload, payload["connection_kind"], payload["connection_id"],
                s3_client=lambda: s3_client_factory(job), s3_partition=s3_partition_factory(job),
                now=datetime.now(UTC), request_budget=RequestBudget(),
            )
        return list_resources(
            payload, s3_client=lambda: s3_client_factory(job), http_client=http_client_factory
        )

    from cremore.detection.engine import EngineConfig
    from cremore.detection.verify import VerifierConfig
    from cremore.scanning.learned_fp import LearnedFPService

    # The engine only verifies when its own VerifierConfig is enabled; the
    # per-scan `verify` flag alone is not enough. Keyed fingerprints likewise.
    orchestrator = Orchestrator(
        repo,
        config=EngineConfig(
            fingerprint_key=settings.fingerprint_key_bytes,
            verify=VerifierConfig(enabled=settings.verification_enabled,
                                  known_github_hosts=settings.known_github_hosts),
        ),
        potential_access_provider=provider,
        rule_provider=repo.list_rules,  # operator rules compiled in per job
        learned_fp=LearnedFPService(repo, settings),  # reads the Admin's live auto-triage policy
    )
    # Deliberately separate from source-scanning clients: only this consumer
    # touches the operator-confirmed CreMore-owned queue. Built on the first poll
    # that has a binding, so a worker with no queue never resolves a region for
    # one, and an Admin who binds a queue does not have to restart anything.
    _sqs = {}

    def sqs_client():
        import boto3

        if "client" not in _sqs:
            _sqs["client"] = boto3.client("sqs", region_name=settings.aws_region)
        return _sqs["client"]

    def lifecycle_sqs_client(region):
        import boto3
        if region not in _sqs:
            _sqs[region] = boto3.client("sqs", region_name=region)
        return _sqs[region]

    def control_tower_client(account_id, region):
        from cremore_aws_provider import aws_access
        # Organizations membership grants no access to management-account APIs.
        return aws_sessions.open(account_id, aws_access.SCANNER).client("controltower", region)
    from cremore_aws_provider import aws_identity
    from cremore_aws_provider.investigation.role_validation import validate_account_access

    def aws_identity_probe():
        # The identity this process's SDK credential chain really resolves to.
        import boto3

        session = boto3.Session()
        region = settings.aws_region
        local = aws_identity.local_sso_session()
        identity = aws_identity.describe(readonly_client(session.client("sts", region_name=region), "sts"),
                                         readonly_client(session.client("iam", region_name=region), "iam"),
                                         sso_region=local["region"], sso_start_url=local["start_url"])
        identity["credential_source"] = aws_identity.server_workload_source(session)
        return identity

    def sso_probe(account):
        """Prove an SSO_PERMISSION_SET account from the process that scans it.

        Built per check so a token refreshed by a new `aws sso login` on the host
        is picked up without restarting the worker.
        """
        import boto3
        from cremore_aws_provider import aws_access, aws_sso
        from cremore_aws_provider.investigation.role_validation import (
            RoleValidation,
            validate_sso_access,
        )

        approved = aws_access.approval(repo, aws_access.SCANNER, settings)
        try:
            region = aws_sso.region_for(approved)
            token = aws_sso.access_token()
        except aws_sso.SsoRegionUnknown:
            return RoleValidation("INVALID", "no Identity Center Region is configured",
                                  code="IDENTITY_CENTER_REGION_REQUIRED")
        except aws_sso.SsoCacheNotWritable:
            # Not a fact about the account: the cache cannot be rewritten.
            return RoleValidation("INVALID", "the Identity Center token cache is not writable",
                                  code="SSO_CACHE_NOT_WRITABLE")
        except aws_identity.AwsLoginRequired:
            return RoleValidation("INVALID", "the Identity Center sign-in expired", code="AWS_LOGIN_REQUIRED")

        def sts_for(credentials):
            # The vended session's own client; the scanner's would report the hub.
            return boto3.client("sts", region_name=settings.aws_region,
                                aws_access_key_id=credentials["AccessKeyId"],
                                aws_secret_access_key=credentials["SecretAccessKey"],
                                aws_session_token=credentials["SessionToken"])

        return validate_sso_access(account, scanner_client("sso", region_name=region), token, sts_for)

    def aws_role_checker(account):
        return validate_account_access(account, scanner_client("sts", region_name=settings.aws_region),
                                       sso_probe=sso_probe)

    # Opt-in: read the organization's account list from a delegated-admin account
    # so new accounts are registered for scanning without being added by hand.
    # Whether the sweep runs is an Admin's dashboard switch read every poll, so
    # the factory is wired unless configuration hard-locks the route off.
    org_client_factory = None
    if settings.org_discovery_allowed:
        def org_client_factory():
            return scanner_client("organizations", region_name=settings.aws_region)

    # Register the accounts this computer's Identity Center sign-in is assigned
    # to. Whether the sweep runs is an Admin's dashboard switch read every poll,
    # so this factory is always wired unless configuration hard-locks it off.
    # The client lives in the Identity Center Region, not AWS_REGION.
    sso_session_factory = None
    if settings.sso_discovery_allowed:
        def sso_session_factory():
            from cremore_aws_provider import aws_access, aws_sso

            approved = aws_access.approval(repo, aws_access.SCANNER, settings)
            region = aws_sso.region_for(approved)
            return scanner_client("sso", region_name=region), aws_sso.access_token()

    queue_openers = {}

    worker_ref["worker"] = worker = JobWorker(
        repo,
        orchestrator=orchestrator,
        collector_factory=collector_factory,
        verify=settings.verification_enabled,
        credential_checker=credential_checker,
        secret_scanning_reader=secret_scanning_reader,
        catalog_lister=catalog_lister,
        settings=settings,
        sqs_client_factory=sqs_client if settings.scan_sqs_allowed else None,
        aws_identity_probe=aws_identity_probe,
        aws_role_checker=aws_role_checker,
        org_client_factory=org_client_factory,
        control_tower_client_factory=control_tower_client if settings.org_discovery_allowed else None,
        lifecycle_sqs_client_factory=lifecycle_sqs_client if settings.scan_sqs_allowed else None,
        sso_session_factory=sso_session_factory,
        aws_sessions=aws_sessions,
        aws_content_sessions=aws_content_sessions,
        metadata_secret_resolver=secret_resolver,
        change_reader=change_reader if settings.scan_change_feeds_allowed else None,
        queue_openers=queue_openers,
        http_client_factory=http_client_factory,
        plan_reader=plan_reader,
    )
    return worker


def build_dedicated_worker(settings, repo, role):
    """No collector factories, queue consumers or scanner identities in these processes."""
    from cremore.worker import JobWorker
    if role == "control":
        return JobWorker(repo, settings=settings)
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.aws_sessions import (
        AccountSessions,
        boto3_client_factory,
        identity_probe,
    )
    from cremore_aws_provider.investigation.role_validation import validate_account_access
    from cremore_aws_provider.remediation.aws_clients import build_rotation_service_factory
    from cremore_aws_provider.remediation.key_actions import build_key_action_adapter_factory

    from cremore.secretstore.resolver import SecretResolver

    clients = boto3_client_factory(settings)
    identity = identity_probe(clients)
    sessions = AccountSessions(repo, settings, client_factory=clients, identity=identity)
    key_factory = build_key_action_adapter_factory(settings.aws_region)
    rotation_factory = build_rotation_service_factory(settings.aws_region)

    def action_clients(plan):
        from cremore.remediation.action_plans import ROTATION_ACTIONS
        session = sessions.open(plan.account_id, aws_access.REMEDIATION)
        if plan.action_type in ROTATION_ACTIONS:
            region = (plan.rotation or {}).get("secret_arn", "").split(":")[3]
            return None, rotation_factory(session, region)
        return key_factory(session), None

    def role_check(account):
        return validate_account_access(account, clients("remediation", "sts", settings.aws_region, None),
                                       purpose="remediation")

    kv = None
    if settings.secret_store_enabled:
        from cremore.secretstore.vault import kv_from_settings
        kv = kv_from_settings(settings)
    resolver = SecretResolver(kv, sealing_key=settings.credential_sealing_keys
                              if getattr(settings, "isolated_deployment", False) else settings.sealing_keys)
    return JobWorker(repo, settings=settings, aws_sessions=sessions, metadata_secret_resolver=resolver,
                     aws_identity_probe=lambda: identity("remediation", True), aws_role_checker=role_check,
                     action_clients=action_clients)


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # httpx logs every request URL at INFO: a provider's path or a site's query (a token) stays out of the worker log.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _runner_identity(slot: int, environ: dict) -> None:
    """Point a task runner's machine-identity keeper at its own start and its own token files.

    ``environ`` is the container's identity environment from before the control loop's keeper changed it, so a
    cloud an Admin turns off is given back to the same original in every process. The token directory is the
    runner's own: a keeper starting during an IdP failure blanks its files, and those of the control loop and
    the other runners must stay readable.
    """
    import os

    from cremore.identity import machine

    for key, value in environ.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    os.environ["CREMORE_MACHINE_IDENTITY_DIR"] = str(machine.default_directory() / f"runner-{slot}")


def task_runner(stop, liveness, slot, owner, environ) -> None:  # pragma: no cover -- a spawned process
    """One task-runner process of a scanning worker: its own settings, engine, repository and worker.

    ``owner`` names the supervisor's process, so the runner's machine-identity status keeps one row per slot.
    """
    import signal

    # Ctrl+C reaches the whole process group; the supervisor stops its runners in order.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    _configure_logging()
    log = logging.getLogger("cremore.worker")
    try:
        from cremore.config import get_settings
        from cremore.db.sql import SqlRepository, make_engine
        from cremore.identity import machine
        from cremore.worker.supervisor import run_task_loop

        _runner_identity(slot, environ)
        settings = get_settings("worker")
        repo = SqlRepository(make_engine(settings.sqlalchemy_url))
        worker = build_worker(settings, repo)
        # The IdP machine identity an Admin set in the dashboard, kept current where the tasks run.
        machine.start_keeper(repo, settings, f"{owner}:runner-{slot}")
        log.info("task runner %d ready", slot)
        run_task_loop(worker, stop, liveness)
    except Exception as exc:  # noqa: BLE001 -- its text can carry SQL parameters; the supervisor restarts the runner
        # Not the traceback multiprocessing would print for an escaping exception, again on every restart.
        log.error("task runner %d stopped: %s", slot, type(exc).__name__)
        raise SystemExit(1) from None


def serve(settings, repo, worker) -> None:
    """Scanning roles run a supervisor with task-runner processes; dedicated roles keep their single loop."""
    import os

    from cremore.identity import machine

    if worker.execution_role not in ("mixed", "collector"):
        worker.run_forever(heartbeat_path=settings.worker_heartbeat_file)
        return
    environ = {key: os.environ.get(key) for key in machine.ENV_KEYS}  # before the keeper below changes them
    owner = f"worker:{worker.worker_id}"
    # The control loop's own SDK calls (queue polling, the AWS identity it reports) see the identity the runners use.
    machine.start_keeper(repo, settings, owner)
    from cremore.worker.supervisor import Supervisor
    from cremore.worker.worker import ALERT_GRACE_SECONDS, ALERT_ROLES, ALERT_SECONDS

    supervisor = Supervisor(worker, settings.effective_worker_concurrency, target=task_runner,
                            target_args=(owner, environ), heartbeat_path=settings.worker_heartbeat_file)
    if worker.execution_role in ALERT_ROLES:
        # Slack alerts about every second on a thread of their own: once per container, never in a task runner. A
        # shutdown tells the pass in hand to send nothing new and waits for the message in flight.
        alerts = supervisor.alongside(
            "slack-alerts", ALERT_SECONDS,
            lambda: worker.deliver_alerts(stop=lambda: supervisor.stopping() or alerts.stopped.is_set()),
            grace=ALERT_GRACE_SECONDS)
    supervisor.run()


def main() -> None:  # pragma: no cover -- exercised by build_worker, serve and a live run
    _configure_logging()
    from cremore.config import get_settings
    from cremore.db.sql import SqlRepository, make_engine
    from cremore.db.startup import startup

    settings = get_settings("worker")
    engine = make_engine(settings.sqlalchemy_url)
    # Idempotent: the worker may start before the API, so it must not depend
    # on the API having created the schema first. Once per worker: the task
    # runners start after it and never migrate.
    from cremore.worker.isolation import execution_role
    startup(settings, engine, runtime_role=execution_role(settings))
    repo = SqlRepository(engine)
    serve(settings, repo, build_worker(settings, repo))


if __name__ == "__main__":  # pragma: no cover
    main()
