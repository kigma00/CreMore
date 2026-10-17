"""Run IAM metadata inventory under existing account approvals and task leases."""

import uuid
from datetime import timedelta

from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_readonly import VAULT_OPERATIONS
from cremore_aws_provider.coverage import collect_aws_vault, collect_iam, collect_usage

from cremore.coverage.collection import CollectionLimit
from cremore.coverage.models import (
    MAX_BATCH,
    Batch,
    ConnectionSpec,
    Contract,
    Finish,
    worker_collected,
)
from cremore.coverage.store import CoverageError, CoverageStore
from cremore.db.task_store import TaskStore


def require_current_access(repo, account_id, pin, settings, *, scheduled_spec=None, feature_spec=None):
    """Called only in a lease transaction; no identity or provider I/O here."""
    if getattr(repo, "engine", None) is not None:
        from sqlalchemy import select

        from cremore.db.schema import aws_accounts, installation_settings
        with repo.engine.begin() as conn:
            conn.execute(select(aws_accounts.c.id).where(aws_accounts.c.account_id == account_id).with_for_update()).all()
            conn.execute(select(installation_settings.c.key).where(
                installation_settings.c.key == aws_access.APPROVAL_KEYS[aws_access.SCANNER]).with_for_update()).all()
            if scheduled_spec is not None:
                from cremore_aws_provider.aws_inventory_settings import KEY
                conn.execute(select(installation_settings.c.key).where(
                    installation_settings.c.key == KEY).with_for_update()).all()
    account = next((row for row in repo.list_aws_accounts() if row.account_id == account_id), None)
    if feature_spec is not None:
        from cremore.coverage.aws_scheduling import feature_refusal

        if code := feature_refusal(repo, feature_spec):
            raise aws_access.AccessBlocked(code)
    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    if (account is None or approved is None or aws_access.use_refusal(account, aws_access.SCANNER, approved)
            or aws_access.validation_key(account, aws_access.SCANNER, approved["revision"]) != pin):
        raise aws_access.AccessBlocked("AWS_ACCESS_REVISION_CHANGED")
    if scheduled_spec is not None:
        from cremore.coverage.aws_scheduling import scheduled_refusal
        if code := scheduled_refusal(repo, settings, scheduled_spec):
            raise aws_access.AccessBlocked(code)


def run(worker, job, task, context):
    cid = uuid.UUID(job.payload["coverage_connection_id"])
    store = CoverageStore(worker.repo)
    connection = store.get(cid)
    if not connection or connection["revision"] != job.payload["coverage_revision"] or not connection["enabled"]:
        raise CoverageError("CONNECTION_REVISION_CONFLICT")
    spec = ConnectionSpec.model_validate(connection["spec"])
    if not worker_collected(spec):
        raise CoverageError("INVALID_INVENTORY_PROVIDER")
    if worker.aws_sessions is None:
        raise aws_access.AccessBlocked("AWS_SESSION_UNAVAILABLE")
    from cremore.coverage.aws_scheduling import feature_refusal, scheduled_refusal
    settings = getattr(worker.aws_sessions, "settings", None) or getattr(worker, "settings", None)
    scheduled_spec = spec if job.payload.get("aws_inventory_scheduled") else None
    if code := feature_refusal(worker.repo, spec):
        raise aws_access.AccessBlocked(code)
    if job.payload.get("aws_inventory_scheduled") and (code := scheduled_refusal(worker.repo, settings, spec)):
        raise aws_access.AccessBlocked(code)
    session = worker.aws_sessions.open(spec.account_id, aws_access.SCANNER)
    if session.pin != job.payload["access_pin"]:
        raise aws_access.AccessBlocked("AWS_ACCESS_REVISION_CHANGED")
    scanner = _ScannerSession(worker.aws_sessions, spec.account_id, session)
    values = _ValueReads(worker.aws_sessions, spec, cid, session.pin) if spec.value_reader_role else None
    with context() as repo:
        require_current_access(repo, spec.account_id, session.pin, settings, scheduled_spec=scheduled_spec, feature_spec=spec)
        snapshot = CoverageStore(repo).start(cid, connection["revision"], str(job.id),
            Contract(engine_digest=worker.orchestrator.engine.detection_digest, policy_digest=worker.orchestrator.coverage_policy_digest).model_dump())

    def checkpoint():
        with context():
            pass
        code, account, approval = worker.aws_sessions.refusal(spec.account_id, aws_access.SCANNER)
        if code or aws_access.validation_key(account, aws_access.SCANNER, approval["revision"]) != session.pin:
            raise CollectionLimit("AWS_ACCESS_REVISION_CHANGED")
        current = store.get(cid)
        if not current or not current["enabled"] or current["revision"] != connection["revision"]:
            raise CollectionLimit("COLLECTION_SCOPE_CHANGED")
        if code := feature_refusal(worker.repo, spec):
            raise CollectionLimit(code)
        if job.payload.get("aws_inventory_scheduled") and (code := scheduled_refusal(worker.repo, settings, spec)):
            raise CollectionLimit(code)

    def collect():
        if spec.provider == "aws_iam":
            from cremore_aws_provider.investigation import investigation_switches

            return collect_iam(spec, scanner.client("iam"), checkpoint=checkpoint,
                policy_enabled=lambda: investigation_switches.policy_metadata_enabled(settings, worker.repo, spec))
        if spec.provider == "aws_cloudtrail":
            return collect_usage(spec, lambda region: scanner.client("cloudtrail", region), checkpoint=checkpoint,
                                 s3_client=scanner.client("s3", spec.regions[0]) if spec.cloudtrail_source == "s3" else None)
        # Values are read and fingerprinted in memory, exactly as the customer-side CLI does.
        reads = values or (lambda service, region: scanner.client(service, region, operations=VAULT_OPERATIONS))
        return collect_aws_vault(spec, reads, worker.orchestrator.engine, checkpoint=checkpoint)

    _publish(context, cid, snapshot, task, collect, checkpoint, lambda repo: require_current_access(
        repo, spec.account_id, session.pin, settings, scheduled_spec=scheduled_spec, feature_spec=spec))


class _ValueReads:
    """One run's value reads through the account's value-reader role.

    The role is assumed at the first read, every scanner check included, and again once its
    credentials are within five minutes of expiring: role chaining caps that session at an
    hour (it lasts 15 minutes) and no value is read with expired credentials. A refusal ends
    the run with its code as a reason, never as absence. The run's checkpoint still rechecks
    the approvals before every request.
    """

    MARGIN = timedelta(minutes=5)

    def __init__(self, sessions, spec, cid, pin):
        self.sessions, self.spec, self.label, self.pin = sessions, spec, str(cid), pin
        self.session = None

    def current(self):
        from cremore_aws_provider.aws_identity import AwsLoginRequired

        if self.session is None or self.session.credentials["Expiration"] - self.MARGIN <= self.sessions.now():
            try:
                session = self.sessions.value_reader(self.spec.account_id, self.spec.value_reader_role, self.label)
            except aws_access.AccessBlocked as exc:
                raise CollectionLimit(exc.code) from None
            except AwsLoginRequired:
                raise CollectionLimit("AWS_LOGIN_REQUIRED") from None
            if session.pin != self.pin:
                raise CollectionLimit("AWS_ACCESS_REVISION_CHANGED")
            self.session = session
        return self.session

    def __call__(self, service, region):
        return _ValueClient(self, service, region, operations=VAULT_OPERATIONS)


class _ScannerSession:
    """The run's scanner session, opened again once its credentials are within five minutes of
    expiring, with every check ``open`` makes: a member-role session lasts 15 minutes and a long
    IAM or CloudTrail run would otherwise read with expired credentials. Runtime credentials
    (no expiry here) are refreshed by the SDK itself."""

    def __init__(self, sessions, account_id, session):
        self.sessions, self.account_id, self.session, self.pin = sessions, account_id, session, session.pin

    def current(self):
        from cremore_aws_provider.aws_identity import AwsLoginRequired

        expiry = (getattr(self.session, "credentials", None) or {}).get("Expiration")
        if expiry is not None and expiry - _ValueReads.MARGIN <= self.sessions.now():
            try:
                session = self.sessions.open(self.account_id, aws_access.SCANNER)
            except aws_access.AccessBlocked as exc:
                raise CollectionLimit(exc.code) from None
            except AwsLoginRequired:
                raise CollectionLimit("AWS_LOGIN_REQUIRED") from None
            if session.pin != self.pin:
                raise CollectionLimit("AWS_ACCESS_REVISION_CHANGED")
            self.session = session
        return self.session

    def client(self, *args, **kwargs):
        return _ValueClient(self, *args, **kwargs)


class _ValueClient:
    """Resolves the current session at each call; a new session gets a new client."""

    def __init__(self, reads, *args, **kwargs):
        self.reads, self.args, self.kwargs = reads, args, kwargs
        self.client = self.session = None

    def __getattr__(self, operation):
        def call(**kwargs):
            session = self.reads.current()
            if session is not self.session:
                self.client = session.client(*self.args, **self.kwargs)
                self.session = session
            return getattr(self.client, operation)(**kwargs)
        return call


def _publish(context, cid, snapshot, task, collect, checkpoint, recheck):
    try:
        result = collect()
        checkpoint()
        with context() as repo:
            recheck(repo)
            bound = CoverageStore(repo)
            batches = [result.items[i:i + MAX_BATCH] for i in range(0, len(result.items), MAX_BATCH)]
            for index, items in enumerate(batches):
                bound.append(cid, snapshot["id"], Batch(index=index, items=items))
            run = bound.finish(cid, snapshot["id"], Finish(batch_count=len(batches), item_count=len(result.items),
                                                          status=result.status, reasons=sorted(result.reasons)))
            # The stored run status: finish may have downgraded the collector's COMPLETE to PARTIAL.
            if run["status"] == "FAILED":
                TaskStore(repo).fail(task["id"], task["token"], "AWS_INVENTORY_FAILED")
            else:
                TaskStore(repo).finish(task["id"], task["token"], {"metadata_items": len(result.items),
                    "coverage_status": run["status"], "coverage_run_id": str(snapshot["id"])})
    except Exception as exc:
        # A revoked scope must not leave a six-hour RUNNING lock behind. This
        # records failure only and publishes none of the collected observations.
        from cremore.collectors.base import CollectorError
        from cremore.db.task_store import LeaseLost
        # A CollectorError code is fixed and secret-free (a refused login, for one): keep it on the run.
        reason = exc.code if isinstance(exc, CollectorError) else "INVENTORY_INTERRUPTED"
        try:
            with context() as repo:
                CoverageStore(repo).abort(cid, snapshot["id"], reason)
        except LeaseLost:
            pass  # A replacement lease owns this run now.
        raise
