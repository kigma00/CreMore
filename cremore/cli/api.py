"""`cremore-api` entrypoint: serve the FastAPI app over the SQL repository."""

from __future__ import annotations

import logging


def build_app(settings, repo):
    """Wire the API's optional services for one installation, and return the app.

    Separate from :func:`main` so the wiring can be exercised without a database
    or a server: which services exist is a function of configuration, and the
    shape each one is passed in has to match what the API calls it with.
    """
    # Every AWS investigation and action opens a session in the account it
    # concerns; nothing below calls AWS with this process's identity directly.
    from cremore_aws_provider.aws_sessions import (
        AccountSessions,
        boto3_client_factory,
        identity_probe,
    )

    from cremore.api import create_app

    isolated = getattr(settings, "isolated_deployment", False)
    if isolated:
        from cremore.secretstore.isolation import validate_process_keys
        validate_process_keys(settings, "api")
        if settings.action_execution_enabled:
            from cremore.remediation.authorization import verifier
            verifier(settings)
    def worker_only(*args, **kwargs):
        raise RuntimeError("AWS_READ_REQUIRES_COLLECTOR")

    client_factory = worker_only if isolated else boto3_client_factory(settings)
    if isolated:
        from cremore.coverage.aws_requests import DeclaredSessions
        aws_sessions = DeclaredSessions(repo, settings)
    else:
        aws_sessions = AccountSessions(repo, settings, client_factory=client_factory, identity=identity_probe(client_factory))
    region = settings.aws_region

    def aws_remediation_validator(account):
        from cremore_aws_provider.investigation.role_validation import validate_account_access

        sts = client_factory("remediation", "sts", region, None)
        return validate_account_access(account, sts, purpose="remediation")

    # Optional live AWS Secrets Manager inventory (read-only). Wired whenever
    # configuration allows it; whether it runs is an Admin's dashboard switch,
    # read per request (cremore/investigation/investigation_switches.py).
    secrets_inventory_factory = secret_metadata_factory = None
    if settings.aws_secrets_inventory_allowed:

        from cremore_aws_provider.investigation import SecretsManagerService
        from cremore_aws_provider.investigation.secret_metadata import SecretMetadataService

        def secrets_inventory_factory(session):  # type: ignore[misc]
            return SecretsManagerService(session.client("secretsmanager", region), region=region).collect()

        # Metadata-only reads of exact, allowlisted secrets (DescribeSecret), in the ARN's account and region.
        def secret_metadata_factory(session, secret_region):  # type: ignore[misc]
            return SecretMetadataService(session.client("secretsmanager", secret_region))

    # Approved two-phase rotation executes only when explicitly enabled; the
    # factory binds live IAM/Secrets Manager/STS clients per request.
    rotation_service_factory = None
    if settings.rotation_execution_enabled and not isolated:
        from cremore_aws_provider.remediation.aws_clients import build_rotation_service_factory

        rotation_service_factory = build_rotation_service_factory(settings.aws_region)
        logging.getLogger("cremore.api").info("approved rotation execution ENABLED")

    # Observed-use lookup (CloudTrail event history + IAM last-used) and the
    # curated IAM potential-access evaluation: read-only, opt-in, scanner identity.
    usage_service_factory = potential_access_factory = None
    if settings.aws_usage_lookup_allowed:

        from cremore_aws_provider.investigation.usage import CredentialUsageService

        def usage_service_factory(session):  # type: ignore[misc]
            return CredentialUsageService(lambda r: session.client("cloudtrail", r), session.client("ec2", region),
                                          session.client("iam", region))
        logging.getLogger("cremore.api").info("observed-use lookup enabled")
    if settings.iam_potential_access_allowed:

        from cremore_aws_provider.investigation.potential_access import service_for

        def potential_access_factory(session):  # type: ignore[misc]
            return service_for(session, region)

    # Approved IAM key actions (disable / delete) run through a per-request
    # adapter only when execution is enabled; deletion has its own gate.
    key_action_adapter_factory = None
    if settings.action_execution_enabled and not isolated:
        from cremore_aws_provider.remediation.key_actions import build_key_action_adapter_factory

        key_action_adapter_factory = build_key_action_adapter_factory(settings.aws_region)
        logging.getLogger("cremore.api").info("approved key action execution ENABLED (deletion=%s)",
                                          settings.action_deletion_enabled)

    if isolated:
        secrets_inventory_factory = worker_only if secrets_inventory_factory else None
        secret_metadata_factory = worker_only if secret_metadata_factory else None
        usage_service_factory = worker_only if usage_service_factory else None
        potential_access_factory = worker_only if potential_access_factory else None

    def _task_states(repo):
        try:
            from cremore.db.task_store import TaskStore
            store = TaskStore(repo)
        except Exception:  # noqa: BLE001 -- run progress is optional
            return None
        return lambda run_id: store.run_states(run_id)

    app = create_app(repo=repo, settings=settings,
                     secrets_inventory_factory=secrets_inventory_factory,
                     rotation_service_factory=rotation_service_factory,
                     usage_service_factory=usage_service_factory,
                     potential_access_factory=potential_access_factory,
                     key_action_adapter_factory=key_action_adapter_factory,
                     secret_metadata_factory=secret_metadata_factory,
                     aws_sessions=aws_sessions,
                     aws_remediation_validator=None if isolated else aws_remediation_validator,
                     task_states=_task_states(repo))
    return app


def main() -> None:  # pragma: no cover -- exercised by build_app and a live server
    import uvicorn

    from cremore.config import get_settings
    from cremore.db.sql import SqlRepository, make_engine
    from cremore.db.startup import startup

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # httpx logs every request URL at INFO; outbound calls (Slack, providers) stay out of the API log.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    settings = get_settings()
    engine = make_engine(settings.sqlalchemy_url)
    # cremore/db/schema.py is the schema of record; create missing tables/columns
    # (idempotent) so a fresh database needs no separate migration step.
    startup(settings, engine, runtime_role="api")
    repo = SqlRepository(engine)
    # The IdP machine identity an Admin set in the dashboard, kept current in this process.
    import socket

    from cremore.identity import machine

    if not getattr(settings, "isolated_deployment", False):
        machine.start_keeper(repo, settings, f"api:{socket.gethostname()}")
    app = build_app(settings, repo)
    host, _, port = settings.api_bind.partition(":")

    # In-process TLS when the deployment mounts an internal PKI certificate.
    tls: dict = {}
    if settings.api_tls_cert_file and settings.api_tls_key_file:
        tls = {"ssl_certfile": settings.api_tls_cert_file, "ssl_keyfile": settings.api_tls_key_file}
        logging.getLogger("cremore.api").info("serving HTTPS with %s", settings.api_tls_cert_file)
    uvicorn.run(app, host=host or "127.0.0.1", port=int(port or "8080"), **tls)


if __name__ == "__main__":  # pragma: no cover
    main()
