"""Connection onboarding helpers.

A connection records the *scope* of an integration, never its credential. This
module validates that a connection's ``config`` carries only non-secret scope
and that the provider's required scope fields are present, so a secret can never
be persisted on a connection row by mistake.
"""

from __future__ import annotations

from cremore.domain.models import Connection
from cremore.sources.registry import PROVIDERS

# Config keys that would mean a secret was being stored on the connection by
# mistake. The credential belongs in the secret store, referenced by secret_ref.
_SECRET_KEYS = {
    "token", "secret", "password", "passwd", "api_key", "apikey", "key",
    "access_key", "secret_key", "aws_secret_access_key", "private_key",
    "client_secret", "authorization", "bearer", "credential", "credentials",
}


class ConnectionError(ValueError):
    """A connection's provider or config is invalid."""


def validate_connection(conn: Connection) -> None:
    """Raise :class:`ConnectionError` if the connection is not safe to persist."""

    provider = (conn.provider or "").lower()
    if provider not in PROVIDERS:
        raise ConnectionError(f"unknown provider {conn.provider!r}")
    if not conn.name or not conn.name.strip():
        raise ConnectionError("connection name is required")

    def secret_fields(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.strip().lower() in _SECRET_KEYS:
                    yield key
                yield from secret_fields(child)
        elif isinstance(value, list):
            for child in value:
                yield from secret_fields(child)
    offending = sorted(set(secret_fields(conn.config)))
    if offending:
        raise ConnectionError(
            "config must not contain secrets "
            f"({', '.join(offending)}); put the credential in the secret store "
            "and reference it with secret_ref"
        )

    try:
        conn.config = PROVIDERS[provider].validate_config(conn.config)
    except ValueError as exc:
        raise ConnectionError(str(exc)) from None


def job_payload_for(conn: Connection) -> dict:
    """Build the non-secret part of a scan-job payload from a connection.

    The worker adds the resolved secret (from ``secret_ref``) at run time; this
    payload never carries it.
    """

    return _provider(conn).job_payload(conn.config)


def job_kind_for(conn: Connection) -> str:
    return _provider(conn).job_kind(conn.config)


def _provider(conn: Connection):
    provider = (conn.provider or "").lower()
    if provider not in PROVIDERS:
        raise ConnectionError(f"unknown provider {conn.provider!r}")
    return PROVIDERS[provider]


CREDENTIAL_CHECK = "credential-check"


def queue_credential_check(repo, conn: Connection, requested_by):
    """Queue the worker's read-only identity check of a content connection's credential
    (GitHub /user, Notion /users/me, STS GetCallerIdentity + HeadBucket) and log the request."""
    from cremore.domain.models import ConnectionCheckEvent, ScanJob

    payload = {"provider": conn.provider, **job_payload_for(conn), "requested_by": str(requested_by)}
    if conn.secret_ref:
        payload["secret_ref"] = conn.secret_ref
    job = repo.enqueue_job(ScanJob(kind=CREDENTIAL_CHECK, payload=payload, connection_id=conn.id))
    repo.record_check_event(ConnectionCheckEvent(
        connection_id=conn.id, job_id=job.id, source_type=_provider(conn).SOURCE_TYPE, stage="REQUESTED",
        job_status="QUEUED", requested_by=requested_by, requested_at=job.created_at))
    return job
