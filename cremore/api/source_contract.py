"""API compatibility facade over provider-owned source definitions."""

from __future__ import annotations

from cremore_aws_provider.source import BUCKET_RE  # noqa: F401 -- dashboard compatibility export
from cremore_github_provider.source import (
    GITHUB_NAME_RE,  # noqa: F401 -- dashboard compatibility export
)

from cremore.api.http_support import http_error
from cremore.domain.connections import (
    CREDENTIAL_CHECK,  # noqa: F401 -- one name for the job kind
)
from cremore.sources.registry import (
    BY_JOB_KIND,
    BY_SOURCE,
    PROVIDERS,
    SOURCE_CAPABILITIES,  # noqa: F401 -- API compatibility export
    SOURCE_TYPES,  # noqa: F401 -- API compatibility export
)

SECRET_SCANNING = "github-secret-scanning"
SECRET_ARN_PREFIX = ("arn:aws:secretsmanager:", "arn:aws-us-gov:secretsmanager:", "arn:aws-cn:secretsmanager:",
                     "arn:aws-eusc:secretsmanager:")
SOURCE_TO_PROVIDER = {source: module.PROVIDER for source, module in BY_SOURCE.items()}
REVOCATION_GUIDANCE = {key: module.REVOCATION_GUIDANCE for key, module in PROVIDERS.items()
                       if module.REVOCATION_GUIDANCE is not None}


def config_from_scope(provider: str, scope: str, host: str = "") -> dict:
    module = PROVIDERS.get(provider)
    if module is None:
        return {}
    try:
        return module.config_from_scope(scope, host)
    except ValueError as exc:
        raise http_error(422, str(exc)) from None


def scope_ref(conn) -> str:
    module = PROVIDERS.get(conn.provider)
    return module.scope_ref(conn.config or {}) if module else "workspace"


def provider_to_source(provider: str) -> str:
    module = PROVIDERS.get(provider or "")
    return module.SOURCE_TYPE if module else provider or ""


def job_source_type(kind: str) -> str:
    module = BY_JOB_KIND.get(kind)
    return module.SOURCE_TYPE if module else kind
