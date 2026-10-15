"""AWS Secrets Manager inventory (read-only).

Enumerates the secrets in a connected AWS account and summarises their
governance-relevant metadata — rotation state, age, last-accessed date — without
ever reading a secret's value. ``GetSecretValue`` is deliberately never called;
this is an inventory of what exists and how it is managed, not a dump of
contents, so it produces no synthetic findings and carries no secret material.

The ``ListSecrets`` response already includes the describe-level fields, so one
paginated call is enough. The boto3 client is injected for testability.

https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return str(value)


@dataclass
class SecretRecord:
    """Non-secret metadata for one managed secret."""

    arn: str
    name: str
    rotation_enabled: bool = False
    rotation_lambda_arn: str = ""
    last_rotated_at: str | None = None
    last_changed_at: str | None = None
    last_accessed_at: str | None = None
    created_at: str | None = None
    next_rotation_at: str | None = None
    managed_by: str = ""  # AWS service owner, if any (e.g. an RDS-managed secret)
    tag_keys: tuple[str, ...] = ()  # tag keys only; values can be sensitive

    @property
    def stale(self) -> bool:
        """True when rotation is off and there is no recent change signal."""

        return not self.rotation_enabled


@dataclass
class SecretsManagerInventory:
    region: str = ""
    collection_status: str = "COMPLETE"  # COMPLETE | FAILED
    error_code: str = ""
    secrets: list[SecretRecord] = field(default_factory=list)

    @property
    def without_rotation(self) -> list[SecretRecord]:
        return [s for s in self.secrets if not s.rotation_enabled]


class SecretsManagerService:
    def __init__(self, client, *, region: str = "") -> None:
        self.client = client
        self.region = region

    def collect(self, *, max_secrets: int = 5000) -> SecretsManagerInventory:
        if max_secrets < 1:
            raise ValueError("max_secrets must be positive")
        inv = SecretsManagerInventory(region=self.region)
        token = None
        seen = set()
        try:
            while True:
                kwargs: dict = {"MaxResults": 100}
                if token:
                    kwargs["NextToken"] = token
                page = self.client.list_secrets(**kwargs)
                for item in page.get("SecretList", []):
                    if len(inv.secrets) >= max_secrets:
                        inv.collection_status, inv.error_code = "PARTIAL", "SECRET_LIMIT"
                        return inv
                    inv.secrets.append(_record(item))
                token = page.get("NextToken")
                if not token:
                    break
                if len(inv.secrets) >= max_secrets or token in seen:
                    inv.collection_status = "PARTIAL"
                    inv.error_code = "SECRET_LIMIT" if len(inv.secrets) >= max_secrets else "PAGINATION_LOOP"
                    return inv
                seen.add(token)
        except Exception as exc:  # noqa: BLE001 -- SDK failures become a failed inventory with a safe code, not an empty success.
            return SecretsManagerInventory(region=self.region, collection_status="FAILED",
                                           error_code=_safe_code(exc))
        inv.secrets.sort(key=lambda s: s.name)
        return inv


def _record(item: dict) -> SecretRecord:
    tags = item.get("Tags", []) or []
    return SecretRecord(
        arn=item.get("ARN", ""),
        name=item.get("Name", ""),
        rotation_enabled=bool(item.get("RotationEnabled", False)),
        rotation_lambda_arn=item.get("RotationLambdaARN", "") or "",
        last_rotated_at=_iso(item.get("LastRotatedDate")),
        last_changed_at=_iso(item.get("LastChangedDate")),
        last_accessed_at=_iso(item.get("LastAccessedDate")),
        created_at=_iso(item.get("CreatedDate")),
        next_rotation_at=_iso(item.get("NextRotationDate")),
        managed_by=item.get("OwningService", "") or "",
        tag_keys=tuple(t.get("Key", "") for t in tags if t.get("Key")),
    )


def _safe_code(exc: Exception) -> str:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
    return code or "SECRETS_MANAGER_LIST_FAILED"
