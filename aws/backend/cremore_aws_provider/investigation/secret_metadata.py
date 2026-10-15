"""Secrets Manager storage metadata for one exact ARN (never the value).

``DescribeSecret`` and ``ListSecretVersionIds`` are the only calls. Tags and
description are omitted by policy (they may carry sensitive text) and their
absence is reported as ``OMITTED_BY_SECURITY_POLICY`` so the dashboard never
reads it as "the provider has none".

https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html
https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecretVersionIds.html
"""

from __future__ import annotations

import datetime as _dt

from cremore_aws_provider.aws_identity import collection_error_code as _safe_code


class SecretMetadataError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.UTC)
        return value.isoformat()
    return str(value)


def reference_name(arn: str) -> str:
    """The secret name an ARN encodes: everything after ':secret:' minus the random suffix."""

    name = arn.split(":secret:", 1)[1] if ":secret:" in arn else ""
    parts = name.rsplit("-", 1)
    return parts[0] if len(parts) == 2 and len(parts[1]) == 6 and parts[1].isalnum() else name


class SecretMetadataService:
    def __init__(self, client) -> None:
        self.client = client

    def describe(self, arn: str) -> dict:
        """The dashboard's secret-metadata shape for ``arn``; raises SecretMetadataError."""
        try:
            return self._describe(arn)
        except SecretMetadataError:
            raise
        except Exception as exc:  # noqa: BLE001 -- normalize provider failures without retaining response text
            raise SecretMetadataError(_safe_code(exc)) from None

    def _describe(self, arn: str) -> dict:
        info = self.client.describe_secret(SecretId=arn)
        if not isinstance(info, dict) or info.get("ARN", arn) != arn:
            raise SecretMetadataError("SECRET_METADATA_TARGET_MISMATCH")
        versions = []
        token, seen = None, set()
        for _ in range(10):
            kwargs = {"SecretId": arn, "IncludeDeprecated": True, "MaxResults": 100}
            if token:
                kwargs["NextToken"] = token
            page = self.client.list_secret_version_ids(**kwargs)
            rows = page.get("Versions")
            if not isinstance(rows, list) or len(versions) + len(rows) > 1000:
                raise SecretMetadataError("SECRET_VERSION_LIST_INCOMPLETE")
            for v in rows:
                if not isinstance(v, dict) or not isinstance(v.get("VersionId"), str) \
                        or not isinstance(v.get("VersionStages", []), list):
                    raise SecretMetadataError("SECRET_METADATA_MALFORMED")
                versions.append({
                    "version_id": v["VersionId"],
                    "stages": [s for s in v.get("VersionStages", []) if s in ("AWSCURRENT", "AWSPENDING", "AWSPREVIOUS")],
                    "created_date": _iso(v.get("CreatedDate")),
                    "last_accessed_date": _iso(v.get("LastAccessedDate")),
                })
            token = page.get("NextToken")
            if token is None or token == "":
                break
            if not isinstance(token, str) or len(token) > 4096 or token in seen:
                raise SecretMetadataError("SECRET_VERSION_LIST_INCOMPLETE")
            seen.add(token)
        else:
            raise SecretMetadataError("SECRET_VERSION_LIST_INCOMPLETE")
        stages = info.get("VersionIdsToStages") or {}
        if not isinstance(stages, dict) or any(not isinstance(value, list) for value in stages.values()) \
                or type(info.get("RotationEnabled", False)) is not bool:
            raise SecretMetadataError("SECRET_METADATA_MALFORMED")
        current = next((vid for vid, st in stages.items() if "AWSCURRENT" in (st or [])), "")
        parts = arn.split(":")
        rules = info.get("RotationRules") or {}
        replication = [{
            "region": r.get("Region", ""), "status": r.get("Status", "UNKNOWN"),
            "kms_key_id": r.get("KmsKeyId"), "last_accessed_date": _iso(r.get("LastAccessedDate")),
        } for r in (info.get("ReplicationStatus") or [])]
        return {
            "arn": info.get("ARN", arn),
            "region": parts[3] if len(parts) > 3 else "",
            "account_id": parts[4] if len(parts) > 4 else "",
            "reference_name": reference_name(arn),
            "current_version_id": current,
            "rotation_enabled": bool(info.get("RotationEnabled", False)),
            "rotation_configured": bool(info.get("RotationLambdaARN")),
            "rotation_lambda_arn": info.get("RotationLambdaARN"),
            "rotation_rules": {
                "automatically_after_days": rules.get("AutomaticallyAfterDays"),
                "duration": rules.get("Duration"),
                "schedule_expression": rules.get("ScheduleExpression"),
            } if rules else None,
            "kms_key_id": info.get("KmsKeyId"),
            "primary_region": info.get("PrimaryRegion"),
            "managed_external": None,
            "owning_service": "AWS_SERVICE_MANAGED" if info.get("OwningService") else None,
            "replication": replication,
            "created_date": _iso(info.get("CreatedDate")),
            "last_changed_date": _iso(info.get("LastChangedDate")),
            "last_rotated_date": _iso(info.get("LastRotatedDate")),
            "last_accessed_date": _iso(info.get("LastAccessedDate")),
            "next_rotation_date": _iso(info.get("NextRotationDate")),
            "deleted_date": _iso(info.get("DeletedDate")),
            "field_status": {
                "name": "AVAILABLE",
                "tags": "OMITTED_BY_SECURITY_POLICY",
                "description": "OMITTED_BY_SECURITY_POLICY",
                "rotation_lambda_arn": "AVAILABLE" if info.get("RotationLambdaARN") else "NOT_RETURNED",
                "rotation_rules": "AVAILABLE" if rules else "NOT_RETURNED",
                "resource_policy": "NOT_COLLECTED",
                "provenance": "NOT_COLLECTED",
            },
            "versions": versions,
        }
