"""Live AWS bindings for the approved rotation service.

Kept apart from the rotation logic so ``RotationService`` stays fully testable
with fakes. This module is imported only when rotation execution is enabled.
"""

from __future__ import annotations

from cremore_aws_provider.remediation.rotation import (
    RotationError,
    RotationService,
    STSIdentity,
    STSValidator,
)


class Boto3STSValidator(STSValidator):
    """Proves a candidate key works by calling STS GetCallerIdentity *as it*."""

    def __init__(self, region: str) -> None:
        self.region = region

    def validate(self, access_key_id: str, secret_access_key: str) -> STSIdentity:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            sts = boto3.client(
                "sts", region_name=self.region,
                aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key,
            )
            identity = sts.get_caller_identity()
        except ClientError as exc:
            code = (exc.response or {}).get("Error", {}).get("Code") or "STS_ERROR"
            raise RotationError(code) from exc
        except BotoCoreError as exc:
            raise RotationError("STS_UNREACHABLE") from exc
        return STSIdentity(
            account=identity.get("Account", ""),
            arn=identity.get("Arn", ""),
            user_id=identity.get("UserId", ""),
        )


def build_rotation_service_factory(region: str):
    """Return ``factory(session, secret_region)`` producing a RotationService.

    IAM and Secrets Manager clients come from the one account session selected
    for the request (opened, and every access check re-run, per request). The
    STS validator authenticates *as the candidate key* and uses no session.
    """

    from cremore_aws_provider.remediation.rotation import session_guard

    def factory(session, secret_region: str) -> RotationService:
        return RotationService(
            iam=session.client("iam", region),
            secrets=session.client("secretsmanager", secret_region),
            sts_validator=Boto3STSValidator(region),
            guard=session_guard(session),
        )

    return factory
