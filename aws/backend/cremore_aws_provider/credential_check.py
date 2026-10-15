"""aws connection identity check using the configured scanner credential."""
from __future__ import annotations

from cremore.collectors.base import error_label
from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED, CredentialCheck


def check_s3(sts_client, s3_client, bucket: str) -> CredentialCheck:
    """The scanner's own AWS identity must resolve and must be able to see the bucket."""

    try:
        identity = sts_client.get_caller_identity()
    except Exception as exc:  # noqa: BLE001 -- Provider failures yield a safe status/code, never credential-bearing exception text.
        label = error_label(exc)
        return CredentialCheck(REJECTED if label in ("InvalidClientTokenId", "ExpiredToken", "AccessDenied")
                               else INDETERMINATE, error=label)
    owner = str((identity or {}).get("Arn", ""))
    if not bucket:
        return CredentialCheck(ACTIVE, owner=owner)
    try:
        s3_client.head_bucket(Bucket=bucket)
    except Exception as exc:  # noqa: BLE001 -- Provider failures yield a safe status/code, never credential-bearing exception text.
        label = error_label(exc)
        # 403/AccessDenied: the identity works but cannot see the bucket.
        return CredentialCheck(REJECTED if label in ("403", "AccessDenied", "Forbidden") else INDETERMINATE,
                               owner=owner, error=label)
    return CredentialCheck(ACTIVE, owner=owner, scopes=(f"s3:HeadBucket:{bucket}",))
