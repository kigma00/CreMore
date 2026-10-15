"""Member-account scanner role validation (read-only STS).

Onboarding an AWS account ends with the platform proving it can assume the
member account's scanner role *and* that the assumed identity really belongs to
the account the administrator registered. Both halves matter: a role that
assumes fine but lives in a different account would let a mistyped account id
scan the wrong estate.

Only ``sts:AssumeRole`` (with the per-account ExternalId) and
``sts:GetCallerIdentity`` are called. Nothing is read from the account.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RoleValidation:
    status: str  # VALID | INVALID
    detail: str = ""
    assumed_arn: str = ""
    # Safe, stable reason: SCANNER_ROLE_ASSUMED | REMEDIATION_ROLE_ASSUMED |
    # RUNTIME_ACCOUNT_CONFIRMED | SSO_ROLE_ASSUMED | NO_ROLE_RECORDED | NO_EXTERNAL_ID |
    # NO_PERMISSION_SET_RECORDED | AWS_LOGIN_REQUIRED | ASSUME_ROLE_DENIED |
    # SSO_ROLE_NOT_ASSIGNED | PERMISSION_SET_MISMATCH | ACCOUNT_MISMATCH |
    # CALLER_IDENTITY_FAILED | ACCESS_NOT_CONFIGURED | WORKER_AWS_NOT_CONFIGURED
    code: str = ""


def validate_scanner_role(role_arn: str, external_id: str, expected_account: str,
                          sts_client, *, session_name: str = "cremore-role-validation",
                          success_code: str = "SCANNER_ROLE_ASSUMED") -> RoleValidation:
    """Assume ``role_arn`` and confirm the identity is in ``expected_account``."""

    if not role_arn:
        return RoleValidation("INVALID", "no scanner role ARN recorded for this account", code="NO_ROLE_RECORDED")
    if not external_id:
        return RoleValidation("INVALID", "no ExternalId recorded for this account", code="NO_EXTERNAL_ID")
    kwargs = {"RoleArn": role_arn, "RoleSessionName": session_name, "DurationSeconds": 900}
    kwargs["ExternalId"] = external_id
    try:
        assumed = sts_client.assume_role(**kwargs)
    except Exception as exc:  # noqa: BLE001 -- SDK failures become a failed role validation with a safe code.
        from cremore_aws_provider.aws_identity import error_code, is_login_required

        code = "AWS_LOGIN_REQUIRED" if is_login_required(exc) else "ASSUME_ROLE_DENIED"
        return RoleValidation("INVALID", f"assume role failed: {error_code(exc)}", code=code)
    arn = ((assumed or {}).get("AssumedRoleUser") or {}).get("Arn", "")
    account = _account_from_arn(arn)
    if not account:
        # Never fall back to sts_client.get_caller_identity(): that client is the
        # *calling* identity, so it would report the hub account, not the role's.
        return RoleValidation("INVALID", "assume role returned no assumed identity", code="CALLER_IDENTITY_FAILED")
    if account != expected_account:
        return RoleValidation(
            "INVALID",
            f"assumed identity belongs to account {account or 'unknown'}, not {expected_account}",
            assumed_arn=arn,
            code="ACCOUNT_MISMATCH",
        )
    return RoleValidation("VALID", "role assumed; identity is in the registered account", arn, code=success_code)


def validate_runtime_account(expected_account: str, sts_client) -> RoleValidation:
    """RUNTIME_IDENTITY accounts: prove the identity in use is in the account.

    This confirms the account only; it does not prove any scan or action permission.
    """

    try:
        identity = sts_client.get_caller_identity()
    except Exception as exc:  # noqa: BLE001 -- every credential failure is a reported state
        from cremore_aws_provider.aws_identity import error_code, is_login_required

        code = "AWS_LOGIN_REQUIRED" if is_login_required(exc) else "CALLER_IDENTITY_FAILED"
        return RoleValidation("INVALID", f"caller identity failed: {error_code(exc)}", code=code)
    account = str((identity or {}).get("Account") or "")
    if account != expected_account:
        return RoleValidation("INVALID", f"runtime identity is in account {account or 'unknown'}, not {expected_account}",
                              code="ACCOUNT_MISMATCH")
    return RoleValidation("VALID", "runtime identity is in the registered account", str(identity.get("Arn") or ""),
                          code="RUNTIME_ACCOUNT_CONFIRMED")


def validate_sso_access(account, sso, token: str, sts_factory) -> RoleValidation:
    """SSO_PERMISSION_SET accounts: mint credentials and prove what they are.

    Two facts, both required. The credentials are in the account the
    administrator registered, and the role they assumed is the reserved role of
    the permission set this record names -- an assignment can be swapped for a
    different permission set, and a name alone would not notice.

    ``sts_factory(credentials)`` builds an STS client for the minted session; it
    must not be the calling identity's own client, which would report the hub.
    """

    from cremore_aws_provider import aws_sso
    from cremore_aws_provider.aws_identity import AwsLoginRequired, error_code, is_login_required

    role_name = (getattr(account, "sso_role_name", "") or "").strip()
    if not role_name:
        return RoleValidation("INVALID", "no permission set recorded for this account",
                              code="NO_PERMISSION_SET_RECORDED")
    try:
        credentials = aws_sso.role_credentials(sso, token, account.account_id, role_name)
    except AwsLoginRequired:
        # Not a fact about the account: the operator's sign-in is what expired.
        return RoleValidation("INVALID", "the Identity Center sign-in expired", code="AWS_LOGIN_REQUIRED")
    except aws_sso.SsoRoleUnavailable as exc:
        return RoleValidation("INVALID", str(exc), code="SSO_ROLE_NOT_ASSIGNED")
    except Exception as exc:  # noqa: BLE001 -- never raise to the caller
        code = "AWS_LOGIN_REQUIRED" if is_login_required(exc) else "SSO_ROLE_NOT_ASSIGNED"
        return RoleValidation("INVALID", f"credential vending failed: {error_code(exc)}", code=code)
    try:
        identity = sts_factory(credentials).get_caller_identity()
    except Exception as exc:  # noqa: BLE001 -- every credential failure is a reported state
        code = "AWS_LOGIN_REQUIRED" if is_login_required(exc) else "CALLER_IDENTITY_FAILED"
        return RoleValidation("INVALID", f"caller identity failed: {error_code(exc)}", code=code)
    arn = str((identity or {}).get("Arn") or "")
    account_id = str((identity or {}).get("Account") or "") or _account_from_arn(arn)
    if account_id != account.account_id:
        return RoleValidation("INVALID",
                              f"vended identity belongs to account {account_id or 'unknown'}, not {account.account_id}",
                              assumed_arn=arn, code="ACCOUNT_MISMATCH")
    if not _is_reserved_sso_role(arn, role_name):
        return RoleValidation("INVALID", f"credentials are not the reserved role of permission set {role_name}",
                              assumed_arn=arn, code="PERMISSION_SET_MISMATCH")
    return RoleValidation("VALID", "Identity Center vended this account's permission set", arn,
                          code="SSO_ROLE_ASSUMED")


def validate_account_access(account, sts_client, *, purpose: str = "scanner", sso_probe=None) -> RoleValidation:
    """Validate one account for a purpose by its access mode.

    ``sso_probe(account) -> RoleValidation`` is supplied only by a process that
    has an Identity Center client and token; without one an SSO account reports
    that rather than a fact about the account.
    """

    if account.access == "RUNTIME_IDENTITY":
        return validate_runtime_account(account.account_id, sts_client)
    if account.access == "SSO_PERMISSION_SET":
        if purpose != "scanner":
            return RoleValidation("INVALID", "Identity Center access is scanner-only; key actions need a member role",
                                  code="ACCESS_NOT_CONFIGURED")
        if sso_probe is None:
            return RoleValidation("INVALID", "this process has no Identity Center client configured",
                                  code="WORKER_AWS_NOT_CONFIGURED")
        return sso_probe(account)
    if purpose == "remediation":
        return validate_scanner_role(account.remediation_role_arn or "", account.external_id or "", account.account_id,
                                     sts_client, success_code="REMEDIATION_ROLE_ASSUMED")
    return validate_scanner_role(account.scanner_role_arn or "", account.external_id or "", account.account_id, sts_client)


def _account_from_arn(arn: str) -> str:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


# arn:aws:sts::<account>:assumed-role/AWSReservedSSO_<permission set>_<16 hex>/<user>
# The permission set name may itself contain "_", so the greedy group is correct:
# it backtracks only far enough to leave the 16-character suffix AWS appends.
_SSO_ASSUMED = re.compile(r"^arn:aws[a-z-]*:sts::\d{12}:assumed-role/AWSReservedSSO_(.+)_[0-9a-f]{16}/")


def _is_reserved_sso_role(arn: str, permission_set: str) -> bool:
    match = _SSO_ASSUMED.match(arn or "")
    return bool(match) and match[1] == permission_set
