"""AWS onboarding, account-session guards and read-only metadata support.

Clients are created only when a caller invokes a probe or service function.
Importing this module never registers routes or contacts a provider."""

from __future__ import annotations

import secrets
from urllib.parse import quote, urlencode

from cremore_aws_provider import (
    aws_access,
    aws_identity,
    aws_org_settings,
    aws_sso,
    aws_sso_settings,
)

from cremore.api.http_support import (
    http_error,
    isoformat,
)
from cremore.domain.models import AwsAccount

SCANNER_ROLE_NAME = "CredentialExposureScannerRole"


def present_aws_account(a, approvals: dict) -> dict:
    """Validation fields are the *effective* results under the current revisions."""
    scanner = aws_access.effective_validation(a, aws_access.SCANNER, approvals.get(aws_access.SCANNER))
    remediation = aws_access.effective_validation(a, aws_access.REMEDIATION, approvals.get(aws_access.REMEDIATION))
    return {
        "id": str(a.id),
        "account_id": a.account_id,
        "name": a.name,
        "environment": a.environment,
        "access": a.access,
        "sso_role_name": a.sso_role_name,
        "scanner_role_arn": a.scanner_role_arn,
        "remediation_role_arn": a.remediation_role_arn,
        "enabled": a.enabled,
        "validation_status": scanner["status"],
        "validation_detail": scanner["detail"],
        "validated_at": isoformat(scanner["validated_at"]),
        "remediation_validation_status": remediation["status"],
        "remediation_validation_detail": remediation["detail"],
        "remediation_validated_at": isoformat(remediation["validated_at"]),
        "source": a.source,
        "org_state": a.org_state,
        "org_blocks": aws_access.org_blocks(a),
    }


def onboarding_configured(settings) -> bool:
    return bool(settings.aws_onboarding_template_url and settings.scanner_principal_arn)


def partition(arn: str) -> str:
    parts = arn.split(":")
    return parts[1] if len(parts) > 1 and parts[1].startswith("aws") else "aws"


def console_host(partition: str, region: str) -> str:
    if partition == "aws-cn":
        return f"{region}.console.amazonaws.cn"
    if partition == "aws-us-gov":
        return f"{region}.console.amazonaws-us-gov.com"
    if partition == "aws-eusc":  # AWS European Sovereign Cloud (eusc-de-east-1.console.amazonaws-eusc.eu)
        return f"{region}.console.amazonaws-eusc.eu"
    return f"{region}.console.aws.amazon.com"


STACK_NAME = "cremore-scanner"


REMEDIATION_ROLE_NAME = "CredentialExposureRemediationRole"


TEMPLATE_FILE = "member-account-role.yaml"


def hub_scope(repo) -> dict:
    """Where the hub policy lets CreMore's identity assume member roles (aws_identity.hub_policy): the organization when
    its last complete sync placed every registered role account in it, else those accounts (none before the first)."""
    from cremore_aws_provider.aws_org_context import SUMMARY_KEY, account_context

    accounts = sorted(account.account_id for account in repo.list_aws_accounts() if account.access == "ROLE")
    summary = (repo.get_setting(SUMMARY_KEY) or {}).get("value") or {}
    organization = summary.get("organization_id") if summary.get("status") == "COMPLETE" else None
    # A sync records the organization's id on every account; only a path places the account inside it.
    if organization and accounts and all(account_context(repo, account)["organization"].get("path") for account in accounts):
        return {"organizations": [organization]}
    return {"accounts": accounts}


def role_name(role_arn: str | None, default: str) -> str:
    return (role_arn or "").rsplit("/", 1)[-1] or default


def quick_create_url(settings, approved: dict, params: dict) -> str:
    """CloudFormation quick-create link in the form AWS documents (#/stacks/create/review); AWS requires the
    template to be hosted in Amazon S3."""

    region = settings.aws_region
    query = {"templateURL": settings.aws_onboarding_template_url, "stackName": STACK_NAME,
             **{f"param_{key}": value for key, value in params.items()}}
    host = console_host(approved.get("partition") or "aws", region)
    return (f"https://{host}/cloudformation/home?region={quote(region)}"
            f"#/stacks/create/review?{urlencode(query)}")


def member_template_path():
    import os
    from pathlib import Path

    for candidate in (Path(os.environ.get("CREMORE_CLOUDFORMATION_DIR", "/app/cloudformation")) / TEMPLATE_FILE,
                      Path(__file__).resolve().parents[2] / "deploy" / "cloudformation" / TEMPLATE_FILE):
        if candidate.is_file():
            return candidate
    return None


DISCOVERY_LIMIT = 500


def permission_set_options(listed: list[dict]) -> list[dict]:
    """Every permission set this sign-in holds, with how many accounts carry it.

    This is what the dashboard offers instead of asking an operator to name one
    blind, and it is why no default is guessed: AdministratorAccess usually
    appears in this list too, and only a person should decide against it.
    """
    counts: dict[str, int] = {}
    for entry in listed:
        for role in entry.get("roles") or []:
            name = str(role)
            if aws_sso.PERMISSION_SET.fullmatch(name):
                counts[name] = counts.get(name, 0) + 1
    return [{"name": name, "accounts": count}
            for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


def default_discovery_probe(settings):
    """Live, read-only probe of one account-discovery source.

    Returns ``available``, a safe ``reason`` when it is not, and the accounts the
    source would offer. Nothing here mutates AWS or the local registry.
    """

    def probe(source: str, approved: dict | None) -> dict:
        if source == "sso":
            return probe_sso(settings, approved)
        if source == "org":
            return probe_org(settings)
        return {"available": False, "reason": "UNKNOWN_SOURCE", "accounts": []}

    return probe


def probe_sso(settings, approved: dict | None) -> dict:
    from cremore_aws_provider.aws_readonly import readonly_client

    out = {"accounts": [], "start_url": (approved or {}).get("sso_start_url"),
           "region": (approved or {}).get("sso_region")}
    if approved is None:
        return {**out, "available": False, "reason": "IDENTITY_NOT_APPROVED"}
    if approved.get("kind") != "IDENTITY_CENTER":
        return {**out, "available": False, "reason": "NOT_AN_IDENTITY_CENTER_IDENTITY"}
    if not approved.get("sso_start_url"):
        return {**out, "available": False, "reason": "IDENTITY_CENTER_START_URL_REQUIRED"}
    try:
        region = aws_sso.region_for(approved)
        token = aws_sso.access_token()
        listed = aws_sso.list_assigned(readonly_client(aws_sso.client(region), "sso"), token)
    except aws_sso.SsoRegionUnknown:
        return {**out, "available": False, "reason": "IDENTITY_CENTER_REGION_REQUIRED"}
    except aws_sso.SsoCacheNotWritable:
        return {**out, "available": False, "reason": "SSO_CACHE_NOT_WRITABLE"}
    except aws_identity.AwsLoginRequired:
        return {**out, "available": False, "reason": "AWS_LOGIN_REQUIRED"}
    except Exception as exc:  # noqa: BLE001 -- a safe code, never provider text
        return {**out, "available": False, "reason": aws_identity.error_code(exc)}
    return {**out, "available": True, "reason": None, "region": region, "accounts": listed}


def probe_org(settings) -> dict:
    import boto3
    from cremore_aws_provider.aws_org_discovery import list_org_accounts
    from cremore_aws_provider.aws_readonly import readonly_client

    out = {"accounts": [], "start_url": None, "region": settings.aws_region}
    try:
        client = readonly_client(boto3.client("organizations", region_name=settings.aws_region), "organizations")
        listed = list_org_accounts(client)
    except aws_identity.AwsLoginRequired:
        return {**out, "available": False, "reason": "AWS_LOGIN_REQUIRED"}
    except Exception as exc:  # noqa: BLE001 -- AccessDeniedException is the expected answer here
        code = "AWS_LOGIN_REQUIRED" if aws_identity.is_login_required(exc) else aws_identity.error_code(exc)
        return {**out, "available": False, "reason": code}
    return {**out, "available": True, "reason": None, "accounts": listed}


def default_discovery_sweep(settings, repo):
    """Run one registration sweep of a discovery source, as the worker would.

    Read-only against AWS: it lists accounts and writes the local registry.
    Both sources share the worker's reconcile functions, so a sweep started here
    and one started there cannot drift apart.
    """

    def sweep(source: str, approved: dict, queue_validation) -> dict:
        from cremore_aws_provider.aws_readonly import readonly_client

        if source == "sso":
            from cremore_aws_provider.aws_sso_discovery import reconcile_sso_accounts

            region = aws_sso.region_for(approved)
            return reconcile_sso_accounts(
                repo, settings, readonly_client(aws_sso.client(region), "sso"), aws_sso.access_token(),
                aws_sso_settings.permission_set(settings, repo)["name"], queue_validation=queue_validation)
        import boto3
        from cremore_aws_provider.aws_org_discovery import reconcile_org_accounts

        config = aws_org_settings.config(settings, repo)
        client = readonly_client(boto3.client("organizations", region_name=settings.aws_region), "organizations")
        return reconcile_org_accounts(repo, settings, client, config,
                                      queue_validation=queue_validation if config["auto_validate"] else None)

    return sweep


def default_identity_probe(settings):
    def probe(role_arn=None, sso_region=None, purpose=aws_access.SCANNER):
        import boto3
        from cremore_aws_provider.aws_readonly import readonly_client
        from cremore_aws_provider.roles_anywhere import diagnostic

        renewal = diagnostic() if purpose == aws_access.SCANNER else None
        if renewal and renewal["state"] == "ERROR":
            return {"state": "ERROR", "error_code": renewal["error_code"], "renewal_health": renewal}

        region = settings.aws_region
        profile = settings.aws_remediation_profile if purpose == aws_access.REMEDIATION else ""
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        local = aws_identity.local_sso_session()
        try:
            identity = aws_identity.describe(readonly_client(session.client("sts", region_name=region), "sts"),
                                         readonly_client(session.client("iam", region_name=region), "iam"),
                                         sso_region=sso_region or local["region"], role_arn=role_arn,
                                         sso_start_url=local["start_url"])
            identity["credential_source"] = aws_identity.server_workload_source(session)
        except Exception as exc:  # fixed diagnostic only; never provider output
            if not renewal:
                raise
            identity = {"state": "ERROR", "error_code": aws_identity.error_code(exc)}
        if renewal:
            identity["renewal_health"] = diagnostic(identity)
        return identity

    return probe


def access_key_metadata(session, cred, user_name: str = "") -> dict:
    from cremore_aws_provider.investigation.usage import access_key_metadata as read

    return read(session, cred, user_name)


def open_account_session(aws_sessions, account_id: str | None, purpose: str):
    """An account-verified session, or an HTTP error carrying the safe refusal code."""
    from cremore_aws_provider.aws_identity import AwsLoginRequired

    if aws_sessions is None:
        raise http_error(503, "AWS_ACCESS_NOT_CONFIGURED: this API has no AWS session provider")
    try:
        return aws_sessions.open(account_id, purpose)
    except aws_access.AccessBlocked as exc:
        raise http_error(409, f"{exc.code}: AWS {purpose} access to account {account_id or 'unknown'} is not available")
    except AwsLoginRequired:
        raise http_error(409, "AWS_LOGIN_REQUIRED: sign in to AWS again on the computer running CreMore")


def secrets_inventory_session(repo, settings, aws_sessions, account_id: str | None):
    """Inventory is per account; without one named, the explicit RUNTIME_IDENTITY account."""
    if account_id is None:
        own = next((a for a in repo.list_aws_accounts() if a.access == aws_access.RUNTIME_IDENTITY), None)
        account_id = own.account_id if own else None
        if account_id is None:
            raise http_error(409, "ACCOUNT_NOT_CONNECTED: name an account_id or register this identity's own account")
    return open_account_session(aws_sessions, account_id, aws_access.SCANNER)


def sign_in_diagnosis(settings, identity: dict | None) -> dict | None:
    """A local, no-network look at why this process has no AWS sign-in.

    None while the identity is usable: there is nothing to prescribe. Profile
    names come from the AWS CLI config and are not secrets; no credentials file
    is ever read.
    """
    state = (identity or {}).get("state")
    if state not in ("NO_CREDENTIALS", "LOGIN_REQUIRED", "ERROR"):
        return None
    import os

    workload = ("IRSA" if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") else
                "CONTAINER_ROLE" if os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") else
                "EC2_INSTANCE_ROLE" if os.environ.get("AWS_EC2_METADATA_DISABLED", "true").lower() == "false" and not os.environ.get("AWS_PROFILE") else
                "SERVER_WORKLOAD" if settings.auth_mode == "oidc" and not os.environ.get("AWS_PROFILE") else None)
    if workload:
        return {"state": state, "reason": "WORKLOAD_IDENTITY_UNAVAILABLE", "workload": workload,
                "config_present": False, "credentials_present": False, "profiles": [], "sso_cache_entries": 0}
    sources = aws_identity.local_credential_sources(os.environ.get("AWS_PROFILE", ""))
    if state == "LOGIN_REQUIRED" and sources["reason"] is None:
        # The configuration is fine; the session simply expired.
        sources["reason"] = "SIGN_IN_EXPIRED"
    return {**sources, "state": state}


def present_identity(identity: dict | None) -> dict | None:
    if identity is None:
        return None
    return {k: identity.get(k) for k in ("state", "kind", "account_id", "caller_arn", "principal_arn",
                                          "permission_set", "sso_region", "sso_start_url", "requires",
                                          "error_code", "match_key")}


def present_approved_identity(approved: dict | None) -> dict | None:
    if approved is None:
        return None
    return {k: approved.get(k) for k in ("kind", "account_id", "principal_arn", "permission_set", "sso_region",
                                          "sso_start_url", "approved_by", "approved_at", "source")}


def iam_user_from_arn(arn: str) -> tuple[str, str]:
    """('user-name', 'account-id') from arn:aws:iam::123456789012:user/path/name, else ('', '')."""

    parts = arn.split(":")
    if len(parts) != 6 or parts[2] != "iam" or not parts[5].startswith("user/"):
        return "", ""
    account = parts[4]
    name = parts[5][len("user/"):].split("/")[-1]
    if not (account.isdigit() and len(account) == 12 and name):
        return "", ""
    return name, account


def secret_record_public(s) -> dict:
    """A managed secret's inventory row: metadata only, never its value."""

    return {
        "arn": s.arn,
        "name": s.name,
        "rotation_enabled": s.rotation_enabled,
        "last_rotated_at": s.last_rotated_at,
        "last_accessed_at": s.last_accessed_at,
        "created_at": s.created_at,
        "next_rotation_at": s.next_rotation_at,
        "managed_by": s.managed_by,
        "tag_keys": list(s.tag_keys),
        "stale": s.stale,
    }


class AccountRefused(Exception):
    """An account the access mode cannot take; ``detail`` starts with a stable code."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def account_refusal(repo, settings, approved: dict | None, body: dict, *, known=None) -> AccountRefused | None:
    """Why an account cannot be registered in its access mode, or None.

    Everything that makes the access mode safe is checked here, before a record
    exists; ``known`` is the set of registered account ids, when the caller has it.
    """
    account_id = str(body.get("account_id", "")).strip()
    if not account_id.isdigit() or len(account_id) != 12:
        return AccountRefused(422, "ACCOUNT_ID_INVALID: account_id must be a 12-digit AWS account id")
    known = {a.account_id for a in repo.list_aws_accounts()} if known is None else known
    if account_id in known:
        return AccountRefused(409, f"ACCOUNT_ALREADY_REGISTERED: account {account_id} is already registered")
    access = body.get("access") or aws_access.ROLE
    if access == aws_access.RUNTIME_IDENTITY:
        # Explicit single-account mode: only the approved identity's own
        # account, used directly and still subject to every block and hold.
        if approved is None or approved.get("account_id") != account_id:
            return AccountRefused(409, "RUNTIME_IDENTITY_ACCOUNT_MISMATCH: only the approved AWS identity's own "
                                       "account can be used without a member role")
        return None
    if access == aws_access.SSO_PERMISSION_SET:
        # Identity Center vends this account's credentials for the operator's
        # own assignment, so nothing is deployed.
        if approved is None:
            return AccountRefused(409, "IDENTITY_NOT_APPROVED: approve the AWS identity CreMore runs as first")
        if approved.get("kind") != "IDENTITY_CENTER":
            return AccountRefused(409, "NOT_AN_IDENTITY_CENTER_IDENTITY: CreMore must itself run as an IAM Identity "
                                       "Center permission set to reach accounts this way")
        if not approved.get("sso_start_url"):
            # Without the approved directory there is nothing to pin the
            # account to, and cremore/aws_sessions.py would refuse every session.
            return AccountRefused(409, "IDENTITY_CENTER_START_URL_REQUIRED: re-approve the AWS identity so the "
                                       "Identity Center instance is recorded; accounts are pinned to it")
        role = _permission_set(repo, settings, body)
        if not role:
            return AccountRefused(409, "PERMISSION_SET_NOT_CHOSEN: choose the IAM Identity Center permission set "
                                       "CreMore may use before connecting accounts this way")
        if not aws_sso.PERMISSION_SET.fullmatch(role):
            return AccountRefused(422, "PERMISSION_SET_NAME_INVALID: sso_role_name must be an IAM Identity Center permission set name")
        return None
    if access != aws_access.ROLE:
        return AccountRefused(422, "ACCESS_MODE_INVALID: access must be ROLE, RUNTIME_IDENTITY or SSO_PERMISSION_SET")
    return None


def _permission_set(repo, settings, body) -> str:
    chosen = aws_sso_settings.permission_set(settings, repo)["name"] or ""
    return str(body.get("sso_role_name") or chosen or "").strip()


def register_account(repo, settings, approved: dict | None, body: dict, *, discovery: dict | None = None) -> AwsAccount:
    """Register one AWS account in its access mode; ``approved`` is the approved scanner identity."""
    refusal = account_refusal(repo, settings, approved, body)
    if refusal is not None:
        raise refusal
    account_id = str(body["account_id"]).strip()
    access = body.get("access") or aws_access.ROLE
    if discovery is not None and (access != aws_access.ROLE
            or set(discovery) - {"external_id", "in_deployment_scope", "source"}
            or not {"external_id", "in_deployment_scope"} <= set(discovery)
            or discovery.get("source", "ORGANIZATION") not in {"ORGANIZATION", "MANUAL"}
            or not isinstance(discovery["external_id"], str)
            or not aws_org_settings.EXTERNAL_ID.fullmatch(discovery["external_id"])
            or (discovery["in_deployment_scope"] is not None and discovery["in_deployment_scope"] is not True)):
        raise AccountRefused(422, "AWS_DISCOVERY_SETTINGS_INVALID")
    name = str(body.get("name", "")).strip() or account_id
    environment = str(body.get("environment", "") or "")
    if access == aws_access.RUNTIME_IDENTITY:
        return repo.create_aws_account(AwsAccount(account_id=account_id, name=name, environment=environment,
                                                  access=aws_access.RUNTIME_IDENTITY))
    if access == aws_access.SSO_PERMISSION_SET:
        # source=SSO so the assignment sweep owns this record's presence: an
        # assignment taken away later blocks it instead of failing silently.
        return repo.create_aws_account(AwsAccount(account_id=account_id, name=name, environment=environment,
                                                  access=aws_access.SSO_PERMISSION_SET,
                                                  sso_role_name=_permission_set(repo, settings, body),
                                                  source="SSO", org_present=True))
    aws_partition = (approved or {}).get("partition") or partition(settings.scanner_principal_arn)
    acct = AwsAccount(
        account_id=account_id,
        name=name,
        environment=environment,
        scanner_role_arn=body.get("scanner_role_arn")
        or f"arn:{aws_partition}:iam::{account_id}:role/{SCANNER_ROLE_NAME}",
        remediation_role_arn=body.get("remediation_role_arn"),
        # Confused-deputy guard baked into the role's trust policy. It is a
        # unique identifier, not a secret; it appears in the quick-create link.
        external_id=discovery["external_id"] if discovery is not None else secrets.token_urlsafe(24),
        **({"source": "ORGANIZATION", "org_state": "ACTIVE", "org_present": True,
            "in_deployment_scope": discovery["in_deployment_scope"]}
           if discovery is not None and discovery.get("source", "ORGANIZATION") == "ORGANIZATION" else {}),
    )
    return repo.create_aws_account(acct)


def queue_aws_read(repo, settings, operation, actor, params):
    """Return a bounded worker request, with a poll URL bound to its requester."""
    from fastapi.responses import JSONResponse

    from cremore.engine.aws_read_engine import AwsReadEngine, AwsReadError

    try:
        job = AwsReadEngine.enqueue(repo, settings, operation, actor, params)
    except AwsReadError as exc:
        raise http_error(exc.status, exc.code) from None
    return JSONResponse({"status": job.status, "request_id": str(job.id),
                         "poll_url": f"/api/v1/aws/requests/{job.id}"}, status_code=202)
