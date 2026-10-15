"""The AWS identity CreMore itself runs as, and how member scanner roles trust it.

CreMore never handles AWS sign-in. The API and the worker each resolve the SDK's
default credential chain in their own process: on a single computer (Docker
Compose) that is the operator's mounted AWS CLI login; on a server it is the
workload's role. This module turns ``sts:GetCallerIdentity`` into:

* a **stable principal** — an IAM user or role ARN, never an STS session ARN;
* a **match key** used to prove the API and worker run as the same identity and
  to detect a change against the Admin-approved identity;
* the **trust** that the member scanner role template is deployed with.

IAM Identity Center roles are trusted the way AWS documents it: the account
root as principal plus ``aws:PrincipalArn`` ``ArnLike`` pinned to the reserved
path, the Identity Center Region and the exact permission set name, with the
16-character suffix (which changes when the role is re-created) matched by
``?`` wildcards so a longer permission set name cannot match. A plain IAM role's
path is looked up with ``iam:GetRole`` or supplied exactly; it is never widened
with a path wildcard.
"""

from __future__ import annotations

import re

_SESSION = re.compile(r"^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role/([^/]+)/(.+)$")
_USER = re.compile(r"^arn:(aws[a-z-]*):iam::(\d{12}):user/(.+)$")
_ROOT = re.compile(r"^arn:(aws[a-z-]*):iam::(\d{12}):root$")
_ROLE = re.compile(r"^arn:(aws[a-z-]*):iam::(\d{12}):role/(?:[A-Za-z0-9+=,.@_/-]*/)?([A-Za-z0-9+=,.@_-]{1,64})$")
_SSO_ROLE = re.compile(r"^AWSReservedSSO_([A-Za-z0-9+=,.@_-]{1,32})_([0-9a-f]{16})$")
_SSO_PATH = re.compile(r"^role/aws-reserved/sso\.amazonaws\.com/(?:([a-z]{2,4}(?:-[a-z]+)+-\d)/)?AWSReservedSSO_")
_REGION = re.compile(r"^[a-z]{2,4}(?:-[a-z]+)+-\d$")
# The Identity Center portal URL, which names the directory instance. Only an
# https URL is accepted: it is compared against the approved one, so a malformed
# value must drop out rather than become a second thing that matches.
_START_URL = re.compile(r"^https://[A-Za-z0-9][A-Za-z0-9.-]{0,254}(?:/[^\s]*)?$")

# Credential failures that a fresh sign-in (aws sso login / aws login /
# aws configure) fixes, as opposed to missing permissions or roles.
_LOGIN_ERRORS = {
    "UnauthorizedSSOTokenError", "SSOTokenLoadError", "TokenRetrievalError", "SSOError",
    "NoCredentialsError", "PartialCredentialsError", "CredentialRetrievalError",
    "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "RequestExpired",
}
SUPPORTED = ("IDENTITY_CENTER", "IAM_USER", "IAM_ROLE")
# installation_settings keys shared by the API and the worker.
WORKER_IDENTITY_KEY = "aws_identity:worker"
APPROVED_IDENTITY_KEY = "aws_scanner_identity"
ROLE_CHECK_JOB = "aws-role-check"


class AwsLoginRequired(Exception):
    """The runtime's own AWS sign-in expired or is missing; AWS work must wait."""

    code = "AWS_LOGIN_REQUIRED"


def error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    detail = response.get("Error") if isinstance(response, dict) else None
    candidates = [detail.get("Code") if isinstance(detail, dict) else None,
                  getattr(exc, "code", None), type(exc).__name__]
    return next((code for code in candidates if isinstance(code, str)
                 and re.fullmatch(r"(?:[A-Za-z][A-Za-z0-9_.-]{0,79}|[1-5][0-9]{2})", code)), "ProviderError")


def is_login_required(exc: BaseException | str | None) -> bool:
    """Whether an exception (including its causes) or a saved error code needs sign-in."""
    if isinstance(exc, str):
        return exc in _LOGIN_ERRORS or exc in (AwsLoginRequired.code, AwsLoginRequired.__name__)
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, AwsLoginRequired) or error_code(exc) in _LOGIN_ERRORS or any(
            cls.__name__ in _LOGIN_ERRORS for cls in type(exc).__mro__
        ):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def collection_error_code(exc: BaseException) -> str:
    """Keep scanner sign-in failures recognizable across serialized collection results."""
    return AwsLoginRequired.code if is_login_required(exc) else error_code(exc)


def local_credential_sources(profile: str = "") -> dict:
    """What this process can see of an AWS CLI configuration, without calling AWS.

    ``describe`` reports that there are no credentials; it cannot say *why*, and
    the three causes need different fixes. On the single-operator install the
    usual one is that ``AWS_CONFIG_DIR`` was never set, so the container has an
    empty placeholder mounted at ``~/.aws`` and nothing to sign in with.

    Only existence and profile *names* are read -- never a credentials file's
    contents. Returns ``reason``: one of ``AWS_CONFIG_NOT_MOUNTED``,
    ``AWS_CONFIG_UNREADABLE``, ``PROFILE_NOT_IN_CONFIG``, ``NO_CACHED_SIGN_IN``,
    or None when the local configuration looks usable and the failure is
    something else.

    "Mounted but unreadable" is its own answer because it is the common Linux
    first run: ``~/.aws`` is mode 700, the containers default to uid 65532, and
    without ``CREMORE_UID``/``CREMORE_GID`` they cannot read a single file in it.
    That needs a different fix from a directory that was never mounted, and the
    two look identical if only file existence is checked.
    """
    out: dict = {"config_present": False, "credentials_present": False, "profiles": [],
                 "requested_profile": (profile or "").strip() or None, "sso_cache_entries": 0,
                 "home_readable": None, "reason": None}
    try:
        import os
        from pathlib import Path

        import botocore.session

        # Deliberately botocore, not a boto3 session: when AWS_PROFILE names a
        # profile that does not exist, constructing one of those raises
        # ProfileNotFound -- a state this function exists to report, not hit.
        session = botocore.session.get_session()
        config_file = Path(os.path.expanduser(session.get_config_variable("config_file") or ""))
        creds_file = Path(os.path.expanduser(session.get_config_variable("credentials_file") or ""))
        out["config_present"] = config_file.is_file()
        out["credentials_present"] = creds_file.is_file()
        out["profiles"] = sorted(session.full_config.get("profiles", {}))
        cache = config_file.parent / "sso" / "cache"
        out["sso_cache_entries"] = len(list(cache.glob("*.json"))) if cache.is_dir() else 0
        # A directory that is there but cannot be listed is the uid mismatch.
        home = config_file.parent
        if home.is_dir():
            try:
                next(home.iterdir(), None)
                out["home_readable"] = True
            except PermissionError:
                out["home_readable"] = False
    except Exception:  # noqa: BLE001 -- a diagnostic must never be the thing that fails
        return out
    if out["home_readable"] is False:
        out["reason"] = "AWS_CONFIG_UNREADABLE"
    elif not out["config_present"] and not out["credentials_present"]:
        # Nothing at all: on Compose this is the unset AWS_CONFIG_DIR bind mount.
        out["reason"] = "AWS_CONFIG_NOT_MOUNTED"
    elif out["requested_profile"] and out["requested_profile"] not in out["profiles"]:
        out["reason"] = "PROFILE_NOT_IN_CONFIG"
    elif not out["sso_cache_entries"] and not out["credentials_present"]:
        out["reason"] = "NO_CACHED_SIGN_IN"
    return out


def local_sso_session() -> dict:
    """The active AWS CLI profile's Identity Center session: Region, start URL, name.

    Each may be missing. Values come from the profile's own ``sso_region`` /
    ``sso_start_url`` keys first, then from the ``sso-session`` block it names.
    A value that is not a well-formed Region or https URL is dropped rather than
    reported: these are compared against what an Admin approved, so a malformed
    config must narrow what matches, never widen it.
    """
    out: dict = {"region": None, "start_url": None, "session_name": None}
    try:
        import boto3

        session = boto3.Session()._session
        scoped = session.get_scoped_config() or {}
        region, start_url = scoped.get("sso_region"), scoped.get("sso_start_url")
        name = scoped.get("sso_session")
        if name:
            block = session.full_config.get("sso_sessions", {}).get(name) or {}
            region = region or block.get("sso_region")
            start_url = start_url or block.get("sso_start_url")
            out["session_name"] = str(name)
        if isinstance(region, str) and _REGION.fullmatch(region):
            out["region"] = region
        if isinstance(start_url, str) and _START_URL.fullmatch(start_url.strip()):
            out["start_url"] = start_url.strip()
    except Exception:  # noqa: BLE001 -- no CLI config is a normal state
        return {"region": None, "start_url": None, "session_name": None}
    return out


def local_sso_region() -> str | None:
    """Identity Center Region from the active AWS CLI profile, when it names one."""
    return local_sso_session()["region"]


def server_workload_source(session=None) -> str | None:
    """Identify SDK refresh paths we can prove are independent of human sign-in.

    Only a fixed source name leaves this function, never credential material or
    profile contents. Roles Anywhere is recognized only through the operator's
    pinned, bounded bridge; arbitrary credential processes are not accepted.
    """
    try:
        if session is None:
            import boto3

            session = boto3.Session()
        method = getattr(session.get_credentials(), "method", None)
        supported = {"iam-role", "container-role", "assume-role-with-web-identity"}
        if method in supported:
            return method
        if method not in {"assume-role", "custom-process"}:
            return None
        profiles = session._session.full_config.get("profiles", {})
        profile, seen = session.profile_name, set()
        for _ in range(20):
            if profile in seen:
                return None
            seen.add(profile)
            config = profiles.get(profile, {})
            if any(k in config for k in ("sso_session", "sso_start_url", "aws_access_key_id", "mfa_serial")):
                return None
            if config.get("credential_process"):
                from cremore_aws_provider.roles_anywhere import SOURCE, trusted_process

                return SOURCE if trusted_process(config["credential_process"]) else None
            if config.get("role_arn") and config.get("web_identity_token_file"):
                return "assume-role-with-web-identity"
            source = config.get("credential_source")
            if source in {"Ec2InstanceMetadata", "EcsContainer"}:
                return "iam-role" if source == "Ec2InstanceMetadata" else "container-role"
            profile = config.get("source_profile")
            if not profile:
                return None
    except Exception:  # noqa: BLE001 -- unknown provenance must never advertise unattended renewal
        return None
    return None


def require_server_workload(identity):
    if identity.get("kind") != "IAM_ROLE" or identity.get("credential_source") not in {
            "iam-role", "container-role", "assume-role-with-web-identity", "roles-anywhere"}:
        from cremore_aws_provider.onboarding import OnboardingValueError

        raise OnboardingValueError("AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED")


def describe(sts, iam=None, *, sso_region: str | None = None, role_arn: str | None = None,
             sso_start_url: str | None = None) -> dict:
    """Resolve and classify the identity these clients run as. Never raises."""
    try:
        caller = sts.get_caller_identity()
    except Exception as exc:  # noqa: BLE001 -- every credential failure is a reported state
        state = "LOGIN_REQUIRED" if is_login_required(exc) else "ERROR"
        if error_code(exc) == "NoCredentialsError":
            state = "NO_CREDENTIALS"
        return {"state": state, "error_code": error_code(exc)}
    caller_arn = str(caller.get("Arn") or "")
    out = {"state": "READY", "caller_arn": caller_arn, "account_id": str(caller.get("Account") or ""),
           "kind": "UNSUPPORTED", "match_key": None, "principal_arn": None, "trust": None, "requires": None}

    if m := _ROOT.fullmatch(caller_arn):
        out.update(kind="ROOT", partition=m[1])
        return out
    if m := _USER.fullmatch(caller_arn):
        out.update(kind="IAM_USER", partition=m[1], principal_arn=caller_arn, match_key=f"user:{caller_arn}",
                   trust={"type": "IamUser", "principal_arn": caller_arn})
        return out
    m = _SESSION.fullmatch(caller_arn)
    if not m:
        return out
    partition, account, role_name = m[1], m[2], m[3]
    out["partition"] = partition
    looked_up = _role_arn(iam, role_name)

    if sso := _SSO_ROLE.fullmatch(role_name):
        permission_set = sso[1]
        region = None
        if looked_up and (path := _SSO_PATH.match(looked_up.split(":", 5)[5])):
            region = path[1] or "us-east-1"
        region = region or (sso_region if sso_region and _REGION.fullmatch(sso_region) else None)
        out.update(kind="IDENTITY_CENTER", permission_set=permission_set,
                   match_key=f"identity-center:{partition}:{account}:{permission_set}")
        # The directory instance this sign-in came from. It is NOT part of
        # match_key (the permission set alone identifies the runtime identity);
        # it is what SSO_PERMISSION_SET accounts are pinned to, because the same
        # profile name can be repointed at another Identity Center instance.
        if isinstance(sso_start_url, str) and _START_URL.fullmatch(sso_start_url.strip()):
            out["sso_start_url"] = sso_start_url.strip()
        if not region:
            out["requires"] = "IDENTITY_CENTER_REGION"
            return out
        # AWS omits the Region segment when the identity source is hosted in us-east-1.
        segment = "" if region == "us-east-1" else f"{region}/"
        base = f"arn:{partition}:iam::{account}:role/aws-reserved/sso.amazonaws.com/{segment}AWSReservedSSO_{permission_set}_"
        out.update(sso_region=region, principal_arn=looked_up or f"{base}{sso[2]}",
                   trust={"type": "IdentityCenter", "account_id": account, "principal_pattern": base + "?" * 16})
        return out

    out.update(kind="IAM_ROLE", role_name=role_name, match_key=f"role:{partition}:{account}:{role_name}")
    exact = looked_up
    if not exact and role_arn:
        given = _ROLE.fullmatch(role_arn.strip())
        if given and given[1] == partition and given[2] == account and given[3] == role_name:
            exact = role_arn.strip()
    if not exact:
        out["requires"] = "ROLE_ARN"
        return out
    out.update(principal_arn=exact, trust={"type": "IamRole", "principal_arn": exact})
    return out


def _role_arn(iam, role_name: str) -> str | None:
    if iam is None:
        return None
    try:
        return str(iam.get_role(RoleName=role_name)["Role"]["Arn"])
    except Exception:  # noqa: BLE001 -- lacking iam:GetRole is expected; callers fall back
        return None


def approvable(identity: dict) -> str | None:
    """Why this identity cannot be approved as the scanner identity, or None."""
    if identity.get("state") != "READY":
        return identity.get("state") or "UNKNOWN"
    if identity.get("kind") == "ROOT":
        return "ROOT_CREDENTIALS_REFUSED"
    if identity.get("kind") not in SUPPORTED:
        return "UNSUPPORTED_IDENTITY"
    if identity.get("requires"):
        return f"{identity['requires']}_REQUIRED"
    return None


def stack_parameters(trust: dict, *, target_account: str, external_id: str, role_name: str,
                     remediation_trust: dict | None = None, remediation_role_name: str | None = None) -> dict:
    """Parameters for deploy/cloudformation/member-account-role.yaml.

    ``remediation_trust`` (the separately approved remediation identity) also
    creates the remediation role trusting only that identity.
    """
    params = {
        "TargetAccountId": target_account,
        "MemberScannerRoleName": role_name,
        "ExternalId": external_id,
        **_trust_parameters(trust, ""),
    }
    if remediation_trust is not None:
        params.update(EnableRemediation="true", MemberRemediationRoleName=remediation_role_name or "",
                      **_trust_parameters(remediation_trust, "Remediation"))
    return params


def _trust_parameters(trust: dict, prefix: str) -> dict:
    kind = trust["type"]
    if kind == "IdentityCenter":
        return {f"{prefix}TrustedPrincipalType": kind, f"{prefix}IdentityCenterAccountId": trust["account_id"],
                f"{prefix}TrustedPrincipalPattern": trust["principal_pattern"]}
    return {f"{prefix}TrustedPrincipalType": kind, f"{prefix}TrustedPrincipalArn": trust["principal_arn"]}


def cli_command(params: dict, *, region: str, template_file: str, stack_name: str) -> str:
    """One line valid in bash, zsh and PowerShell (single quotes keep ``?`` literal)."""
    overrides = " ".join(f"'{key}={value}'" for key, value in params.items())
    return (f"aws cloudformation deploy --region {region} --stack-name {stack_name} "
            f"--template-file {template_file} --capabilities CAPABILITY_NAMED_IAM "
            f"--parameter-overrides {overrides}")


def hub_policy(partition: str, role_name: str, *, accounts=(), organizations=()) -> dict:
    """Least privilege for the approved identity: assume only the member roles of this name, in the organizations
    every registered account belongs to (``aws:ResourceOrgID``, so an organization sync's new accounts are covered),
    else in the registered accounts (``aws:ResourceAccount``, as security-account.yaml's MemberAccountIds does).
    Before any account is registered the role name alone limits it; each member role's trust still requires CreMore's
    identity and that account's ExternalId."""
    statement = {
        "Sid": "AssumeCreMoreScannerRoles",
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": f"arn:{partition}:iam::*:role/{role_name}",
    }
    if organizations:
        statement["Condition"] = {"StringEquals": {"aws:ResourceOrgID": sorted(set(organizations))}}
    elif accounts:
        statement["Condition"] = {"StringEquals": {"aws:ResourceAccount": sorted(set(accounts))}}
    return {"Version": "2012-10-17", "Statement": [statement]}


# Read-only work CreMore does inside an account, kept in step with the member
# role template (deploy/cloudformation/member-account-role.yaml) and with the SDK
# allowlist (cremore/aws_readonly.py). Deliberately excludes iam:UpdateAccessKey,
# which only the separately approved remediation path may ever hold.
SCANNER_ACTIONS = (
    "sts:GetCallerIdentity",
    "s3:ListAllMyBuckets", "s3:ListBucket", "s3:ListBucketVersions",
    "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging",
    "s3:GetBucketLocation", "s3:GetBucketTagging", "s3:GetBucketVersioning",
    "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
    # Who can read where a credential was found (cremore_aws_provider.context).
    "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetObjectAcl",
    "iam:GetUser", "iam:ListUsers", "iam:ListUserTags", "iam:ListAccessKeys",
    "iam:GetAccessKeyLastUsed", "iam:GenerateCredentialReport", "iam:GetCredentialReport",
    "iam:ListServiceSpecificCredentials",
    "iam:ListUserPolicies", "iam:GetUserPolicy", "iam:ListAttachedUserPolicies",
    "iam:ListGroupsForUser", "iam:ListGroupPolicies", "iam:GetGroupPolicy", "iam:ListAttachedGroupPolicies",
    "iam:GetRole", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
    "iam:GetPolicy", "iam:GetPolicyVersion",
    "iam:SimulatePrincipalPolicy",
    "cloudtrail:LookupEvents", "ec2:DescribeRegions",
    "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecretVersionIds", "secretsmanager:GetResourcePolicy",
    # Whether a key's policy lets IAM policies grant its use (cremore_aws_provider.investigation.potential_access).
    "kms:GetKeyPolicy",
    # Parameter names and types only, the vault check's listing (cremore_aws_provider.onboarding).
    "ssm:DescribeParameters",
)


def permission_set_policy() -> dict:
    """What an IAM Identity Center permission set needs for SSO_PERMISSION_SET access.

    ``hub_policy`` is the wrong answer for this access mode: nothing is assumed,
    so ``sts:AssumeRole`` buys nothing and a permission set holding only that
    would fail on the first object read. Here the permission set *is* the access
    in each account, so it carries the read-only work itself.

    Optional investigations are included because they are dashboard switches an
    Admin may turn on later; CreMore never calls what its switches leave off, and
    the SDK allowlist refuses anything outside this set either way.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CreMoreReadOnlyScanning",
            "Effect": "Allow",
            "Action": list(SCANNER_ACTIONS),
            "Resource": "*",
        }],
    }
