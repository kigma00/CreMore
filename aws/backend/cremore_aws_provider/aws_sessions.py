"""The one place investigations and actions get an AWS session for an account.

``AccountSessions.open(account_id, purpose)`` re-evaluates on every call:

1. the account is registered (``ACCOUNT_NOT_CONNECTED`` otherwise);
2. an identity is approved for the purpose, and this process currently runs as it
   (``AWS_LOGIN_REQUIRED`` / ``AWS_IDENTITY_CHANGED``);
3. the account is usable for the purpose (``cremore_aws_provider.aws_access.use_refusal``);
4. the session really is in the account: ROLE access assumes the purpose's
   member role with the account's ExternalId and checks the assumed ARN;
   RUNTIME_IDENTITY access checks the runtime identity's own account;
   SSO_PERMISSION_SET access additionally pins the Identity Center instance,
   because the same profile name can be repointed at another directory and
   would then vend a different estate under the same approval.

Only scanner credentials are cached, keyed by purpose, account, access mode,
role or permission set, ExternalId and both revisions; the checks above still
run first on every call. Remediation sessions are never cached. Scanner clients
are wrapped read-only.

``AccountSessions.value_reader`` is the one way to a secret value through a role
CreMore's templates make: the scanner session, opened as above, assumes the
account's value-reader role (role chaining). Its clients hold only
``VAULT_OPERATIONS``; the scanner session itself still reads no value.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable
from dataclasses import dataclass

from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_readonly import VAULT_OPERATIONS, readonly_client

_ACCOUNT_IN_ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
_CACHE_MARGIN = _dt.timedelta(minutes=5)
ROLE_NAME = re.compile(r"[A-Za-z0-9+=,.@_-]{1,64}")
# AccountSession.via of a session chained from the scanner to the value-reader role.
VALUE_READER_ROLE = "VALUE_READER_ROLE"
ClientFactory = Callable[[str, str, "str | None", "dict | None"], object]  # (purpose, service, region, creds)
IdentityProbe = Callable[[str, bool], dict]  # (purpose, fresh) -> cremore_aws_provider.aws_identity.describe(...)


def account_of_arn(arn: str | None) -> str | None:
    """The 12-digit account in an ARN, or None when it does not name one."""
    match = _ACCOUNT_IN_ARN.match(arn or "")
    return match[1] if match else None


@dataclass
class AccountSession:
    account_id: str
    purpose: str
    via: str  # ROLE | RUNTIME_IDENTITY | SSO_PERMISSION_SET | VALUE_READER_ROLE
    credentials: dict | None
    _factory: ClientFactory
    # "<access_revision>:<approval_revision>" this session was authorized under.
    pin: str = ""

    def client(self, service: str, region: str | None = None, *, operations=None):
        client = self._factory(self.purpose, service, region, self.credentials)
        if self.via == VALUE_READER_ROLE:  # value-read clients only, whatever the purpose or the caller says
            return readonly_client(client, service, VAULT_OPERATIONS)
        if self.purpose != aws_access.SCANNER:
            return client
        return readonly_client(client, service, operations) if operations else readonly_client(client, service)

    def evidence(self) -> dict:
        """Recorded with anything collected through this session."""
        return {"collected_account_id": self.account_id, "collected_via": self.via}


class AccountSessions:
    def __init__(self, repo, settings, *, client_factory: ClientFactory, identity: IdentityProbe,
                 now: Callable[[], _dt.datetime] | None = None) -> None:
        self.repo, self.settings = repo, settings
        self.client_factory, self.identity = client_factory, identity
        self.now = now or (lambda: _dt.datetime.now(_dt.UTC))
        self._cache: dict[tuple, dict] = {}

    def _account(self, account_id: str):
        return next((a for a in self.repo.list_aws_accounts() if a.account_id == account_id), None)

    def refusal(self, account_id: str | None, purpose: str, *, fresh: bool = False) -> tuple[str | None, object, dict | None]:
        """(code, account, approval) without calling AWS beyond the identity probe."""
        if not account_id:
            return "ACCOUNT_OWNER_UNKNOWN", None, None
        account = self._account(account_id)
        if account is None:
            return "ACCOUNT_NOT_CONNECTED", None, None
        approved = aws_access.approval(self.repo, purpose, self.settings)
        if approved is None:
            return "IDENTITY_NOT_APPROVED", account, None
        if code := aws_access.use_refusal(account, purpose, approved):
            return code, account, approved
        current = self.identity(purpose, fresh or purpose == aws_access.REMEDIATION)
        if current.get("state") in ("LOGIN_REQUIRED", "NO_CREDENTIALS"):
            return "AWS_LOGIN_REQUIRED", account, approved
        if current.get("state") != "READY":
            return "AWS_IDENTITY_UNAVAILABLE", account, approved
        if approved.get("match_key"):
            matches = current.get("match_key") == approved["match_key"]
        else:  # pinned by configuration: an exact role ARN
            matches = current.get("principal_arn") == approved.get("principal_arn")
        if not matches:
            return "AWS_IDENTITY_CHANGED", account, approved
        if account.access == aws_access.RUNTIME_IDENTITY and current.get("account_id") != account.account_id:
            return "ACCOUNT_MISMATCH", account, approved
        if account.access == aws_access.SSO_PERMISSION_SET:
            if not account.sso_role_name:
                return "ACCESS_NOT_CONFIGURED", account, approved
            # match_key proves the permission set CreMore RUNS as; it says nothing
            # about which directory vends the other accounts. Pin that separately.
            approved_url = approved.get("sso_start_url")
            if not approved_url:
                return "AWS_SSO_SESSION_UNKNOWN", account, approved
            if current.get("sso_start_url") != approved_url:
                return "AWS_SSO_SESSION_CHANGED", account, approved
        return None, account, approved

    def open(self, account_id: str | None, purpose: str) -> AccountSession:
        return self._open(account_id, purpose)[0]

    def value_reader(self, account_id: str | None, role_name: str, label: str) -> AccountSession:
        """This account's value-reader role, assumed from its scanner session.

        The scanner session opens first, with every check ``open`` makes; only member-role
        access chains (the role trusts the scanner role and the account's ExternalId). Never
        cached: the credentials last 900 seconds and a long run asks again before they expire
        (cremore.coverage.job). ``label`` names the connection in the RoleSessionName.
        """
        scanner, account = self._open(account_id, aws_access.SCANNER, role_only=True)
        return chain_value_reader(scanner, value_reader_arn(account.scanner_role_arn, account.account_id, role_name),
                                  account.external_id, label, region=getattr(self.settings, "aws_region", None),
                                  now=self.now)

    def _open(self, account_id: str | None, purpose: str, *, role_only: bool = False) -> tuple[AccountSession, object]:
        code, account, approved = self.refusal(account_id, purpose)
        if code:
            raise aws_access.AccessBlocked(code)
        if role_only and account.access != aws_access.ROLE:
            # Before anything is vended or cached: the value reader trusts the member scanner role only.
            raise aws_access.AccessBlocked("VALUE_READER_NEEDS_ROLE_ACCESS")
        pin = aws_access.validation_key(account, purpose, approved["revision"])
        if account.access == aws_access.RUNTIME_IDENTITY:
            return AccountSession(account.account_id, purpose, aws_access.RUNTIME_IDENTITY, None, self.client_factory,
                                  pin), account
        via = aws_access.SSO_PERMISSION_SET if account.access == aws_access.SSO_PERMISSION_SET else aws_access.ROLE
        if via == aws_access.SSO_PERMISSION_SET:
            role, external_id = account.sso_role_name, None
        else:
            role = account.scanner_role_arn if purpose == aws_access.SCANNER else account.remediation_role_arn
            external_id = account.external_id
        # A permission set takes the role ARN's cache slot; both access modes
        # share expiration and eviction, keyed by the same approval revisions.
        key = (purpose, str(account.id), account.access, role, external_id,
               aws_access.access_revision(account, purpose), approved["revision"])
        cached = self._cache.get(key) if purpose == aws_access.SCANNER else None
        if cached is None or cached["Expiration"] - _CACHE_MARGIN <= self.now():
            cached = (self._vend(account, purpose, approved) if via == aws_access.SSO_PERMISSION_SET
                      else self._assume(account, purpose, role))
            if purpose == aws_access.SCANNER:
                self._cache = {k: v for k, v in self._cache.items() if k[:2] != key[:2]}
                self._cache[key] = cached
        return AccountSession(account.account_id, purpose, via, cached, self.client_factory, pin), account

    def _vend(self, account, purpose: str, approved: dict) -> dict:
        """Identity Center credentials for this account's permission set.

        Never proves the account: ``refusal`` already did, and the recorded
        validation proved the vended role really is in it. A vended credential
        whose account turned out wrong would have failed validation first.
        """
        from cremore_aws_provider import aws_sso
        from cremore_aws_provider.aws_identity import AwsLoginRequired, is_login_required

        try:
            region = aws_sso.region_for(approved)
            token = aws_sso.access_token()
            sso = self.client_factory(purpose, "sso", region, None)
            return aws_sso.role_credentials(sso, token, account.account_id, account.sso_role_name, now=self.now)
        except AwsLoginRequired:
            raise
        except aws_sso.SsoRegionUnknown as exc:
            raise aws_access.AccessBlocked("IDENTITY_CENTER_REGION_REQUIRED") from exc
        except aws_sso.SsoCacheNotWritable as exc:
            # The assignment is fine; the token cache just cannot be rewritten.
            raise aws_access.AccessBlocked("SSO_CACHE_NOT_WRITABLE") from exc
        except aws_sso.SsoRoleUnavailable as exc:
            raise aws_access.AccessBlocked("SSO_ROLE_NOT_ASSIGNED") from exc
        except Exception as exc:  # Report SDK failures as safe codes.
            if is_login_required(exc):
                raise AwsLoginRequired() from exc
            raise aws_access.AccessBlocked("SSO_ROLE_NOT_ASSIGNED") from exc

    def _assume(self, account, purpose: str, role_arn: str) -> dict:
        sts = self.client_factory(purpose, "sts", getattr(self.settings, "aws_region", None), None)
        return assume_role_credentials(sts, account.account_id, role_arn, account.external_id, purpose, now=self.now)


def value_reader_arn(scanner_role_arn: str | None, account_id: str, role_name: str) -> str:
    """The account's value-reader role, in its scanner role's partition."""
    if not scanner_role_arn or not ROLE_NAME.fullmatch(role_name or ""):
        raise aws_access.AccessBlocked("VALUE_READER_ROLE_INVALID")
    return f"arn:{scanner_role_arn.split(':')[1]}:iam::{account_id}:role/{role_name}"


def chain_value_reader(scanner: AccountSession, role_arn: str, external_id, label: str, *, region, now) -> AccountSession:
    """Assume ``role_arn`` with ``scanner``'s credentials and the account's ExternalId.

    Shared by registered accounts and an unregistered draft's check. AWS caps a chained
    session at one hour; this one lasts 900 seconds. The RoleSessionName carries ``label``
    so CloudTrail tells value reads apart from the scanner's own work.
    """
    if scanner.purpose != aws_access.SCANNER or scanner.via != aws_access.ROLE:
        raise aws_access.AccessBlocked("VALUE_READER_NEEDS_ROLE_ACCESS")
    creds = assume_role_credentials(scanner.client("sts", region), scanner.account_id, role_arn, external_id,
                                    scanner.purpose, now=now, session_name=f"cremore-vault-{label}"[:64],
                                    denied="VALUE_READER_ASSUME_DENIED")
    return AccountSession(scanner.account_id, scanner.purpose, VALUE_READER_ROLE, creds, scanner._factory, scanner.pin)


def assume_role_credentials(sts, account_id, role_arn, external_id, purpose, *, now, session_name=None,
                            denied="ASSUME_ROLE_DENIED"):
    """Read-only STS proof shared by registered sessions and an unregistered draft.

    The caller must first verify its scanner approval and the target's trust
    configuration. Credentials stay in the worker's memory.
    """
    from cremore_aws_provider.aws_identity import AwsLoginRequired, is_login_required

    try:
        result = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name or f"cremore-{purpose}",
                                 DurationSeconds=900, ExternalId=external_id)
    except Exception as exc:  # reported as a safe code
        if is_login_required(exc):
            raise AwsLoginRequired() from exc
        raise aws_access.AccessBlocked(denied) from exc
    if account_of_arn((result.get("AssumedRoleUser") or {}).get("Arn")) != account_id:
        raise aws_access.AccessBlocked("ACCOUNT_MISMATCH")
    creds = result["Credentials"]
    expiration = creds.get("Expiration")
    if not isinstance(expiration, _dt.datetime):
        expiration = now() + _dt.timedelta(seconds=900)
    return {"AccessKeyId": creds["AccessKeyId"], "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds["SessionToken"], "Expiration": expiration}


def boto3_client_factory(settings) -> ClientFactory:
    """Clients for the base identity of a purpose, or for assumed-role credentials."""

    def factory(purpose: str, service: str, region: str | None, credentials: dict | None):
        import boto3

        if credentials:
            session = boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                                    aws_secret_access_key=credentials["SecretAccessKey"],
                                    aws_session_token=credentials["SessionToken"])
        elif purpose == aws_access.REMEDIATION and getattr(settings, "aws_remediation_profile", ""):
            session = boto3.Session(profile_name=settings.aws_remediation_profile)
        else:
            session = boto3.Session()
        return session.client(service, region_name=region or settings.aws_region)

    return factory


def identity_probe(client_factory: ClientFactory, *, ttl_seconds: float = 15.0) -> IdentityProbe:
    """What each purpose's base identity is; cached briefly unless ``fresh``."""
    import time

    from cremore_aws_provider import aws_identity

    cache: dict[str, tuple[float, dict]] = {}

    def probe(purpose: str, fresh: bool) -> dict:
        now = time.monotonic()
        hit = cache.get(purpose)
        if not fresh and hit and now - hit[0] < ttl_seconds:
            return hit[1]
        try:
            local = aws_identity.local_sso_session()
            value = aws_identity.describe(client_factory(purpose, "sts", None, None),
                                          client_factory(purpose, "iam", None, None),
                                          sso_region=local["region"], sso_start_url=local["start_url"])
            if purpose == aws_access.SCANNER:
                value["credential_source"] = aws_identity.server_workload_source()
        except Exception as exc:  # noqa: BLE001 -- a missing SDK or profile is a reported state
            value = {"state": "ERROR", "error_code": aws_identity.error_code(exc)}
        cache[purpose] = (now, value)
        return value

    return probe
