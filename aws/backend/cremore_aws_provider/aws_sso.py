"""IAM Identity Center assignments as a way into member accounts, for one sign-in.

``ROLE`` access reaches a member account by assuming a role CreMore's own
CloudFormation put there. ``SSO_PERMISSION_SET`` reaches it with the credentials
Identity Center already vends for the operator's own assignment, so nothing is
deployed: ``sso:ListAccounts`` is the account list and ``sso:GetRoleCredentials``
is the way in.

The trade is deliberate and narrow:

* it needs the interactive ``aws sso login`` token cached on this computer. The
  hourly access token is then renewed without anyone present, but only into a
  **writable** cache (botocore rewrites the file, rotated refresh token and all),
  and only until the client registration expires -- about 90 days -- after which
  a person must sign in again. That is why this is the single-operator (Docker
  Compose) default and the Helm chart ships it off;
* CreMore's reach is exactly the operator's own permission set, never a
  read-only role CreMore defined, so ``cremore_aws_provider.aws_readonly`` stays the boundary and
  what the permission set actually holds is reported, never assumed;
* the token is short-lived (an hour is common), so an expired one is reported as
  ``AWS_LOGIN_REQUIRED`` and AWS work waits, exactly as it does for a role.

Two shapes differ from the STS path and are normalised here so no caller has to
know which minted a credential: ``sso:GetRoleCredentials`` reports ``expiration``
as epoch **milliseconds** (``sts:AssumeRole`` returns a datetime), and its
credential keys are camelCase. The Region also differs -- the token is only
valid in the Region hosting the Identity Center instance, which is routinely not
``AWS_REGION``, where buckets are read.
"""

from __future__ import annotations

import datetime as _dt
import errno
import re
from collections.abc import Callable

from cremore_aws_provider.aws_identity import AwsLoginRequired, is_login_required

# The permission set name Identity Center embeds in the reserved role name:
# the character set and 32-character limit AWS documents for a permission set.
PERMISSION_SET = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,32}$")
_ACCOUNT_ID = re.compile(r"^\d{12}$")
# Assumed only when Identity Center reports no usable expiry. Short on purpose:
# a bad value must expire the session cache early, never pin a dead credential.
_FALLBACK_LIFETIME = _dt.timedelta(minutes=15)


class SsoRoleUnavailable(Exception):
    """Identity Center will not vend this (account, permission set) pair."""

    code = "SSO_ROLE_NOT_ASSIGNED"


class SsoRegionUnknown(Exception):
    """No Identity Center Region is known, so no ``sso`` client can be built."""

    code = "IDENTITY_CENTER_REGION_REQUIRED"


class SsoCacheNotWritable(Exception):
    """The token cache cannot be written, so the sign-in can never be refreshed.

    botocore rewrites ``~/.aws/sso/cache`` whenever it renews the hourly access
    token, and it also stores the rotated refresh token there. A read-only mount
    (a Kubernetes Secret, a read-only home) therefore fails with ``EROFS`` the
    moment a renewal is due -- which is neither an expired sign-in nor a
    withdrawn assignment, and must not be reported as either.
    """

    code = "SSO_CACHE_NOT_WRITABLE"


def access_token(profile: str = "") -> str:
    """The cached Identity Center token for the active profile's ``sso-session``.

    botocore owns the cache (``~/.aws/sso/cache``) and refreshes the token while
    the session is still valid, which is what lets a fresh ``aws sso login`` on
    the host reach a running container without restarting it.
    """
    import boto3
    import botocore.tokens

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        # boto3 keeps the botocore session private; cremore_aws_provider.aws_identity reads it the same way.
        token = botocore.tokens.create_token_resolver(session._session).load_token()
        value = token.get_frozen_token().token if token is not None else None
    except AwsLoginRequired:
        raise
    except OSError as exc:
        # Renewal rewrites the cache; a read-only or unwritable one stops here.
        if exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
            raise SsoCacheNotWritable(str(exc)) from exc
        raise
    except Exception as exc:  # An expired or missing cache is a reported state.
        if is_login_required(exc):
            raise AwsLoginRequired() from exc
        raise
    if not value:
        # No cached token at all: the operator has never signed in, or it was cleared.
        raise AwsLoginRequired()
    return str(value)


def region_for(approved: dict | None = None) -> str:
    """The Identity Center Region to call: the approved identity's, else this profile's.

    The approved value wins so a local config edit cannot quietly move CreMore
    to another Region's Identity Center between approval and use.
    """
    from cremore_aws_provider import aws_identity

    region = (approved or {}).get("sso_region")
    if not isinstance(region, str) or not region:
        region = aws_identity.local_sso_region()
    if not region:
        raise SsoRegionUnknown()
    return region


def client(region: str):
    """An ``sso`` client in the Identity Center Region, never the scan Region."""
    import boto3

    if not region:
        raise SsoRegionUnknown()
    return boto3.Session().client("sso", region_name=region)


def list_assigned(sso, token: str) -> list[dict]:
    """``[{account_id, name, email, roles}]`` for every account this sign-in has.

    ``roles`` holds that account's permission set names, sorted. An account whose
    role list cannot be read is still returned with an empty list, so one
    permission problem never silently shortens the account list.
    """
    out: list[dict] = []
    for page in _pages(sso, "list_accounts", accessToken=token):
        for entry in page.get("accountList") or []:
            account_id = str(entry.get("accountId") or "")
            if not _ACCOUNT_ID.fullmatch(account_id):
                continue  # Identity Center should never return one; never carry a malformed id.
            out.append({
                "account_id": account_id,
                "name": str(entry.get("accountName") or "").strip() or account_id,
                "email": str(entry.get("emailAddress") or "").strip() or None,
                "roles": account_roles(sso, token, account_id),
            })
    return out


def account_roles(sso, token: str, account_id: str) -> list[str]:
    """Permission set names assigned in one account, sorted; ``[]`` when unreadable."""
    names: set[str] = set()
    try:
        for page in _pages(sso, "list_account_roles", accessToken=token, accountId=account_id):
            for role in page.get("roleList") or []:
                name = str(role.get("roleName") or "")
                if PERMISSION_SET.fullmatch(name):
                    names.add(name)
    except AwsLoginRequired:
        raise
    except Exception:  # noqa: BLE001 -- one account's roles never hide the rest of the list
        return []
    return sorted(names)


def role_credentials(sso, token: str, account_id: str, role_name: str,
                     now: Callable[[], _dt.datetime] | None = None) -> dict:
    """STS-shaped credentials for one (account, permission set).

    Raises ``AwsLoginRequired`` when the sign-in is what expired, and
    ``SsoRoleUnavailable`` when Identity Center refuses the pair -- the
    assignment was removed, or it never existed.
    """
    clock = now or (lambda: _dt.datetime.now(_dt.UTC))
    try:
        payload = sso.get_role_credentials(accessToken=token, accountId=account_id, roleName=role_name)
    except AwsLoginRequired:
        raise
    except Exception as exc:  # Report either a required login or an unavailable role.
        if is_login_required(exc):
            raise AwsLoginRequired() from exc
        raise SsoRoleUnavailable(f"{role_name} is not available in {account_id}") from exc
    creds = (payload or {}).get("roleCredentials") or {}
    key, secret, session = creds.get("accessKeyId"), creds.get("secretAccessKey"), creds.get("sessionToken")
    if not (key and secret and session):
        raise SsoRoleUnavailable("Identity Center returned no usable credentials")
    return {"AccessKeyId": str(key), "SecretAccessKey": str(secret), "SessionToken": str(session),
            "Expiration": _expiry(creds.get("expiration"), clock)}


def _expiry(value, clock: Callable[[], _dt.datetime]) -> _dt.datetime:
    """``expiration`` is epoch MILLISECONDS here, unlike the datetime STS returns."""
    if isinstance(value, _dt.datetime):  # a stub, or a future API change
        return value if value.tzinfo else value.replace(tzinfo=_dt.UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        try:
            moment = _dt.datetime.fromtimestamp(value / 1000, _dt.UTC)
        except (OverflowError, OSError, ValueError):
            moment = None
        # A value in another unit reads as long past. Falling through re-mints
        # once per call instead of pinning an already-dead credential in cache.
        if moment is not None and moment > clock():
            return moment
    return clock() + _FALLBACK_LIFETIME


def _pages(sso, operation: str, **kwargs):
    try:
        yield from sso.get_paginator(operation).paginate(**kwargs)
    except AwsLoginRequired:
        raise
    except Exception as exc:  # An expired token requires a new login.
        if is_login_required(exc):
            raise AwsLoginRequired() from exc
        raise
