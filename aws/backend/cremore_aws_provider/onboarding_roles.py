"""Organizations metadata and member-role proof for server onboarding drafts.

Discovery never registers accounts or changes AWS. A predeployed StackSet's
ExternalId, or an existing account's exact role settings, is pinned in the draft.
Only completion may register the selected, successfully checked accounts.
"""

import datetime as dt
import secrets

from cremore_aws_provider import aws_access, aws_org_settings
from cremore_aws_provider.aws_org_discovery import SCANNER_ROLE_NAME, accounts_under_ous
from cremore_aws_provider.aws_readonly import readonly_client
from cremore_aws_provider.aws_sessions import AccountSession, assume_role_credentials


def _error(code):
    from cremore_aws_provider.onboarding import OnboardingValueError

    return OnboardingValueError(code)


def _config(repo, settings):
    config = aws_org_settings.config(settings, repo)
    return {key: config[key] for key in ("external_id", "ou_ids", "excludes")}


def _known(account):
    return {"id": str(account.id), "access_revision": account.access_revision,
            "access": account.access, "enabled": account.enabled, "scanner_role_arn": account.scanner_role_arn,
            "external_id": account.external_id, "source": account.source,
            "org_state": account.org_state, "org_present": account.org_present,
            "in_deployment_scope": account.in_deployment_scope}


def discover_roles(record, context, identity, approved):
    from cremore_aws_provider.onboarding import _ACCOUNT, _denied
    from cremore_aws_provider.onboarding_discovery import _BoundClient

    client = readonly_client(_BoundClient(context.aws_sessions.client_factory(
        aws_access.SCANNER, "organizations", context.settings.aws_region, None), context), "organizations")
    auth = record["target"]["auth"]
    config = _config(context.repo, context.settings)
    previous = auth.get("role_accounts", {}) if auth.get("role_config") == config else {}
    continuation = record.get("discovery_cursor") or {}
    if continuation and auth.get("role_config") != config:
        raise _error("AWS_ACCOUNT_SETTINGS_CHANGED")
    auth["role_config"] = config
    known = {a.account_id: a for a in context.repo.list_aws_accounts()}
    saved = auth.setdefault("role_accounts", {}) if continuation else {}
    auth["role_accounts"] = saved
    record.pop("discovery_notice", None)
    try:
        scoped = accounts_under_ous(client, config["ou_ids"]) if config["ou_ids"] else None
        token, seen, roots = continuation.get("next_token"), set(continuation.get("seen", [])), []
        # At most 200 accounts per job; the next page remains a private cursor.
        for _ in range(10):
            page = client.list_accounts(MaxResults=20, **({"NextToken": token} if token else {}))
            if not isinstance(page, dict) or not isinstance(page.get("Accounts"), list) or len(page["Accounts"]) > 20:
                raise _error("AWS_ORGANIZATIONS_RESPONSE_INVALID")
            for item in page["Accounts"]:
                if not isinstance(item, dict) or not isinstance(item.get("Id"), str) or not _ACCOUNT.fullmatch(item["Id"]):
                    raise _error("AWS_ORGANIZATIONS_RESPONSE_INVALID")
                aid = item["Id"]
                state = item.get("State") or item.get("Status")
                if state != "ACTIVE" or aid in config["excludes"] or (scoped is not None and aid not in scoped):
                    continue
                current = known.get(aid)
                name = str(item.get("Name") or aid)[:128]
                saved[aid] = _account(current, aid, name, approved, config, source="ORGANIZATION", previous=previous.get(aid))
                roots.append({"label": f"{name} · {aid}", "target": {"accounts": [aid]}})
            if len(saved) > 10000:
                raise _error("ONBOARDING_TARGET_LIMIT")
            token = page.get("NextToken")
            if not token:
                _setup(record, context, approved)
                return roots, "COMPLETE", None
            if not isinstance(token, str) or len(token) > 8192 or token in seen:
                raise _error("AWS_ORGANIZATIONS_PAGINATION_INVALID")
            seen.add(token)
        _setup(record, context, approved)
        return roots, "PARTIAL", {"next_token": token, "seen": sorted(seen)}
    except Exception as exc:
        no_org = getattr(exc, "response", {}).get("Error", {}).get("Code") == "AWSOrganizationsNotInUseException"
        if _denied(exc) or no_org:
            # Do not reinterpret a failed OU restriction or later page as a
            # different scope. Local account candidates still require STS proof.
            if config["ou_ids"] or continuation:
                raise _error("AWS_ORGANIZATIONS_ACCESS_DENIED") from None
            saved.clear()
            candidates = {aid: account for aid, account in known.items()
                          if account.enabled and account.access == aws_access.ROLE and not aws_access.org_blocks(account)}
            own = identity["account_id"]
            if own not in known:
                candidates[own] = None
            for aid, account in candidates.items():
                if aid not in config["excludes"]:
                    saved[aid] = _account(account, aid, account.name if account else aid, approved, config, source="MANUAL", previous=previous.get(aid))
            if not saved:
                raise _error("AWS_ORGANIZATIONS_ACCESS_DENIED") from None
            record["discovery_notice"] = "AWS_ORGANIZATIONS_NOT_AVAILABLE"
            _setup(record, context, approved)
            return [{"label": a["name"], "target": {"accounts": [aid]}} for aid, a in saved.items()], "PARTIAL", None
        raise


def _account(current, aid, name, approved, config, *, source, previous=None):
    return {"name": name, "known": _known(current) if current else None, "source": source,
            "scanner_role_arn": current.scanner_role_arn if current else
                f"arn:{approved.get('partition') or 'aws'}:iam::{aid}:role/{SCANNER_ROLE_NAME}",
            "external_id": current.external_id if current else config["external_id"] or (previous or {}).get("external_id") or secrets.token_urlsafe(24)}


def _setup(record, context, approved):
    from cremore_aws_provider.aws_identity import cli_command, stack_parameters

    trust = approved.get("trust")
    if not trust:
        return
    record["target"]["generated"] = {"aws_roles": [{"account_id": aid,
        "role_arn": a["scanner_role_arn"], "existing": bool(a["known"]),
        "parameters": stack_parameters(trust, target_account=aid, external_id=a["external_id"],
            role_name=a["scanner_role_arn"].rsplit("/", 1)[-1]),
        "command": cli_command(stack_parameters(trust, target_account=aid, external_id=a["external_id"],
            role_name=a["scanner_role_arn"].rsplit("/", 1)[-1]), region=context.settings.aws_region,
            template_file="member-account-role.yaml", stack_name="cremore-scanner")}
        for aid, a in record["target"]["auth"]["role_accounts"].items() if a["scanner_role_arn"] and a["external_id"]]}


def role_account(record, account_id, repo, settings):
    """Recheck the trust settings both before an AWS call and at completion."""
    auth = record["target"].get("auth", {})
    config = _config(repo, settings)
    if auth.get("role_config") != config:
        raise _error("AWS_ACCOUNT_SETTINGS_CHANGED")
    saved = auth.get("role_accounts", {}).get(account_id)
    if not isinstance(saved, dict):
        raise _error("AWS_ACCOUNT_NOT_DISCOVERED")
    current = next((a for a in repo.list_aws_accounts() if a.account_id == account_id), None)
    if (_known(current) if current else None) != saved.get("known"):
        raise _error("AWS_ACCOUNT_SETTINGS_CHANGED")
    if current:
        if current.access != aws_access.ROLE:
            raise _error("ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS")
        if blocks := aws_access.org_blocks(current):
            raise _error(blocks[0])
    if not saved.get("scanner_role_arn") or not saved.get("external_id"):
        raise _error("AWS_MEMBER_ROLE_SETUP_REQUIRED")
    return saved


def registration(record, account_id, repo, settings):
    """Internal registration metadata; never accepted from a public request body."""
    saved = role_account(record, account_id, repo, settings)
    if saved["known"]:
        return None
    return {"external_id": saved["external_id"],
            "source": saved.get("source", "ORGANIZATION"),
            "in_deployment_scope": True if record["target"]["auth"]["role_config"]["ou_ids"] else None}


def open_role(record, context, approved):
    from cremore_aws_provider.onboarding_discovery import _BoundClient

    accounts = record["target"].get("accounts") or []
    if len(accounts) != 1:
        raise _error("AWS_ACCOUNT_IDS_INVALID")
    aid = accounts[0]
    saved = role_account(record, aid, context.repo, context.settings)
    key = ("onboarding-role", aid)
    if key in context.memo:
        return context.memo[key]

    def factory(*args):
        return _BoundClient(context.aws_sessions.client_factory(*args), context)

    creds = assume_role_credentials(factory(aws_access.SCANNER, "sts", context.settings.aws_region, None),
        aid, saved["scanner_role_arn"], saved["external_id"], aws_access.SCANNER, now=lambda: dt.datetime.now(dt.UTC))
    session = AccountSession(aid, aws_access.SCANNER, aws_access.ROLE, creds, factory)
    context.memo[key] = session
    return session


def open_reader(record, context, session, role_name):
    """Assume a draft account's value-reader role from its scanner session to prove the trust; returns its ARN.

    The session it makes is dropped: a check reads no value."""
    from cremore_aws_provider.aws_sessions import chain_value_reader, value_reader_arn

    if session.via != aws_access.ROLE:
        raise aws_access.AccessBlocked("VALUE_READER_NEEDS_ROLE_ACCESS")
    saved = role_account(record, session.account_id, context.repo, context.settings)
    arn = value_reader_arn(saved["scanner_role_arn"], session.account_id, role_name)
    chain_value_reader(session, arn, saved["external_id"], "check", region=context.settings.aws_region,
                       now=lambda: dt.datetime.now(dt.UTC))
    return arn
