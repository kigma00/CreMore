"""Read-only AWS Organizations account discovery.

When an administrator switches the sweep on (``cremore/aws_org_settings.py``), the
worker lists the organization's accounts from a delegated-administrator account
and registers new ones
(``source = ORGANIZATION``) so they do not have to be added to the dashboard by
hand. Each account's organization facts are recorded (``org_state``,
``org_present``, ``in_deployment_scope``); ``cremore_aws_provider.aws_access`` turns those into
use/validation blocks, so an account that is suspended, has left the org, or
falls outside the configured OUs is blocked from scanning without deleting its
record. An account's lifecycle comes from the response's ``State`` (falling back
to the older ``Status``); an undetermined state is recorded as such, never as a
false ACTIVE.

Discovery can optionally limit itself to a set of OUs (nested OUs included) and,
opt-in, immediately queue a new account's scanner-role validation so it becomes
READY at once. It only ever reads Organizations and writes the local account
registry; it never mutates AWS and never deletes an account record.
"""

from __future__ import annotations

import logging

from cremore.domain.models import AwsAccount

logger = logging.getLogger("cremore_aws_provider.aws_org_discovery")

# Matches the member scanner role name the CloudFormation templates create.
SCANNER_ROLE_NAME = "CredentialExposureScannerRole"


def _account_state(acct: dict) -> str | None:
    """The account's lifecycle state, or None when the response omits it.

    Organizations returns the richer ``State`` (PENDING_ACTIVATION, ACTIVE,
    SUSPENDED, PENDING_CLOSURE, CLOSED) and, on older responses, the narrower
    ``Status`` (ACTIVE, SUSPENDED, PENDING_CLOSURE). ``State`` wins; an absent or
    empty value stays None so the account is treated as state-undetermined.
    """

    value = acct.get("State") or acct.get("Status")
    return str(value) if value else None


def list_org_accounts(org_client) -> list[dict]:
    """Every account in the organization as ``{id, name, state}``, paginated."""

    out: list[dict] = []
    for page in org_client.get_paginator("list_accounts").paginate():
        for acct in page.get("Accounts", []):
            account_id = str(acct.get("Id") or "")
            if account_id:
                out.append({"id": account_id,
                            "name": str(acct.get("Name") or account_id),
                            "state": _account_state(acct)})
    return out


def accounts_under_ous(org_client, ou_ids) -> set[str]:
    """Account ids under the given OU ids, descending nested OUs."""

    seen: set[str] = set()
    stack = list(ou_ids)
    found: set[str] = set()
    while stack:
        parent = stack.pop()
        if parent in seen:
            continue
        seen.add(parent)
        for page in org_client.get_paginator("list_accounts_for_parent").paginate(ParentId=parent):
            for acct in page.get("Accounts", []):
                if acct.get("Id"):
                    found.add(str(acct["Id"]))
        for page in org_client.get_paginator("list_organizational_units_for_parent").paginate(ParentId=parent):
            for ou in page.get("OrganizationalUnits", []):
                if ou.get("Id"):
                    stack.append(str(ou["Id"]))
    return found


def _partition(arn: str) -> str:
    parts = arn.split(":") if arn else []
    return parts[1] if len(parts) > 3 and parts[1] else "aws"


def reconcile_org_accounts(repo, settings, org_client, config: dict, *, queue_validation=None) -> dict:
    """Register new in-scope org accounts and refresh org facts on known ones.

    ``config`` is the effective configuration an administrator set in the
    dashboard, or pinned in the environment (``cremore/aws_org_settings.py``): its
    ``external_id``, ``ou_ids`` and ``excludes``. This module never reads them
    from either place itself. ``queue_validation`` (opt-in) is called with each
    newly registered account so its scanner role is validated immediately. One
    bad account never stops the sweep. Returns a summary for logging.
    """

    external_id = str((config or {}).get("external_id") or "").strip()
    if not external_id:
        # Without the StackSet's shared ExternalId a registered account could not
        # be assumed, so registering it would only create broken records.
        logger.warning("org discovery skipped: no shared ExternalId has been set")
        return {"registered": [], "changed": [], "skipped": 0, "error": "no_external_id"}

    partition = _partition(settings.scanner_principal_arn)
    excluded = frozenset((config or {}).get("excludes") or ())
    ou_ids = frozenset((config or {}).get("ou_ids") or ())
    # None means "no OU limit"; a set means only these OUs' accounts are in scope.
    scoped = accounts_under_ous(org_client, ou_ids) if ou_ids else None

    listed = {a["id"]: a for a in list_org_accounts(org_client)}
    existing = {a.account_id: a for a in repo.list_aws_accounts()}
    registered: list[str] = []
    changed: list[str] = []
    skipped = 0

    for account_id, info in listed.items():
        if account_id in excluded:
            skipped += 1
            known = existing.get(account_id)
            if known is not None and known.source == "ORGANIZATION":
                want = {"org_state": info["state"], "org_present": True, "in_deployment_scope": False}
                diff = {key: value for key, value in want.items() if getattr(known, key) != value}
                if diff and repo.update_aws_account(known.id, **diff):
                    changed.append(account_id)
            continue
        in_scope = scoped is None or account_id in scoped
        state = info["state"]  # None when Organizations returned no state
        known = existing.get(account_id)
        if known is None:
            # Only bring in accounts that are usable now: ACTIVE and in scope. Any
            # other or undetermined state (SUSPENDED, CLOSED, PENDING_*, None) waits.
            if state != "ACTIVE" or not in_scope:
                continue
            try:
                created = repo.create_aws_account(AwsAccount(
                    account_id=account_id,
                    name=info["name"],
                    environment="",
                    scanner_role_arn=f"arn:{partition}:iam::{account_id}:role/{SCANNER_ROLE_NAME}",
                    external_id=external_id,
                    source="ORGANIZATION",
                    org_state=state,
                    org_present=True,
                    in_deployment_scope=(True if scoped is not None else None),
                ))
            except Exception as exc:  # noqa: BLE001 -- one bad account cannot stop the sweep
                logger.warning("org discovery could not register %s: %s", account_id, type(exc).__name__)
                continue
            registered.append(account_id)
            if queue_validation is not None:
                try:
                    queue_validation(created)
                except Exception as exc:  # noqa: BLE001 -- validation is a best-effort follow-up
                    logger.warning("could not queue validation for %s: %s", account_id, type(exc).__name__)
        elif known.source == "ORGANIZATION":
            # Refresh only org-sourced accounts; never stomp a hand-registered one.
            # A None state records ORG_STATE_UNKNOWN rather than a false ACTIVE.
            want = {"org_state": state, "org_present": True,
                    "in_deployment_scope": in_scope if scoped is not None else None}
            diff = {k: v for k, v in want.items() if getattr(known, k) != v}
            if diff and repo.update_aws_account(known.id, **diff):
                changed.append(account_id)
            # Retry an initially missing StackSet role on later sweeps/events.
            if queue_validation is not None and state == "ACTIVE" and in_scope and known.enabled:
                from cremore_aws_provider import aws_access
                approved = aws_access.approval(repo, aws_access.SCANNER, settings)
                current = repo.get_aws_account(known.id)
                if aws_access.effective_validation(current, aws_access.SCANNER, approved)["status"] != "VALID":
                    try:
                        queue_validation(current)
                    except Exception as exc:  # noqa: BLE001 -- one account must not stop reconciliation
                        logger.warning("could not queue validation for %s: %s", account_id, type(exc).__name__)

    # Org-sourced accounts absent from this complete sync have left the org.
    for account_id, acct in existing.items():
        if (acct.source == "ORGANIZATION" and account_id not in listed and acct.org_present is not False
                and repo.update_aws_account(acct.id, org_present=False)):
            changed.append(account_id)

    from cremore_aws_provider.aws_org_context import refresh_org_context
    refresh_org_context(repo, org_client)

    if registered or changed:
        logger.info("org discovery: registered %d, changed %d, skipped %d",
                    len(registered), len(changed), skipped)
    return {"registered": registered, "changed": changed, "skipped": skipped}
