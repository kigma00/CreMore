"""Read-only IAM Identity Center account discovery.

When an Admin switches the sweep on (``cremore/aws_sso_settings.py``), the worker
lists the accounts the operator's own sign-in is assigned to and registers the
ones that carry the chosen permission set (``source = SSO``,
``access = SSO_PERMISSION_SET``), so they do not have to be added to the
dashboard by hand and nothing is deployed into them.

The permission set is always named, never "whatever role this sign-in happens to
hold": an operator commonly also holds ``AdministratorAccess``, and discovering
accounts through that would hand CreMore far more than scanning needs.

Two facts are deliberately handled at different layers, because they fail
differently:

* **the account is no longer assigned** -- it disappears from ``sso:ListAccounts``,
  which this sweep records as ``org_present = False`` (``cremore_aws_provider.aws_access`` turns
  that into ``SSO_ASSIGNMENT_REMOVED``);
* **the permission set is no longer assigned in an account that is still
  listed** -- this sweep leaves the record alone and validation reports
  ``SSO_ROLE_NOT_ASSIGNED``. Reading one account's role list can fail on its own,
  and an empty list must never be mistaken for a removed assignment.

It only ever reads Identity Center and writes the local account registry; it
never mutates AWS and never deletes an account record.
"""

from __future__ import annotations

import logging

from cremore.domain.models import AwsAccount
from cremore_aws_provider import aws_access, aws_sso

logger = logging.getLogger("cremore_aws_provider.aws_sso_discovery")


def reconcile_sso_accounts(repo, settings, sso, token: str, permission_set: str, *,
                           queue_validation=None) -> dict:
    """Register newly assigned accounts and refresh presence on known ones.

    ``permission_set`` is the effective one an Admin chose in the dashboard, or
    the configured pin (``cremore/aws_sso_settings.py``); this module never reads it
    from either place itself. ``queue_validation`` is called with each newly
    registered account so its access is proved at once -- there is no stack to
    wait for. One bad account never stops the sweep. Returns a summary.
    """

    permission_set = (permission_set or "").strip()
    if not permission_set:
        # Without a named permission set a sweep could only guess which of the
        # operator's assignments CreMore should use. Guessing is not an option.
        logger.warning("sso discovery skipped: no permission set has been chosen")
        return {"registered": [], "changed": [], "skipped": 0, "error": "no_permission_set"}
    if not aws_sso.PERMISSION_SET.fullmatch(permission_set):
        logger.warning("sso discovery skipped: the chosen permission set is not a permission set name")
        return {"registered": [], "changed": [], "skipped": 0, "error": "bad_permission_set"}

    excluded = getattr(settings, "aws_sso_discovery_exclude_set", frozenset())
    # Materialised before any write: a listing that fails part way raises here
    # rather than leaving half the estate looking unassigned.
    listed = {entry["account_id"]: entry for entry in aws_sso.list_assigned(sso, token)}
    existing = {a.account_id: a for a in repo.list_aws_accounts()}
    registered: list[str] = []
    changed: list[str] = []
    skipped = 0

    for account_id, info in listed.items():
        if account_id in excluded:
            skipped += 1
            continue
        known = existing.get(account_id)
        if known is None:
            if permission_set not in info["roles"]:
                # Assigned to the account, but not with the permission set CreMore
                # is configured to use. Registering it would only create a record
                # that cannot be validated.
                skipped += 1
                continue
            try:
                created = repo.create_aws_account(AwsAccount(
                    account_id=account_id,
                    name=info["name"],
                    environment="",
                    access=aws_access.SSO_PERMISSION_SET,
                    sso_role_name=permission_set,
                    source="SSO",
                    org_present=True,
                ))
            except Exception as exc:  # noqa: BLE001 -- one bad account cannot stop the sweep
                logger.warning("sso discovery could not register %s: %s", account_id, type(exc).__name__)
                continue
            registered.append(account_id)
            if queue_validation is not None:
                try:
                    queue_validation(created)
                except Exception as exc:  # noqa: BLE001 -- validation is a best-effort follow-up
                    logger.warning("could not queue validation for %s: %s", account_id, type(exc).__name__)
        elif known.source == "SSO":
            # Refresh only SSO-sourced accounts; never stomp a hand-registered or
            # organization-registered one that happens to share an account id.
            want = {"org_present": True}
            if known.sso_role_name != permission_set and permission_set in info["roles"]:
                # The configured permission set changed and this account has it.
                # access_changes bumps the revision, which forces revalidation.
                want["sso_role_name"] = permission_set
            diff = {k: v for k, v in want.items() if getattr(known, k) != v}
            if diff and repo.update_aws_account(known.id, **aws_access.access_changes(known, diff)):
                changed.append(account_id)

    # SSO-sourced accounts absent from this complete sweep are no longer assigned.
    for account_id, account in existing.items():
        if (account.source == "SSO" and account_id not in listed
                and account_id not in excluded and account.org_present is not False
                and repo.update_aws_account(account.id, org_present=False)):
            changed.append(account_id)

    if registered or changed:
        logger.info("sso discovery: registered %d, changed %d, skipped %d",
                    len(registered), len(changed), skipped)
    return {"registered": registered, "changed": changed, "skipped": skipped}
