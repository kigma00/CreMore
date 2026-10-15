"""Whether CreMore may validate or use an AWS account, per purpose.

Two purposes never share a result: ``scanner`` (read-only scanning and
investigation) and ``remediation`` (approved key actions). Each has its own
Admin-approved identity with a ``revision`` that grows on every approval.

A validation result is stored with the key ``<revision>:<approval_revision>``,
where ``revision`` is the purpose's own access revision, and counts only while
both still match: a change to that purpose's role, the ExternalId or a new
approval turns earlier results into "revalidation required" without a bulk
rewrite, and adding a remediation role never invalidates the scanner result. Results are written compare-and-set, so a check started under an
older revision never overwrites a newer one.

Organization blocks are computed from facts stored by the last complete
organization sync (state, membership, deployment scope); nothing "clears" a
block, so an ACTIVE state can never lift a deployment-scope exit.
"""

from __future__ import annotations

import datetime as _dt

from cremore.domain.models import ScanJob
from cremore_aws_provider import aws_identity

SCANNER = "scanner"
REMEDIATION = "remediation"
PURPOSES = (SCANNER, REMEDIATION)
ROLE = "ROLE"
RUNTIME_IDENTITY = "RUNTIME_IDENTITY"
# Identity Center vends this account's credentials for the operator's own
# permission set, so nothing is deployed into it (cremore/aws_sso.py). Scanner only.
SSO_PERMISSION_SET = "SSO_PERMISSION_SET"
ACCESS_MODES = (ROLE, RUNTIME_IDENTITY, SSO_PERMISSION_SET)
APPROVAL_KEYS = {SCANNER: aws_identity.APPROVED_IDENTITY_KEY, REMEDIATION: "aws_remediation_identity"}
# Fields that decide what each purpose trusts; a change bumps that purpose's
# revision. sso_role_name is in both: changing the permission set changes what
# CreMore can reach just as surely as swapping a role ARN does.
ACCESS_FIELDS = {"scanner": ("access", "scanner_role_arn", "external_id", "sso_role_name"),
                 "remediation": ("access", "remediation_role_arn", "external_id", "sso_role_name")}
REVISION_FIELDS = {"scanner": "access_revision", "remediation": "remediation_access_revision"}
_TERMINAL_ORG_STATES = ("CLOSED",)


class AccessBlocked(Exception):
    """The account may not be used for this purpose right now (safe code only)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def approval(repo, purpose: str, settings=None) -> dict | None:
    """The approved identity for a purpose, with its revision (0 = pinned by configuration)."""
    record = repo.get_setting(APPROVAL_KEYS[purpose])
    if record:
        value = dict(record["value"])
        value.setdefault("revision", 1)
        return value
    arn = getattr(settings, "scanner_principal_arn", "") if purpose == SCANNER and settings else ""
    if arn:
        return {"kind": "IAM_ROLE", "partition": arn.split(":")[1], "account_id": arn.split(":")[4],
                "principal_arn": arn, "match_key": None, "trust": {"type": "IamRole", "principal_arn": arn},
                "revision": 0, "source": "SETTING"}
    return None


def next_revision(repo, purpose: str) -> int:
    """Preview only; approval writers must use atomic ``save_approval``."""
    current = repo.get_setting(APPROVAL_KEYS[purpose])
    return int(current["value"].get("revision", 1)) + 1 if current else 1


def save_approval(repo, purpose: str, identity: dict, actor: str) -> dict:
    """Persist the approved identity with a distinct validation revision."""
    value = {key: identity.get(key) for key in (
        "kind", "partition", "account_id", "principal_arn", "match_key",
        "permission_set", "sso_region", "sso_start_url", "trust", "credential_source")}
    return repo.put_revisioned_setting(APPROVAL_KEYS[purpose], value, actor)["value"]


def _fields(purpose: str) -> tuple[str, str, str, str]:
    prefix = "" if purpose == SCANNER else "remediation_"
    return (f"{prefix}validation_status", f"{prefix}validation_detail", f"{prefix}validated_at",
            f"{prefix}validation_key")


def access_revision(account, purpose: str) -> int:
    return getattr(account, REVISION_FIELDS[purpose])


def validation_key(account, purpose: str, approval_revision: int) -> str:
    return f"{access_revision(account, purpose)}:{approval_revision}"


def configured(account, purpose: str) -> bool:
    if account.access == RUNTIME_IDENTITY:
        return True
    if account.access == SSO_PERMISSION_SET:
        # Scanning only in this release: key actions keep their separately
        # approved identity and that account's own remediation role, so an
        # operator's permission set can never become the path that disables keys.
        return purpose == SCANNER and bool(account.sso_role_name)
    role = account.scanner_role_arn if purpose == SCANNER else account.remediation_role_arn
    return bool(role and account.external_id)


def effective_validation(account, purpose: str, approved: dict | None) -> dict:
    """The stored result if it was produced under the current revisions, else what is needed."""
    status_f, detail_f, at_f, key_f = _fields(purpose)
    if not configured(account, purpose):
        return {"status": "NOT_CONFIGURED", "detail": None, "validated_at": None}
    if approved is None:
        return {"status": "PENDING", "detail": "IDENTITY_NOT_APPROVED", "validated_at": None}
    stored_key = getattr(account, key_f)
    if stored_key != validation_key(account, purpose, approved["revision"]):
        return {"status": "PENDING", "detail": "REVALIDATION_REQUIRED" if stored_key else None,
                "validated_at": None}
    return {"status": getattr(account, status_f), "detail": getattr(account, detail_f),
            "validated_at": getattr(account, at_f)}


def org_blocks(account) -> list[str]:
    """Every discovery fact that currently forbids use; evaluated independently.

    ponytail: SSO-discovered accounts reuse ``org_present`` for "the last
    complete sync still listed this account". The name says ORGANIZATION but the
    fact is the same one, and a third discovery source is what should pay for
    renaming the column. ``org_state`` has no Identity Center equivalent and is
    read for organization accounts only, so an SSO account is never blocked for
    a lifecycle state nothing reports.
    """
    if account.source not in ("ORGANIZATION", "SSO"):
        return []
    blocks = []
    if account.org_present is False:
        blocks.append("ORG_ACCOUNT_REMOVED" if account.source == "ORGANIZATION" else "SSO_ASSIGNMENT_REMOVED")
    if account.source == "ORGANIZATION":
        if account.org_state is None:
            blocks.append("ORG_STATE_UNKNOWN")
        elif account.org_state != "ACTIVE":
            blocks.append(f"ORG_ACCOUNT_{account.org_state}")
    if account.in_deployment_scope is False:
        blocks.append("OUT_OF_DEPLOYMENT_SCOPE")
    return blocks


def validation_refusal(account, purpose: str, approved: dict | None) -> str | None:
    """Why a validation cannot even be attempted. A prior VALID result is never required."""
    if not configured(account, purpose):
        return "ACCESS_NOT_CONFIGURED"
    if approved is None:
        return "IDENTITY_NOT_APPROVED"
    if account.source == "ORGANIZATION" and (account.org_present is False or account.org_state in _TERMINAL_ORG_STATES):
        return "ORG_ACCOUNT_GONE"
    if account.source == "SSO" and account.org_present is False:
        # The assignment is gone; a check could only re-prove that.
        return "SSO_ASSIGNMENT_GONE"
    return None


def use_refusal(account, purpose: str, approved: dict | None) -> str | None:
    """Why the account may not be used for this purpose now. Evaluated on every request."""
    if not account.enabled:
        return "ACCOUNT_DISABLED"
    if blocks := org_blocks(account):
        return blocks[0]
    result = effective_validation(account, purpose, approved)
    if result["status"] == "NOT_CONFIGURED":
        return "ACCESS_NOT_CONFIGURED"
    if result["status"] != "VALID":
        return result["detail"] or "ACCOUNT_NOT_VALIDATED"
    return None


def record_validation(repo, account, purpose: str, *, access_revision: int, approval_revision: int,
                      current_approval_revision: int | None, status: str, detail: str) -> bool:
    """Store a result only if it was produced under the account's and approval's current revisions."""
    if current_approval_revision != approval_revision:
        return False
    status_f, detail_f, at_f, key_f = _fields(purpose)
    # ponytail: the approval revision is compared just before the row CAS, not
    # inside it; a result racing a new approval is still inert because
    # effective_validation re-checks the key on every read.
    stored = repo.update_aws_account_if_revision(account.id, REVISION_FIELDS[purpose], access_revision, **{
        status_f: status, detail_f: detail, at_f: _dt.datetime.now(_dt.UTC),
        key_f: f"{access_revision}:{approval_revision}"})
    return stored is not None


def job_payload(account, purpose: str, approval_revision: int) -> dict:
    return {"aws_account_id": str(account.id), "purpose": purpose,
            "access_revision": access_revision(account, purpose), "approval_revision": approval_revision}


def pending_validations(repo) -> dict:
    # ponytail: looks at the newest 500 jobs; a duplicate beyond that is harmless (results are CAS).
    return {tuple(sorted((job.payload or {}).items())): str(job.id) for job in repo.list_jobs(500)
            if job.kind == aws_identity.ROLE_CHECK_JOB and job.status in ("QUEUED", "RUNNING")}


def queue_validation(repo, account, purpose: str, approval_revision: int, pending: dict | None = None) -> str:
    """Queue one check per (account, purpose, revisions); a pending identical check is reused."""
    wanted = job_payload(account, purpose, approval_revision)
    pending = pending_validations(repo) if pending is None else pending
    key = tuple(sorted(wanted.items()))
    if key not in pending:
        pending[key] = str(repo.enqueue_job(ScanJob(kind=aws_identity.ROLE_CHECK_JOB, payload=wanted)).id)
    return pending[key]


def access_changes(account, changes: dict) -> dict:
    """Bump each purpose's revision when a field that purpose trusts really changes."""
    out = dict(changes)
    for purpose, fields in ACCESS_FIELDS.items():
        if any(field in changes and changes[field] != getattr(account, field) for field in fields):
            out[REVISION_FIELDS[purpose]] = access_revision(account, purpose) + 1
    return out
