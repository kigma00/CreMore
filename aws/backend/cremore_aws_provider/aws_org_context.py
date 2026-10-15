"""Bounded Organizations topology, stored separately from access approvals."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

from cremore_aws_provider.aws_identity import error_code

SUMMARY_KEY = "aws-organization-context"
ACCOUNT_PREFIX = "aws-account-context:"
MAX_REQUESTS = 5000
MAX_ITEMS = 100000


class ContextLimit(ValueError):
    code = "AWS_CONTEXT_BUDGET_EXCEEDED"


class Reader:
    def __init__(self, client, check=None):
        self.client, self.check, self.requests, self.items = client, check or (lambda: None), 0, 0

    def call(self, operation, **kwargs):
        self.check()
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise ContextLimit()
        return getattr(self.client, operation)(**kwargs)

    def pages(self, operation, key, **kwargs):
        token, seen = None, set()
        # Organizations uses NextToken; Control Tower uses nextToken.
        token_key = "nextToken" if operation in ("list_baselines", "list_enabled_baselines") else "NextToken"
        while True:
            page = self.call(operation, **kwargs, **({token_key: token} if token else {}))
            rows = page.get(key, [])
            if not isinstance(rows, list):
                raise TypeError("AWS_CONTEXT_INVALID_RESPONSE")
            self.items += len(rows)
            if self.items > MAX_ITEMS:
                raise ContextLimit()
            yield from rows
            token = page.get(token_key)
            if not token:
                return
            if not isinstance(token, str) or len(token) > 8192 or token in seen:
                raise ValueError("AWS_CONTEXT_PAGINATION_CYCLE")
            seen.add(token)


def account_context(repo, account_id):
    value = deepcopy((repo.get_setting(ACCOUNT_PREFIX + account_id) or {}).get("value") or {})
    value.setdefault("organization", {"status": "NOT_COLLECTED", "path": []})
    value.setdefault("control_tower", {"status": "NOT_COLLECTED", "account_status": "UNKNOWN"})
    return value


def put_account_context(repo, account_id, section, value):
    from cremore.db.settings_store import locked_settings

    with locked_settings(repo, account_id=account_id) as bound:
        current = account_context(bound, account_id)
        current[section] = value
        bound.put_setting(ACCOUNT_PREFIX + account_id, current, "aws-discovery")


def refresh_org_context(repo, org_client, *, check=None, now=None):
    """Only a complete traversal replaces prior OU facts; failures remain visible."""
    now = (now or datetime.now(UTC)).isoformat()
    reader = Reader(org_client, check)
    previous = (repo.get_setting(SUMMARY_KEY) or {}).get("value") or {}
    try:
        organization = reader.call("describe_organization")["Organization"]
        organization_id = str(organization["Id"])[:64]
        management_id = str(organization.get("ManagementAccountId") or organization.get("MasterAccountId") or "")
        roots = list(reader.pages("list_roots", "Roots"))
        if not roots:
            raise ValueError("AWS_ORGANIZATION_ROOT_MISSING")
        stack = [(root, []) for root in roots]
        seen, account_paths = set(), {}
        while stack:
            node, ancestors = stack.pop()
            node_id = str(node["Id"])
            if node_id in seen:
                raise ValueError("AWS_ORGANIZATION_TREE_CYCLE")
            seen.add(node_id)
            path = [*ancestors, {"id": node_id[:128], "name": str(node.get("Name") or node_id)[:256]}]
            if len(path) > 100:
                raise ContextLimit()
            for account in reader.pages("list_accounts_for_parent", "Accounts", ParentId=node_id):
                aid = str(account["Id"])
                if aid in account_paths:
                    raise ValueError("AWS_ORGANIZATION_PARENT_CONFLICT")
                account_paths[aid] = path
            stack.extend((ou, path) for ou in reader.pages(
                "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=node_id))
        summary = {"status": "COMPLETE", "organization_id": organization_id,
                   "management_account_id": management_id, "last_successful_at": now, "reason": None}
        for account in repo.list_aws_accounts():
            path = account_paths.get(account.account_id, [])
            put_account_context(repo, account.account_id, "organization", {**summary,
                                "parent_id": path[-1]["id"] if path else None, "path": path})
    except Exception as exc:  # noqa: BLE001 -- optional metadata never invents membership
        summary = {**previous, "status": "PARTIAL", "reason": error_code(exc)}
        for account in repo.list_aws_accounts():
            old = account_context(repo, account.account_id)["organization"]
            put_account_context(repo, account.account_id, "organization",
                                {**old, "status": "PARTIAL", "reason": error_code(exc)})
    repo.put_setting(SUMMARY_KEY, summary, "aws-discovery")
    return summary
