"""The identity-based IAM policies attached to a principal, read as written (read-only IAM).

The curated simulation (``potential_access``) asks whether a few actions are
allowed; this reads policy statements, not effective grants: inline and managed policies on
the user and its groups, or on the role behind an assumed-role session, plus
the permissions boundary. It runs with CreMore's scanner session in the
principal's own account, never with the discovered credential.

Condition values are not stored (only operator and key). Resource policies
(bucket, KMS key), SCPs and session policies are outside this view.
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from urllib.parse import unquote

from cremore_aws_provider.aws_identity import collection_error_code
from cremore_aws_provider.aws_pagination import iam_pages

# Every IAM call this module makes (the scanner role grants exactly these).
READ_ACTIONS = (
    "iam:GetUser", "iam:ListUserPolicies", "iam:GetUserPolicy", "iam:ListAttachedUserPolicies",
    "iam:ListGroupsForUser", "iam:ListGroupPolicies", "iam:GetGroupPolicy", "iam:ListAttachedGroupPolicies",
    "iam:GetRole", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
    "iam:GetPolicy", "iam:GetPolicyVersion",
)
MAX_STATEMENTS = 300
MAX_ITEMS = 200
LIMITATIONS = (
    "Identity-based policies only: resource policies, SCPs and session policies can further allow or deny.",
    "Condition values are not stored; a conditional statement applies only when its condition matches.",
    "Quarantine policy attachments do not establish the attaching actor or exposure of a specific key.",
)
_USER = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:user/(?:.*/)?([\w+=,.@-]+)$")
_ROLE = re.compile(r"^arn:aws[a-z-]*:(?:iam::\d{12}:role/(?:.*/)?|sts::\d{12}:assumed-role/)([\w+=,.@-]+)(?:/[^/]+)?$")
_ROOT = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:root$")
# These AWS-managed policies can be attached by AWS or by a customer with IAM
# permission. The attachment identifies a policy on the principal, not an
# attaching actor or an exposure event for a particular key. Reject lookalikes
# in customer namespaces, but do not promote a genuine attachment to exposure.
_QUARANTINE = re.compile(r"^arn:aws[a-z-]*:iam::aws:policy/AWSCompromisedKeyQuarantine")


def _pages(call, key: str, **kwargs) -> list:
    out = []
    required = {"AttachedPolicies": "PolicyArn", "Groups": "GroupName"}.get(key)
    for page in iam_pages(call, **kwargs):
        items = page.get(key)
        if not isinstance(items, list):
            raise ValueError("IAM_LIST_MALFORMED")  # noqa: TRY004 -- preserve the malformed-response contract
        for item in items:
            value = _object(item).get(required) if required else item
            if not isinstance(value, str) or not value:
                raise ValueError("IAM_LIST_MALFORMED")
        out.extend(items)
    return out


def _object(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError("IAM_RESPONSE_MALFORMED")  # noqa: TRY004 -- preserve the malformed-response contract
    return value


def _items(value) -> tuple[list[str], bool]:
    values = [value] if isinstance(value, str) else [] if value is None else value
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        raise ValueError("IAM_POLICY_MALFORMED")
    return values[:MAX_ITEMS], len(values) > MAX_ITEMS


def _statements(document) -> list[dict]:
    if isinstance(document, str):
        document = json.loads(unquote(document))
    raw = _object(document).get("Statement", [])
    if not isinstance(raw, (dict, list)):
        raise ValueError("IAM_POLICY_MALFORMED")  # noqa: TRY004 -- preserve the malformed-response contract
    out = []
    for s in [raw] if isinstance(raw, dict) else raw:
        if not isinstance(s, dict) or s.get("Effect") not in ("Allow", "Deny"):
            raise ValueError("IAM_POLICY_MALFORMED")
        condition = _object(s.get("Condition", {}))
        if any(not isinstance(keys, dict) for keys in condition.values()):
            raise ValueError("IAM_POLICY_MALFORMED")
        row = {"sid": str(s.get("Sid") or "")[:128], "effect": s["Effect"],
               "condition_keys": sorted(f"{op}:{key}" for op, keys in condition.items() for key in keys)[:MAX_ITEMS]}
        truncated = False
        for field, source in (("actions", "Action"), ("not_actions", "NotAction"),
                              ("resources", "Resource"), ("not_resources", "NotResource")):
            row[field], cut = _items(s.get(source))
            truncated |= cut
        row["truncated"] = truncated
        out.append(row)
    return out


def _everything(s: dict) -> bool:
    """Unconditional ``*`` on ``*``."""
    return "*" in s["actions"] and "*" in s["resources"] and not (s["condition_keys"] or s["not_actions"] or s["not_resources"])


def summarize(policies: list[dict]) -> dict:
    boundary = [p for p in policies if p["source"] == "PERMISSIONS_BOUNDARY"]
    granted = [p for p in policies if p["source"] != "PERMISSIONS_BOUNDARY"]
    statements = [s for p in policies for s in p["statements"]]
    # An explicit deny in any applicable policy overrides every allow, including resource policies.
    deny_all = [p["name"] for p in policies if any(s["effect"] == "Deny" and _everything(s) for s in p["statements"])]
    allow_all = [p["name"] for p in granted if any(s["effect"] == "Allow" and _everything(s) for s in p["statements"])]
    bounded = bool(boundary) and not any(s["effect"] == "Allow" and _everything(s) for p in boundary for s in p["statements"])
    allowed = sorted({a for p in granted for s in p["statements"] if s["effect"] == "Allow" for a in s["actions"]})
    return {
        "quarantine_policies": [p["name"] for p in policies if _QUARANTINE.match(str(p.get("arn") or ""))],
        "deny_all_policies": deny_all,
        "allow_all_policies": [] if deny_all else allow_all,
        "permissions_boundary": bool(boundary),
        "boundary_limits_allow_all": bool(allow_all) and bounded,
        "allow_statements": sum(s["effect"] == "Allow" for s in statements),
        "deny_statements": sum(s["effect"] == "Deny" for s in statements),
        "conditional_statements": sum(bool(s["condition_keys"]) for s in statements),
        "allowed_actions": allowed[:MAX_ITEMS],
        "allowed_actions_truncated": len(allowed) > MAX_ITEMS,
    }


def collect_identity_policies(iam, principal_arn: str, now: _dt.datetime | None = None) -> dict:
    """Read the principal's identity policies with a read-only IAM client; never raises."""

    arn = str(principal_arn or "")
    base = {"principal_arn": arn, "method": "IAM_IDENTITY_POLICY_DOCUMENTS",
            "collected_at": (now or _dt.datetime.now(_dt.UTC)).isoformat(), "limitations": list(LIMITATIONS)}
    if _ROOT.match(arn):
        return {**base, "collection_status": "NOT_APPLICABLE", "principal_type": "ROOT", "policies": [], "errors": []}
    user, role = _USER.match(arn), _ROLE.match(arn)
    if not (user or role):
        return {**base, "collection_status": "UNSUPPORTED", "principal_type": "UNKNOWN", "policies": [], "errors": []}
    policies: list[dict] = []
    errors: list[dict] = []
    documents: dict[str, list[dict]] = {}
    succeeded = 0

    def attempt(step: str, fn, default=None):
        nonlocal succeeded
        try:
            value = fn()
            succeeded += 1
            return value
        except Exception as exc:  # noqa: BLE001 -- recorded as a safe code, never provider text
            errors.append({"step": step, "error_code": collection_error_code(exc)})
            return default

    def managed(arn_: str, name: str, source: str, **extra) -> None:
        def read():
            if arn_ not in documents:
                version = iam.get_policy(PolicyArn=arn_)["Policy"]["DefaultVersionId"]
                documents[arn_] = _statements(iam.get_policy_version(PolicyArn=arn_, VersionId=version)["PolicyVersion"]["Document"])
            return documents[arn_]
        statements = attempt(f"GetPolicyVersion:{name}", read)
        if statements is not None:
            policies.append({"source": source, "name": name, "arn": arn_, "aws_managed": ":iam::aws:policy/" in arn_,
                             "statements": statements, **extra})

    # Operations are looked up inside ``attempt`` so a refused one is recorded, never raised.
    def inline(kind: str, source: str, **target) -> None:
        listed = attempt(f"List{kind}Policies", lambda: _pages(getattr(iam, f"list_{kind.lower()}_policies"), "PolicyNames", **target), [])
        for name in listed:
            statements = attempt(f"Get{kind}Policy:{name}", lambda name=name: _statements(
                getattr(iam, f"get_{kind.lower()}_policy")(**target, PolicyName=name)["PolicyDocument"]))
            if statements is not None:
                policies.append({"source": source, "name": name, "statements": statements,
                                 **({"group": target["GroupName"]} if "GroupName" in target else {})})

    def attached(kind: str, source: str, **target) -> None:
        listed = attempt(f"ListAttached{kind}Policies",
                         lambda: _pages(getattr(iam, f"list_attached_{kind.lower()}_policies"), "AttachedPolicies", **target), [])
        for item in listed:
            managed(item["PolicyArn"], item.get("PolicyName") or item["PolicyArn"].rsplit("/", 1)[-1], source,
                    **({"group": target["GroupName"]} if "GroupName" in target else {}))

    if user:
        name = user.group(1)
        entity = attempt("GetUser", lambda: _object(iam.get_user(UserName=name)["User"]), {})
        inline("User", "INLINE_USER", UserName=name)
        attached("User", "MANAGED_USER", UserName=name)
        for group in attempt("ListGroupsForUser", lambda: _pages(iam.list_groups_for_user, "Groups", UserName=name), []):
            inline("Group", "INLINE_GROUP", GroupName=group["GroupName"])
            attached("Group", "MANAGED_GROUP", GroupName=group["GroupName"])
    else:
        name = role.group(1)
        entity = attempt("GetRole", lambda: _object(iam.get_role(RoleName=name)["Role"]), {})
        inline("Role", "INLINE_ROLE", RoleName=name)
        attached("Role", "MANAGED_ROLE", RoleName=name)
    boundary = entity.get("PermissionsBoundary", {})
    if not isinstance(boundary, dict) or (boundary and not isinstance(boundary.get("PermissionsBoundaryArn"), str)):
        errors.append({"step": "PermissionsBoundary", "error_code": "IAM_RESPONSE_MALFORMED"})
        boundary = {}
    if boundary.get("PermissionsBoundaryArn"):
        managed(boundary["PermissionsBoundaryArn"], boundary["PermissionsBoundaryArn"].rsplit("/", 1)[-1], "PERMISSIONS_BOUNDARY")

    summary = summarize(policies)  # from every statement read, before the stored list is capped
    total = truncated = 0
    for policy in policies:
        keep = policy["statements"][:max(0, MAX_STATEMENTS - total)]
        truncated += len(policy["statements"]) - len(keep)
        policy["statements"], total = keep, total + len(keep)
    status = "COMPLETE" if not errors else "PARTIAL" if succeeded else "FAILED"
    return {**base, "collection_status": status, "principal_type": "IAM_USER" if user else "IAM_ROLE",
            "policies": policies, "errors": errors, "summary": summary, "statements_truncated": truncated > 0}


def quarantined(credential) -> bool:
    """Legacy name: whether a saved snapshot records a quarantine policy attachment.

    Read from the saved identity-policy snapshot, and only when that snapshot was
    collected in the principal's own account — the same gate the rest of the
    dashboard applies before it treats a snapshot as evidence about the principal.
    This establishes neither the attaching actor nor exposure of a specific key,
    and must not be used to raise risk or infer credential status.
    """

    from cremore_aws_provider.aws_sessions import account_of_arn

    snapshot = getattr(credential, "usage_snapshot", None) or {}
    owner = account_of_arn(getattr(credential, "principal_arn", "") or "")
    if not owner or snapshot.get("collected_account_id") != owner:
        return False
    summary = (snapshot.get("identity_policies") or {}).get("summary") or {}
    return bool(summary.get("quarantine_policies"))
