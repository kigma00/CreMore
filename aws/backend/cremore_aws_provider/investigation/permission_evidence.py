"""Saved IAM evidence for one principal. No AWS calls or authentication claims."""

from dataclasses import replace

from cremore_aws_provider.aws_sessions import account_of_arn
from cremore_aws_provider.investigation.potential_access import (
    ACTION_CATALOG,
    ActionDecision,
    PotentialAccess,
    _missing_context,
    to_risk_signal,
)


def permission_snapshot(snapshot, principal_arn):
    """Only the owner account's results naming this exact principal are reusable."""
    account = account_of_arn(principal_arn)
    if (not isinstance(snapshot, dict) or not account
            or snapshot.get("collected_account_id") != account
            or snapshot.get("collection_status") == "ACCOUNT_UNVERIFIED"):
        return {}
    return {key: row for key in ("identity_policies", "potential_access")
            if isinstance(row := snapshot.get(key), dict) and row.get("principal_arn") == principal_arn}


def saved_risk_signal(potential, account):
    """Re-read a complete saved simulation through the collector's score mapping. Version 2 keeps the missing
    condition context; version 3 adds actions allowed only on resources the principal's policies name."""
    result = PotentialAccess(potential.get("principal_arn", ""), "FAILED")
    rows = potential.get("actions")
    risks = dict(ACTION_CATALOG)
    if (potential.get("assessment_version") in (2, 3) and potential.get("collection_status") == "COMPLETE"
            and isinstance(rows, list) and len(rows) == len(risks)
            and all(isinstance(row, dict) and isinstance(row.get("action"), str)
                    and row["action"] in risks
                    and row.get("decision") in ("ALLOWED", "EXPLICIT_DENY", "IMPLICIT_DENY") for row in rows)
            and {row["action"] for row in rows} == set(risks)):
        try:
            result.actions = [ActionDecision(
                row["action"], row["decision"], risks[row["action"]],
                _missing_context(row.get("missing_context_values", [])),
                _saved_detail(row, "organizations_allowed"), _saved_detail(row, "permissions_boundary_allowed"),
                *_saved_scope(row),
            ) for row in rows]
            result.collection_status = "COMPLETE"
        except ValueError:
            pass  # Malformed stored evidence never establishes low privilege.
    return replace(to_risk_signal(result), account_id=account)


def _saved_scope(row):
    """A saved decision's resource scope: ``*`` unless it was allowed only on named resource ARNs."""
    scope, resources = row.get("resource_scope", "ALL"), row.get("resources", [])
    if (scope not in ("ALL", "NAMED") or not isinstance(resources, list) or len(resources) > 25
            or any(not isinstance(arn, str) or not arn.startswith("arn:") or len(arn) > 2048 for arn in resources)
            or (scope == "NAMED") != bool(resources) or (scope == "NAMED" and row["decision"] != "ALLOWED")):
        raise ValueError("IAM_SIMULATION_MALFORMED")
    return scope, tuple(resources)


def _saved_detail(row, name):
    value = row.get(name)
    if value is not None and type(value) is not bool:
        raise ValueError("IAM_SIMULATION_MALFORMED")
    return value
