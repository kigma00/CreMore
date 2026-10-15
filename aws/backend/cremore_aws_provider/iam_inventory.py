"""Bounded IAM inventory with separate issuance, report and operation evidence."""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cremore.coverage.collection import Collection, CollectionLimit, iso
from cremore.coverage.models import IAMPolicySummary, Observation, in_scope
from cremore_aws_provider.aws_identity import error_code
from cremore_aws_provider.investigation.usage import normalize_last_used

_FLAGS = ("password_enabled", "mfa_active", "access_key_1_active", "access_key_2_active",
          "cert_1_active", "cert_2_active")
_SENTINELS = {"": "NOT_RETURNED", "N/A": "NOT_APPLICABLE", "no_information": "NO_INFORMATION",
              "not_supported": "NOT_SUPPORTED"}
_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


@dataclass
class _Operation:
    name: str
    requested: bool = True
    requests: int = 0
    records: int = 0
    completed: int = 0
    failures: int = 0
    reason: str | None = None

    def track(self, fn):
        def call(**kwargs):
            self.requests += 1
            return fn(**kwargs)
        return call

    def fail(self, out, reason):
        self.failures += 1
        self.reason = self.reason or reason
        out.reasons.add(reason)

    def report(self):
        status = "COMPLETE"
        if not self.requested:
            status = "NOT_REQUESTED"
        elif self.failures:
            status = "PARTIAL" if self.completed or self.records else "FAILED"
        return {"name": self.name, "status": status, "requests": self.requests,
                "records": self.records, "reason": self.reason}


def _failure(exc, fallback):
    return fallback.removesuffix("_FAILED") + "_DENIED" if error_code(exc) in _DENIED else fallback


def _pages(out, op, fn, field, **kwargs):
    def checked(**params):
        response = fn(**params)
        if (not isinstance(response, dict) or not isinstance(response.get(field), list)
                or not isinstance(response.get("IsTruncated", False), bool)
                or (response.get("Marker") is not None and not isinstance(response["Marker"], str))):
            raise ValueError("INVALID_IAM_PAGE")
        return response
    return out.pages(op.track(checked), field, **kwargs)


def _time(value):
    text = iso(value)
    if not isinstance(text, str) or len(text) > 40:
        raise ValueError("INVALID_TIME")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("TIMEZONE_REQUIRED")
    return text


def _report_field(value, *, timestamp=False, region=False):
    if value is None:
        return "", "NOT_RETURNED"
    if value in _SENTINELS:
        return "", _SENTINELS[value]
    try:
        if timestamp:
            return _time(value), "AVAILABLE"
        pattern = r"[a-z][a-z0-9-]{0,63}" if region else r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}"
        if not re.fullmatch(pattern, value):
            raise ValueError("INVALID_REPORT_FIELD")
        return value, "AVAILABLE"
    except (TypeError, ValueError):
        return "", "INVALID"


def _report_metadata(row, generated_at):
    report = {"generated_at": generated_at, "field_status": {}, "access_keys": [], "certificates": []}
    columns = {"user_created_at": "user_creation_time", "password_last_used_at": "password_last_used",
               "password_last_changed_at": "password_last_changed", "password_next_rotation_at": "password_next_rotation"}
    for name, column in columns.items():
        report[name], report["field_status"][name] = _report_field(row.get(column), timestamp=True)
    for name in ("password_enabled", "mfa_active"):
        report["field_status"][name] = _flag_state(row.get(name))
    for slot in (1, 2):
        key = {"slot": slot, "active": {"true": True, "false": False}.get(row.get(f"access_key_{slot}_active")),
               "field_status": {"active": _flag_state(row.get(f"access_key_{slot}_active"))}}
        columns = {"last_rotated_at": "last_rotated", "last_used_at": "last_used_date",
                   "last_used_region": "last_used_region", "last_used_service": "last_used_service"}
        for name, suffix in columns.items():
            key[name], key["field_status"][name] = _report_field(
                row.get(f"access_key_{slot}_{suffix}"), timestamp=name.endswith("_at"), region=name.endswith("region"))
        report["access_keys"].append(key)
        rotated, state = _report_field(row.get(f"cert_{slot}_last_rotated"), timestamp=True)
        report["certificates"].append({"slot": slot,
            "active": {"true": True, "false": False}.get(row.get(f"cert_{slot}_active")),
            "last_rotated_at": rotated, "field_status": {
                "active": _flag_state(row.get(f"cert_{slot}_active")), "last_rotated_at": state}})
    invalid = any(status == "INVALID" for status in report["field_status"].values())
    invalid |= any("INVALID" in entry["field_status"].values() for entry in report["access_keys"] + report["certificates"])
    invalid |= any(row.get(name) not in (None, "true", "false", *_SENTINELS) for name in _FLAGS)
    return report, invalid


def _flag_state(value):
    if value in ("true", "false"):
        return "AVAILABLE"
    return "NOT_RETURNED" if value is None else _SENTINELS.get(value, "INVALID")


def _credential_report(out, client, op):
    try:
        generated = out.call(op.track(client.generate_credential_report))
        if generated.get("State") not in ("STARTED", "INPROGRESS", "COMPLETE"):
            raise ValueError("INVALID_REPORT_STATE")
        if generated.get("State") != "COMPLETE":
            op.fail(out, "CREDENTIAL_REPORT_PENDING")
            return
        response = out.call(op.track(client.get_credential_report))
        raw = response["Content"]
        if not isinstance(raw, bytes):
            raise TypeError("INVALID_REPORT_CONTENT")
        if len(raw) > out.spec.max_value_bytes:
            raise CollectionLimit("REPORT_SIZE_LIMIT")
        generated_at = _time(response.get("GeneratedTime"))
        rows = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        if (not rows.fieldnames or not {"user", "arn"}.issubset(rows.fieldnames)
                or len(set(rows.fieldnames)) != len(rows.fieldnames)):
            raise ValueError("INVALID_REPORT_COLUMNS")
        root_seen = False
        seen = set()
        for row in rows:
            out.checkpoint()
            try:
                root = row.get("user") == "<root_account>"
                arn = row["arn"]
                if (not isinstance(row.get("user"), str) or not row["user"]
                        or (root != arn.endswith(":root"))):
                    raise ValueError("INVALID_REPORT_PRINCIPAL")
                if arn in seen:
                    op.fail(out, "CREDENTIAL_REPORT_DUPLICATE_PRINCIPAL")
                    continue
                report, invalid = _report_metadata(row, generated_at)
                item = Observation(reference=arn, account_id=out.spec.account_id,
                    principal_arn=arn, evidence="ROOT_STATUS" if root else "USER_STATUS",
                    created_at=generated_at if root else report["user_created_at"], iam_report=report,
                    **{key: {"true": True, "false": False}.get(row.get(key)) for key in _FLAGS})
                if not in_scope(out.spec, item) or (not root and arn.rsplit("/", 1)[-1] != row["user"]):
                    raise ValueError("REPORT_SCOPE_MISMATCH")
                out.add(item)
                seen.add(arn)
                root_seen |= root
                op.records += 1
                if invalid:
                    op.fail(out, "CREDENTIAL_REPORT_INVALID_FIELD")
            except CollectionLimit:
                raise
            except Exception:  # noqa: BLE001 -- keep malformed provider rows out of inventory and errors.
                op.fail(out, "CREDENTIAL_REPORT_INVALID_ROW")
        if not root_seen:
            op.fail(out, "ROOT_REPORT_ROW_MISSING")
        if not op.failures:
            op.completed += 1
    except CollectionLimit:
        raise
    except Exception as exc:  # noqa: BLE001 -- provider content must never become an error message.
        op.fail(out, _failure(exc, "CREDENTIAL_REPORT_FAILED"))


def _user_credentials(out, client, user, location, op, *, service=False):
    fallback = "IAM_SERVICE_CREDENTIALS_FAILED" if service else "IAM_KEY_LIST_FAILED"
    try:
        method = client.list_service_specific_credentials if service else client.list_access_keys
        field = "ServiceSpecificCredentials" if service else "AccessKeyMetadata"
        for key in _pages(out, op, method, field, UserName=user["UserName"], MaxItems=100):
            try:
                if key.get("UserName", user["UserName"]) != user["UserName"]:
                    raise ValueError("KEY_OWNER_MISMATCH")
                # A service-specific credential with an expiry (a Bedrock or CloudWatch API key) ends as Expired.
                if key["Status"] not in (("Active", "Inactive", "Expired") if service else ("Active", "Inactive")):
                    raise ValueError("INVALID_KEY_STATUS")
                item = Observation(**location, evidence="ISSUED",
                    credential_type="AWS_SERVICE_CREDENTIAL" if service else "AWS_ACCESS_KEY",
                    identifier=key["ServiceSpecificCredentialId" if service else "AccessKeyId"],
                    state=key["Status"], created_at=iso(key.get("CreateDate")),
                    service=key.get("ServiceName", "") if service else "")
                out.add(item)
                op.records += 1
            except CollectionLimit:
                raise
            except Exception:  # noqa: BLE001 -- preserve good keys and classify malformed rows as incomplete.
                op.fail(out, fallback.removesuffix("_FAILED") + "_INVALID_ROW")
        op.completed += 1
    except CollectionLimit:
        raise
    except Exception as exc:  # noqa: BLE001 -- a denied user must not suppress other users or sources.
        reason = _failure(exc, fallback)
        op.fail(out, reason)
        out.unresolved(location, reason)


def _last_used(out, client, op, checked_at):
    for index, item in enumerate(out.items):
        if item.evidence != "ISSUED" or item.credential_type != "AWS_ACCESS_KEY":
            continue
        try:
            response = out.call(op.track(client.get_access_key_last_used), AccessKeyId=item.identifier)
            if response.get("UserName", item.principal_arn.rsplit("/", 1)[-1]) != item.principal_arn.rsplit("/", 1)[-1]:
                raise ValueError("LAST_USED_OWNER_MISMATCH")
            used = normalize_last_used(response["AccessKeyLastUsed"])
            metadata = {"status": "AVAILABLE" if used.at else "NO_INFORMATION", "checked_at": checked_at,
                        "service": used.service, "region": used.region}
            last_used_at = iso(used.at)
            op.completed += 1
            op.records += 1
        except CollectionLimit:
            raise
        except Exception as exc:  # noqa: BLE001 -- a failed enrichment never removes a known issued key.
            reason = _failure(exc, "IAM_LAST_USED_FAILED")
            op.fail(out, reason)
            metadata = {"status": "DENIED" if error_code(exc) in _DENIED else "FAILED",
                        "checked_at": checked_at, "reason": reason}
            last_used_at = ""
        out.items[index] = Observation.model_validate(item.model_dump() | {
            "last_used_at": last_used_at, "iam_last_used": metadata})


def _policies(out, client, op, enabled, checked_at):
    from cremore_aws_provider.investigation.identity_policies import collect_identity_policies

    interrupted = None

    class BudgetedIAM:
        def __getattr__(self, name):
            def call(**kwargs):
                nonlocal interrupted
                if interrupted:
                    raise interrupted
                try:
                    if not enabled():
                        raise CollectionLimit("IAM_POLICY_COLLECTION_DISABLED")
                    out.charge()
                except Exception as exc:
                    interrupted = exc
                    raise
                return op.track(getattr(client, name))(**kwargs)
            return call

    # Both keys of a user share one policy read, within this run's request budget.
    by_principal = {}
    for index, item in enumerate(out.items):
        if item.evidence != "ISSUED" or item.credential_type != "AWS_ACCESS_KEY":
            continue
        if item.principal_arn not in by_principal:
            snapshot = collect_identity_policies(BudgetedIAM(), item.principal_arn)
            if interrupted:
                raise interrupted  # the reusable reader records errors; a budget/cancellation must still stop this run
            summary = snapshot.get("summary") or {}
            errors = snapshot.get("errors") or []
            status = snapshot["collection_status"]
            if status == "FAILED" and errors and all(e["error_code"] in _DENIED for e in errors):
                status = "DENIED"
            reason = "IAM_POLICY_READ_DENIED" if status == "DENIED" else "IAM_POLICY_READ_FAILED" if errors else None
            names = list(dict.fromkeys(p["name"] for p in snapshot.get("policies") or []))
            try:
                evidence = IAMPolicySummary(status=status, checked_at=checked_at, policy_names=names[:100],
                    allow_actions=summary.get("allowed_actions", []), deny_statements=summary.get("deny_statements", 0),
                    conditional_statements=summary.get("conditional_statements", 0),
                    permissions_boundary=summary.get("permissions_boundary", False),
                    truncated=len(names) > 100 or bool(snapshot.get("statements_truncated") or summary.get("allowed_actions_truncated")
                        or any(s.get("truncated") for p in snapshot.get("policies", []) for s in p["statements"])),
                    reason=reason)
            except ValueError:
                reason = "IAM_POLICY_RESPONSE_INVALID"
                evidence = IAMPolicySummary(status="FAILED", checked_at=checked_at, reason=reason)
            by_principal[item.principal_arn] = evidence
            if reason:
                op.fail(out, reason)
            else:
                op.completed += 1
            op.records += 1
        out.items[index] = item.model_copy(update={"iam_policies": by_principal[item.principal_arn]})


def collect_iam(spec, client, *, checkpoint=None, now=None, policy_enabled=None):
    """Collect IAM issuance and credential reports without retrieving secret values."""
    if policy_enabled is None:
        policy_enabled = lambda: spec.iam_policy_metadata is True
    out = Collection(spec, checkpoint=checkpoint)
    users = _Operation("LIST_USERS")
    keys = _Operation("LIST_ACCESS_KEYS")
    service = _Operation("LIST_SERVICE_CREDENTIALS", spec.service_credentials)
    report = _Operation("CREDENTIAL_REPORT", spec.credential_report)
    used = _Operation("GET_ACCESS_KEY_LAST_USED", spec.last_used)
    policies = _Operation("IAM_IDENTITY_POLICIES", bool(policy_enabled and policy_enabled()))
    operations = (users, keys, service, report, used) + ((policies,) if policies.requested else ())
    interrupted = None
    current = users
    try:
        try:
            for user in _pages(out, users, client.list_users, "Users", MaxItems=100):
                current = users
                try:
                    location = {"reference": user["Arn"], "account_id": spec.account_id, "principal_arn": user["Arn"]}
                    valid = Observation(**location, evidence="UNRESOLVED", reason="CHECKING_SCOPE")
                    if (not in_scope(spec, valid) or not isinstance(user["UserName"], str)
                            or user["Arn"].rsplit("/", 1)[-1] != user["UserName"] or ":user/" not in user["Arn"]):
                        raise ValueError("USER_SCOPE_MISMATCH")
                except Exception:  # noqa: BLE001 -- invalid users cannot expand this account's scope.
                    users.fail(out, "PROVIDER_SCOPE_MISMATCH")
                    continue
                users.records += 1
                current = keys
                _user_credentials(out, client, user, location, keys)
                if service.requested:
                    current = service
                    _user_credentials(out, client, user, location, service, service=True)
                current = users
            users.completed += 1
        except CollectionLimit:
            raise
        except Exception as exc:  # noqa: BLE001 -- reports can still provide evidence when user listing is denied.
            users.fail(out, _failure(exc, "IAM_USER_LIST_FAILED"))
        if report.requested:
            current = report
            _credential_report(out, client, report)
        if used.requested:
            current = used
            _last_used(out, client, used, _time(now or datetime.now(UTC)))
        if policies.requested:
            current = policies
            _policies(out, client, policies, policy_enabled, _time(now or datetime.now(UTC)))
    except CollectionLimit as exc:
        interrupted = str(exc)
        current.fail(out, interrupted)
    if interrupted:
        for op in operations:
            if op.requested and not op.completed and not op.failures:
                op.fail(out, interrupted)
    if users.failures:
        keys.fail(out, "IAM_USER_ENUMERATION_INCOMPLETE")
        if service.requested:
            service.fail(out, "IAM_USER_ENUMERATION_INCOMPLETE")
    if used.requested and (users.failures or keys.failures):
        used.fail(out, "IAM_KEY_ENUMERATION_INCOMPLETE")
    if policies.requested and (users.failures or keys.failures):
        policies.fail(out, "IAM_KEY_ENUMERATION_INCOMPLETE")
    for op in operations:
        if len(out.items) >= spec.max_records:
            out.reasons.add("OPERATION_REPORT_LIMIT")
            break
        out.add(Observation(reference="account/" + spec.account_id, account_id=spec.account_id,
                            evidence="OPERATION", operation=op.report()))
    return out
