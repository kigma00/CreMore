"""Bounded discovery with an approved server identity, before account registration."""

import datetime as dt
import uuid


def _identity(record, context):
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.onboarding import OnboardingValueError

    approved = aws_access.approval(context.repo, aws_access.SCANNER, context.settings)
    if approved is None or context.aws_sessions is None:
        raise OnboardingValueError("AWS_SCANNER_IDENTITY_NOT_APPROVED")
    if context.before_request:
        context.before_request()
    identity = context.aws_sessions.identity(aws_access.SCANNER, True)
    expected = record["target"].get("auth", {}).get("scanner_approval_revision", approved["revision"])
    matches = identity.get("match_key") == approved["match_key"] if approved.get("match_key") else (
        identity.get("principal_arn") == approved.get("principal_arn"))
    if identity.get("state") != "READY" or not matches or expected != approved["revision"]:
        raise OnboardingValueError("AWS_SCANNER_IDENTITY_CHANGED")
    from cremore_aws_provider.aws_identity import require_server_workload

    require_server_workload(identity)
    require_server_workload(approved)
    account = identity.get("account_id")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        raise OnboardingValueError("AWS_ACCOUNT_IDS_INVALID")
    record["target"].setdefault("auth", {})["scanner_approval_revision"] = approved["revision"]
    return identity, approved


def _session(record, context):
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.aws_sessions import AccountSession
    from cremore_aws_provider.onboarding import OnboardingValueError

    identity, approved = _identity(record, context)
    if record["auth_method"] == "role":
        from cremore_aws_provider.onboarding_roles import open_role

        return open_role(record, context, approved)
    account = identity["account_id"]
    if record["target"].get("accounts") and record["target"]["accounts"] != [account]:
        raise OnboardingValueError("RUNTIME_IDENTITY_IS_ONE_ACCOUNT")

    def factory(*args):
        raw = context.aws_sessions.client_factory(*args)
        return _BoundClient(raw, context)

    return AccountSession(account, aws_access.SCANNER, aws_access.RUNTIME_IDENTITY, None, factory)


class _BoundClient:
    def __init__(self, client, context):
        self.client, self.context = client, context

    def __getattr__(self, name):
        call = getattr(self.client, name)
        if name == "get_paginator":
            return lambda *args, **kwargs: _BoundPaginator(call(*args, **kwargs), self.context)
        if not callable(call):
            return call

        def bounded(*args, **kwargs):
            if self.context.before_request:
                self.context.before_request()
            return call(*args, **kwargs)
        return bounded


class _BoundPaginator:
    def __init__(self, paginator, context):
        self.paginator, self.context = paginator, context

    def paginate(self, **kwargs):
        pages = iter(self.paginator.paginate(**kwargs))
        while True:
            if self.context.before_request:
                self.context.before_request()
            try:
                yield next(pages)
            except StopIteration:
                return


def authenticate(record, secrets, context):
    identity, _approved = _identity(record, context)
    return {"status": "GRANTED", "subject": identity["account_id"]}


def discover(record, secrets, context):
    if record["auth_method"] == "role":
        from cremore_aws_provider.onboarding_roles import discover_roles

        identity, approved = _identity(record, context)
        return discover_roles(record, context, identity, approved)
    session = _session(record, context)
    # An explicit failure stays a failure; never substitute default regions.
    from cremore_aws_provider.onboarding import _REGION, OnboardingValueError, _denied

    try:
        regions = session.client("ec2", context.settings.aws_region).describe_regions(AllRegions=False)
    except Exception as exc:  # Name the refused read without retaining provider text.
        if _denied(exc):
            raise OnboardingValueError("AWS_REGIONS_ACCESS_DENIED") from None
        raise

    rows = regions.get("Regions")
    if not isinstance(rows, list) or len(rows) > 100:
        raise OnboardingValueError("AWS_REGIONS_RESPONSE_INVALID")
    names = sorted({r["RegionName"] for r in rows if isinstance(r, dict)
                    and isinstance(r.get("RegionName"), str) and _REGION.fullmatch(r["RegionName"])})
    return [{"label": session.account_id, "target": {"accounts": [session.account_id]},
             "plan_options": {"regions": names, "cloudtrail_regions": names}}], "COMPLETE"


def check_draft(record, purpose, context):
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.onboarding import (
        PROBES,
        _denied,
        _permissions,
        policy_permission_items,
        value_permission_items,
        value_reader_items,
    )
    from cremore_aws_provider.onboarding_roles import open_reader

    try:
        session = _session(record, context)
    except aws_access.AccessBlocked as exc:
        # Role entry failed before any service permission could be tested. Keep
        # the account and the dependency failure instead of blaming each read.
        account = record["target"]["accounts"][0]
        status = "MISSING" if exc.code == "ASSUME_ROLE_DENIED" else "ERROR"
        return [{"permission": p["id"], "subject": account,
                 "status": status if p["id"] == "scanner_access" else "NOT_REPORTED",
                 "detail": exc.code if p["id"] == "scanner_access" else "SCANNER_ACCESS_REQUIRED"}
                for p in _permissions(purpose)]
    account = session.account_id
    out = [{"permission": "scanner_access", "status": "GRANTED", "subject": account},
           *value_permission_items(record, purpose), *policy_permission_items(record, purpose, session, context),
           *value_reader_items(record, purpose, session, lambda role: open_reader(record, context, session, role))]
    plan = record.get("checks", {}).get("requested_plans", {}).get(purpose, {})
    for key, service, call, args, *_labels in PROBES[purpose]:
        if key == "cloudtrail_read" and not plan.get("cloudtrail") or key == "ssm_list" and not plan.get("ssm_prefixes"):
            continue
        if purpose == "vault" and plan.get("value_reader") is True:
            continue  # the value reader reads named secrets and paths: no list is read or needed
        regions = plan.get("cloudtrail_regions") if service == "cloudtrail" else plan.get("regions")
        for region in regions or [context.settings.aws_region]:
            try:
                getattr(session.client(service, None if service == "iam" else region), call)(**args)
                out.append({"permission": key, "status": "GRANTED", "subject": account})
            except Exception as exc:  # noqa: BLE001 -- keep only safe status codes
                out.append({"permission": key, "status": "MISSING" if _denied(exc) else "ERROR", "subject": account,
                            "detail": "ACCESS_DENIED" if _denied(exc) else "REQUEST_FAILED"})
    return out


def list_onboarding_scope(record, sid, context, budget):
    from cremore.onboarding.targets import records_of
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.catalog import _aws
    from cremore_aws_provider.onboarding import OnboardingValueError

    listed, complete = [], "COMPLETE"
    for root in records_of(record, "exposure"):
        session = _session(root, context)
        approved = aws_access.approval(context.repo, aws_access.SCANNER, context.settings)
        if approved is None or approved["revision"] != root["target"]["auth"]["scanner_approval_revision"]:
            raise OnboardingValueError("AWS_SCANNER_IDENTITY_CHANGED")
        partition = approved.get("partition")
        if partition not in ("aws", "aws-cn", "aws-us-gov", "aws-eusc"):
            raise OnboardingValueError("AWS_PARTITION_UNAVAILABLE")
        key = "aws:" + session.account_id
        items, completeness = _aws({"account_id": session.account_id}, "aws", uuid.uuid5(sid, key),
                                  session.client("s3"), dt.datetime.now(dt.UTC), budget, partition=partition)
        listed.extend({**item, "source_key": key} for item in items)
        if len(listed) > 10000:
            raise OnboardingValueError("ONBOARDING_RESOURCE_LIMIT")
        if completeness != "COMPLETE":
            complete = "PARTIAL"
    return listed, complete, {}


def role_account(record, account_id, repo, settings):
    from cremore_aws_provider.onboarding_roles import role_account as read

    return read(record, account_id, repo, settings)
