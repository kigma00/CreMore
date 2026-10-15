"""Curated IAM potential-access evaluation.

Runs ``iam:SimulatePrincipalPolicy`` for a principal against a curated list of
high-impact actions and summarises which are allowed. This is *potential*
evidence -- it does not prove a request would succeed -- but it lets the risk
model score an AWS principal's privilege the way provider scopes score a token.

A request on ``*`` never matches a statement written for ``arn:aws:s3:::*`` or
one bucket, so the actions no grant on ``*`` allowed are simulated again on the
resource ARNs the principal's own Allow statements name (``NAMED`` scope). For
an IAM user the simulator also takes the resource's own policy: the bucket
policy of a same-account S3 bucket, a Secrets Manager secret's policy and a KMS
key's policy, so their explicit denies count (it accepts a resource policy only
for a user caller). The simulator joins a same-account resource policy to the
identity policies, but KMS does not: an identity policy grants a key's use only
where the key policy lets IAM policies grant it, unless the key policy grants
the user itself, so that is checked here from the key policy read.
https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html

The action catalog and risk categories are authored here from AWS's own action
reference; the simulation call is the documented IAM API.
https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from cremore.risk.model import AWSPrivilegeSignal
from cremore_aws_provider.aws_identity import collection_error_code
from cremore_aws_provider.aws_pagination import iam_pages

# arn:{partition}:sts::{account}:assumed-role/{role-name}/{session-name}
_ASSUMED_ROLE = re.compile(r"arn:(aws[\w-]*):sts::(\d{12}):assumed-role/([\w+=,.@-]+)/.+")

# (action, risk category). Categories drive the privilege score bands.
ACTION_CATALOG: tuple[tuple[str, str], ...] = (
    ("iam:AttachUserPolicy", "PRIVILEGE_ESCALATION"),
    ("iam:AttachRolePolicy", "PRIVILEGE_ESCALATION"),
    ("iam:CreateAccessKey", "PRIVILEGE_ESCALATION"),
    ("iam:PassRole", "PRIVILEGE_ESCALATION"),
    ("iam:PutUserPolicy", "PRIVILEGE_ESCALATION"),
    ("sts:AssumeRole", "PRIVILEGE_ESCALATION"),
    ("s3:DeleteObject", "DESTRUCTIVE"),
    ("dynamodb:DeleteItem", "DESTRUCTIVE"),
    ("secretsmanager:GetSecretValue", "SECRET_ACCESS"),
    ("kms:Decrypt", "SECRET_ACCESS"),
    ("ssm:GetParameter", "SECRET_ACCESS"),
    ("lambda:UpdateFunctionCode", "CODE_MODIFICATION"),
    ("lambda:InvokeFunction", "EXECUTION"),
    ("ec2:RunInstances", "RESOURCE_CREATION"),
    ("s3:PutObject", "WRITE"),
    ("dynamodb:PutItem", "WRITE"),
    ("s3:GetObject", "READ"),
    ("s3:ListBucket", "READ"),
    ("logs:GetLogEvents", "READ"),
    ("ecr:GetDownloadUrlForLayer", "READ"),
)

_RISK_BY_ACTION = {action: risk for action, risk in ACTION_CATALOG}
# The ARN service each curated action's resources carry (sts:AssumeRole acts on IAM roles). ec2:RunInstances acts on
# several resource types at once, so it stays a request on ``*``.
_ARN_SERVICE = {"iam": "iam", "sts": "iam", "s3": "s3", "dynamodb": "dynamodb", "secretsmanager": "secretsmanager",
                "kms": "kms", "ssm": "ssm", "lambda": "lambda", "logs": "logs", "ecr": "ecr"}
# Bucket-level S3 actions take a bucket ARN; the other S3 actions take an object ARN.
_S3_BUCKET_ACTIONS = {"s3:ListBucket"}
MAX_NAMED_RESOURCES = 25
_ARN = re.compile(r"arn:(aws[\w-]*):([a-z0-9-]+):([a-z0-9-]*):(\d{12})?:(.+)")
# The characters SimulatePrincipalPolicy accepts in a ResourcePolicy (up to 131072 of them); a resource policy read here
# is at most 32 KB (a KMS key policy; S3 and Secrets Manager allow 20 KB).
_SIMULATOR_TEXT = re.compile(r"[\t\n\r\x20-\xff]{1,32768}")
_CONTEXT_KEY = re.compile(r"[\w:/+.@=-]{1,256}")

_BASE_LIMITATIONS = (
    "Curated high-impact actions only; not a complete IAM inventory.",
    ("Grants on particular resources are checked only on the ARNs the principal's own Allow statements name "
     f"(up to {MAX_NAMED_RESOURCES}); access another account's resource policy grants is not found."),
    "No request context was supplied; decisions apply only to the simulated input.",
    ("Resource policies are evaluated only for an IAM user, and only a same-account S3 bucket policy, Secrets "
     "Manager secret policy or KMS key policy of a resource its own ARN names; a pattern or *, other resource "
     "policies and resource control policies are not. An action on a KMS key whose policy could not be read is "
     "judged by the identity policies alone."),
    "Organizations and permissions-boundary details apply only where returned by IAM; absent details are unknown.",
    "SCP evaluation does not report missing context keys; no supplied request context is not proof of complete conditions.",
    "Actual session policies, session tags and request conditions are not reproduced.",
    "KMS grants, encryption context and dependent permissions are not evaluated; a grant can allow what policies do not.",
)
# IAM can include the role's boundary, but cannot reproduce the actual STS session.
_SESSION_LIMITATION = ("Evaluated the assumed role, not the STS session; session policies, session tags and "
                       "other session context can change access. The role's boundary is separate evidence.")


def _limitations(is_session: bool) -> tuple[str, ...]:
    return _BASE_LIMITATIONS + ((_SESSION_LIMITATION,) if is_session else ())


@dataclass
class ActionDecision:
    action: str
    decision: str  # ALLOWED | EXPLICIT_DENY | IMPLICIT_DENY
    risk: str
    missing_context_values: tuple[str, ...] = ()
    organizations_allowed: bool | None = None
    permissions_boundary_allowed: bool | None = None
    #: ALL: decided on ``*``; NAMED: allowed only on ``resources``, ARNs the principal's own policies name.
    resource_scope: str = "ALL"
    resources: tuple[str, ...] = ()


@dataclass
class NamedResource:
    """One ARN the principal's Allow statements name, simulated for the curated actions ``*`` did not allow."""

    resource: str
    actions: tuple[str, ...]
    allowed: tuple[str, ...] = ()
    explicit_deny: tuple[str, ...] = ()
    missing_context_values: tuple[str, ...] = ()
    #: EVALUATED (its own policy was simulated), NONE (it has none), NOT_READ, or NOT_SUPPORTED (no user caller, or a
    #: resource whose policy is not read here).
    resource_policy: str = "NOT_SUPPORTED"
    #: A KMS key's: actions an identity policy allows that its key policy neither lets IAM policies grant (no statement
    #: for the account itself) nor grants the user or everyone (``*``), so KMS refuses them.
    key_policy_blocks: tuple[str, ...] = ()
    #: Actions with no answer here because a condition needs request context the simulation did not have (the keys
    #: are ``missing_context_values``, gathered for the resource).
    conditional: tuple[str, ...] = ()


@dataclass
class PotentialAccess:
    principal_arn: str
    collection_status: str  # COMPLETE | UNSUPPORTED | FAILED
    method: str = "IAM_SIMULATE_PRINCIPAL_POLICY"
    scope: str = "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_RESOURCES"
    error_code: str = ""
    #: The role ARN actually simulated when ``principal_arn`` is an STS session.
    evaluated_role_arn: str = ""
    actions: list[ActionDecision] = field(default_factory=list)
    limitations: tuple[str, ...] = _BASE_LIMITATIONS
    named_resources: list[NamedResource] = field(default_factory=list)
    #: Whether every named resource was simulated (``False``: identity policies unread, or more than the limit).
    named_resources_complete: bool = False

    @property
    def allowed(self) -> list[ActionDecision]:
        return [a for a in self.actions if a.decision == "ALLOWED" and not a.missing_context_values
                and a.organizations_allowed is not False and a.permissions_boundary_allowed is not False]


class PotentialAccessService:
    def __init__(self, iam, *, s3=None, secrets=None, kms=None) -> None:
        """``iam`` simulates. ``s3`` (a client), ``secrets`` and ``kms`` (Region -> client) read the resource policies
        of named resources; without them those policies are not read."""
        self.iam, self.s3, self.secrets, self.kms = iam, s3, secrets, kms

    def _simulation_source(self, principal_arn: str) -> tuple[str, str]:
        """Return (arn to simulate, session arn or "").

        SimulatePrincipalPolicy cannot take an STS session ARN, so a temporary
        credential is evaluated through the role it assumed. The role's real ARN
        (with its path) is resolved with ``iam:GetRole``; without that permission
        or for a deleted role, fall back to the path-less role ARN.
        """
        match = _ASSUMED_ROLE.fullmatch(principal_arn or "")
        if not match:
            return principal_arn, ""
        partition, account, role_name = match.group(1), match.group(2), match.group(3)
        fallback = f"arn:{partition}:iam::{account}:role/{role_name}"
        try:
            resolved = str(self.iam.get_role(RoleName=role_name)["Role"]["Arn"])
        except Exception:  # noqa: BLE001 -- missing iam:GetRole or a deleted role falls back to the path-less ARN
            resolved = ""
        return (resolved or fallback), principal_arn

    def collect(self, principal_arn: str, identity_policies: dict | None = None) -> PotentialAccess:
        """``identity_policies``: the principal's policies as identity_policies.collect_identity_policies read them, when
        the caller already has them; otherwise they are read here for the named-resource pass."""
        source_arn, session_arn = self._simulation_source(principal_arn)
        evaluated_role_arn = source_arn if session_arn else ""
        limitations = _limitations(bool(session_arn))
        if not _is_principal(source_arn):
            return PotentialAccess(principal_arn, "UNSUPPORTED", error_code="IAM_PRINCIPAL_UNRESOLVED",
                                   evaluated_role_arn=evaluated_role_arn, limitations=limitations)
        actions = [a for a, _ in ACTION_CATALOG]
        result = PotentialAccess(principal_arn, "COMPLETE", evaluated_role_arn=evaluated_role_arn,
                                 limitations=limitations)
        seen = set()
        try:
            for page in iam_pages(self.iam.simulate_principal_policy, PolicySourceArn=source_arn,
                                  ActionNames=actions, ResourceArns=["*"]):
                rows = page.get("EvaluationResults")
                if not isinstance(rows, list):
                    raise ValueError("IAM_SIMULATION_MALFORMED")  # noqa: TRY004 -- preserve the malformed-response contract
                for ev in rows:
                    if not isinstance(ev, dict):
                        raise ValueError("IAM_SIMULATION_MALFORMED")  # noqa: TRY004 -- preserve the malformed-response contract
                    action = ev.get("EvalActionName", "")
                    if not isinstance(action, str) or action not in _RISK_BY_ACTION or action in seen:
                        raise ValueError("IAM_SIMULATION_MALFORMED")
                    decision = _decision(ev.get("EvalDecision", ""))
                    if decision == "UNKNOWN":
                        raise ValueError("IAM_SIMULATION_MALFORMED")
                    seen.add(action)
                    result.actions.append(ActionDecision(
                        action=action,
                        decision=decision,
                        risk=_RISK_BY_ACTION.get(action, ""),
                        missing_context_values=_missing_context(ev.get("MissingContextValues", [])),
                        organizations_allowed=_detail(ev, "OrganizationsDecisionDetail", "AllowedByOrganizations"),
                        permissions_boundary_allowed=_detail(ev, "PermissionsBoundaryDecisionDetail",
                                                             "AllowedByPermissionsBoundary"),
                    ))
            if seen != set(actions):
                raise ValueError("IAM_SIMULATION_INCOMPLETE")
        except Exception as exc:  # noqa: BLE001 -- Provider failure yields a failed snapshot and safe code, not an empty permission set.
            result.collection_status = "PARTIAL" if result.actions else "FAILED"
            result.error_code = _safe_code(exc)
        if result.collection_status == "COMPLETE":
            self._named(source_arn, result, identity_policies)
        result.actions.sort(key=lambda a: a.action)
        return result

    def _named(self, source_arn: str, result: PotentialAccess, policies: dict | None) -> None:
        """Simulate the curated actions ``*`` did not allow again on the ARNs the principal's Allow statements name; an
        action allowed on one of them reads ALLOWED with ``NAMED`` scope. A failure leaves the ``*`` decisions."""
        from cremore_aws_provider.investigation.identity_policies import collect_identity_policies

        pending = {a.action: a for a in result.actions if a.decision == "IMPLICIT_DENY"}
        if not pending:
            result.named_resources_complete = True
            return
        if policies is None or policies.get("principal_arn") not in (source_arn, result.principal_arn):
            policies = collect_identity_policies(self.iam, source_arn)
        if policies.get("collection_status") != "COMPLETE" or policies.get("statements_truncated"):
            return
        targets = _named_targets(policies, pending)
        user = ":user/" in source_arn
        try:
            for resource in sorted(targets)[:MAX_NAMED_RESOURCES]:
                extra, state = self._resource_policy(resource, source_arn) if user else ({}, "NOT_SUPPORTED")
                key_policy = extra.get("ResourcePolicy") if resource.split(":")[2] == "kms" else None
                named = NamedResource(resource, tuple(sorted(targets[resource])), resource_policy=state)
                missing: set[str] = set()
                for page in iam_pages(self.iam.simulate_principal_policy, PolicySourceArn=source_arn,
                                      ActionNames=list(named.actions), ResourceArns=[resource], **extra):
                    rows = page.get("EvaluationResults")
                    if not isinstance(rows, list):
                        raise ValueError("IAM_SIMULATION_MALFORMED")  # noqa: TRY004 -- preserve the malformed-response contract
                    for ev in rows:
                        action = ev.get("EvalActionName") if isinstance(ev, dict) else None
                        decision = _decision(ev.get("EvalDecision", "")) if action in named.actions else "UNKNOWN"
                        if decision == "UNKNOWN":
                            raise ValueError("IAM_SIMULATION_MALFORMED")
                        # With a resource ARN the simulator reports missing context per resource.
                        parts = _with_resource_results(ev)
                        context = tuple(sorted({key for part in parts
                                                for key in _missing_context(part.get("MissingContextValues", []))}))
                        missing.update(context)
                        layers = (_detail(ev, "OrganizationsDecisionDetail", "AllowedByOrganizations"),
                                  _detail(ev, "PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"))
                        if decision == "ALLOWED" and not context and False not in layers:
                            verdict, keys = (_key_policy_admits(key_policy, resource, source_arn, action)
                                             if key_policy and not _resource_statement_matched(parts) else ("ENABLED", ()))
                            missing.update(keys)
                            if verdict == "ENABLED":
                                named.allowed += (action,)
                            elif verdict == "REFUSED":
                                named.key_policy_blocks += (action,)
                            else:
                                named.conditional += (action,)
                        elif decision == "EXPLICIT_DENY":
                            named.explicit_deny += (action,)
                        elif context:
                            named.conditional += (action,)
                named.missing_context_values = tuple(sorted(missing))
                result.named_resources.append(named)
        except Exception as exc:  # noqa: BLE001 -- the ``*`` decisions stand; the pass is marked incomplete
            result.error_code = result.error_code or _safe_code(exc)
            return
        for named in result.named_resources:
            for action in named.allowed:
                pending[action].resources += (named.resource,)
        for action in pending.values():
            if action.resources:
                action.decision, action.resource_scope = "ALLOWED", "NAMED"
        result.scope = "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_AND_NAMED_RESOURCES"
        result.named_resources_complete = len(targets) <= MAX_NAMED_RESOURCES

    def _resource_policy(self, resource: str, user_arn: str) -> tuple[dict, str]:
        """The named resource's own policy as simulation arguments, and what became of it. Only one resource's policy
        is read: a pattern (``*``, ``?``) names many, and another account's resource is owned by that account."""
        match = _ARN.fullmatch(resource)
        service = match.group(2) if match else ""
        if {"s3": self.s3, "secretsmanager": self.secrets, "kms": self.kms}.get(service) is None:
            return {}, "NOT_SUPPORTED"
        account = user_arn.split(":")[4]
        name = match.group(5).split("/", 1)[0] if service == "s3" else resource
        if "*" in name or "?" in name or (service != "s3" and match.group(4) != account):
            return {}, "NOT_READ"
        try:
            if service == "s3":
                # The simulator owns a resource policy by the caller's account, so the bucket must be that account's.
                policy = self.s3.get_bucket_policy(Bucket=name, ExpectedBucketOwner=account).get("Policy")
            elif service == "secretsmanager":
                policy = self.secrets(match.group(3)).get_resource_policy(SecretId=resource).get("ResourcePolicy")
            else:
                policy = self.kms(match.group(3)).get_key_policy(KeyId=resource, PolicyName="default").get("Policy")
        except Exception as exc:  # noqa: BLE001 -- an unread policy is simulated without, and says so
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            return {}, "NONE" if code == "NoSuchBucketPolicy" else "NOT_READ"
        if not policy:
            return {}, "NONE"
        if not isinstance(policy, str) or not _SIMULATOR_TEXT.fullmatch(policy):
            return {}, "NOT_READ"
        return {"ResourcePolicy": policy}, "EVALUATED"


def _named_targets(policies: dict, pending) -> dict[str, set[str]]:
    """Resource ARN -> the pending curated actions an Allow statement grants on it. A permissions boundary grants
    nothing, and NotAction or NotResource statements name no particular resource."""
    targets: dict[str, set[str]] = {}
    for policy in policies.get("policies", []):
        if policy.get("source") == "PERMISSIONS_BOUNDARY":
            continue
        for statement in policy.get("statements", []):
            if statement.get("effect") != "Allow" or statement.get("not_actions") or statement.get("not_resources"):
                continue
            for action in pending:
                if any(fnmatchcase(action.lower(), str(pattern).lower()) for pattern in statement.get("actions", [])):
                    for resource in statement.get("resources", []):
                        if resource != "*" and _fits(action, resource):
                            targets.setdefault(resource, set()).add(action)
    return targets


def _fits(action: str, resource: str) -> bool:
    """Whether ``resource`` is an ARN ``action`` acts on: its service's, and for S3 a bucket for ListBucket and an
    object for the other actions (a pattern may name both)."""
    match = _ARN.fullmatch(resource)
    service = _ARN_SERVICE.get(action.split(":", 1)[0])
    if not match or not service or match.group(2) != service:
        return False
    rest = match.group(5)
    if service == "kms":
        # KMS authorizes a key's use on the key's ARN; an alias ARN in a policy grants none.
        return fnmatchcase("key", rest.split("/", 1)[0])
    if service != "s3" or "*" in rest or "?" in rest:
        return True
    return ("/" in rest) != (action in _S3_BUCKET_ACTIONS)


def _with_resource_results(evaluation: dict) -> list[dict]:
    """One evaluation and its ``ResourceSpecificResults``, where a request on a resource ARN puts its details."""
    rows = evaluation.get("ResourceSpecificResults", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("IAM_SIMULATION_MALFORMED")
    return [evaluation, *rows]


def _resource_statement_matched(parts: list[dict]) -> bool:
    """Whether the simulator says a statement of the supplied resource policy decided the result. The API reference
    lists ``resource`` as the type, while its examples (and the service) say ``Resource Policy`` with the id
    ``ResourcePolicy``; the id alone counts only without a type, as a managed policy's id is its own name."""
    return any(isinstance(statement, dict) and (
        statement.get("SourcePolicyType") in ("resource", "Resource Policy")
        or ("SourcePolicyType" not in statement and statement.get("SourcePolicyId") == "ResourcePolicy"))
        for part in parts for statement in _listed(part.get("MatchedStatements")))


def _key_policy_admits(policy: str, key_arn: str, principal_arn: str, action: str) -> tuple[str, tuple[str, ...]]:
    """Whether the key policy of ``key_arn`` lets ``principal_arn`` (an IAM user) use the key for ``action`` beside the
    identity policy that allows it: by an Allow for the account itself (its root ARN or ID, as the default key policy
    has, which lets IAM policies grant it) or for the user or everyone. ENABLED; UNKNOWN when only under a condition,
    whose keys come back; or REFUSED, as KMS refuses what only an identity policy allows."""
    partition, account = principal_arn.split(":")[1], principal_arn.split(":")[4]
    admitted = {account, f"arn:{partition}:iam::{account}:root", principal_arn, "*"}
    try:
        statements = _listed(json.loads(policy).get("Statement"))
    except (ValueError, AttributeError):
        return "UNKNOWN", ()
    verdict, keys = "REFUSED", set()
    for statement in statements:
        if (not isinstance(statement, dict) or statement.get("Effect") != "Allow" or "NotPrincipal" in statement
                or ("Action" in statement) == ("NotAction" in statement) or "NotResource" in statement):
            continue
        # A key policy's Resource is "*" (this key); a statement naming only other keys says nothing of this one.
        if not any(fnmatchcase(key_arn, str(pattern)) for pattern in _listed(statement.get("Resource", "*"))):
            continue
        principal = statement.get("Principal")
        names = _listed(principal.get("AWS")) if isinstance(principal, dict) else _listed(principal)
        if not admitted & {name for name in names if isinstance(name, str)}:
            continue
        named = any(fnmatchcase(action.lower(), str(pattern).lower())
                    for pattern in _listed(statement.get("Action", statement.get("NotAction"))))
        if named != ("Action" in statement):  # NotAction covers the actions it does not name
            continue
        condition = statement.get("Condition")
        if not condition:
            return "ENABLED", ()
        verdict = "UNKNOWN"
        tests = condition.values() if isinstance(condition, dict) else ()
        keys.update(key for test in tests if isinstance(test, dict) for key in test if _CONTEXT_KEY.fullmatch(key))
    return verdict, tuple(sorted(keys))


def _listed(value) -> list:
    """A policy field that may hold one value or a list of them."""
    return value if isinstance(value, list) else [] if value is None else [value]


def service_for(session, region: str | None = None) -> PotentialAccessService:
    """The evaluation in one account's scanner session: IAM simulates; S3, Secrets Manager and KMS read the named
    resources' policies (the scanner's read-only operations: get_bucket_policy, get_resource_policy, get_key_policy)."""
    return PotentialAccessService(session.client("iam", region), s3=session.client("s3", region),
                                  secrets=lambda name: session.client("secretsmanager", name),
                                  kms=lambda name: session.client("kms", name))


def provider_from_service(service: PotentialAccessService):
    """A cached ``PotentialAccessProvider`` for the scan orchestrator.

    Maps a principal ARN to an :class:`AWSPrivilegeSignal`, memoising per ARN so
    one IAM simulation serves every exposure of the same principal in a run. A
    failed or unsupported evaluation yields an unevaluated signal (no score),
    never an exception, so one bad principal never fails a scan.
    """

    cache: dict[str, AWSPrivilegeSignal] = {}

    def provider(principal_arn: str) -> AWSPrivilegeSignal:
        signal = cache.get(principal_arn)
        if signal is None:
            signal = to_risk_signal(service.collect(principal_arn))
            cache[principal_arn] = signal
        return signal

    return provider


def provider_from_sessions(sessions, region: str, *, ttl_seconds: float = 600.0):
    """Like :func:`provider_from_service`, but evaluated in the principal's own account.

    The account session is opened (and every access check re-run) on each call;
    only the evaluation is memoised, briefly. A principal whose account is not
    usable yields an unevaluated signal.
    """

    import time

    from cremore_aws_provider.aws_access import SCANNER, AccessBlocked
    from cremore_aws_provider.aws_sessions import account_of_arn

    cache: dict[str, tuple[float, AWSPrivilegeSignal]] = {}

    def provider(principal_arn: str) -> AWSPrivilegeSignal:
        try:
            session = sessions.open(account_of_arn(principal_arn), SCANNER)
        except AccessBlocked:
            return AWSPrivilegeSignal(evaluated=False)
        now = time.monotonic()
        hit = cache.get(principal_arn)
        if hit and now - hit[0] < ttl_seconds:
            return hit[1]
        signal = to_risk_signal(service_for(session, region).collect(principal_arn))
        if signal.evaluated:
            from dataclasses import replace

            signal = replace(signal, account_id=session.account_id)
        cache[principal_arn] = (now, signal)
        return signal

    return provider


def to_risk_signal(access: PotentialAccess) -> AWSPrivilegeSignal:
    """Summarise a completed evaluation for the risk model's privilege axis."""

    if access.collection_status != "COMPLETE" or any(
            a.missing_context_values or (a.decision == "ALLOWED" and
                (a.organizations_allowed is False or a.permissions_boundary_allowed is False))
            for a in access.actions):
        return AWSPrivilegeSignal(evaluated=False)
    allowed = access.allowed
    return AWSPrivilegeSignal(
        evaluated=True,
        allowed_risks=frozenset(a.risk for a in allowed if a.risk),
        allowed_count=len(allowed),
        actions_evaluated=len(access.actions),
    )


def _missing_context(value) -> tuple[str, ...]:
    """Only bounded IAM context key names, never context values or response bodies."""
    if (not isinstance(value, (list, tuple)) or len(value) > 200
            or any(not isinstance(key, str) or not _CONTEXT_KEY.fullmatch(key) for key in value)):
        raise ValueError("IAM_SIMULATION_MALFORMED")
    return tuple(sorted(set(value)))


def _detail(evaluation, field, key):
    detail = evaluation.get(field)
    if detail is None:
        return None
    if not isinstance(detail, dict) or type(detail.get(key)) is not bool:
        raise ValueError("IAM_SIMULATION_MALFORMED")
    return detail[key]


def _decision(value: str) -> str:
    mapping = {"allowed": "ALLOWED", "explicitDeny": "EXPLICIT_DENY", "implicitDeny": "IMPLICIT_DENY"}
    return mapping.get(value, "UNKNOWN") if isinstance(value, str) else "UNKNOWN"


def _is_principal(arn: str) -> bool:
    return ":iam::" in arn and ("user/" in arn or "role/" in arn)


def _safe_code(exc: Exception) -> str:
    return collection_error_code(exc)
