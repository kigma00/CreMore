"""AWS in the connection wizard (cremore.onboarding).

An AWS connection is a set of accounts reached one way: a member role CloudFormation
deploys (recommended), the operator's IAM Identity Center permission set, this
installation's own identity for its own account, or -- for inventory and secret stores
only -- the CreMore CLI in the customer's own AWS environment, which reports with a
collector token so no value and no AWS access ever reaches CreMore. The accounts are registered when the
connection is created -- a member role's ExternalId must exist before the stack is
deployed -- so the check can prove each one from the worker, as the account screen
always did, and then read one list per purpose through the scanner session.

Every use reads with the approved scanner identity; nothing here stores a credential.
Credential inventory follows the installation's AWS inventory settings (IAM, and
CloudTrail when those settings enable it); secret stores are read by the worker, their
values optionally through the account's value-reader role the scanner session assumes.
"""

from __future__ import annotations

import re
import uuid

_ACCOUNT = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2,4}(?:-[a-z]+)+-[0-9]+")
_PERMISSION_SET = re.compile(r"[\w+=,.@-]{1,32}")
_KMS_KEY = re.compile(r"arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{1,128}")
_READER_ROLE = "CredentialVaultValueReaderRole"  # the templates' VaultValueReaderRoleName default
# The value-reader role's inline policies share IAM's 10,240-character limit. Its fixed part takes about 2,900;
# a secret ARN is written twice (its allow, and the deny of every other secret), a path with its "/*", a key once.
_READER_POLICY_BUDGET = 6500
_SIMULATED = 20  # resources per SimulatePrincipalPolicy call, so a page of results comes back whole
_LISTED_ONLY = "VaultValueReaderListedSecretsOnly"  # the templates' deny of every secret the stack does not list
# A Parameter Store path as the templates' VaultParameterPathArns takes it (and as SSM names allow).
_SSM_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")

_SCANNER = {"id": "scanner_access", "label": "Scanner access to the account", "label_ko": "계정 스캐너 접근",
            "methods": ["role", "sso", "runtime"]}
_CLI = "customer_cli"
PROBES = {
    "exposure": (("list_buckets", "s3", "list_buckets", {}, "List S3 buckets", "S3 버킷 목록"),),
    # Only ListUsers is asked; keys, the credential report and last use are separate IAM actions the collection reports.
    "inventory": (("iam_read", "iam", "list_users", {"MaxItems": 1}, "List IAM users (iam:ListUsers)", "IAM 사용자 목록(iam:ListUsers)"),
                  ("cloudtrail_read", "cloudtrail", "lookup_events", {"MaxResults": 1},
                   "Look up CloudTrail events", "CloudTrail 이벤트 조회")),
    "vault": (("secrets_list", "secretsmanager", "list_secrets", {"MaxResults": 1},
               "List Secrets Manager secrets", "Secrets Manager 시크릿 목록"),
              ("ssm_list", "ssm", "describe_parameters", {"MaxResults": 1},
               "List Parameter Store parameters (ssm:DescribeParameters, names only)",
               "Parameter Store 파라미터 목록(ssm:DescribeParameters, 이름만)")),
}
# Advisory catalog, not a validation allowlist or evidence that an account enabled a Region.
REGION_OPTIONS = [{"id": region, "label": region, "label_ko": region} for region in (
    "af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
    "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-central-1", "ca-west-1", "cn-north-1", "cn-northwest-1",
    "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3",
    "eusc-de-east-1",
    "il-central-1", "me-central-1", "me-south-1", "mx-central-1", "sa-east-1", "us-east-1", "us-east-2",
    "us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2",
)]
_REGIONS = {"name": "regions", "label": "Regions", "label_ko": "리전", "kind": "list", "required": True,
            "options": REGION_OPTIONS,
            "description": "Choose regions enabled in your account and partition. Selecting all does not grant access.",
            "description_ko": "계정과 파티션에서 사용할 수 있는 리전을 선택하세요. 모두 선택해도 접근 권한이 추가되지는 않습니다."}
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}


# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state).
INVENTORY_TYPES = [
    {"id": "access_key", "label": "IAM user access key", "label_ko": "IAM 사용자 액세스 키",
     "description": "Key ID, status, creation date and last use.", "description_ko": "키 ID·상태·생성일과 마지막 사용 시각입니다.",
     "permission": "iam_read", "credential_type": "AWS_ACCESS_KEY",
     "match": [{"credential_type": ["AWS_ACCESS_KEY"]}], "support": "YNYNPPYYY", "reasons": {
         "name": ["액세스 키에는 이름이 없습니다", "Access keys have no name"],
         "expires": ["액세스 키에는 만료일이 없습니다", "Access keys do not expire"],
         "scopes": ["발급 목록의 IAM 정책 메타데이터 수집을 켜면 사용자·그룹 정책을 읽습니다. 실제 접근 권한 검증은 아닙니다", "Reads user and group policies when IAM policy metadata collection is enabled; not effective access verification"],
         "creator": ["선택한 리전·기간의 CloudTrail CreateAccessKey 이벤트에서 키 ID가 일치할 때 확인합니다", "Matched by key ID to CloudTrail CreateAccessKey events in the selected regions and time window"]}},
    {"id": "service_credential", "label": "Service-specific credential", "label_ko": "서비스 전용 Credential",
     "description": "Service-specific credentials of IAM users: CodeCommit and Keyspaces user names and passwords, and "
                    "long-term API keys for Amazon Bedrock, Claude Platform on AWS, CloudWatch and CloudWatch Logs.",
     "description_ko": "IAM 사용자의 서비스 전용 자격증명입니다: CodeCommit·Keyspaces 사용자 이름·비밀번호와 Amazon Bedrock·"
                       "Claude Platform on AWS·CloudWatch·CloudWatch Logs 장기 API 키.",
     "permission": "iam_read", "credential_type": "AWS_SERVICE_CREDENTIAL",
     "match": [{"credential_type": ["AWS_SERVICE_CREDENTIAL"]}], "support": "YYYNPNYNY", "reasons": {
         "expires": ["API 키의 만료일(ExpirationDate)은 수집하지 않으며, 만료된 키는 상태(Expired)로 보입니다",
                     "An API key's ExpirationDate is not collected; an expired key shows by its state (Expired)"],
         "scopes": ["어느 서비스에 쓰는지만 줍니다", "Only the service it is for is given"],
         "creator": ["이 자격증명 종류의 생성자 대조는 지원하지 않습니다", "Creator correlation is not supported for this credential type"],
         "last_used": ["마지막 사용을 주지 않습니다", "No last use is given"]}},
]


def _permissions(purpose):
    values = ([{"id": "secrets_values", "label": "secretsmanager:GetSecretValue", "label_ko": "Secrets Manager 값 읽기",
                "methods": ["role", "sso", "runtime"]},
               {"id": "ssm_values", "label": "ssm:GetParametersByPath with decryption", "label_ko": "Parameter Store 값 복호화 읽기",
                "methods": ["role", "sso", "runtime"], "nonempty": "ssm_prefixes"}] if purpose == "vault" else [])
    if purpose == "inventory":
        values.append({"id": "iam_policy_read", "label": "Read IAM user and group policies", "label_ko": "IAM 사용자·그룹 정책 조회",
                       "methods": ["role", "sso", "runtime"], "option": "iam_policy_metadata"})
    return [_SCANNER] + values + [{"id": key, "label": label, "label_ko": label_ko,
                         "methods": ["role", "sso", "runtime"],
                         **({"option": "cloudtrail"} if key == "cloudtrail_read" else {}),
                         **({"nonempty": "ssm_prefixes"} if key == "ssm_list" else {}),
                         # The value reader reads named secrets and paths: no list is read or needed.
                         **({"unless": "value_reader"} if purpose == "vault" else {})}
                         for key, _service, _call, _args, label, label_ko in PROBES[purpose]]


def permission_subjects(connection, purpose, permission, plan):
    return connection["target"]["accounts"]


def _plan(connection, purpose):
    """The plan a check answers for: the one asked for, else the saved one."""
    return connection.get("checks", {}).get("requested_plans", {}).get(purpose, connection.get("plans", {}).get(purpose, {}))


def _paths(partition, account, regions, prefixes):
    """The Parameter Store path ARNs GetParametersByPath is authorized on, for each prefix in each region."""
    return [f"arn:{partition}:ssm:{region}:{account}:parameter/{prefix.strip('/')}"
            for prefix in prefixes if prefix.strip("/") for region in regions]


def plan_problem(roots, purpose, plan):
    """What a vault plan could never read, and what the value-reader stack could not name, checked against every
    target of the plan at once (cremore.onboarding.targets.normalize_plan). A later-adopted account takes only its own
    ARNs (children)."""
    if purpose != "vault":
        return None
    # The platform's list field also takes ~@+=:, which no Parameter Store name (nor the stack's path pattern) has: a
    # read would fail the whole region and the stack could not name the path. A "." or ".." segment is refused by
    # CreMore's own collection scope rule (models.scope_path), which used to fail only at activation.
    for prefix in plan.get("ssm_prefixes") or []:
        path = prefix.strip("/")
        if not _SSM_PATH.fullmatch(path) or any(segment in (".", "..") for segment in path.split("/")):
            return "AWS_PARAMETER_PATH_INVALID"
    if plan.get("value_reader") is not True:
        return None
    from cremore_aws_provider.aws_sessions import ROLE_NAME
    from cremore_aws_provider.secret_inventory import _ARN

    if any(root["auth_method"] != "role" for root in roots):
        return "VALUE_READER_NEEDS_ROLE_ACCESS"  # it trusts the member scanner role only
    if not ROLE_NAME.fullmatch(plan.get("value_reader_role") or ""):
        return "VALUE_READER_ROLE_INVALID"
    accounts = {account for root in roots for account in root["target"]["accounts"]}
    regions = plan.get("regions") or []
    secrets, keys = {}, {}
    for arn in plan.get("secret_arns") or []:
        match = _ARN.fullmatch(arn)
        if not match:
            return "AWS_SECRET_ARNS_INVALID"
        if match[2] not in regions or match[3] not in accounts:
            return "AWS_SECRET_ARN_OUTSIDE_SCOPE"
        secrets.setdefault(match[3], []).append(arn)
    for arn in plan.get("kms_key_arns") or []:
        if not _KMS_KEY.fullmatch(arn):
            return "AWS_KMS_KEY_ARNS_INVALID"
        if arn.split(":")[4] not in accounts:
            return "AWS_KMS_KEY_ARN_OUTSIDE_SCOPE"  # a key is named in its own account's stack
        keys.setdefault(arn.split(":")[4], []).append(arn)
    for account in sorted(accounts):
        if account not in secrets:
            return "AWS_SECRET_ARNS_REQUIRED"  # the role reads only named secrets, never a list
        # As the stack writes them, in the longest partition name.
        paths = [arn for path in _paths("aws-us-gov", account, regions, plan.get("ssm_prefixes") or []) for arn in (path, path + "/*")]
        if (sum(2 * (len(arn) + 3) for arn in secrets[account])
                + sum(len(arn) + 3 for arn in paths + keys.get(account, [])) > _READER_POLICY_BUDGET):
            return "AWS_VALUE_READER_POLICY_TOO_LARGE"
    return None


def value_permission_items(connection, purpose):
    if purpose != "vault" or connection["auth_method"] == _CLI:
        return []
    plan = _plan(connection, purpose)
    if plan.get("value_reader") is True:
        return []  # each account's value-reader role answers (value_reader_items)
    # ListSecrets/DescribeParameters do not prove value access or KMS decryption, and reading a parameter to prove it
    # would read its value. Existing IAM potential-access simulation is not effective access evidence.
    # The role CreMore's CloudFormation templates make denies GetSecretValue outright (ScannerMutationDeny), which no
    # Allow overrides, and grants no GetParametersByPath (an administrator may have added it); a role an administrator
    # named instead may allow either.
    from cremore_aws_provider.aws_org_discovery import SCANNER_ROLE_NAME

    roles = (connection["target"].get("auth") or {}).get("role_accounts") or {}
    templated = {account for account, row in roles.items() if connection["auth_method"] == "role"
                 and str((row or {}).get("scanner_role_arn", "")).endswith("/" + SCANNER_ROLE_NAME)}
    template = {"secrets_values": "AWS_SCANNER_ROLE_DENIES_SECRET_VALUES",
                "ssm_values": "AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES"}
    return [{"permission": permission, "status": "NOT_REPORTED", "subject": account,
             "detail": template[permission] if account in templated else "VALUE_READ_PERMISSION_NOT_CHECKED"}
            for account in connection["target"]["accounts"]
            for permission in ("secrets_values", "ssm_values") if permission != "ssm_values" or plan.get("ssm_prefixes")]


def value_reader_items(connection, purpose, session, open_reader):
    """With the value-reader role, value access is decided without reading a value or a list.

    ``open_reader(role_name)`` assumes the role from the scanner ``session`` (its trust and
    ExternalId) and returns its ARN; a refusal answers MISSING with its code. IAM then simulates the
    role's own policy for GetSecretValue on every secret listed for the account and
    GetParametersByPath on every path in every region: one resource refused refuses the permission.
    A simulation leaves out resource policies and KMS key policies, so GRANTED is the role's policy
    allowing the reads, not a read.
    """
    plan = _plan(connection, purpose)
    if purpose != "vault" or connection["auth_method"] == _CLI or plan.get("value_reader") is not True:
        return []
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.aws_identity import AwsLoginRequired
    from cremore_aws_provider.aws_sessions import account_of_arn

    account = session.account_id
    wanted = ["secrets_values"] + (["ssm_values"] if plan.get("ssm_prefixes") else [])

    def item(permission, status, detail=None):
        return {"permission": permission, "status": status, "subject": account, **({"detail": detail} if detail else {})}

    try:
        role_arn = open_reader(plan.get("value_reader_role") or _READER_ROLE)
    except aws_access.AccessBlocked as exc:
        return [item(permission, "MISSING", exc.code) for permission in wanted]
    except AwsLoginRequired:
        return [item(permission, "ERROR", "AWS_LOGIN_REQUIRED") for permission in wanted]
    asked = {"secrets_values": ("secretsmanager:GetSecretValue", "AWS_SECRET_ARNS_REQUIRED",
                                [arn for arn in plan.get("secret_arns") or [] if account_of_arn(arn) == account]),
             "ssm_values": ("ssm:GetParametersByPath", "AWS_REGIONS_INVALID",
                            _paths(role_arn.split(":")[1], account, plan.get("regions") or [], plan.get("ssm_prefixes") or []))}
    iam = session.client("iam")
    out = []
    for permission in wanted:
        action, nothing, resources = asked[permission]  # nothing: the code when there is nothing to simulate
        out.append(item(permission, *(_simulated(iam, role_arn, action, resources) if resources else ("NOT_REPORTED", nothing))))
    return out


def _simulated(iam, role_arn, action, resources):
    """(status, detail) of ``action`` on every resource, from each resource's own simulated decision."""
    decided = {}
    try:
        for start in range(0, len(resources), _SIMULATED):
            page = iam.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=[action],
                                                 ResourceArns=resources[start:start + _SIMULATED])
            if page.get("IsTruncated"):
                raise ValueError("SIMULATION_TRUNCATED")
            for result in page["EvaluationResults"]:
                for each in result.get("ResourceSpecificResults") or [{
                        "EvalResourceName": result["EvalResourceName"], "EvalResourceDecision": result["EvalDecision"],
                        "MissingContextValues": result.get("MissingContextValues"),
                        "MatchedStatements": result.get("MatchedStatements")}]:
                    decision = "unknown" if each.get("MissingContextValues") else each["EvalResourceDecision"]
                    if decision == "explicitDeny" and any(_LISTED_ONLY in str(statement.get("SourcePolicyId"))
                                                          for statement in each.get("MatchedStatements") or []):
                        decision = "implicitDeny"  # the stack's own deny of every unlisted secret: listing it is the fix
                    if decision in ("implicitDeny", "explicitDeny") and any(
                            (each.get(field, result.get(field)) or {}).get(allowed) is False
                            for field, allowed in (
                                ("PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"),
                                ("OrganizationsDecisionDetail", "AllowedByOrganizations"))):
                        decision = "explicitDeny"
                    decided[each["EvalResourceName"]] = decision
    except Exception as exc:  # noqa: BLE001 -- only a fixed code leaves the probe
        return "NOT_REPORTED", "VALUE_READER_SIMULATION_DENIED" if _denied(exc) else "VALUE_READER_SIMULATION_FAILED"
    decisions = [decided.get(resource) for resource in resources]
    if "explicitDeny" in decisions:  # a permissions boundary, an SCP or another deny, which no stack list lifts
        return "MISSING", "VALUE_READER_POLICY_EXPLICITLY_DENIED"
    if "implicitDeny" in decisions:
        return "MISSING", "VALUE_READER_POLICY_DENIES"
    if "unknown" in decisions:
        return "NOT_REPORTED", "VALUE_READER_SIMULATION_NEEDS_CONTEXT"
    if all(decision == "allowed" for decision in decisions):
        return "GRANTED", None
    return "NOT_REPORTED", "VALUE_READER_SIMULATION_FAILED"  # a resource without its own answer


def policy_permission_items(connection, purpose, session, context):
    """Probe one user's real policy reads; never infer access from ListUsers alone."""
    plan = _plan(connection, purpose)
    if purpose != "inventory" or plan.get("iam_policy_metadata") is not True:
        return []
    from cremore_aws_provider.investigation import investigation_switches
    from cremore_aws_provider.investigation.identity_policies import collect_identity_policies

    item = {"permission": "iam_policy_read", "subject": session.account_id}
    if not investigation_switches.allowed(context.settings, investigation_switches.POTENTIAL_ACCESS):
        return [{**item, "status": "MISSING", "detail": "IAM_POLICY_COLLECTION_DISABLED"}]
    calls = 0
    client = session.client("iam")

    class BoundedIAM:
        def __getattr__(self, name):
            def call(**kwargs):
                nonlocal calls
                calls += 1
                if calls > 100:
                    raise OnboardingValueError("IAM_POLICY_CHECK_LIMIT")
                return getattr(client, name)(**kwargs)
            return call

    try:
        iam = BoundedIAM()
        users = iam.list_users(MaxItems=1)["Users"]
        if not isinstance(users, list) or len(users) > 1:
            raise ValueError("INVALID_USERS")
        if not users:
            return [{**item, "status": "NOT_REPORTED", "detail": "IAM_POLICY_NO_USER_TO_CHECK"}]
        arn = users[0]["Arn"]
        if not isinstance(arn, str) or f":iam::{session.account_id}:user/" not in arn:
            raise ValueError("INVALID_USER_ACCOUNT")
        result = collect_identity_policies(iam, arn)
        if calls > 100:
            return [{**item, "status": "NOT_REPORTED", "detail": "IAM_POLICY_CHECK_LIMIT"}]
        if result["collection_status"] == "COMPLETE":
            return [{**item, "status": "GRANTED"}]
        denied = any(e["error_code"] in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation") for e in result.get("errors", []))
    except Exception as exc:  # noqa: BLE001 -- no policy, user name, provider message or response leaves the probe
        denied = _denied(exc)
    return [{**item, "status": "MISSING" if denied else "ERROR",
             "detail": "IAM_POLICY_READ_DENIED" if denied else "IAM_POLICY_READ_FAILED"}]


DESCRIPTORS = [{
    "provider": "aws",
    "label": "Amazon Web Services", "label_ko": "Amazon Web Services",
    "category": "cloud",
    "editions": [{"id": "cloud", "label": "AWS", "label_ko": "AWS"}],
    "target": [
        {"name": "accounts", "label": "Account IDs", "label_ko": "계정 ID", "kind": "list", "required": True,
         "hint": "123456789012, 210987654321"},
        {"name": "environment", "label": "Environment", "label_ko": "환경", "kind": "text"},
        {"name": "adopt_discovered", "label": "Take in accounts that discovery registers",
         "label_ko": "자동 발견으로 등록되는 계정도 포함", "kind": "bool", "default": False},
    ],
    "purposes": {
        "exposure": {"permissions": _permissions("exposure"),
                     "scans": [{"id": "objects", "label": "Bucket objects", "label_ko": "버킷 객체",
                                "description": "Objects in the buckets or prefixes in scope, read with CreMore's AWS identity. "
                                               "The CloudFormation collection role can read every bucket; CreMore keeps "
                                               "to the scope. SSE-KMS objects also need kms:Decrypt (the template's "
                                               "EnableKmsDecrypt and KmsKeyArns).",
                                "description_ko": "검사 범위에 넣은 버킷·접두사의 객체를 CreMore의 AWS 신원으로 읽습니다. "
                                                  "CloudFormation 수집 역할은 모든 버킷을 읽을 수 있고 범위는 CreMore가 지킵니다. "
                                                  "SSE-KMS로 암호화한 객체는 kms:Decrypt(템플릿의 EnableKmsDecrypt·KmsKeyArns)도 필요합니다."}]},
        "inventory": {"permissions": _permissions("inventory"), "types": INVENTORY_TYPES,
            "plan": [{"name": "iam_policy_metadata", "kind": "bool", "default": True,
                      "label": "Collect IAM policy metadata", "label_ko": "IAM 정책 메타데이터 수집",
                      "description": "Collects IAM user and group policy names, action summaries and boundary presence with the issued keys. Separate from permission simulation; no secret values are read. Preflight reads one user's policies; other resource-specific denials are reported during collection.",
                      "description_ko": "발급 키와 함께 IAM 사용자·그룹의 정책 이름, 작업 요약, 권한 경계 여부를 수집합니다. 권한 시뮬레이션과 별개이며 비밀값은 읽지 않습니다. 사전 점검은 한 사용자의 정책을 읽으며, 다른 리소스의 권한 거절은 수집 결과에 표시합니다."},
                     {"name": "cloudtrail", "kind": "bool", "default": False,
                      "label": "Enable CloudTrail collection", "label_ko": "CloudTrail 수집 사용",
                      "description": "Adds CloudTrail Event History to IAM inventory. It can provide key creator evidence and requires cloudtrail:LookupEvents in the selected regions. Turning it off keeps IAM inventory enabled.",
                      "description_ko": "IAM 발급 목록에 CloudTrail Event History를 추가해 키 생성자 등의 근거를 가져옵니다. 선택한 리전의 cloudtrail:LookupEvents 권한이 필요합니다. 꺼도 IAM 발급 목록은 수집합니다."},
                     {"name": "cloudtrail_creation_only", "kind": "bool", "default": True,
                      "label": "Limit CloudTrail to key creation events", "label_ko": "CloudTrail 조회를 키 생성 이벤트로 제한",
                      "description": "Applies when CloudTrail collection is enabled. On: queries CreateAccessKey only to find key creators with fewer requests. Off: queries other management events too, including available credential usage and STS issuance evidence; collection may take longer. This does not include S3 object data events.",
                      "description_ko": "CloudTrail 수집을 켰을 때 적용합니다. 켜면 CreateAccessKey만 조회해 적은 호출로 키 생성자를 찾습니다. 끄면 다른 관리 이벤트도 조회해 제공되는 키 사용·STS 발급 근거를 수집하므로 시간이 더 걸릴 수 있습니다. S3 객체 데이터 이벤트는 포함하지 않습니다."},
                     {"name": "cloudtrail_regions", "kind": "list", "default": [],
                      "label": "CloudTrail regions", "label_ko": "CloudTrail 리전",
                      "options": REGION_OPTIONS,
                      "description": "Choose enabled regions in your partition. For commercial AWS IAM global events include us-east-1. Required with CloudTrail.",
                      "description_ko": "계정과 파티션에서 사용할 수 있는 리전을 선택하세요. 일반 AWS의 IAM 전역 이벤트는 us-east-1을 포함합니다. CloudTrail 선택 시 필수입니다."},
                     {"name": "cloudtrail_days", "kind": "number", "default": 90, "min": 1, "max": 90,
                      "label": "CloudTrail history days", "label_ko": "CloudTrail 조회 기간(일)",
                      "description": "How far back to query Event History, from 1 to 90 days. Only events in the selected regions and period are considered; older or unavailable creation events cannot identify a creator.",
                      "description_ko": "Event History를 최근 며칠까지 조회할지 정합니다(1~90일). 선택한 리전·기간의 이벤트만 근거로 사용하며, 그 이전이나 조회할 수 없는 생성 이벤트는 생성자를 확인할 수 없습니다."},
                     {key: value for key, value in _SCHEDULE.items() if key != "default"}]},
        "vault": {"permissions": _permissions("vault"),
                  "plan": [_REGIONS, {"name": "ssm_prefixes", "label": "Parameter Store path prefixes",
                                      "label_ko": "Parameter Store 경로 접두어", "kind": "list", "hint": "/prod/",
                                      "description": "Also compare Parameter Store values below these paths. Requires GetParametersByPath with decryption and applicable KMS access. Leave empty to skip Parameter Store.",
                                      "description_ko": "입력한 경로 아래의 Parameter Store 값도 대조합니다. 복호화를 사용하는 GetParametersByPath와 해당 KMS 권한이 필요합니다. 비워 두면 Parameter Store는 읽지 않습니다."},
                           {"name": "previous_versions", "kind": "bool", "default": False,
                            "label": "Also compare earlier secret versions",
                            "label_ko": "이전 시크릿 버전도 대조",
                            "description": "Also reads earlier secret versions in memory to calculate fingerprints. This adds version reads; a historical match does not prove current storage. Original values are never stored.",
                            "description_ko": "이전 시크릿 버전도 메모리에서 읽어 지문을 계산합니다. 버전별 읽기 호출이 추가되며 과거 버전의 일치는 현재 보관을 뜻하지 않습니다. 원문 값은 저장하지 않습니다."},
                           {"name": "max_versions", "kind": "number", "default": 20, "min": 1, "max": 1000,
                            "label": "Versions per secret", "label_ko": "시크릿당 버전 수",
                            "description": "Maximum versions to compare per secret (1–1,000) when earlier versions are included. Reaching the limit leaves the version coverage incomplete.",
                            "description_ko": "이전 버전 대조 시 시크릿 하나당 비교할 최대 버전 수입니다(1~1,000). 한도에 걸리면 전체 버전을 확인한 것으로 처리하지 않습니다."},
                           {"name": "value_reader", "kind": "bool", "default": False,
                            "label": "Read values with a separate value-reader role",
                            "label_ko": "별도 값 읽기 역할로 값 읽기",
                            "description": "The collection role's stack also creates a value-reader role (EnableVaultValueRead) that may read only the secrets, Parameter Store paths and KMS keys listed here; the collection role assumes it for value reads and itself still reads no value. Per-account collection roles only. The check assumes the role and simulates its policy for every listed secret and path; it reads no value and no list. A scheduled run also needs the installation's AWS automatic collection to include the account.",
                            "description_ko": "수집 역할 스택이 여기 적은 시크릿·Parameter Store 경로·KMS 키만 읽는 값 읽기 역할(EnableVaultValueRead)도 만듭니다. 수집 역할은 값을 읽을 때만 이 역할을 맡고 스스로는 값을 읽지 않습니다. 계정별 수집 역할에서만 쓸 수 있습니다. 권한 확인은 역할을 맡은 뒤 적은 시크릿·경로마다 역할 정책을 시뮬레이션하며, 값과 목록은 읽지 않습니다. 주기 수집은 설치의 AWS 자동 수집 설정이 이 계정을 포함할 때만 돕니다."},
                           {"name": "value_reader_role", "kind": "text", "default": _READER_ROLE,
                            "label": "Value-reader role name", "label_ko": "값 읽기 역할 이름",
                            "description": "The VaultValueReaderRoleName of the stack; the same name in every account.",
                            "description_ko": "스택의 VaultValueReaderRoleName입니다. 모든 계정에서 같은 이름을 씁니다."},
                           {"name": "secret_arns", "kind": "list", "label": "Secret ARNs to compare",
                            "label_ko": "대조할 시크릿 ARN", "hint": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
                            "description": "Full Secrets Manager ARNs (with the six-character suffix) in the selected accounts and regions, at least one per account. Only these secrets are read; no secret list is read. One account's secrets, paths and keys must fit the role's policy (IAM allows 10,240 characters): about 30 secrets of usual length.",
                            "description_ko": "선택한 계정·리전의 Secrets Manager 전체 ARN(끝의 여섯 글자 포함)입니다. 계정마다 하나 이상 적습니다. 이 시크릿만 읽고 시크릿 목록은 읽지 않습니다. 한 계정의 시크릿·경로·키가 역할 정책(IAM 한도 10,240자)에 들어가야 하며, 보통 길이의 시크릿은 30개 정도입니다."},
                           {"name": "kms_key_arns", "kind": "list", "label": "Customer-managed KMS key ARNs",
                            "label_ko": "고객 관리형 KMS 키 ARN",
                            "description": "Keys of the secrets and parameters above, in the same accounts, when they are not AWS managed. The role may decrypt with them only through Secrets Manager or Parameter Store.",
                            "description_ko": "위 시크릿·파라미터를 AWS 관리형이 아닌 키로 암호화했을 때 같은 계정의 그 키입니다. 역할은 Secrets Manager·Parameter Store를 거쳐서만 복호화할 수 있습니다."},
                           _SCHEDULE]},
    },
    "auth_methods": [
        {"id": "role", "label": "Use per-account collection roles (recommended)", "label_ko": "계정별 수집 역할 사용(권장)",
         "renewal": "AUTOMATIC", "purposes": ["exposure", "inventory", "vault"], "fields": [],
         "auth_first": {"context": []}},
        {"id": "sso", "label": "IAM Identity Center permission set", "label_ko": "IAM Identity Center 권한 세트",
         "renewal": "EXPIRES", "new_setup": False, "purposes": ["exposure", "inventory", "vault"],
         "fields": [{"name": "permission_set", "label": "Permission set name", "label_ko": "권한 세트 이름",
                     "kind": "text", "public": True, "optional": True}]},
        {"id": "runtime", "label": "Use current server permissions directly (single account)", "label_ko": "현재 서버 권한 직접 사용(단일 계정)",
         "renewal": "AUTOMATIC", "advanced": True, "purposes": ["exposure", "inventory", "vault"], "fields": [],
         "auth_first": {"context": []}},
        {"id": _CLI, "label": "CreMore CLI in your AWS environment", "label_ko": "고객 AWS 환경의 CreMore CLI",
         "renewal": "NONE", "new_setup": False, "advanced": True, "purposes": ["inventory", "vault"], "fields": []},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    accounts = values.get("accounts") or []
    if not accounts or len(accounts) > 500 or any(not _ACCOUNT.fullmatch(a) for a in accounts):
        raise OnboardingValueError("AWS_ACCOUNT_IDS_INVALID")
    return {"accounts": list(dict.fromkeys(accounts)), "environment": values.get("environment", ""),
            "adopt_discovered": bool(values.get("adopt_discovered"))}


def credential(provider, method, fields):
    name = (fields.get("permission_set") or "").strip()
    if name and not _PERMISSION_SET.fullmatch(name):
        raise OnboardingValueError("AWS_PERMISSION_SET_INVALID")
    return {}  # the worker's approved identity reads; nothing is stored


def ready(repo, settings, connection):
    """Accounts are reached only through the identity an administrator approved; the installation's
    own identity reaches only its own single account. Each account's own refusal (already held,
    another access mode, no permission set) comes from registering it: all of them or none."""
    from cremore_aws_provider import aws_access

    if connection["auth_method"] == _CLI:
        return  # the customer's own environment reads; CreMore reaches no account
    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    if approved is None:
        raise OnboardingValueError("AWS_SCANNER_IDENTITY_NOT_APPROVED")
    if not connection.get("id") and connection["auth_method"] in {"role", "runtime"}:
        from cremore_aws_provider.aws_identity import require_server_workload

        require_server_workload(approved)
    checked_revision = connection["target"].get("auth", {}).get("scanner_approval_revision")
    if checked_revision is not None and checked_revision != approved["revision"]:
        raise OnboardingValueError("AWS_SCANNER_IDENTITY_CHANGED")
    accounts = connection["target"]["accounts"]
    if connection["auth_method"] == "runtime" and len(accounts) != 1:
        raise OnboardingValueError("RUNTIME_IDENTITY_IS_ONE_ACCOUNT")
    if (not connection.get("id") and connection["auth_method"] == "role"
            and "role_accounts" in connection["target"].get("auth", {})):
        from cremore_aws_provider.onboarding_discovery import role_account

        for account_id in accounts:
            role_account(connection, account_id, repo, settings)


def prepare(connection):
    """Register every account now: a member role's ExternalId must exist before its stack does."""
    from cremore_aws_provider import aws_access

    if connection["auth_method"] == _CLI:
        return []

    access = {"role": aws_access.ROLE, "sso": aws_access.SSO_PERMISSION_SET,
              "runtime": aws_access.RUNTIME_IDENTITY}[connection["auth_method"]]
    purpose = connection["purposes"][0]
    permission_set = (connection["target"].get("auth") or {}).get("permission_set")
    role_accounts = connection["target"].get("auth", {}).get("role_accounts", {})
    return [{"kind": "aws_account", "purpose": purpose,
             "account": {"account_id": account_id, "name": account_id,
                         "environment": connection["target"].get("environment", ""), "access": access,
                         **({"name": role_accounts[account_id]["name"],
                             "scanner_role_arn": role_accounts[account_id]["scanner_role_arn"]}
                            if account_id in role_accounts else {}),
                         **({"sso_role_name": permission_set} if permission_set else {})}}
            for account_id in connection["target"]["accounts"]]


def adoptable(repo, connection):
    """Accounts discovery registered in this connection's access mode, which it takes in
    (cremore.onboarding.adoption): Identity Center sweeps for a permission-set connection,
    Organizations sweeps (the StackSet's shared ExternalId) for a member-role one. An
    account an administrator disabled stays out."""
    from cremore_aws_provider import aws_access

    method = connection["auth_method"]
    if method not in ("role", "sso"):
        return []
    source, access = ("SSO", aws_access.SSO_PERMISSION_SET) if method == "sso" else ("ORGANIZATION", aws_access.ROLE)
    permission_set = (connection["target"].get("auth") or {}).get("permission_set")
    return [{"kind": "aws_account", "id": account.id,
             "target": {**connection["target"], "accounts": [account.account_id]}}
            for account in repo.list_aws_accounts()
            if account.source == source and account.access == access and account.enabled
            and not (permission_set and account.sso_role_name != permission_set)]


def _accounts(context):
    for link in context.children:
        if link["kind"] == "aws_account":
            account = context.repo.get_aws_account(uuid.UUID(link["child_id"]))
            if account is not None:
                yield account


def _prove(account, context):
    """The account screen's validation, from the worker, recorded under the job's lease.
    Once per account in one check, however many purposes ask."""
    if account.id in context.memo:
        return context.memo[account.id]
    context.memo[account.id] = result = _prove_once(account, context)
    return result


def _prove_once(account, context):
    from cremore_aws_provider import aws_access

    approved = aws_access.approval(context.repo, aws_access.SCANNER, context.settings)
    refusal = aws_access.validation_refusal(account, aws_access.SCANNER, approved)
    if refusal:
        return "MISSING", refusal
    if context.aws_role_checker is None:
        return "ERROR", "WORKER_AWS_NOT_CONFIGURED"
    result = context.aws_role_checker(account)
    code = result.code or ("SCANNER_ROLE_ASSUMED" if result.status == "VALID" else "ASSUME_ROLE_DENIED")
    with context.write() as repo:
        latest = aws_access.approval(repo, aws_access.SCANNER, context.settings)
        aws_access.record_validation(repo, account, aws_access.SCANNER, access_revision=account.access_revision,
                                     approval_revision=approved["revision"],
                                     current_approval_revision=(latest or {}).get("revision"),
                                     status=result.status, detail=code)
    return ("GRANTED", None) if result.status == "VALID" else ("MISSING", code)


def _denied(exc):
    code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", "")) if hasattr(exc, "response") else ""
    return code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError")


def check(connection, purpose, secrets, context):
    if "scanner_approval_revision" in connection["target"].get("auth", {}) and not context.children:
        from cremore_aws_provider.onboarding_discovery import check_draft

        return check_draft(connection, purpose, context)
    from cremore_aws_provider import aws_access

    if connection["auth_method"] == _CLI:
        return [{"permission": key, "status": "NOT_REPORTED", "detail": "CUSTOMER_CLI_REPORTS_ON_UPLOAD"}
                for key, *_rest in PROBES[purpose]]
    items = value_permission_items(connection, purpose)
    region = getattr(context.settings, "aws_region", None) or "us-east-1"
    # The value reader reads named secrets and paths: the scanner's list reads are neither asked nor needed.
    probes = [] if purpose == "vault" and _plan(connection, purpose).get("value_reader") is True else PROBES[purpose]
    for account in _accounts(context):
        status, detail = _prove(account, context)
        items.append({"permission": "scanner_access", "status": status, "subject": account.account_id,
                      **({"detail": detail} if detail else {})})
        if status != "GRANTED":
            items.extend({"permission": key, "status": "NOT_REPORTED", "detail": "SCANNER_ACCESS_REQUIRED",
                          "subject": account.account_id} for key, *_rest in probes)
            continue
        try:
            session = context.aws_sessions.open(account.account_id, aws_access.SCANNER)
        except aws_access.AccessBlocked as exc:
            items.extend({"permission": key, "status": "MISSING", "detail": exc.code, "subject": account.account_id}
                         for key, *_rest in probes)
            continue
        items.extend(policy_permission_items(connection, purpose, session, context))

        def reader(role, account=account):
            from cremore_aws_provider.aws_sessions import value_reader_arn

            context.aws_sessions.value_reader(account.account_id, role, "check")  # proves the trust; nothing is read
            return value_reader_arn(account.scanner_role_arn, account.account_id, role)
        items.extend(value_reader_items(connection, purpose, session, reader))
        for key, service, call, arguments, _label, _label_ko in probes:
            try:
                getattr(session.client(service, None if service == "iam" else region), call)(**arguments)
                items.append({"permission": key, "status": "GRANTED", "subject": account.account_id})
            except Exception as exc:  # noqa: BLE001 -- only the AWS error code is kept
                items.append({"permission": key, "status": "MISSING" if _denied(exc) else "ERROR",
                              "detail": "ACCESS_DENIED" if _denied(exc) else "REQUEST_FAILED",
                              "subject": account.account_id})
    return items


# The same provider owns the discovery and the account/collection descriptions.
from cremore_aws_provider.onboarding_discovery import (  # noqa: F401
    authenticate,
    discover,
    list_onboarding_scope,
)


def children(connection, purpose, plan):
    accounts = connection["target"]["accounts"]
    cli = connection["auth_method"] == _CLI
    if purpose == "exposure":
        return []  # the registered accounts are what S3 scope is chosen from
    if purpose == "inventory":
        # Describing an old saved plan applies today's field defaults. Its raw
        # choice must remain absent so reconciliation sees the explicit opt-in.
        chosen = connection.get("activating", {}).get(purpose, plan)
        policy = {"iam_policy_metadata": chosen["iam_policy_metadata"]} if "iam_policy_metadata" in chosen else {}
        scheduled = {"schedule_minutes": plan["schedule_minutes"], "schedule_source": "connection"} if "schedule_minutes" in plan and not cli else {}
        trails = []
        if plan.get("cloudtrail"):
            regions = plan.get("cloudtrail_regions") or []
            if not regions or any(not _REGION.fullmatch(region) for region in regions):
                raise OnboardingValueError("AWS_REGIONS_INVALID")
            trails = [{"kind": "coverage", "purpose": purpose, "collector_token": cli, "spec": {
                "name": f"CloudTrail {account_id}", "provider": "aws_cloudtrail", "account_id": account_id,
                "regions": regions, "window_days": plan.get("cloudtrail_days", 90),
                "cloudtrail_event_name": "CreateAccessKey" if plan.get("cloudtrail_creation_only") else "", **scheduled}} for account_id in accounts]
        if cli:
            return [{"kind": "coverage", "purpose": purpose, "collector_token": True, "spec": {
                "name": f"IAM {account_id}", "provider": "aws_iam", "account_id": account_id, "last_used": True, **policy}}
                for account_id in accounts] + trails
        if scheduled or policy:
            return [{"kind": "coverage", "purpose": purpose, "spec": {
                "name": f"IAM {account_id}", "provider": "aws_iam", "account_id": account_id,
                "service_credentials": True, "credential_report": True, "last_used": True, **policy, **scheduled}}
                for account_id in accounts] + trails
        return [{"kind": "aws_inventory", "purpose": purpose, "account_id": account_id,
                 **({"iam_only": True} if trails else {})} for account_id in accounts] + trails
    regions = plan.get("regions") or []
    if not regions or any(not _REGION.fullmatch(region) for region in regions):
        raise OnboardingValueError("AWS_REGIONS_INVALID")
    # The worker reads with the approved scanner access on a schedule; the CLI reads in the
    # customer's environment whenever it is run there.
    where = {"collector_token": True} if cli else {}
    run = {} if cli else {"server_collection": True, "schedule_minutes": plan.get("schedule_minutes", 1440),
                         "schedule_source": "connection"}
    history = {"include_previous_versions": bool(plan.get("previous_versions")),
               "max_versions_per_secret": plan.get("max_versions", 20)}
    role, secrets = _value_reader(connection, plan) if plan.get("value_reader") is True else (None, {})
    reader = {"value_reader_role": role} if role else {}
    out = []
    for account_id in accounts:
        # The role reads only the secrets named for its account. A plan names at least one for each of
        # its accounts (plan_problem); an account adopted later compares none.
        if not role or secrets.get(account_id):
            out.append({"kind": "coverage", "purpose": purpose, **where, "spec": {
                "name": f"Secrets Manager {account_id}", "provider": "aws_secrets_manager", "account_id": account_id,
                "regions": regions, **history, **run, **reader, **({"references": secrets[account_id]} if role else {})}})
        if plan.get("ssm_prefixes"):
            out.append({"kind": "coverage", "purpose": purpose, **where, "spec": {
                "name": f"Parameter Store {account_id}", "provider": "aws_ssm", "account_id": account_id,
                "regions": regions, "prefixes": plan["ssm_prefixes"], **run, **reader}})
    return out


def _value_reader(connection, plan):
    """The value-reader role and each of this target's accounts' own declared secrets.

    The plan was checked against every target (plan_problem). Here a target, or an account adopted
    later, keeps only the ARNs of its own accounts and ignores the others: they are other targets'.
    """
    from cremore_aws_provider.aws_sessions import ROLE_NAME, account_of_arn

    if connection["auth_method"] != "role":
        raise OnboardingValueError("VALUE_READER_NEEDS_ROLE_ACCESS")  # it trusts the member scanner role only
    role = plan.get("value_reader_role") or _READER_ROLE
    if not ROLE_NAME.fullmatch(role):
        raise OnboardingValueError("VALUE_READER_ROLE_INVALID")
    secrets = {}
    for arn in plan.get("secret_arns") or []:
        if (account := account_of_arn(arn)) in connection["target"]["accounts"]:
            secrets.setdefault(account, []).append(arn)
    return role, secrets
