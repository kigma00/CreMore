"""Vault metadata access is not proof that AWS will return or decrypt values."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from cremore.onboarding import check, permissions, service
from cremore_aws_provider import onboarding, onboarding_discovery


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("prefixes", [[], ["/synthetic/"]])
def test_vault_list_permissions_do_not_approve_value_reads(monkeypatch, draft, prefixes):
    account = "111111111111"
    plan = {"regions": ["us-east-1"], "ssm_prefixes": prefixes}
    record = {"provider": "aws", "edition": "cloud", "auth_method": "runtime", "secret_refs": {},
              "target": {"accounts": [account], "auth": {"scanner_approval_revision": 1} if draft else {}},
              "purposes": ["vault"], "plans": {}, "checks": {"requested_plans": {"vault": plan}}}
    calls = []

    class Client:
        def list_secrets(self, **kwargs):
            calls.append("list_secrets")
            return {"SecretList": []}

        def describe_parameters(self, **kwargs):
            calls.append("describe_parameters")
            return {"Parameters": []}

    session = SimpleNamespace(account_id=account, client=lambda *_: Client())
    context = SimpleNamespace(children=[], settings=SimpleNamespace(aws_region="us-east-1"),
                              aws_sessions=SimpleNamespace(open=lambda *_: session))
    monkeypatch.setattr(onboarding_discovery, "_session", lambda *_: session)
    monkeypatch.setattr(onboarding, "_accounts", lambda _: [SimpleNamespace(account_id=account)])
    monkeypatch.setattr(onboarding, "_prove", lambda *_: ("GRANTED", None))
    record["checks"].update(results=check.evaluate(record, {}, context), checked_at=datetime.now(UTC).isoformat(),
                           digest=service.check_digest(record))
    blockers = permissions.blockers(record, {"vault": plan})
    assert {b["permission"] for b in blockers} == {"secrets_values", *(["ssm_values"] if prefixes else [])}
    assert all(b["status"] == "NOT_REPORTED" and b["detail"] == "VALUE_READ_PERMISSION_NOT_CHECKED" for b in blockers)
    assert calls and set(calls) <= {"list_secrets", "describe_parameters"}
    record["auth_method"] = "customer_cli"
    assert onboarding.value_permission_items(record, "vault") == []
    assert not permissions.required(record, "vault", plan)


def test_the_template_role_says_which_values_it_cannot_read():
    # The CloudFormation role's ScannerMutationDeny refuses GetSecretValue; Parameter Store values it does not grant.
    templated, named = "111111111111", "222222222222"
    record = {"provider": "aws", "auth_method": "role", "target": {"accounts": [templated, named], "auth": {"role_accounts": {
        templated: {"scanner_role_arn": f"arn:aws:iam::{templated}:role/CredentialExposureScannerRole"},
        named: {"scanner_role_arn": f"arn:aws:iam::{named}:role/team/OwnReadRole"}}}},
        "plans": {"vault": {"ssm_prefixes": ["/synthetic/"]}}}
    # A role an administrator named may allow the read: that stays unknown, not denied.
    assert {(item["subject"], item["permission"], item["detail"]) for item in onboarding.value_permission_items(record, "vault")} == {
        (templated, "secrets_values", "AWS_SCANNER_ROLE_DENIES_SECRET_VALUES"),
        (templated, "ssm_values", "AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES"),
        (named, "secrets_values", "VALUE_READ_PERMISSION_NOT_CHECKED"),
        (named, "ssm_values", "VALUE_READ_PERMISSION_NOT_CHECKED")}


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("selected,allowed,mode,expected", [
    (False, True, "complete", None), (True, True, "complete", "GRANTED"),
    (True, True, "denied", "MISSING"), (True, True, "partial", "MISSING"),
    (True, False, "complete", "MISSING"),
])
def test_policy_metadata_has_its_own_read_check(monkeypatch, draft, selected, allowed, mode, expected):
    from cremore_aws_provider.iam_inventory_test import ACCOUNT, SECRET, PolicyIAM

    client = PolicyIAM(mode)
    session = SimpleNamespace(account_id=ACCOUNT, client=lambda *_: client)
    context = SimpleNamespace(children=[], settings=SimpleNamespace(aws_region="us-east-1", iam_potential_access_allowed=allowed),
                              aws_sessions=SimpleNamespace(open=lambda *_: session))
    record = {"provider": "aws", "edition": "cloud", "auth_method": "runtime", "secret_refs": {},
              "target": {"accounts": [ACCOUNT], "auth": {"scanner_approval_revision": 1} if draft else {}},
              "purposes": ["inventory"], "plans": {}, "checks": {"requested_plans": {"inventory": {"iam_policy_metadata": selected}}}}
    monkeypatch.setattr(onboarding_discovery, "_session", lambda *_: session)
    monkeypatch.setattr(onboarding, "_accounts", lambda _: [SimpleNamespace(account_id=ACCOUNT)])
    monkeypatch.setattr(onboarding, "_prove", lambda *_: ("GRANTED", None))
    items = onboarding.check(record, "inventory", {}, context)
    policy = [item for item in items if item["permission"] == "iam_policy_read"]
    assert [item["status"] for item in policy] == ([] if expected is None else [expected])
    assert SECRET not in str(items) and "PolicyDocument" not in str(items)
    assert not any(name.startswith("simulate") for name, _ in client.calls)
    assert bool(any(name == "get_user" for name, _ in client.calls)) == (selected and allowed)


@pytest.mark.parametrize("case,detail", [("empty", "IAM_POLICY_NO_USER_TO_CHECK"), ("limit", "IAM_POLICY_CHECK_LIMIT")])
def test_policy_check_does_not_treat_missing_or_unbounded_evidence_as_access(case, detail):
    from cremore_aws_provider.iam_inventory_test import ACCOUNT, PolicyIAM

    client = PolicyIAM()
    if case == "empty":
        client.list_users = lambda **_: {"Users": []}
    else:
        client.list_user_policies = lambda **kwargs: {"PolicyNames": [], "IsTruncated": True,
                                                     "Marker": str(int(kwargs.get("Marker", "0")) + 1)}
    session = SimpleNamespace(account_id=ACCOUNT, client=lambda *_: client)
    context = SimpleNamespace(settings=SimpleNamespace())
    record = {"plans": {"inventory": {"iam_policy_metadata": True}}}
    [answer] = onboarding.policy_permission_items(record, "inventory", session, context)
    assert answer == {"permission": "iam_policy_read", "subject": ACCOUNT, "status": "NOT_REPORTED", "detail": detail}


READER_ACCOUNT, OTHER_ACCOUNT, ADOPTED_ACCOUNT = "111111111111", "222222222222", "333333333333"
SECRET_ARN = f"arn:aws:secretsmanager:us-east-1:{READER_ACCOUNT}:secret:prod/db-AbCdEf"
OTHER_SECRET = f"arn:aws:secretsmanager:us-east-1:{OTHER_ACCOUNT}:secret:prod/db-GhIjKl"
SCANNER_ROLE = f"arn:aws:iam::{READER_ACCOUNT}:role/CredentialExposureScannerRole"
READER_ROLE = f"arn:aws:iam::{READER_ACCOUNT}:role/CredentialVaultValueReaderRole"
KEY_ARN = f"arn:aws:kms:us-east-1:{READER_ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
PATH_ARN = f"arn:aws:ssm:us-east-1:{READER_ACCOUNT}:parameter/prod"
ALLOWED = {"EvalDecision": "allowed"}


def reader_plan(**changes):
    return {"regions": ["us-east-1"], "ssm_prefixes": ["/prod/"], "value_reader": True,
            "value_reader_role": "CredentialVaultValueReaderRole", "secret_arns": [SECRET_ARN], **changes}


class Simulator:
    """IAM that only simulates, one result per resource as IAM reports it; any other call would be a read.

    ``answer`` is the result fields of every resource, a function of (action, resource) giving them, or an
    exception for the call. ``specific`` reports them as one result's ResourceSpecificResults."""

    def __init__(self, answer, *, specific=False, truncated=False):
        self.answer, self.specific, self.truncated, self.calls = answer, specific, truncated, []

    def simulate_principal_policy(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.answer, Exception):
            raise self.answer
        [action] = kwargs["ActionNames"]
        rows = [(arn, self.answer(action, arn) if callable(self.answer) else self.answer) for arn in kwargs["ResourceArns"]]
        if self.specific:
            return {"EvaluationResults": [{"EvalActionName": action, "EvalResourceName": "*", "EvalDecision": "allowed",
                    "ResourceSpecificResults": [{"EvalResourceName": arn, "EvalResourceDecision": fields["EvalDecision"],
                                                 **{k: v for k, v in fields.items() if k != "EvalDecision"}}
                                                for arn, fields in rows]}], "IsTruncated": self.truncated}
        return {"EvaluationResults": [{"EvalActionName": action, "EvalResourceName": arn, **fields} for arn, fields in rows],
                "IsTruncated": self.truncated}


class Lister:
    """The scanner's list reads; a value-reader check must not ask for them."""

    def __init__(self, calls):
        self.calls = calls

    def list_secrets(self, **_kwargs):
        self.calls.append("list_secrets")
        return {"SecretList": []}

    def describe_parameters(self, **_kwargs):
        self.calls.append("describe_parameters")
        return {"Parameters": []}


def checked_items(monkeypatch, plan, iam, *, refuse=None):
    """A registered account's vault check; returns its value answers, the roles assumed, the list reads and the record."""
    from cremore_aws_provider import aws_access

    assumed, lists = [], []

    def value_reader(account_id, role, label):
        assumed.append((account_id, role, label))
        if refuse:
            raise aws_access.AccessBlocked(refuse)
        return SimpleNamespace(client=lambda *_a, **_k: pytest.fail("a check reads no value"))

    session = SimpleNamespace(account_id=READER_ACCOUNT,
                              client=lambda service, region=None: iam if service == "iam" else Lister(lists))
    context = SimpleNamespace(children=[], settings=SimpleNamespace(aws_region="us-east-1"),
                              aws_sessions=SimpleNamespace(open=lambda *_: session, value_reader=value_reader))
    record = {"provider": "aws", "edition": "cloud", "auth_method": "role", "secret_refs": {},
              "target": {"accounts": [READER_ACCOUNT]}, "purposes": ["vault"], "plans": {},
              "checks": {"requested_plans": {"vault": plan}}}
    monkeypatch.setattr(onboarding, "_accounts", lambda _: [SimpleNamespace(account_id=READER_ACCOUNT,
                                                                            scanner_role_arn=SCANNER_ROLE)])
    monkeypatch.setattr(onboarding, "_prove", lambda *_: ("GRANTED", None))
    items = onboarding.check(record, "vault", {}, context)
    return ({item["permission"]: (item["status"], item.get("detail")) for item in items
             if item["permission"] in ("secrets_values", "ssm_values")}, assumed, lists, record, context)


LISTED_ONLY = {"EvalDecision": "explicitDeny", "MatchedStatements": [{"SourcePolicyId": "VaultValueReaderListedSecretsOnly"}]}


@pytest.mark.parametrize("specific", [False, True])
@pytest.mark.parametrize("answer,status,detail", [
    (ALLOWED, "GRANTED", None),
    ({"EvalDecision": "implicitDeny"}, "MISSING", "VALUE_READER_POLICY_DENIES"),
    # The stack's own deny of every unlisted secret is fixed by listing it; any other deny is not.
    (LISTED_ONLY, "MISSING", "VALUE_READER_POLICY_DENIES"),
    ({"EvalDecision": "explicitDeny", "MatchedStatements": [{"SourcePolicyId": "PermissionsBoundary"}]},
     "MISSING", "VALUE_READER_POLICY_EXPLICITLY_DENIED"),
    ({"EvalDecision": "allowed", "MissingContextValues": ["aws:SourceVpc"]}, "NOT_REPORTED", "VALUE_READER_SIMULATION_NEEDS_CONTEXT"),
    ({"EvalDecision": "notADecision"}, "NOT_REPORTED", "VALUE_READER_SIMULATION_FAILED"),
])
def test_the_value_reader_check_simulates_every_listed_resource_and_reads_no_value_or_list(monkeypatch, specific, answer,
                                                                                          status, detail):
    iam = Simulator(answer, specific=specific)
    plan = reader_plan(regions=["us-east-1", "eu-west-1"], secret_arns=[SECRET_ARN, SECRET_ARN.replace("db-", "api-")])
    answers, assumed, lists, record, context = checked_items(monkeypatch, plan, iam)
    assert answers == {"secrets_values": (status, detail), "ssm_values": (status, detail)}
    assert assumed == [(READER_ACCOUNT, "CredentialVaultValueReaderRole", "check")]
    # Every listed secret, and the requested path in every region: what IAM authorizes each call on.
    assert iam.calls == [
        {"PolicySourceArn": READER_ROLE, "ActionNames": ["secretsmanager:GetSecretValue"], "ResourceArns": plan["secret_arns"]},
        {"PolicySourceArn": READER_ROLE, "ActionNames": ["ssm:GetParametersByPath"],
         "ResourceArns": [PATH_ARN, PATH_ARN.replace("us-east-1", "eu-west-1")]}]
    assert lists == []  # no ListSecrets or DescribeParameters: the value reader names what it reads
    assert onboarding.value_permission_items(record, "vault") == []  # the scanner's template answer is not asked
    if status == "GRANTED":
        record["checks"].update(results=check.evaluate(record, {}, context), checked_at=datetime.now(UTC).isoformat(),
                               digest=service.check_digest(record))
        assert permissions.blockers(record, {"vault": plan}) == []


@pytest.mark.parametrize("specific", [False, True])
@pytest.mark.parametrize("field,allowed", [
    ("PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"),
    ("OrganizationsDecisionDetail", "AllowedByOrganizations"),
])
@pytest.mark.parametrize("decision", ["implicitDeny", "explicitDeny"])
def test_boundary_and_organization_denials_cannot_be_fixed_by_listing_resources(
        monkeypatch, specific, field, allowed, decision):
    answer = {**LISTED_ONLY, "EvalDecision": decision, field: {allowed: False}}
    answers, *_ = checked_items(monkeypatch, reader_plan(), Simulator(answer, specific=specific))
    assert answers == dict.fromkeys(
        ("secrets_values", "ssm_values"), ("MISSING", "VALUE_READER_POLICY_EXPLICITLY_DENIED"))


@pytest.mark.parametrize("field,allowed", [
    ("PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"),
    ("OrganizationsDecisionDetail", "AllowedByOrganizations"),
])
def test_aggregate_boundary_denial_applies_to_resource_specific_denials(monkeypatch, field, allowed):
    iam = Simulator({"EvalDecision": "implicitDeny"}, specific=True)
    simulate = iam.simulate_principal_policy

    def aggregate(**kwargs):
        page = simulate(**kwargs)
        page["EvaluationResults"][0][field] = {allowed: False}
        return page

    iam.simulate_principal_policy = aggregate
    answers, *_ = checked_items(monkeypatch, reader_plan(), iam)
    assert answers == dict.fromkeys(
        ("secrets_values", "ssm_values"), ("MISSING", "VALUE_READER_POLICY_EXPLICITLY_DENIED"))


def test_one_refused_secret_refuses_the_permission_and_a_long_list_is_simulated_in_pages(monkeypatch):
    secrets = [SECRET_ARN.replace("db-", f"s{index:02d}-") for index in range(25)]
    refused = secrets[22]
    iam = Simulator(lambda action, arn: {"EvalDecision": "implicitDeny"} if arn == refused else ALLOWED)
    answers, *_rest = checked_items(monkeypatch, reader_plan(secret_arns=secrets), iam)
    assert answers == {"secrets_values": ("MISSING", "VALUE_READER_POLICY_DENIES"), "ssm_values": ("GRANTED", None)}
    assert [len(call["ResourceArns"]) for call in iam.calls] == [20, 5, 1]
    # A page that comes back cut short, or a resource without its own answer, decides nothing.
    for broken in (Simulator(ALLOWED, truncated=True), Simulator(lambda action, arn: {} if arn == refused else ALLOWED)):
        answers, *_rest = checked_items(monkeypatch, reader_plan(secret_arns=secrets), broken)
        assert answers["secrets_values"] == ("NOT_REPORTED", "VALUE_READER_SIMULATION_FAILED")


@pytest.mark.parametrize("answer,detail", [
    (ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic"}}, "SimulatePrincipalPolicy"), "VALUE_READER_SIMULATION_DENIED"),
    (RuntimeError("synthetic"), "VALUE_READER_SIMULATION_FAILED"),
])
def test_a_simulation_that_cannot_run_is_not_reported(monkeypatch, answer, detail):
    answers, *_rest = checked_items(monkeypatch, reader_plan(), Simulator(answer))
    assert answers == {"secrets_values": ("NOT_REPORTED", detail), "ssm_values": ("NOT_REPORTED", detail)}


@pytest.mark.parametrize("plan,refuse,expected", [
    (reader_plan(), "VALUE_READER_ASSUME_DENIED", {"secrets_values": ("MISSING", "VALUE_READER_ASSUME_DENIED"),
                                                   "ssm_values": ("MISSING", "VALUE_READER_ASSUME_DENIED")}),
    (reader_plan(ssm_prefixes=[], secret_arns=[OTHER_SECRET]), None,
     {"secrets_values": ("NOT_REPORTED", "AWS_SECRET_ARNS_REQUIRED")}),
    # Paths but no region: nothing to simulate, said as such rather than failing the whole check.
    (reader_plan(regions=[]), None, {"secrets_values": ("GRANTED", None), "ssm_values": ("NOT_REPORTED", "AWS_REGIONS_INVALID")}),
])
def test_an_unassumable_reader_or_nothing_to_simulate_is_not_granted(monkeypatch, plan, refuse, expected):
    iam = Simulator(ALLOWED)
    answers, *_rest = checked_items(monkeypatch, plan, iam, refuse=refuse)
    assert answers == expected
    assert bool(iam.calls) == (expected.get("secrets_values") == ("GRANTED", None))


@pytest.mark.parametrize("reader", [True, False])
def test_the_scanners_list_reads_are_required_and_asked_only_without_the_value_reader(monkeypatch, reader):
    plan = reader_plan(value_reader=reader)
    _answers, _assumed, lists, record, _context = checked_items(monkeypatch, plan, Simulator(ALLOWED))
    required = {p["id"] for p in permissions.required(record, "vault", plan)}
    assert {"secrets_list", "ssm_list"} & required == (set() if reader else {"secrets_list", "ssm_list"})
    assert lists == ([] if reader else ["list_secrets", "describe_parameters"])


@pytest.mark.parametrize("method", ["role", "runtime"])
def test_a_draft_check_chains_from_its_scanner_session_with_the_drafts_external_id(monkeypatch, method):
    import datetime as dt

    from cremore_aws_provider import aws_access, onboarding_roles
    from cremore_aws_provider.aws_sessions import AccountSession

    assumed, lists, iam = [], [], Simulator(ALLOWED)
    scanner = {"AccessKeyId": "ASIASCANNER0000000001", "SecretAccessKey": "s", "SessionToken": "t",
               "Expiration": dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15)}

    def factory(purpose, service, region, creds):
        if service != "sts":
            return iam if service == "iam" else Lister(lists)

        class STS:
            def assume_role(self, **kwargs):
                assumed.append((kwargs, creds))
                return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{READER_ACCOUNT}:assumed-role/reader/check"},
                        "Credentials": {**scanner, "AccessKeyId": "ASIAREADER00000000001"}}
        return STS()

    via = aws_access.ROLE if method == "role" else aws_access.RUNTIME_IDENTITY
    session = AccountSession(READER_ACCOUNT, aws_access.SCANNER, via, scanner if method == "role" else None, factory)
    monkeypatch.setattr(onboarding_discovery, "_session", lambda *_: session)
    monkeypatch.setattr(onboarding_roles, "role_account", lambda *_: {"scanner_role_arn": SCANNER_ROLE,
                                                                      "external_id": "draft-external-id-0001"})
    record = {"provider": "aws", "edition": "cloud", "auth_method": method, "secret_refs": {},
              "target": {"accounts": [READER_ACCOUNT], "auth": {"scanner_approval_revision": 1}},
              "purposes": ["vault"], "plans": {}, "checks": {"requested_plans": {"vault": reader_plan()}}}
    context = SimpleNamespace(children=[], repo=None, settings=SimpleNamespace(aws_region="us-east-1"))
    items = {item["permission"]: (item["status"], item.get("detail")) for item in onboarding.check(record, "vault", {}, context)}
    assert lists == [] and "secrets_list" not in items  # the draft check asks for no list either
    if method == "runtime":
        assert items["secrets_values"] == ("MISSING", "VALUE_READER_NEEDS_ROLE_ACCESS") and assumed == []
        return
    assert items["secrets_values"] == items["ssm_values"] == ("GRANTED", None)
    [(call, creds)] = assumed
    assert call == {"RoleArn": READER_ROLE, "RoleSessionName": "cremore-vault-check", "DurationSeconds": 900,
                    "ExternalId": "draft-external-id-0001"}
    assert creds is scanner  # chained with the scanner's credentials


def test_value_reader_specs_name_the_role_and_each_targets_own_secrets():
    from cremore.coverage.models import ConnectionSpec

    record = {"auth_method": "role", "target": {"accounts": [READER_ACCOUNT, OTHER_ACCOUNT]}}
    plan = reader_plan(secret_arns=[SECRET_ARN, OTHER_SECRET], kms_key_arns=[KEY_ARN])
    specs = [ConnectionSpec.model_validate(child["spec"]) for child in onboarding.children(record, "vault", plan)]
    assert [(s.provider, s.account_id, s.references, s.value_reader_role) for s in specs] == [
        ("aws_secrets_manager", READER_ACCOUNT, [SECRET_ARN], "CredentialVaultValueReaderRole"),
        ("aws_ssm", READER_ACCOUNT, [], "CredentialVaultValueReaderRole"),
        ("aws_secrets_manager", OTHER_ACCOUNT, [OTHER_SECRET], "CredentialVaultValueReaderRole"),
        ("aws_ssm", OTHER_ACCOUNT, [], "CredentialVaultValueReaderRole")]
    # Off, the specs read as before: the scanner session, no declared secrets.
    plain = onboarding.children(record, "vault", {**plan, "value_reader": False})
    assert all("value_reader_role" not in child["spec"] and "references" not in child["spec"] for child in plain)
    # One target, or an account adopted later, keeps its own ARNs and ignores the others' (never refuses them).
    root = {"auth_method": "role", "target": {"accounts": [READER_ACCOUNT]}}
    assert [child["spec"].get("references") for child in onboarding.children(root, "vault", plan)] == [[SECRET_ARN], None]
    adopted = {"auth_method": "role", "target": {"accounts": [ADOPTED_ACCOUNT]}}
    assert [child["spec"]["provider"] for child in onboarding.children(adopted, "vault", plan)] == ["aws_ssm"]


def roots(*accounts, method="role"):
    return [{"auth_method": method, "target": {"accounts": [account]}} for account in accounts]


@pytest.mark.parametrize("targets,changes,code", [
    (roots(READER_ACCOUNT, method="runtime"), {}, "VALUE_READER_NEEDS_ROLE_ACCESS"),
    (roots(READER_ACCOUNT, method="customer_cli"), {}, "VALUE_READER_NEEDS_ROLE_ACCESS"),
    (roots(READER_ACCOUNT), {"value_reader_role": "Reader/../Other"}, "VALUE_READER_ROLE_INVALID"),
    (roots(READER_ACCOUNT), {"secret_arns": [f"arn:aws:secretsmanager:us-east-1:{READER_ACCOUNT}:secret:*"]}, "AWS_SECRET_ARNS_INVALID"),
    (roots(READER_ACCOUNT), {"secret_arns": [SECRET_ARN[:-7]]}, "AWS_SECRET_ARNS_INVALID"),  # no six-character suffix
    (roots(READER_ACCOUNT), {"secret_arns": [SECRET_ARN, OTHER_SECRET]}, "AWS_SECRET_ARN_OUTSIDE_SCOPE"),
    (roots(READER_ACCOUNT), {"secret_arns": [SECRET_ARN.replace("us-east-1", "eu-west-1")]}, "AWS_SECRET_ARN_OUTSIDE_SCOPE"),
    (roots(READER_ACCOUNT, OTHER_ACCOUNT), {}, "AWS_SECRET_ARNS_REQUIRED"),  # the other account names none
    (roots(READER_ACCOUNT), {"kms_key_arns": [f"arn:aws:kms:us-east-1:{READER_ACCOUNT}:alias/app"]}, "AWS_KMS_KEY_ARNS_INVALID"),
    (roots(READER_ACCOUNT), {"kms_key_arns": [KEY_ARN.replace(READER_ACCOUNT, OTHER_ACCOUNT)]}, "AWS_KMS_KEY_ARN_OUTSIDE_SCOPE"),
    (roots(READER_ACCOUNT), {"secret_arns": [SECRET_ARN.replace("db-", f"secret-number-{index:03d}-") for index in range(40)]},
     "AWS_VALUE_READER_POLICY_TOO_LARGE"),
    (roots(READER_ACCOUNT), {"ssm_prefixes": [f"/path-{index}/" for index in range(30)], "regions": ["us-east-1", "eu-west-1"]},
     "AWS_VALUE_READER_POLICY_TOO_LARGE"),
    # The platform's list field takes ~@+=: (no SSM name or stack path has them) and "."/".." segments (CreMore's
    # collection scope refuses them).
    (roots(READER_ACCOUNT), {"ssm_prefixes": ["/prod/", "/prod@x/"]}, "AWS_PARAMETER_PATH_INVALID"),
    (roots(READER_ACCOUNT), {"ssm_prefixes": ["/a:b/"]}, "AWS_PARAMETER_PATH_INVALID"),
    (roots(READER_ACCOUNT), {"ssm_prefixes": ["/prod/../x/"]}, "AWS_PARAMETER_PATH_INVALID"),
    (roots(READER_ACCOUNT), {"ssm_prefixes": ["/./"]}, "AWS_PARAMETER_PATH_INVALID"),
    # Without the value-reader role too: a read of such a path would only fail the whole region.
    (roots(READER_ACCOUNT, method="runtime"), {"value_reader": False, "ssm_prefixes": ["/prod=x/"]}, "AWS_PARAMETER_PATH_INVALID"),
])
def test_value_reader_plans_the_stack_could_not_name_are_refused_against_every_target(targets, changes, code):
    assert onboarding.plan_problem(targets, "vault", reader_plan(**changes)) == code


def test_value_reader_plans_are_judged_where_every_target_is_known():
    from cremore.onboarding import targets as platform_targets

    plan = reader_plan(secret_arns=[SECRET_ARN, OTHER_SECRET])
    assert onboarding.plan_problem(roots(READER_ACCOUNT, OTHER_ACCOUNT), "vault", plan) is None
    assert onboarding.plan_problem(roots(READER_ACCOUNT), "vault", {**plan, "value_reader": False}) is None
    assert onboarding.plan_problem(roots(READER_ACCOUNT), "inventory", plan) is None
    # Twenty-five usual secrets still fit one account's policy.
    many = [SECRET_ARN.replace("db-", f"s{index:02d}-") for index in range(25)]
    assert onboarding.plan_problem(roots(READER_ACCOUNT), "vault", reader_plan(secret_arns=many)) is None
    # The platform asks at normalization, with all of a multi-account connection's targets at once.
    record = {"provider": "aws", "edition": "cloud", "auth_method": "role", "purposes": ["vault"],
              "target": {"accounts": [READER_ACCOUNT]}}
    with pytest.raises(service.OnboardingError) as raised:
        platform_targets.normalize_plan(record, "vault", plan)
    assert raised.value.code == "AWS_SECRET_ARN_OUTSIDE_SCOPE"
    both = {**record, "target": {"accounts": [READER_ACCOUNT, OTHER_ACCOUNT]}}
    assert platform_targets.normalize_plan(both, "vault", plan)["secret_arns"] == [SECRET_ARN, OTHER_SECRET]
    # A path the list field takes but the stack cannot is refused there too, before any check.
    with pytest.raises(service.OnboardingError) as raised:
        platform_targets.normalize_plan(record, "vault", reader_plan(ssm_prefixes=["/prod@x/"]))
    assert raised.value.code == "AWS_PARAMETER_PATH_INVALID"
    assert platform_targets.normalize_plan(record, "vault", reader_plan(ssm_prefixes=["/prod/app/"]))["ssm_prefixes"] == ["/prod/app/"]


def test_an_account_adopted_later_joins_a_value_reader_connection_without_its_secrets():
    """Adoption narrows the connection to the new account (cremore.onboarding.adoption): the ARNs of the
    connection's own accounts must not refuse it, or its whole inventory would roll back on every retry."""
    import uuid

    from cremore.coverage.store import CoverageStore
    from cremore.db.repository import InMemoryRepository
    from cremore.onboarding.adoption import adopt
    from cremore.onboarding.fixtures_test import legacy_aws_setup
    from cremore.onboarding.onboarding_test import (
        SETTINGS,
        activate,
        approve_aws,
        checked,
        discovered,
    )
    from cremore.onboarding.store import ProviderConnectionStore

    repo = InMemoryRepository()
    approve_aws(repo)
    with legacy_aws_setup():
        record = checked(repo, {"provider": "aws", "purposes": ["inventory", "vault"], "auth_method": "role",
                                "target": {"accounts": [READER_ACCOUNT], "adopt_discovered": True}})
    activate(repo, record, {"inventory": {"schedule_minutes": 60}, "vault": reader_plan(schedule_minutes=60)})
    found = discovered(repo, ADOPTED_ACCOUNT, "ORGANIZATION", external_id="shared-external-id-0001")
    assert [item["id"] for item in adopt(repo, SETTINGS)] == [str(found.id)]
    store = ProviderConnectionStore(repo)
    specs = [CoverageStore(repo).get(uuid.UUID(link["child_id"]))["spec"] for link in store.children(record["id"])
             if link["kind"] == "coverage"]
    adopted = {(spec["provider"], spec.get("value_reader_role", "")) for spec in specs if spec["account_id"] == ADOPTED_ACCOUNT}
    assert adopted == {("aws_iam", ""), ("aws_ssm", "CredentialVaultValueReaderRole")}  # no secrets named: none compared
    assert {spec["provider"] for spec in specs if spec["account_id"] == READER_ACCOUNT} == {"aws_iam", "aws_secrets_manager", "aws_ssm"}
    assert adopt(repo, SETTINGS) == []  # taken once, not retried


@pytest.mark.parametrize("selected", [True, False])
def test_policy_option_reaches_manual_and_scheduled_iam_specs(selected):
    from cremore.coverage.models import ConnectionSpec

    record = {"auth_method": "runtime", "target": {"accounts": ["111111111111"]}}
    for schedule in ({}, {"schedule_minutes": 15}):
        [child] = onboarding.children(record, "inventory", {"iam_policy_metadata": selected, **schedule})
        assert child["kind"] == "coverage"
        spec = ConnectionSpec.model_validate(child["spec"])
        assert spec.iam_policy_metadata is selected
        assert spec.schedule_minutes == schedule.get("schedule_minutes", 0)
    assert onboarding.children(record, "inventory", {})[0]["kind"] == "aws_inventory"
