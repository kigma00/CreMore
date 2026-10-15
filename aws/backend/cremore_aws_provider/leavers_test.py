"""Who owns an IAM access key the inventory listed: an IAM user, a candidate until confirmed."""

from cremore_aws_provider import leavers

ISSUED = {"credential_type": "AWS_ACCESS_KEY", "evidence": "ISSUED", "identifier": "AKIAABCDEFGHIJKLMNOP",
          "principal_arn": "arn:aws:iam::123456789012:user/team/dana", "state": "Inactive",
          "last_used_at": "2026-09-01T00:00:00+00:00"}


def test_an_iam_users_key_is_named_by_account_and_user_with_what_a_disable_needs():
    owner = leavers.credential_owner(ISSUED)
    assert (owner["account"], owner["label"], owner["keys"]) == (
        "123456789012:dana", "dana (123456789012)", [("PROVIDER_LOGIN", "dana")])
    assert (owner["state"], owner["name"]) == ("REVOKED_OR_EXPIRED", "AKIA••••MNOP")
    assert owner["action"] == {"principal_arn": ISSUED["principal_arn"], "key_id": ISSUED["identifier"],
                               "account_id": "123456789012"}


def test_sessions_roles_and_service_credentials_are_nobodys():
    assert leavers.credential_owner({**ISSUED, "identifier": "ASIAABCDEFGHIJKLMNOP"}) is None
    assert leavers.credential_owner({**ISSUED, "principal_arn": "arn:aws:iam::123456789012:role/app"}) is None
    assert leavers.credential_owner({**ISSUED, "credential_type": "AWS_SERVICE_CREDENTIAL"}) is None
    assert leavers.credential_owner({**ISSUED, "evidence": "USAGE"}) is None
