from pathlib import Path


def test_member_account_role_requires_account_guard_and_external_id():
    template = (
        Path(__file__).resolve().parent.parent
        / "deploy"
        / "cloudformation"
        / "member-account-role.yaml"
    ).read_text(encoding="utf-8")

    external = template.split("  ExternalId:", 1)[1].split("  EnableRemediation:", 1)[0]
    # SingleAccount is the default and keeps the account-match guard (gated below,
    # asserted present at the end); Organization mode leaves TargetAccountId empty.
    assert "Default: SingleAccount" in template
    assert "RuleCondition: !Equals [!Ref DeploymentMode, 'SingleAccount']" in template
    # ExternalId is never optional in either mode.
    assert "Default:" not in external and "MinLength: 16" in external and "^$|" not in external
    assert "HasExternalId" not in template
    # scanner and remediation roles: Identity Center and ARN trust, each with/without an org,
    # and the value-reader role's one trust of the scanner role
    assert template.count("sts:ExternalId: !Ref ExternalId") == 9
    assert template.count("aws:PrincipalArn: !Ref TrustedPrincipalPattern") == 2
    assert template.count("aws:PrincipalArn: !Ref RemediationTrustedPrincipalPattern") == 2
    # the remediation role never reuses the scanner's trust parameters
    remediation = template.split("  RemediationRole:", 1)[1].split("\nOutputs:", 1)[0]
    assert "TrustedPrincipalPattern" not in remediation.replace("RemediationTrustedPrincipalPattern", "")
    assert "!Ref TrustedPrincipalArn" not in remediation and "IdentityCenterAccountId}" not in remediation.replace("RemediationIdentityCenterAccountId}", "")
    assert template.count("AWSReservedSSO_[A-Za-z0-9+=,.@_-]{1,32}_[?]{16}$'") == 2
    assert "Fn::Equals:\n            - !Ref TargetAccountId\n            - !Ref AWS::AccountId" in template
