from cremore.api.exposure_surface import surface


def row(identifier, severity="HIGH", *, arn="", name="", status="OPEN", locations=1, found=("github",), provider="aws"):
    return {"id": identifier, "workflow_status": status, "severity": severity, "exposure_count": locations,
            "provider": provider, "source_types": list(found), "principal": arn, "principal_name": name,
            "credential_type": "AWS_ACCESS_KEY", "identifier_hint": "AKIA"}


CI = "arn:aws:iam::123456789012:user/ops/ci-deployer"


def test_one_identity_gathers_its_credentials_and_every_place_they_were_found():
    result = surface([
        row("1", "HIGH", arn=CI, name="ci-deployer", locations=3, found=("github",)),
        row("2", "CRITICAL", arn=CI, name="ci-deployer", locations=2, found=("s3", "notion")),
        row("3", "LOW", arn="arn:aws:iam::123456789012:user/reader", locations=1),
    ])
    first = result["principals"][0]
    # Two credentials, five places, one problem — which the flat list cannot show.
    assert first["credentials"] == 2 and first["locations"] == 5 and first["label"] == "ci-deployer"
    assert first["severity"] == "CRITICAL" and first["account_id"] == "123456789012"
    assert first["found_in"] == ["github", "notion", "s3"]
    assert [f["id"] for f in first["findings"]] == ["2", "1"]  # most severe first
    # Most severe group first, and the one identity carrying more than one credential is counted.
    assert [g["label"] for g in result["principals"]] == ["ci-deployer", "reader"]
    assert result["totals"] == {"principals": 2, "credentials": 3, "locations": 6, "shared_identities": 1}


def test_an_arn_and_a_login_name_are_never_merged_into_one_identity():
    """The same human may hold both; asserting they are one is not ours to make."""

    result = surface([row("1", arn=CI, name="ci-deployer"), row("2", name="ci-deployer", provider="github")])
    assert [(g["basis"], g["key"]) for g in result["principals"]] == [
        ("PRINCIPAL_ARN", CI), ("PRINCIPAL_NAME", "github:ci-deployer")]
    assert result["bases"] == ["PRINCIPAL_ARN", "PRINCIPAL_NAME"]
    # Only the bases this installation's rows actually carry are reported.
    assert surface([row("1", arn=CI)])["bases"] == ["PRINCIPAL_ARN"]
    assert surface([])["bases"] == [] and surface([])["principals"] == []


def test_rejected_matches_are_not_surface_and_an_unknown_identity_is_not_a_person():
    result = surface([
        row("1", arn=CI, locations=2),
        row("2", arn=CI, locations=9, status="FALSE_POSITIVE"),
        row("3", arn=CI, locations=9, status="IGNORED"),
        row("4", locations=4, provider="notion"),
    ])
    assert result["principals"][0]["locations"] == 2  # the rejected and ignored rows are gone
    # A credential whose identity nobody established is counted apart, never grouped.
    assert result["unattributed"] == {"credentials": 1, "locations": 4}
    assert all(group["label"] for group in result["principals"])
    assert result["totals"]["credentials"] == 2
