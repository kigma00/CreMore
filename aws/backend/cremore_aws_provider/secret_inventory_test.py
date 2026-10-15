"""Secrets Manager boundary/history regressions with synthetic GitHub values."""

import json

import pytest

from cremore.coverage.coverage_test import ACCOUNT, ARN, GH, engine, spec
from cremore_aws_provider.coverage import collect_aws_vault

CURRENT, PREVIOUS, OLD = "a" * 32, "b" * 32, "c" * 32


class Secrets:
    def __init__(self):
        self.calls = []

    def list_secrets(self, **kwargs):
        self.calls.append(("list", kwargs))
        return {"SecretList": [{"ARN": ARN}]}

    def list_secret_version_ids(self, **kwargs):
        self.calls.append(("versions", kwargs))
        return {"ARN": ARN, "Versions": [{"VersionId": v} for v in (CURRENT, PREVIOUS, OLD)]}

    def get_secret_value(self, **kwargs):
        self.calls.append(("read", kwargs))
        version = kwargs.get("VersionId", CURRENT if kwargs.get("VersionStage") == "AWSCURRENT" else PREVIOUS)
        stages = ["AWSCURRENT"] if version == CURRENT else ["AWSPREVIOUS"] if version == PREVIOUS else []
        return {"ARN": kwargs["SecretId"], "VersionId": version, "VersionStages": stages, "SecretBinary": GH.encode()}


def collect(client, **changes):
    result = collect_aws_vault(spec(**changes), lambda *_: client, engine())
    assert GH not in json.dumps([r.model_dump() for r in result.items])
    return result


def test_history_reads_current_first_pins_older_versions_and_keeps_unlabelled_unknown():
    client = Secrets()
    result = collect(client, include_previous_versions=True)
    assert result.status == "COMPLETE"
    assert [i.version_state for i in result.items] == ["CURRENT", "PREVIOUS", "UNKNOWN"]
    assert all(i.credential_type == "GITHUB_TOKEN" for i in result.items)
    assert client.calls[2][1]["IncludeDeprecated"] is True
    assert [c[1].get("VersionId") for c in client.calls if c[0] == "read"] == [None, PREVIOUS, OLD]


def test_history_limit_and_denial_preserve_current_value():
    result = collect(Secrets(), include_previous_versions=True, max_versions_per_secret=1)
    assert len(result.items) == 1 and result.status == "PARTIAL" and "SECRET_VERSION_LIMIT" in result.reasons
    class Denied(Secrets):
        def list_secret_version_ids(self, **kwargs):
            raise RuntimeError(GH)
    result = collect(Denied(), include_previous_versions=True)
    assert result.status == "PARTIAL" and result.items[0].version == CURRENT
    assert "SECRET_VERSION_LIST_FAILED" in result.reasons


@pytest.mark.parametrize("bad", [{}, {"SecretList": None}, {"SecretList": [], "NextToken": 3}])
def test_malformed_listing_never_becomes_empty_success(bad):
    client = Secrets()
    client.list_secrets = lambda **_: bad
    assert collect(client).status == "FAILED"


@pytest.mark.parametrize("arn", [ARN.replace(ACCOUNT, "999999999999"), ARN.replace("us-east-1", "eu-west-1"),
                                  ARN + "?bad", "not-an-arn"])
def test_outside_arn_is_not_read_or_counted_as_an_empty_complete_scope(arn):
    client = Secrets()
    client.list_secrets = lambda **_: {"SecretList": [{"ARN": arn}]}
    result = collect(client)
    assert not client.calls and result.status == "FAILED" and "PROVIDER_SCOPE_MISMATCH" in result.reasons


@pytest.mark.parametrize("field,value", [("ARN", ARN.replace(ACCOUNT, "999999999999")),
                                         ("VersionStages", ["unexpected"]), ("SecretBinary", "base64-is-not-sdk-bytes")])
def test_get_response_mismatch_never_fingerprints_value(field, value):
    client = Secrets()
    original = client.get_secret_value
    client.get_secret_value = lambda **kw: {**original(**kw), field: value}
    result = collect(client)
    assert all(i.evidence == "UNRESOLVED" for i in result.items)
    assert "SECRET_RESPONSE_MISMATCH" in result.reasons


def test_version_mismatch_and_version_listing_arn_mismatch_are_partial():
    client = Secrets()
    original = client.get_secret_value
    client.get_secret_value = lambda **kw: {**original(**kw), "VersionId": CURRENT}
    assert "SECRET_RESPONSE_MISMATCH" in collect(client, include_previous_versions=True).reasons
    client = Secrets()
    client.list_secret_version_ids = lambda **_: {"ARN": "wrong", "Versions": []}
    assert "SECRET_VERSION_LIST_FAILED" in collect(client, include_previous_versions=True).reasons


def test_empty_page_with_next_token_continues_and_loop_is_partial():
    client, calls = Secrets(), []
    def listing(**kwargs):
        calls.append(kwargs)
        return {"SecretList": [] if len(calls) == 1 else [{"ARN": ARN}], "NextToken": "next"}
    client.list_secrets = listing
    result = collect(client)
    assert len(calls) == 2 and result.status == "PARTIAL" and "PAGINATION_LOOP" in result.reasons


def test_declared_secrets_are_read_without_a_listing_and_a_refused_one_is_not_absence():
    other = ARN.replace("app/db-Ab12Cd", "app/api-Ef34Gh")
    client = Secrets()
    complete = collect(client, references=[ARN, other])
    # Every declared secret read, none listed: the run is complete over exactly that scope.
    assert complete.status == "COMPLETE" and [c[0] for c in client.calls] == ["read", "read"]
    assert {i.reference for i in complete.items} == {ARN, other}
    client = Secrets()
    original = client.get_secret_value

    def read(**kwargs):
        if kwargs["SecretId"] == other:
            raise RuntimeError("AccessDeniedException " + GH)  # refused, with provider text that must not leak
        return original(**kwargs)

    client.get_secret_value = read
    partial = collect(client, references=[ARN, other])
    assert partial.status == "PARTIAL" and "SECRET_READ_FAILED" in partial.reasons
    assert [c[0] for c in client.calls] == ["read"]
    [refused] = [i for i in partial.items if i.evidence == "UNRESOLVED"]
    assert refused.reference == other and refused.reason == "SECRET_READ_FAILED"


def test_references_only_are_routed_to_their_own_region():
    remote = ARN.replace("us-east-1", "eu-west-1")
    calls = []
    def factory(service, region):
        client = Secrets()
        original = client.get_secret_value
        def read(**kwargs):
            calls.append((region, kwargs["SecretId"]))
            return original(**kwargs)
        client.get_secret_value = read
        return client
    config = spec().model_copy(update={"regions": ["us-east-1", "eu-west-1"], "references": [ARN, remote]})
    result = collect_aws_vault(config, factory, engine())
    assert result.status == "COMPLETE" and calls == [("us-east-1", ARN), ("eu-west-1", remote)]
