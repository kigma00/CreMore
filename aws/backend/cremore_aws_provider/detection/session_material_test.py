"""JSON binding decodes values but keeps raw spans for redaction."""

import json
from dataclasses import asdict

import pytest

from cremore.detection.aws_session_test import (
    _STS_OK,
    FIELDS,
    KEY,
    TOKEN,
    _RecordingClient,
    _Resp,
    aws,
)
from cremore.detection.fingerprint import fingerprint
from cremore.detection.verify import VerifierConfig
from cremore_aws_provider.detection.session_material import bind_sessions
from cremore_aws_provider.detection.verify.aws import _session_token


@pytest.mark.parametrize("escape", [r"\/", r"\u002f"])
def test_json_escaped_token_binds_decoded_value_and_verifies(escape):
    text = json.dumps(FIELDS).replace("/", escape)
    client = _RecordingClient(_Resp(200, _STS_OK))
    pair = next(item for item in aws(text, verify=VerifierConfig(enabled=True), http_client=client)
                if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.extra_safe_data["aws_session_material"] == "COMPLETE"
    assert pair.extra_safe_data["aws_session_fingerprint"] == fingerprint(
        ("AWS_STS_SESSION_V1\0" + FIELDS["AccessKeyId"] + "\0" + FIELDS["SecretAccessKey"] + "\0" + TOKEN).encode(), key=KEY)
    assert pair.engine_verified is True
    assert client.calls[0]["X-Amz-Security-Token"] == TOKEN
    serialized = json.dumps(asdict(pair))
    assert TOKEN not in serialized and TOKEN.replace("/", escape) not in pair.redacted_line
    data = text.encode()
    _, _, spans = bind_sessions(data, [], key=KEY, validate_secret=None)
    assert [data[slice(*span)] for span in spans.values()] == [TOKEN.replace("/", escape).encode()]


@pytest.mark.parametrize("field", list(FIELDS))
@pytest.mark.parametrize("duplicate", ['"escaped\\/tokenAAAAAAAA"', "null", "false", "123", "{}", "[]"])
@pytest.mark.parametrize("first", [False, True])
def test_duplicate_json_fields_are_ambiguous_even_when_not_strings(field, duplicate, first):
    extra = json.dumps(field) + ":" + duplicate
    original = json.dumps(FIELDS)
    text = "{" + extra + "," + original[1:] if first else original[:-1] + "," + extra + "}"
    client = _RecordingClient(_Resp(200, _STS_OK))
    pair = next(item for item in aws(text, verify=VerifierConfig(enabled=True), http_client=client)
                if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.extra_safe_data["aws_session_material"] == "AMBIGUOUS"
    assert "aws_session_fingerprint" not in pair.extra_safe_data
    assert client.calls == []


def test_equivalent_escaped_tokens_are_not_conflicting_material():
    text = "[" + json.dumps(FIELDS) + "," + json.dumps(FIELDS).replace("/", r"\/") + "]"
    pair = next(item for item in aws(text) if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.extra_safe_data["aws_session_material"] == "COMPLETE"


@pytest.mark.parametrize("token", [r"AAAAAAAAAAAAAAAA\n", r"AAAAAAAAAAAAAAAA\q", r"AAAAAAAAAAAAAAAA\u0022"])
def test_decoded_token_still_rejects_invalid_header_material(token):
    assert _session_token({"aws_session_token": token}) == ""
