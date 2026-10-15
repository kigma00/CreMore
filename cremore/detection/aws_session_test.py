"""Only synthetic STS material; binding is passive and scoped to direct fields."""
import itertools
import json
from dataclasses import asdict

import pytest
from cremore_aws_provider.detection.session_material import MAX_BINDING_BYTES, MAX_TOKEN_BYTES

from cremore.db.repository import InMemoryRepository
from cremore.detection import DetectorInput, Engine, ResourceRef
from cremore.detection.engine import EngineConfig
from cremore.detection.fingerprint import fingerprint
from cremore.detection.verify import VerifierConfig
from cremore.scanning.orchestrator import Orchestrator

ID = "ASIA" + "Z5X9K2MBV7QP3LN6"
SECRET = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f"
TOKEN = "IQoJb3JpZ2luX2Vj" + "A1b2C3d4E5f6G7h8I9j0K+l/M=n" * 8
OTHER_TOKEN = "IQoJb3JpZ2luX2Vj" + "Z9y8X7w6V5u4T3s2R1q0P+o/N=m" * 8
KEY = b"synthetic-session-fingerprint-domain"
FIELDS = {"AccessKeyId": ID, "SecretAccessKey": SECRET, "SessionToken": TOKEN}


def engine(**kwargs):
    return Engine(EngineConfig(fingerprint_key=KEY, **kwargs))


def aws(text, **kwargs):
    return [item for item in engine(**kwargs).scan(DetectorInput(text.encode())) if item.provider == "aws"]


@pytest.mark.parametrize("order", list(itertools.permutations(FIELDS)))
@pytest.mark.parametrize("format_name", ["json", "env", "profile"])
def test_all_field_orders_bind_without_changing_pair_fingerprint(order, format_name):
    text = json.dumps({name: FIELDS[name] for name in order}) if format_name == "json" else "\n".join(
        name + "=" + FIELDS[name] for name in order)
    if format_name == "profile":
        text = "[profile synthetic]\n" + text
    result = aws(text)
    assert [item.credential_type for item in result] == ["AWS_ACCESS_KEY"]
    pair = result[0]
    assert pair.fingerprint == fingerprint((ID + "\0" + SECRET).encode(), key=KEY)
    assert pair.extra_safe_data["aws_session_material"] == "COMPLETE"
    assert pair.extra_safe_data["aws_session_fingerprint"] == fingerprint(
        ("AWS_STS_SESSION_V1\0" + ID + "\0" + SECRET + "\0" + TOKEN).encode(), key=KEY)
    assert TOKEN not in json.dumps([asdict(item) for item in result])


@pytest.mark.parametrize("text", [
    json.dumps({"AccessKeyId": ID, "SecretAccessKey": SECRET, "child": {"SessionToken": TOKEN}}),
    json.dumps({"child": {"AccessKeyId": ID, "SecretAccessKey": SECRET}, "SessionToken": TOKEN}),
    f"[one]\nAccessKeyId={ID}\nSecretAccessKey={SECRET}\n[two]\nSessionToken={TOKEN}",
    f"AccessKeyId={ID}\nSecretAccessKey={SECRET}\n\nSessionToken={TOKEN}",
    f"AccessKeyId={ID}\nSecretAccessKey={SECRET}\n  SessionToken={TOKEN}",
])
def test_nested_objects_profiles_and_assignment_blocks_never_share_tokens(text):
    result = aws(text)
    pair = next(item for item in result if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.extra_safe_data["aws_session_material"] == "UNBOUND"
    assert "aws_session_fingerprint" not in pair.extra_safe_data
    assert any(item.credential_type == "AWS_SESSION_TOKEN" for item in result)


def test_duplicate_labels_and_repeated_pair_with_different_tokens_are_ambiguous():
    duplicate = json.dumps(FIELDS)[:-1] + ', "SessionToken": ' + json.dumps(OTHER_TOKEN) + "}"
    for text in (duplicate, json.dumps([FIELDS, FIELDS | {"SessionToken": OTHER_TOKEN}])):
        pair = next(item for item in aws(text) if item.credential_type == "AWS_ACCESS_KEY")
        assert pair.extra_safe_data["aws_session_material"] == "AMBIGUOUS"
        assert "aws_session_fingerprint" not in pair.extra_safe_data


def test_shell_assignments_and_long_tokens_are_bounded_and_redacted():
    text = f'export AWS_ACCESS_KEY_ID={ID} AWS_SESSION_TOKEN="{TOKEN}" AWS_SECRET_ACCESS_KEY={SECRET}'
    pair = next(item for item in aws(text) if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.extra_safe_data["aws_session_material"] == "COMPLETE"
    oversized = "A" * (MAX_TOKEN_BYTES + 1)
    result = aws(f"AccessKeyId={ID}\nSecretAccessKey={SECRET}\nSessionToken={oversized}")
    assert not any(item.credential_type == "AWS_SESSION_TOKEN" for item in result)
    assert result[0].extra_safe_data["aws_session_material"] == "UNBOUND"
    github = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
    all_found = engine().scan(DetectorInput(f"SessionToken={oversized} github_token={github}".encode()))
    assert all_found and all(oversized not in item.redacted_line for item in all_found)
    padded = json.dumps(FIELDS) + " " * MAX_BINDING_BYTES
    assert next(item for item in aws(padded) if item.credential_type == "AWS_ACCESS_KEY").extra_safe_data["aws_session_material"] == "UNBOUND"


_STS_OK = (
    '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    "<GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/demo/sess</Arn>"
    "<UserId>AROAEXAMPLEID:sess</UserId><Account>123456789012</Account>"
    "</GetCallerIdentityResult></GetCallerIdentityResponse>")


class _Resp:
    def __init__(self, status, text):
        self.status_code, self.text, self.headers = status, text, {}


class _RecordingClient:
    """Captures the headers of the single GetCallerIdentity probe; sends nothing real."""

    def __init__(self, resp):
        self._resp, self.calls = resp, []

    def post(self, url, headers=None, content=None):
        self.calls.append(headers)
        return self._resp

    def close(self):
        pass


def test_complete_session_is_verified_and_sends_token_without_saving_it():
    client = _RecordingClient(_Resp(200, _STS_OK))
    pair = next(item for item in aws(json.dumps(FIELDS), verify=VerifierConfig(enabled=True), http_client=client)
                if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.engine_verified is True
    assert pair.extra_safe_data["verification_state"] == "verified"
    assert pair.extra_safe_data["verification_account"] == "123456789012"
    # The bound session token is signed as the STS security-token header ...
    assert client.calls and client.calls[0]["X-Amz-Security-Token"] == TOKEN
    # ... but never lands on the finding.
    assert TOKEN not in json.dumps(asdict(pair))


def test_unbound_asia_pair_stays_unsupported_and_never_calls_the_provider():
    class NoNetwork:
        def __getattr__(self, _):
            raise AssertionError("an unbound STS pair cannot be sent to a provider")
    text = json.dumps({"AccessKeyId": ID, "SecretAccessKey": SECRET, "child": {"SessionToken": TOKEN}})
    pair = next(item for item in aws(text, verify=VerifierConfig(enabled=True), http_client=NoNetwork())
                if item.credential_type == "AWS_ACCESS_KEY")
    assert pair.engine_verified is None
    assert pair.extra_safe_data["aws_session_material"] == "UNBOUND"
    assert pair.extra_safe_data["verification_state"] == "unsupported"
    assert pair.extra_safe_data["verification_error"] == "AWS_STS_SESSION_TOKEN_NOT_BOUND"


def test_fresh_unbound_scan_clears_saved_session_binding_and_never_saves_raw_token():
    repo = InMemoryRepository()
    scanner = engine()
    orch = Orchestrator(repo, engine=scanner, config=scanner.config)
    resource = ResourceRef(source_type="inline", resource="synthetic", location="same-input")
    orch.scan_resource(json.dumps(FIELDS).encode(), resource, verify=False)
    finding = repo.list_findings()[0]
    exposure = repo.exposures_for_credential(finding.credential_id)[0]
    assert exposure.metadata["aws_session_material"] == "COMPLETE"
    assert TOKEN not in json.dumps(exposure.model_dump(mode="json"))
    orch.scan_resource(json.dumps({key: value for key, value in FIELDS.items() if key != "SessionToken"}).encode(), resource, verify=False)
    refreshed = repo.exposures_for_credential(finding.credential_id)[0]
    assert refreshed.metadata["aws_session_material"] == "UNBOUND"
    assert "aws_session_fingerprint" not in refreshed.metadata
