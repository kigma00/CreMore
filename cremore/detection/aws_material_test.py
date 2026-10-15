"""Synthetic AWS regression cases. No provider or customer content is read."""

import json

import pytest

from cremore.detection import DetectorInput, Engine, ResourceRef
from cremore.detection.engine import EngineConfig
from cremore.detection.fingerprint import fingerprint
from cremore.detection.verify import VerifierConfig

ID = "AKIA" + "Z5X9K2MBV7QP3LN6"
OTHER_ID = "AKIA" + "N6P3Q7VBM2K9X5ZL"
SAK = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f"
LABEL = "aws_secret_access_key="
KEY = b"synthetic-fingerprint-domain-only!"


def aws(text, **config):
    engine = Engine(EngineConfig(fingerprint_key=KEY, **config))
    return [d for d in engine.scan(DetectorInput(text.encode())) if d.provider == "aws"]


@pytest.mark.parametrize("text,expected", [
    (ID, ["AWS_ACCESS_KEY_ID"]),
    ("aws_access_key_id=" + ID, ["AWS_ACCESS_KEY_ID"]),
    (LABEL + SAK, ["AWS_SECRET_ACCESS_KEY"]),
    ('"SecretAccessKey": "' + SAK + '"', ["AWS_SECRET_ACCESS_KEY"]),
    (f"{ID}\ncommit_sha=a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", ["AWS_ACCESS_KEY_ID"]),
    (f"{ID} a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", ["AWS_ACCESS_KEY_ID"]),
    (f"{ID}\n{SAK}G", ["AWS_ACCESS_KEY_ID"]),
    (f"{ID}G\n{LABEL}{SAK}", ["AWS_SECRET_ACCESS_KEY"]),
    (f"{ID}\n{LABEL}{SAK}G", ["AWS_ACCESS_KEY_ID"]),
    (f"{ID}\n{LABEL}" + "A" * 40, ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (json.dumps({"one": {"aws_access_key_id": ID}, "two": {"aws_secret_access_key": SAK}}),
     ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (f"[one]\naws_access_key_id={ID}\n[two]\n{LABEL}{SAK}",
     ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (f"aws_access_key_id: {ID}\n  aws_secret_access_key: {SAK}",
     ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (f"{ID}" + "!" * 513 + f"\n{LABEL}{SAK}",
     ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (f"{ID} {LABEL}{SAK} aws_access_key_id={OTHER_ID}",
     ["AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
])
def test_partial_material_is_retained_without_inventing_a_pair(text, expected):
    found = aws(text)
    assert sorted(d.credential_type for d in found) == sorted(expected)
    assert all(d.engine_verified is None for d in found)
    assert all(SAK not in d.redacted_line for d in found)


@pytest.mark.parametrize("text", [
    f"aws_access_key_id={ID}\n{LABEL}{SAK}",
    f"{LABEL}{SAK}\naws_access_key_id={ID}",
    f"{ID} {SAK}", f"{SAK}\n{ID}",
    json.dumps({"aws_access_key_id": ID, "aws_secret_access_key": SAK}),
    json.dumps({"AccessKeyId": ID, "SecretAccessKey": SAK}, indent=2),
])
def test_unambiguous_adjacent_pairs_keep_the_original_fingerprint_without_duplicate_parts(text):
    found = aws(text)
    assert [d.credential_type for d in found] == ["AWS_ACCESS_KEY"]
    assert found[0].fingerprint == fingerprint((ID + "\0" + SAK).encode(), key=KEY)
    assert found[0].identifier == ID


@pytest.mark.parametrize("gap,expected", [(512, ["AWS_ACCESS_KEY"]),
    (513, ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (8192, ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])])
def test_distance_limit_does_not_discard_labelled_material(gap, expected):
    text = ID + " " * (gap - len(LABEL)) + LABEL + SAK
    assert sorted(d.credential_type for d in aws(text)) == sorted(expected)


def test_partial_findings_persist_with_distinct_identities_and_no_secret_bytes():
    from cremore.db.repository import InMemoryRepository
    from cremore.scanning.orchestrator import Orchestrator

    repo = InMemoryRepository()
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=engine, config=engine.config)
    for name, value in [("id", ID), ("secret", LABEL + SAK), ("pair", ID + " " + SAK)]:
        orch.scan_resource(value.encode(), ResourceRef(source_type="inline", resource="synthetic", location=name), verify=False)
    findings = repo.list_findings()
    assert len(findings) == 3
    credentials = [repo.get_credential(f.credential_id) for f in findings]
    assert {c.credential_type for c in credentials} == {"AWS_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
    assert len({c.fingerprint for c in credentials}) == 3
    saved = [c.model_dump(mode="json") for c in credentials]
    saved += [e.model_dump(mode="json") for c in credentials for e in repo.exposures_for_credential(c.id)]
    assert SAK not in json.dumps(saved)
    assert all(c.credential_status == "UNKNOWN" for c in credentials)
    severities = {repo.get_credential(f.credential_id).credential_type: f.severity for f in findings}
    assert severities["AWS_ACCESS_KEY_ID"] == "INFO"
    assert severities["AWS_SECRET_ACCESS_KEY"] == "LOW"


def test_incomplete_material_and_temporary_pairs_never_send_an_authentication_request():
    class NoNetwork:
        def __getattr__(self, name):
            raise AssertionError("no authentication request is allowed")

    for value in (ID, LABEL + SAK, ID.replace("AKIA", "ASIA") + " " + SAK,
                  ID.replace("AKIA", "ASIA") + " " + SAK + " AWS_SESSION_TOKEN=synthetic-session-value"):
        found = aws(value, verify=VerifierConfig(enabled=True), http_client=NoNetwork())
        assert found and all(d.extra_safe_data["verification_state"] == "unsupported" for d in found)
        assert all(d.engine_verified is None for d in found)
        assert all("synthetic-session-value" not in d.redacted_line for d in found)


@pytest.mark.parametrize("text,linkable", [
    (f'secret = "{SAK}"', True),                       # AWS secret under a generic name
    (f'secret = "{SAK[:-1]}"', False),                 # 39 characters is not the shape
    (f'secret = "{SAK}x"', False),                     # 41 characters is not the shape
    (f'password = "{SAK}"', True),                     # the label does not decide the shape
    ('secret = "' + "a" * 20 + '"', False),
])
def test_a_value_of_the_aws_secret_shape_carries_a_component_hash_whatever_labels_it(text, linkable):
    """Byte equality is the only way a differently labelled copy can ever link."""
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    found = [d for d in engine.scan(DetectorInput(text.encode())) if d.provider != "aws"]
    assert found, text
    carried = [d for d in found if "aws_secret_component_fingerprint" in d.extra_safe_data]
    assert bool(carried) is linkable
    if linkable:
        assert carried[0].extra_safe_data["aws_secret_component_fingerprint"] == fingerprint(
            b"AWS_SECRET_ACCESS_KEY\x00" + SAK.encode(), key=KEY)
        # The value is not retyped and its confidence is untouched.
        assert carried[0].credential_type.startswith("GENERIC_") and carried[0].confidence == "low"


def test_an_unkeyed_scan_publishes_no_component_hash_for_a_shaped_value():
    found = [d for d in Engine().scan(DetectorInput(f'secret = "{SAK}"'.encode()))]
    assert found and not any("component_fingerprint" in key for d in found for key in d.extra_safe_data)
