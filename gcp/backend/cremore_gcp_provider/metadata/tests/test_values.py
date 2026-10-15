"""Value reads verify what the provider returned and hand back only bytes."""

from __future__ import annotations

import base64
import subprocess
import sys
import unittest

from cremore_gcp_provider.metadata.transport import ApiError
from cremore_gcp_provider.metadata.values import (
    MAX_SECRET_BYTES,
    crc32c,
    read_api_key_string,
    read_secret_version,
    read_service_account_public_key,
)

from .fake import API_KEY_NAME, EMAIL, KEY_ID, PROJECT, REGIONAL_SECRET, SECRET, FakeTransport

VERSION = SECRET + "/versions/2"
SA_KEY = f"projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{KEY_ID}"
PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def payload(data, *, checksum=True, name=VERSION, base=None):
    body = {"data": base64.b64encode(data).decode()}
    if checksum:
        body["dataCrc32c"] = str(crc32c(data))
    url = (base or "https://secretmanager.googleapis.com/v1") + f"/{name}:access"
    return {url: {"name": name, "payload": body}}


class SharedLibraryTests(unittest.TestCase):
    def test_legacy_imports_keep_shared_reader_and_error_identity(self):
        from cremore_gcp import resources, transport, values

        from cremore_gcp_provider.metadata import collector as platform_collector

        self.assertIs(ApiError, transport.ApiError)
        self.assertIs(crc32c, values.crc32c)
        self.assertIs(platform_collector.PROJECT_RE, resources.PROJECT_RE)
        self.assertIs(read_api_key_string, values.read_api_key_string)
        self.assertIs(read_secret_version, values.read_secret_version)
        self.assertIs(read_service_account_public_key, values.read_service_account_public_key)
        error = transport.ApiError("rate_limited", retry_after=12)
        self.assertEqual((error.code, error.retry_after, str(error)), ("rate_limited", 12, "rate_limited"))

    def test_shared_library_imports_without_platform_or_auth_sdk(self):
        script = """import sys
from cremore_gcp import linkage, resources, transport, values
for prefix in ('cremore', 'cremore_gcp_provider', 'google.auth', 'httpx'):
    assert not any(name == prefix or name.startswith(prefix + '.') for name in sys.modules), prefix
"""
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


class ChecksumTests(unittest.TestCase):
    def test_the_castagnoli_checksum_matches_the_documented_polynomial(self):
        self.assertEqual(crc32c(b""), 0)
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)

    def test_a_mismatched_checksum_is_refused_rather_than_fingerprinted(self):
        transport = FakeTransport({
            f"https://secretmanager.googleapis.com/v1/{VERSION}:access": {
                "name": VERSION, "payload": {"data": base64.b64encode(b"abc").decode(),
                                             "dataCrc32c": "1"}}})
        with self.assertRaises(ApiError) as caught:
            read_secret_version(transport, VERSION)
        self.assertEqual(caught.exception.code, "checksum_mismatch")

    def test_a_payload_without_a_checksum_is_still_accepted(self):
        transport = FakeTransport(payload(b"abc", checksum=False))
        self.assertEqual(read_secret_version(transport, VERSION), b"abc")

    def test_a_non_numeric_checksum_is_an_invalid_payload(self):
        transport = FakeTransport({
            f"https://secretmanager.googleapis.com/v1/{VERSION}:access": {
                "name": VERSION, "payload": {"data": base64.b64encode(b"abc").decode(),
                                             "dataCrc32c": "later"}}})
        with self.assertRaises(ApiError) as caught:
            read_secret_version(transport, VERSION)
        self.assertEqual(caught.exception.code, "invalid_checksum")

    def test_checksum_requires_a_bounded_unsigned_decimal_without_coercion(self):
        for checksum in (False, True, 0.0, float("inf"), [], {}, "-1", "+0", " 0", "0 ",
                         "00000000000", 4294967296):
            with self.subTest(checksum=repr(checksum)):
                transport = FakeTransport({
                    f"https://secretmanager.googleapis.com/v1/{VERSION}:access": {
                        "name": VERSION, "payload": {"data": "", "dataCrc32c": checksum}}})
                with self.assertRaises(ApiError) as caught:
                    read_secret_version(transport, VERSION)
                self.assertEqual(caught.exception.code, "invalid_checksum")


class SecretVersionTests(unittest.TestCase):
    def test_the_version_name_must_be_the_one_that_was_asked_for(self):
        transport = FakeTransport({
            f"https://secretmanager.googleapis.com/v1/{VERSION}:access": {
                "name": SECRET + "/versions/9", "payload": {"data": "YQ=="}}})
        with self.assertRaises(ApiError) as caught:
            read_secret_version(transport, VERSION)
        self.assertEqual(caught.exception.code, "invalid_version_name")

    def test_a_name_outside_the_grammar_never_reaches_the_provider(self):
        transport = FakeTransport({})
        for name in (SECRET, SECRET + "/versions/latest", "../../etc/passwd"):
            with self.assertRaises(ApiError):
                read_secret_version(transport, name)
        self.assertEqual(transport.calls, [])

    def test_a_regional_version_is_read_from_its_own_endpoint(self):
        name = REGIONAL_SECRET + "/versions/1"
        transport = FakeTransport(payload(
            b"abc", name=name, base="https://secretmanager.europe-west4.rep.googleapis.com/v1"))
        self.assertEqual(read_secret_version(transport, name), b"abc")
        self.assertIn("europe-west4.rep.googleapis.com", transport.calls[0][1])

    def test_an_oversized_or_undecodable_payload_is_refused(self):
        transport = FakeTransport(payload(b"x" * (MAX_SECRET_BYTES + 1), checksum=False))
        with self.assertRaises(ApiError) as caught:
            read_secret_version(transport, VERSION)
        self.assertEqual(caught.exception.code, "oversized_payload")
        transport = FakeTransport({
            f"https://secretmanager.googleapis.com/v1/{VERSION}:access": {
                "name": VERSION, "payload": {"data": "not base64!!"}}})
        with self.assertRaises(ApiError) as caught:
            read_secret_version(transport, VERSION)
        self.assertEqual(caught.exception.code, "invalid_payload")

    def test_a_binary_payload_is_returned_as_bytes_not_decoded_text(self):
        transport = FakeTransport(payload(b"\xff\xfe\x00"))
        self.assertEqual(read_secret_version(transport, VERSION), b"\xff\xfe\x00")

    def test_non_ascii_base64_is_a_bounded_provider_error(self):
        wire = FakeTransport({f"https://secretmanager.googleapis.com/v1/{VERSION}:access": {
            "name": VERSION, "payload": {"data": "잘못된응답"}}})
        with self.assertRaises(ApiError) as caught:
            read_secret_version(wire, VERSION)
        self.assertEqual(caught.exception.code, "invalid_payload")


class KeyMaterialTests(unittest.TestCase):
    def test_an_api_key_string_is_bounded_and_its_name_is_checked_first(self):
        transport = FakeTransport({
            f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString": {
                "keyString": "AIza" + "B" * 35}})
        self.assertEqual(read_api_key_string(transport, API_KEY_NAME), "AIza" + "B" * 35)
        with self.assertRaises(ApiError):
            read_api_key_string(transport, "projects/p/locations/global/keys/x")
        transport = FakeTransport({
            f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString": {
                "keyString": "A" * 5000}})
        with self.assertRaises(ApiError) as caught:
            read_api_key_string(transport, API_KEY_NAME)
        self.assertEqual(caught.exception.code, "invalid_key_string")

    def test_the_service_account_read_returns_a_public_certificate_only(self):
        transport = FakeTransport({
            f"https://iam.googleapis.com/v1/{SA_KEY}": {
                "name": SA_KEY, "publicKeyData": base64.b64encode(PEM.encode()).decode()}})
        self.assertEqual(read_service_account_public_key(transport, SA_KEY), PEM)
        self.assertEqual(transport.calls[0][2], {"publicKeyType": "TYPE_X509_PEM_FILE"})

    def test_a_response_that_is_not_a_certificate_is_refused(self):
        transport = FakeTransport({
            f"https://iam.googleapis.com/v1/{SA_KEY}": {
                "name": SA_KEY, "publicKeyData": base64.b64encode(b"binary").decode()}})
        with self.assertRaises(ApiError) as caught:
            read_service_account_public_key(transport, SA_KEY)
        self.assertEqual(caught.exception.code, "invalid_public_key")
        wire = FakeTransport({f"https://iam.googleapis.com/v1/{SA_KEY}": {
            "name": SA_KEY, "publicKeyData": base64.b64encode(
                b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----").decode()}})
        with self.assertRaises(ApiError) as caught:
            read_service_account_public_key(wire, SA_KEY)
        self.assertEqual(caught.exception.code, "invalid_public_key")

    def test_a_substituted_key_name_in_the_response_is_refused(self):
        transport = FakeTransport({
            f"https://iam.googleapis.com/v1/{SA_KEY}": {
                "name": SA_KEY + "x", "publicKeyData": base64.b64encode(PEM.encode()).decode()}})
        with self.assertRaises(ApiError) as caught:
            read_service_account_public_key(transport, SA_KEY)
        self.assertEqual(caught.exception.code, "invalid_key_identifier")


if __name__ == "__main__":
    unittest.main()
