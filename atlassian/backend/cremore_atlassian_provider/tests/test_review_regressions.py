"""Regressions found during the complete collector integration review."""

import io
import json
import unittest
from unittest.mock import Mock

from cremore_atlassian_provider.metadata.collector import collect
from cremore_atlassian_provider.metadata.http import CloudClient, Limits

from . import posix_native_io
from .test_collector_cli import KEY, ORG, Response


class ReviewRegressions(unittest.TestCase):
    def test_legacy_inventory_does_not_preserve_authentication_value_in_label(self):
        opener = Mock()
        opener.open.return_value = Response(
            {"data": [{"id": "key-1", "label": "embedded " + KEY}], "links": {"next": None}}
        )
        client = CloudClient(ORG, KEY, Limits(retries=0), opener=opener)
        result = collect(client, ["admin-api-keys"])
        self.assertNotIn(KEY, json.dumps(result))
        self.assertEqual(result["counts"]["identities"], 1)
        self.assertEqual(
            result["collections"]["admin-api-keys"]["redactions"]["sensitive_values_omitted"], 1
        )

    def test_invalid_json_never_silently_overwrites_duplicate_provider_fields(self):
        for body in (b'{"data":[],"data":[{"id":"other"}]}', b'{"data":[],"count":NaN}'):
            with self.subTest(body=body):
                response = io.BytesIO(body)
                response.code, response.headers = 200, {}
                opener = Mock()
                opener.open.return_value = response
                client = CloudClient(ORG, KEY, Limits(retries=0), opener=opener)
                result = client.fetch("admin-api-keys", {"pageSize": 20})
                self.assertEqual(result.reason, "invalid_json")
                self.assertIsNone(result.body)


class ExplicitAccountSelectionTests(unittest.TestCase):
    def test_scoped_discovery_can_delegate_account_reads_without_losing_observed_ids(self):
        from cremore_atlassian_provider.metadata.jobs import collect_job

        from .output_samples import client_factory, job

        item = job("cloud-discovery")
        ordinary = collect_job(item, client_factory(item, None, Limits(retries=0)))
        item["include_account_reads"] = False
        client = client_factory(item, None, Limits(retries=0))
        delegated = collect_job(item, client)
        disabled = {
            "managed-accounts",
            "user-management-permissions",
            "user-profile",
            "user-api-tokens",
        }
        self.assertEqual(set(delegated["not_requested_by_configuration"]), disabled)
        self.assertFalse(disabled & {r["operation"] for r in delegated["collections"]})
        self.assertIn("person-1", delegated["target_discovery"]["user_ids"])
        self.assertLess(client.requests, sum(r["requests"] for r in ordinary["collections"]))
        self.assertFalse(delegated["inventory_complete"])
        urls = [call.args[0].full_url for call in client._opener.open.call_args_list]
        self.assertFalse(any("/manage" in url or url.endswith("/users") for url in urls))

    def test_account_option_is_explicit_boolean_and_discovery_only(self):
        from cremore_atlassian_provider.metadata.jobs import validate_job

        from .output_samples import job

        for mode, option in (
            ("cloud-discovery", "false"),
            ("cloud-discovery", 0),
            ("cloud-accounts", False),
            ("bitbucket-core", False),
        ):
            item = job(mode)
            item["include_account_reads"] = option
            with self.subTest(mode=mode, option=option), self.assertRaises(ValueError):
                validate_job(item)


class ConnectionReaderTests(unittest.TestCase):
    @posix_native_io
    def test_cloud_connection_requires_regular_owned_file_and_unique_json_keys(self):
        import os
        import tempfile
        from pathlib import Path

        from cremore_atlassian_provider.metadata.connections import load_cloud

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            file = directory / "connection-lab.json"
            os.mkfifo(file, 0o600)
            with self.assertRaises(ValueError):
                load_cloud(directory, "lab")
            file.unlink()
            for raw in (
                '{"org_id":"' + ORG + '","api_key":"first","api_key":"second"}',
                "x" * 65537,
            ):
                file.write_text(raw)
                file.chmod(0o600)
                with self.assertRaises(ValueError):
                    load_cloud(directory, "lab")
