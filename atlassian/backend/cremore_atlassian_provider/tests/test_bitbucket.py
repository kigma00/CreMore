"""Read-only workspace scoping, public metadata, limits and private output."""

import base64
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from cremore_atlassian_provider.metadata.bitbucket import (
    OPERATIONS,
    STATIC,
    BitbucketClient,
    bitbucket_snapshot,
    collect_bitbucket,
    main,
    public_ssh_key,
    safe_summary,
)
from cremore_atlassian_provider.metadata.discovery import collect_operation
from cremore_atlassian_provider.metadata.http import FetchResult, Limits
from cremore_atlassian_provider.metadata.qa.bitbucket_connection import (
    load_connection,
    save_connection,
)

from . import posix_native_io
from .test_discovery import Response

SECRET = "synthetic-bitbucket-token"
PUBLIC_KEY = (
    "ssh-ed25519 "
    + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"x" * 32).decode()
)
PGP_PUBLIC = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----"


class TextResponse(io.BytesIO):
    def __init__(self, body):
        super().__init__(body.encode())
        self.code, self.headers = 200, {}


def ok(body):
    return FetchResult(200, body, 1)


def empty():
    return {
        op: [
            ok({"account_id": "person-1"})
            if op == "current-user"
            else ok({"slug": "lab"})
            if op == "workspace"
            else ok(
                {"issuer": "https://example.invalid", "jwks_uri": "https://example.invalid/keys"}
            )
            if op == "workspace-oidc-configuration"
            else ok({"keys": []})
            if op == "workspace-oidc-keys"
            else ok(PGP_PUBLIC)
            if op == "workspace-gpg-key"
            else ok({"values": []})
        ]
        for op in STATIC
    }


class Client:
    def __init__(self, responses, **limits):
        self.workspace, self.requests, self.calls = "lab", 0, []
        self.limits = Limits(**limits)
        self.responses = {k: iter(v) for k, v in responses.items()}

    def read_metadata(self, op, **kwargs):
        self.calls.append((op, kwargs))
        self.requests += 1
        return next(self.responses[op])

    def snapshot(self, body):
        return bitbucket_snapshot(body, SECRET)


def with_user():
    responses = empty()
    responses["user-profile"] = [ok({"account_id": "person-1"})]
    responses["user-ssh-keys"] = [ok({"values": []})]
    responses["user-gpg-keys"] = [ok({"values": []})]
    return responses


class BitbucketTransportTests(unittest.TestCase):
    def test_oidc_public_metadata_uses_fixed_workspace_paths_and_never_follows_links(self):
        config = {
            "issuer": "https://example.invalid/issuer",
            "jwks_uri": "https://example.invalid/untrusted",
        }
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-kid",
                    "n": "public-modulus",
                    "e": "AQAB",
                    "d": "synthetic-private-exponent",
                    "p": "synthetic-private-prime",
                }
            ]
        }
        opener = Mock()
        opener.open.side_effect = [Response(config), Response(jwks)]
        client = BitbucketClient("lab", SECRET, opener=opener)
        first = collect_operation(client, "workspace-oidc-configuration", specs=OPERATIONS)
        second = collect_operation(client, "workspace-oidc-keys", specs=OPERATIONS)
        self.assertEqual(first["pages"][0]["metadata"], config)
        self.assertEqual(second["coverage"], "complete")
        self.assertEqual(second["saved_records"], 1)
        saved = second["pages"][0]["metadata"]["keys"][0]
        self.assertEqual((saved["n"], saved["e"]), ("public-modulus", "AQAB"))
        self.assertIsInstance(saved["d"], dict)
        self.assertIsInstance(saved["p"], dict)
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(
            [req.full_url for req in requests],
            [
                "https://api.bitbucket.org/2.0/workspaces/lab/pipelines-config/identity/oidc/.well-known/openid-configuration",
                "https://api.bitbucket.org/2.0/workspaces/lab/pipelines-config/identity/oidc/keys.json",
            ],
        )
        self.assertTrue(all(req.get_method() == "GET" for req in requests))
        self.assertTrue(all(req.get_header("Authorization") is None for req in requests))
        self.assertEqual(
            {op for op, spec in OPERATIONS.items() if spec.get("public")},
            {"workspace-oidc-configuration", "workspace-oidc-keys"},
        )
        bad = collect_operation(
            Client({"workspace-oidc-keys": [ok({"keys": "bad-shape"})]}),
            "workspace-oidc-keys",
            specs=OPERATIONS,
        )
        self.assertEqual(bad["coverage"], "unverified")

    def test_observed_workspace_gpg_json_preserves_dates_fingerprint_and_public_material(self):
        body = {
            "values": [
                {
                    "type": "gpg_key",
                    "key": PGP_PUBLIC,
                    "fingerprint": "ABC123",
                    "created_on": "2026-01-01T00:00:00Z",
                    "expires_on": None,
                }
            ]
        }
        opener = Mock()
        opener.open.return_value = Response(body)
        client = BitbucketClient("lab", SECRET, opener=opener)
        report = collect_operation(client, "workspace-gpg-key", specs=OPERATIONS)
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(report["saved_records"], 1)
        self.assertEqual(report["pages"][0]["metadata"], body)

    def test_public_gpg_text_response_and_explicit_public_fields(self):
        key = {
            "type": "gpg_key",
            "fingerprint": "ABC123",
            "key": PGP_PUBLIC,
            "subkeys": [{"fingerprint": "DEF456", "expires_on": None}],
            "expires_on": None,
        }
        opener = Mock()
        opener.open.side_effect = [
            TextResponse(PGP_PUBLIC),
            Response({"values": [key]}),
            Response(key),
        ]
        client = BitbucketClient("lab", SECRET, opener=opener)
        report = collect_operation(client, "workspace-gpg-key", specs=OPERATIONS)
        self.assertEqual(report["pages"][0]["metadata"], PGP_PUBLIC)
        self.assertEqual(report["coverage"], "complete")
        listing = collect_operation(
            client, "user-gpg-keys", identifier="person-1", specs=OPERATIONS
        )
        detail = collect_operation(
            client, "user-gpg-key-detail", identifier=("person-1", "ABC123"), specs=OPERATIONS
        )
        self.assertEqual(listing["pages"][0]["metadata"]["values"], [key])
        self.assertEqual(detail["pages"][0]["metadata"], key)
        list_query, detail_query = [
            parse_qs(urlsplit(call.args[0].full_url).query)
            for call in opener.open.call_args_list[1:]
        ]
        self.assertEqual(
            set(list_query["fields"][0].split(",")), {"+values.key", "+values.subkeys"}
        )
        self.assertEqual(set(detail_query["fields"][0].split(",")), {"+key", "+subkeys"})

    def test_unexpected_text_is_unverified_and_pgp_private_material_is_omitted(self):
        private = (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        saved, stats = bitbucket_snapshot({"public_key": private}, SECRET)
        self.assertNotIn("PRIVATE KEY", json.dumps(saved))
        self.assertEqual(stats["sensitive_values_omitted"], 1)
        saved, _ = bitbucket_snapshot({"key": PUBLIC_KEY + "\n" + private}, SECRET)
        self.assertNotIn("PRIVATE KEY", json.dumps(saved))
        report = collect_operation(
            Client({"workspace-gpg-key": [ok("<html>wrong response</html>")]}),
            "workspace-gpg-key",
            specs=OPERATIONS,
        )
        self.assertEqual(report["coverage"], "unverified")

    def test_fixed_origin_workspace_and_bearer_auth_get_only(self):
        opener = Mock()
        opener.open.side_effect = [Response({"values": []}), Response({})]
        client = BitbucketClient("my-lab", SECRET, opener=opener)
        client.read_metadata("repository-deploy-keys", identifier="sample.repo")
        client.read_metadata("user-ssh-key-detail", identifier=("712020:user", "{test-key}"))
        first, second = [c.args[0] for c in opener.open.call_args_list]
        self.assertEqual(
            first.full_url,
            "https://api.bitbucket.org/2.0/repositories/my-lab/sample.repo/deploy-keys?pagelen=20",
        )
        self.assertIn("712020%3Auser/ssh-keys/%7Btest-key%7D", second.full_url)
        self.assertEqual(first.get_header("Authorization"), "Bearer " + SECRET)
        self.assertEqual(first.get_method(), "GET")
        self.assertIsNone(first.data)

    def test_invalid_scope_targets_and_write_operations_never_reach_network(self):
        opener = Mock()
        client = BitbucketClient("lab", SECRET, opener=opener)
        for op, kwargs in [
            ("repository-detail", {"identifier": "../elsewhere"}),
            ("project-detail", {"identifier": "https://evil.invalid"}),
            ("repository-deploy-key-detail", {"identifier": ("repo", "../x")}),
            ("workspace", {"body": {"enabled": True}}),
            ("workspace", {"identifier": "other-workspace"}),
            ("delete-key", {}),
        ]:
            with self.subTest(op=op), self.assertRaises((ValueError, KeyError)):
                client.read_metadata(op, **kwargs)
        opener.open.assert_not_called()

    def test_next_urls_cannot_leave_origin_workspace_or_list(self):
        opener = Mock()
        client = BitbucketClient("lab", SECRET, opener=opener)
        for url in (
            "https://example.invalid/x",
            "https://api.bitbucket.org/2.0/repositories/other",
            "https://api.bitbucket.org/2.0/repositories/lab/repo/src",
            "//example.invalid/x",
        ):
            with self.assertRaises(ValueError):
                client.read_metadata("repositories", next_url=url)
        opener.open.assert_not_called()
        opener.open.return_value = Response({"values": []})
        client.read_metadata("repositories", next_url="?page=2")
        self.assertEqual(
            opener.open.call_args.args[0].full_url,
            "https://api.bitbucket.org/2.0/repositories/lab?page=2",
        )

    def test_unknown_provider_metadata_and_public_keys_survive_but_secrets_do_not(self):
        body = {
            "values": [
                {
                    "key": PUBLIC_KEY,
                    "label": "sample",
                    "future": {"a": None},
                    "private_key": SECRET,
                    "secret": SECRET,
                    "project": {"type": "project", "key": "LAB"},
                },
                {"key": SECRET},
            ]
        }
        saved, stats = bitbucket_snapshot(body, SECRET)
        self.assertEqual(saved["values"][0]["key"], PUBLIC_KEY)
        self.assertEqual(saved["values"][0]["project"]["key"], "LAB")
        self.assertEqual(saved["values"][0]["future"], {"a": None})
        self.assertNotIn(SECRET, json.dumps(saved))
        self.assertEqual(stats["secret_fields_omitted"], 3)
        for value in (
            "-----BEGIN PRIVATE KEY-----",
            "ssh-rsa not_base64",
            "ssh-ed25519 " + base64.b64encode(b"wrong").decode(),
        ):
            self.assertFalse(public_ssh_key(value))

    def test_known_host_split_public_key_survives_list_and_detail_snapshots(self):
        public = {
            "type": "pipeline_ssh_public_key",
            "key_type": "ssh-ed25519",
            "key": PUBLIC_KEY.split()[1],
            "sha256_fingerprint": "fixture-sha256",
            "md5_fingerprint": "fixture-md5",
        }
        host = {
            "type": "pipeline_known_host",
            "uuid": "host-1",
            "hostname": "example.invalid",
            "public_key": public,
        }
        opener = Mock()
        opener.open.side_effect = [Response({"values": [host]}), Response(host)]
        client = BitbucketClient("lab", SECRET, opener=opener)
        listing = collect_operation(
            client, "pipeline-known-hosts", identifier="repo", specs=OPERATIONS
        )
        detail = collect_operation(
            client, "pipeline-known-host-detail", identifier=("repo", "host-1"), specs=OPERATIONS
        )
        self.assertEqual(listing["pages"][0]["metadata"]["values"], [host])
        self.assertEqual(detail["pages"][0]["metadata"], host)
        self.assertEqual(listing["redactions"].get("secret_fields_omitted", 0), 0)

    def test_split_key_restoration_requires_public_type_and_matching_wire_algorithm(self):
        public = {
            "type": "pipeline_ssh_public_key",
            "key_type": "ssh-ed25519",
            "key": PUBLIC_KEY.split()[1],
        }
        for change in (
            {"type": "credential"},
            {"key_type": "ssh-rsa"},
            {"key_type": None},
            {"key_type": "ssh-ed25519 extra"},
            {"key": SECRET},
            {"key": "-----BEGIN PRIVATE KEY-----"},
            {"key": base64.b64encode(b"not an SSH public key").decode()},
            {"key": PUBLIC_KEY.split()[1] + " extra"},
        ):
            with self.subTest(change=change):
                saved, stats = bitbucket_snapshot({"public_key": dict(public, **change)}, SECRET)
                self.assertIsInstance(saved["public_key"]["key"], dict)
                self.assertEqual(stats["secret_fields_omitted"], 1)
        saved, _ = bitbucket_snapshot({"public_key": public}, public["key"])
        self.assertIsInstance(saved["public_key"]["key"], dict)


class BitbucketCollectionTests(unittest.TestCase):
    def test_empty_page_with_next_continues_and_absent_next_terminates(self):
        client = Client(
            {
                "repositories": [
                    ok({"values": [], "next": "?page=2"}),
                    ok({"values": [{"slug": "repo", "uuid": "repo-id"}]}),
                ]
            }
        )
        result = collect_operation(client, "repositories", specs=OPERATIONS)
        self.assertEqual(result["coverage"], "complete")
        self.assertEqual(result["saved_records"], 1)
        self.assertEqual(client.calls[1][1]["next_url"], "?page=2")

    def test_denied_or_missing_does_not_mean_empty_keys(self):
        for status in (401, 403, 404):
            client = Client(
                {
                    "pipeline-ssh-key": [
                        FetchResult(status, attempts=1, reason="http_" + str(status))
                    ]
                }
            )
            result = collect_operation(
                client, "pipeline-ssh-key", identifier="repo", specs=OPERATIONS
            )
            self.assertEqual(result["coverage"], "failed")
            self.assertEqual(result["pages"], [])

    def test_all_observed_key_types_details_and_private_summary(self):
        responses = with_user()
        responses["projects"] = [
            ok({"values": [{"type": "project", "key": "LAB", "uuid": "project-id"}]})
        ]
        responses["repositories"] = [ok({"values": [{"slug": "sample", "uuid": "repo-id"}]})]
        responses["user-ssh-keys"] = [ok({"values": [{"uuid": "key-1", "key": PUBLIC_KEY}]})]
        responses["user-gpg-keys"] = [
            ok({"values": [{"fingerprint": "ABC123", "subkeys": [{"fingerprint": "DEF456"}]}]})
        ]
        responses["user-gpg-key-detail"] = [
            ok({"fingerprint": "ABC123"}),
            ok({"fingerprint": "DEF456", "parent_fingerprint": "ABC123"}),
        ]
        responses["pipeline-known-hosts"] = [ok({"values": [{"uuid": "host-1"}]})]
        responses["pipeline-known-host-detail"] = [ok({"uuid": "host-1"})]
        for op, value in [
            ("user-ssh-key-detail", {"uuid": "key-1"}),
            ("project-detail", {"type": "project", "key": "LAB"}),
            ("repository-detail", {"slug": "sample"}),
            ("pipeline-ssh-key", {"public_key": PUBLIC_KEY}),
            ("project-deploy-key-detail", {"id": 2}),
            ("repository-deploy-key-detail", {"id": 3}),
        ]:
            responses[op] = [ok(value)]
        responses["project-deploy-keys"] = [ok({"values": [{"id": 2, "key": PUBLIC_KEY}]})]
        responses["repository-deploy-keys"] = [ok({"values": [{"id": 3, "key": PUBLIC_KEY}]})]
        client = Client(responses)
        result = collect_bitbucket(client)
        self.assertEqual(result["run_status"], "complete")
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(len(result["collections"]), 23)
        gpg_details = [
            report
            for report in result["collections"]
            if report["operation"] == "user-gpg-key-detail"
        ]
        self.assertEqual(
            [report["target_id"] for report in gpg_details],
            [("person-1", "ABC123"), ("person-1", "DEF456")],
        )
        self.assertEqual(gpg_details[1]["pages"][0]["metadata"]["parent_fingerprint"], "ABC123")
        self.assertEqual(
            result["targets"],
            {"users": ["person-1"], "projects": ["LAB"], "repositories": ["sample"]},
        )
        text = json.dumps(safe_summary(result))
        for value in ("person-1", "LAB", "sample", SECRET, PUBLIC_KEY):
            self.assertNotIn(value, text)

    def test_global_budget_applies_across_discovery_and_key_reads(self):
        opener = Mock()
        opener.open.side_effect = [Response({"account_id": "person-1"}), Response({"slug": "lab"})]
        client = BitbucketClient("lab", SECRET, Limits(max_requests=2), opener=opener)
        result = collect_bitbucket(client)
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(safe_summary(result)["request_count"], 2)
        self.assertEqual(result["run_status"], "partial")

    def test_an_access_token_is_not_a_user_account_so_user_is_not_read(self):
        from .output_samples import response

        def reply(request, **kwargs):
            # An access token is refused at /2.0/user (it names no user account).
            if urlsplit(request.full_url).path == "/2.0/user":
                return Response({"type": "error"}, status=401)
            return response(request, **kwargs)

        for auth, user_read in (({}, False), ({"auth_type": "basic", "email": "ci@example.invalid"}, True)):
            with self.subTest(auth=auth):
                opener = Mock()
                opener.open.side_effect = reply
                result = collect_bitbucket(BitbucketClient("lab", SECRET, opener=opener, **auth))
                paths = [urlsplit(call.args[0].full_url).path for call in opener.open.call_args_list]
                self.assertEqual("/2.0/user" in paths, user_read)
                current = [r for r in result["collections"] if r["operation"] == "current-user"]
                self.assertEqual([r["coverage"] for r in current], ["failed"] if user_read else [])
                if not user_read:
                    self.assertIn("current-user", result["not_requested_operations"])

    def test_parent_and_detail_target_limits_report_omissions(self):
        responses = with_user()
        responses["workspace-members"] = [ok({"values": [{"user": {"account_id": "person-2"}}]})]
        responses["user-ssh-keys"] = [ok({"values": [{"uuid": "key-1"}, {"uuid": "key-2"}]})]
        responses["user-ssh-key-detail"] = [ok({"uuid": "key-1"})]
        result = collect_bitbucket(Client(responses), max_targets=1)
        self.assertEqual(result["targets_omitted_by_limit"]["users"], 1)
        self.assertEqual(result["key_details_omitted_by_limit"], 1)
        self.assertEqual(result["run_status"], "unverified")
        self.assertIn("project-deploy-key-detail", result["not_requested_operations"])

    def test_gpg_subkeys_share_detail_budget_and_do_not_follow_links_or_recurse(self):
        responses = with_user()
        responses["user-gpg-keys"] = [
            ok(
                {
                    "values": [
                        {
                            "fingerprint": "PRIMARY",
                            "subkeys": [
                                {
                                    "fingerprint": "SUB",
                                    "links": {"self": {"href": "https://example.invalid/private"}},
                                    "subkeys": [{"fingerprint": "NOT_A_DIRECT_SUBKEY"}],
                                },
                                {"fingerprint": "SUB"},
                                {"fingerprint": "../invalid"},
                                "malformed",
                                {"fingerprint": "OMITTED_BY_BUDGET"},
                            ],
                        },
                        {"fingerprint": "PRIMARY", "subkeys": "malformed-array"},
                    ]
                }
            )
        ]
        responses["user-gpg-key-detail"] = [
            ok({"fingerprint": "PRIMARY"}),
            ok({"fingerprint": "SUB", "parent_fingerprint": "PRIMARY"}),
        ]
        client = Client(responses)
        result = collect_bitbucket(client, max_targets=2)
        called = [
            kwargs["identifier"] for op, kwargs in client.calls if op == "user-gpg-key-detail"
        ]
        self.assertEqual(called, [("person-1", "PRIMARY"), ("person-1", "SUB")])
        self.assertEqual(result["key_details_omitted_by_limit"], 1)
        self.assertEqual(result["invalid_identifiers"], 3)
        self.assertEqual(result["run_status"], "unverified")

    def test_malformed_identifiers_never_become_followup_paths(self):
        responses = empty()
        responses["current-user"] = [ok({"account_id": "../bad"})]
        responses["projects"] = [ok({"values": [{"type": "project", "key": "../BAD"}]})]
        responses["repositories"] = [ok({"values": [{"slug": "../bad"}]})]
        client = Client(responses)
        result = collect_bitbucket(client)
        self.assertEqual(len(client.calls), 8)
        self.assertEqual(result["invalid_identifiers"], 3)
        self.assertEqual(result["run_status"], "unverified")


class BitbucketConnectionTests(unittest.TestCase):
    @posix_native_io
    def test_private_file_and_separate_provider_connection_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / ".local"
            name = save_connection(directory, "lab", "my-lab", SECRET)
            self.assertEqual(name, "bitbucket-lab.json")
            self.assertEqual((directory / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(load_connection(directory, "lab"), ("my-lab", SECRET))
            with self.assertRaises(FileExistsError):
                save_connection(directory, "lab", "my-lab", "another")
            (directory / name).chmod(0o644)
            with self.assertRaises(ValueError):
                load_connection(directory, "lab")

    @posix_native_io
    def test_no_fallback_symlink_or_cloud_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            (directory / "connection-lab.json").write_text("{}")
            with self.assertRaises(ValueError):
                load_connection(directory, "lab")
            path = directory / "bitbucket-lab.json"
            path.symlink_to(directory / "connection-lab.json")
            with self.assertRaises(ValueError):
                load_connection(directory, "lab")
            path.unlink()
            path.write_text("{}")
            path.chmod(0o600)
            # Keep credential fixtures in memory while exercising real file permissions.
            with patch("cremore_atlassian_provider.metadata.connections.loads",
                       return_value={"provider": "atlassian", "workspace": "lab", "api_token": SECRET}), self.assertRaises(ValueError):
                load_connection(directory, "lab")

    def test_invalid_workspace_and_token_do_not_create_file(self):
        with tempfile.TemporaryDirectory() as temp:
            for workspace, token in (("../x", SECRET), ("lab", "bad\r\nheader")):
                with self.assertRaises(ValueError):
                    save_connection(Path(temp), "lab", workspace, token)
            self.assertEqual(list(Path(temp).iterdir()), [])

    @posix_native_io
    def test_cli_writes_private_metadata_and_only_prints_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            save_connection(directory, "lab", "lab", SECRET)
            bodies = [
                {"account_id": "person-1"},
                {"slug": "lab"},
                {"values": []},
                {"values": []},
                {"values": []},
                PGP_PUBLIC,
                {"issuer": "https://example.invalid"},
                {"keys": []},
                {"account_id": "person-1", "display_name": "private person"},
                {"values": []},
                {"values": []},
            ]
            opener = Mock()
            opener.open.side_effect = [
                TextResponse(b) if isinstance(b, str) else Response(b) for b in bodies
            ]
            out = io.StringIO()
            with (
                patch(
                    "cremore_atlassian_provider.metadata.http.urllib.request.build_opener",
                    return_value=opener,
                ),
                redirect_stdout(out),
            ):
                code = main(["--profile", "lab", "--timeout", "0.5"], directory=directory)
            self.assertEqual(code, 0)
            self.assertNotIn(SECRET, out.getvalue())
            self.assertNotIn("private person", out.getvalue())
            path = next(directory.glob("inventory-*.json"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn("private person", path.read_text())

    def test_cli_without_connection_never_contacts_provider(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            patch(
                "cremore_atlassian_provider.metadata.http.urllib.request.build_opener"
            ) as opener,
        ):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(["--profile", "lab"], directory=Path(temp))
            self.assertEqual(error.exception.code, 2)
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
