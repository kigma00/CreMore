"""Customer-side vault hasher. Never print or persist provider values.

An external vault (one CreMore has no built-in collector for) is read here
too: from a JSON Lines export on a file or standard input, or by an installed
``cremore.vault_readers`` plugin named in ``CREMORE_VAULT_READERS``. Values are
fingerprinted in this process; request bodies carry fingerprints only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from urllib.parse import urlsplit

import httpx
from cremore_aws_provider.coverage import (
    collect_aws_vault,
    collect_iam,
    collect_usage,
)
from cremore_gcp_provider.coverage import collect_gcp
from cremore_vault_provider.coverage import collect_kv

from cremore.coverage.models import MAX_BATCH, ConnectionSpec, Contract, digest
from cremore.detection.catalog import builtin_definitions
from cremore.detection.custom import rule_definition, rule_detection_policy
from cremore.detection.engine import Engine, EngineConfig
from cremore.domain.models import CustomRule
from cremore.http_client import bounded_request

# load_reader's fixed, secret-free codes (cremore.coverage.external_vault): the run and the operator get them.
_READER_CODES = frozenset({"VAULT_READER_NOT_ENABLED", "VAULT_READER_UNAVAILABLE", "VAULT_READER_LOAD_FAILED",
                           "VAULT_READER_CONTRACT_INCOMPATIBLE"})


def _reader_code(exc):
    return str(exc) if isinstance(exc, ValueError) and str(exc) in _READER_CODES else None


def execute(api_url, connection_id, collector_token, fingerprint_key, *, client=None, aws_session=None, vault_token=None, gcp_token=None,
            input_stream=None, declare_complete=False, reader_options=None, allow_readers=()):
    parsed = urlsplit(api_url)
    if (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"))) or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("HTTPS_API_URL_REQUIRED")
    if len(fingerprint_key) < 32 or not collector_token:
        raise ValueError("COLLECTOR_AND_FINGERPRINT_KEYS_REQUIRED")
    cid = str(uuid.UUID(str(connection_id)))
    own_client = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    base = api_url.rstrip("/") + "/api/v1/coverage/collector/" + cid

    def request(method, suffix="", body=None):
        # Start UUIDs, immutable batches and finish payloads are idempotent. A
        # lost response must retry the same request, never create another run.
        for attempt in range(3):
            try:
                response = bounded_request(client, method, base + suffix, json=body,
                    headers={"X-Cremore-Collector-Token": collector_token}, follow_redirects=False,
                    max_response_bytes=4 << 20)
            except httpx.TransportError:
                response = None
            if response is not None and response.status_code in (200, 201):
                return response.json()
            if response is not None and response.status_code not in (429, 500, 502, 503, 504):
                break
            if attempt < 2:
                time.sleep(2 ** attempt)
        raise ValueError("COVERAGE_API_REQUEST_FAILED")

    try:
        config = request("GET")
        spec = ConnectionSpec.model_validate(config["spec"])
        rules = [CustomRule.model_validate(rule) for rule in config["rules"]]
        disabled = set(config.get("disabled_detectors") or [])
        builtins = [definition for definition in builtin_definitions() if definition.catalog.id not in disabled]
        engine = Engine(EngineConfig(fingerprint_key=fingerprint_key), definitions=builtins + [rule_definition(rule) for rule in rules])
        policy = digest([engine.detection_digest, {rule_definition(rule).catalog.id: rule_detection_policy(rule) for rule in rules}])
        contract = Contract(engine_digest=engine.detection_digest, policy_digest=policy).model_dump()
        if contract != config["contract"]:
            raise ValueError("FINGERPRINT_CONTRACT_MISMATCH")
        if (input_stream is not None or declare_complete) and (spec.provider != "external_vault" or spec.reader):
            raise ValueError("INPUT_REQUIRES_EXTERNAL_VAULT_EXPORT")
        if reader_options and not spec.reader:
            raise ValueError("READER_OPTIONS_REQUIRE_A_READER")
        if spec.provider == "external_vault" and not spec.reader and input_stream is None:
            raise ValueError("INPUT_REQUIRED")
        run = request("POST", "/runs", {"revision": config["revision"], "request_id": str(uuid.uuid4()), "contract": contract})
        completeness, skipped = None, 0
        try:
            if spec.provider == "external_vault":
                from cremore.coverage.external_vault import (
                    collect_external,
                    jsonl_entries,
                    load_reader,
                    read_with,
                )
                if spec.reader:
                    provider = load_reader(spec.reader, allow_plugins=allow_readers)
                    result, complete = read_with(provider, spec, engine, reader_options or {})
                    basis = "READER_REPORTED" if complete else None
                else:
                    parse_reasons = set()
                    result = collect_external(spec, engine, jsonl_entries(
                        input_stream, max_line_bytes=spec.max_value_bytes + (64 << 10), reasons=parse_reasons))
                    result.reasons |= parse_reasons
                    basis = "OPERATOR_DECLARED" if declare_complete else None
                skipped = getattr(result, "skipped", 0)
                completeness = basis if result.status == "COMPLETE" else None
            elif spec.provider.startswith("aws_"):
                if aws_session is None:
                    import boto3
                    aws_session = boto3.Session()
                if aws_session.client("sts").get_caller_identity()["Account"] != spec.account_id:
                    raise ValueError("AWS_ACCOUNT_MISMATCH")
                if spec.provider == "aws_iam":
                    from cremore_aws_provider.aws_readonly import readonly_client
                    result = collect_iam(spec, readonly_client(aws_session.client("iam"), "iam"))
                elif spec.provider == "aws_cloudtrail":
                    result = collect_usage(spec, lambda region: aws_session.client("cloudtrail", region_name=region),
                        s3_client=aws_session.client("s3", region_name=spec.regions[0]) if spec.cloudtrail_source == "s3" else None)
                else:
                    result = collect_aws_vault(spec, lambda service, region: aws_session.client(service, region_name=region), engine)
            elif spec.provider in ("vault", "openbao"):
                token = vault_token or os.environ.get("VAULT_TOKEN")
                if not token:
                    # Vault Agent's auto-auth token sink supports AppRole, cloud
                    # auth and Kubernetes without duplicating their lifecycle.
                    from pathlib import Path
                    path = os.environ.get("VAULT_TOKEN_FILE")
                    if not path:
                        raise ValueError("VAULT_TOKEN_REQUIRED")
                    def token():
                        with Path(path).open("rb") as handle:
                            raw = handle.read(65537)
                        if len(raw) > 65536:
                            raise ValueError("VAULT_TOKEN_TOO_LARGE")
                        return raw.decode().strip()
                result = collect_kv(spec, client, token, engine)
            else:
                if gcp_token is None:
                    try:
                        import google.auth
                        from google.auth.transport.requests import Request
                    except ImportError:
                        raise ValueError("INSTALL_CREMore_GCP_EXTRA") from None
                    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
                    def gcp_token():
                        if not credentials.valid:
                            credentials.refresh(Request())
                        return credentials.token
                result = collect_gcp(spec, client, gcp_token, engine)
        except Exception as exc:
            request("POST", f"/runs/{run['id']}/finish", {"batch_count": 0, "item_count": 0, "status": "FAILED",
                                                         "reasons": [_reader_code(exc) or "COLLECTOR_INITIALIZATION_FAILED"]})
            raise
        count = 0
        for start in range(0, len(result.items), MAX_BATCH):
            request("PUT", f"/runs/{run['id']}/batches", {"index": count, "items": [item.model_dump() for item in result.items[start:start + MAX_BATCH]]})
            count += 1
        finish = {"batch_count": count, "item_count": len(result.items), "status": result.status,
                  "reasons": sorted(result.reasons)}
        if completeness:
            finish["completeness"] = completeness
        saved = request("POST", f"/runs/{run['id']}/finish", finish)
        summary = {"run_id": run["id"], "status": saved.get("status", result.status), "items": len(result.items),
                   "reasons": sorted(saved.get("reasons", result.reasons))}
        if spec.provider == "external_vault":
            summary.update(completeness=saved.get("completeness"), outside_declared_scope=skipped)
        return summary
    finally:
        if own_client:
            client.close()


def main():
    parser = argparse.ArgumentParser(description="Collect approved vault scope locally; submit fingerprints and metadata only.")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--connection-id", required=True)
    parser.add_argument("--input", help="external vault: a JSON Lines export file, or - for standard input")
    parser.add_argument("--declare-complete", action="store_true",
                        help="external vault: this export holds every item in the connection's declared scope")
    parser.add_argument("--reader-option", action="append", default=[], metavar="KEY=VALUE",
                        help="external vault: an option for the connection's reader plugin")
    args = parser.parse_args()
    options = {}
    for item in args.reader_option:
        key, sep, value = item.partition("=")
        if not sep or not key:
            print("COVERAGE_COLLECTION_FAILED: --reader-option takes KEY=VALUE.", file=sys.stderr)
            return 1
        options[key] = value
    allow = tuple(name.strip() for name in os.environ.get("CREMORE_VAULT_READERS", "").split(",") if name.strip())
    stream = None
    try:
        if args.input == "-":
            stream = sys.stdin.buffer
        elif args.input:
            stream = open(args.input, "rb")  # noqa: SIM115 -- closed in the finally below.
        result = execute(args.api_url, args.connection_id, os.environ.get("CREMORE_COLLECTOR_TOKEN", ""),
                         bytes.fromhex(os.environ.get("FINGERPRINT_KEY", "")), input_stream=stream,
                         declare_complete=args.declare_complete, reader_options=options, allow_readers=allow)
    except Exception as exc:  # noqa: BLE001 -- SDK and validation errors may contain secrets; report only fixed codes.
        # SDK, HTTP and validation exceptions may embed values or auth headers.
        code = _reader_code(exc)
        print(f"COVERAGE_COLLECTION_FAILED: {code}." if code else
              "COVERAGE_COLLECTION_FAILED: check scope, identity, TLS and fingerprint contract.", file=sys.stderr)
        return 1
    finally:
        if stream is not None and stream is not sys.stdin.buffer:
            stream.close()
    print(json.dumps(result))
    return 0 if result["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    sys.exit(main())
