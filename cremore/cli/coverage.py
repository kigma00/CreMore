"""Collect approved AWS inventory and submit fingerprints without secret values."""

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

from cremore.coverage.models import MAX_BATCH, ConnectionSpec, Contract, digest
from cremore.detection.catalog import builtin_definitions
from cremore.detection.custom import rule_definition, rule_detection_policy
from cremore.detection.engine import Engine, EngineConfig
from cremore.domain.models import CustomRule
from cremore.http_client import bounded_request


def execute(api_url, connection_id, collector_token, fingerprint_key, *, client=None, aws_session=None):
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
        if not spec.provider.startswith("aws_"):
            raise ValueError("INVALID_INVENTORY_PROVIDER")
        run = request("POST", "/runs", {"revision": config["revision"], "request_id": str(uuid.uuid4()), "contract": contract})
        try:
            if spec.provider.startswith("aws_"):
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
            else:
                raise ValueError("INVALID_INVENTORY_PROVIDER")
        except Exception:
            request("POST", f"/runs/{run['id']}/finish", {"batch_count": 0, "item_count": 0, "status": "FAILED",
                                                         "reasons": ["COLLECTOR_INITIALIZATION_FAILED"]})
            raise
        count = 0
        for start in range(0, len(result.items), MAX_BATCH):
            request("PUT", f"/runs/{run['id']}/batches", {"index": count, "items": [item.model_dump() for item in result.items[start:start + MAX_BATCH]]})
            count += 1
        finish = {"batch_count": count, "item_count": len(result.items), "status": result.status,
                  "reasons": sorted(result.reasons)}
        saved = request("POST", f"/runs/{run['id']}/finish", finish)
        summary = {"run_id": run["id"], "status": saved.get("status", result.status), "items": len(result.items),
                   "reasons": sorted(saved.get("reasons", result.reasons))}
        return summary
    finally:
        if own_client:
            client.close()


def main():
    parser = argparse.ArgumentParser(description="Collect approved AWS scope locally; submit fingerprints and metadata only.")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--connection-id", required=True)
    args = parser.parse_args()
    try:
        result = execute(args.api_url, args.connection_id, os.environ.get("CREMORE_COLLECTOR_TOKEN", ""),
                         bytes.fromhex(os.environ.get("FINGERPRINT_KEY", "")))
    except Exception:  # noqa: BLE001 -- SDK and validation errors may contain secrets; report only fixed codes.
        # SDK, HTTP and validation exceptions may embed values or auth headers.
        print("COVERAGE_COLLECTION_FAILED: check scope, identity, TLS and fingerprint contract.", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0 if result["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    sys.exit(main())
