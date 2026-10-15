"""Amazon S3 connection scope and existing collector construction."""

import re

PROVIDER = "aws"
SOURCE_TYPE = "s3"
JOB_KINDS = ("s3",)
RESOURCE_TYPES = ("S3_BUCKET",)
SCOPE_KIND = "object"
FILTERS = ("account_id", "region")
CAPABILITY_ORDER = 0
STRUCTURED_CONFIG = False
TOKEN_AUTH = False
# Integration: True when one resource name can exist on several (self-hosted) instances, so the
# instance is part of an exposure's location. The registry derives INSTANCE_SOURCES from it;
# flipping it for an existing source regroups exposure locations and counts.
INSTANCE_SCOPED = False
# The listed revision identifies the object's content: the scan reuses its result (design 4.3).
REVISION_CACHE = True
ACCESS_CONTEXT_SCOPE = "location"
CONTEXT_AWS_SESSION = True
CAPABILITY = {"id": "s3", "name": "Amazon S3", "command": "s3", "kind": "BATCH",
    "description": "Objects under bucket[/prefix], read with the scanner's own AWS identity.",
    "credential_env": [], "external_credential_env": [],
    "profile_runnable": True, "requires_compatibility": False}
REVOCATION_GUIDANCE = (
    ("This connection used the scanner's own AWS identity; nothing is revoked at AWS. Review the "
     "scanner role's trust and permissions in IAM if it should no longer reach this bucket."),
    "https://console.aws.amazon.com/iam/")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def validate_config(cfg):
    if not cfg.get("bucket"):
        raise ValueError("aws connection requires config: bucket")
    return cfg


def job_payload(cfg):
    return {"bucket": cfg["bucket"], "prefix": cfg.get("prefix", ""),
            "region": cfg.get("region", ""), "account_id": cfg.get("account_id", "")}


def job_kind(cfg):
    return "s3"


def exposure_context(payload, location, *, http_client, members=True, aws_sessions=None, check_scope=None):
    from cremore_aws_provider.context import read

    return read(payload, location, aws_sessions=aws_sessions, check_scope=check_scope, members=members)


def config_from_scope(scope, host=""):
    bucket, _, prefix = scope.partition("/")
    if not BUCKET_RE.match(bucket):
        raise ValueError("profile_ref for s3 must be bucket or bucket/prefix (a valid bucket name)")
    # Region remains unset: the existing client handles bucket-region redirects.
    return {"bucket": bucket, "prefix": prefix}


def scope_ref(cfg):
    return f"{cfg.get('bucket', '')}/{cfg['prefix']}" if cfg.get("prefix") else cfg.get("bucket", "")


def build_collector(job, payload, *, s3_client_factory=None, http_client_factory=None,
                    max_object_bytes=None, s3_partition_factory=None):
    from cremore.sources._collectors import object_limit
    from cremore_aws_provider.collectors.s3 import S3Collector

    if s3_client_factory is None:
        raise ValueError("s3 job requires an s3 client factory")
    partition = s3_partition_factory(job) if s3_partition_factory is not None else "aws"
    return S3Collector(
        s3_client_factory(job), bucket=payload["bucket"], prefix=payload.get("prefix", ""),
        account_id=payload.get("account_id", ""), region=payload.get("region", ""),
        partition=partition,
        max_object_bytes=object_limit(max_object_bytes), lazy=bool(payload.get("_lazy")),
        watermark_since=payload.get("watermark_since"), failed_keys=payload.get("failed_keys"),
        watched_keys=payload.get("watched_keys"), start_after=payload.get("start_after", ""))


def build_root(job, payload, root, *, s3_client_factory=None, http_client_factory=None,
               max_object_bytes=None, request_budget=None, s3_partition_factory=None):
    from cremore.sources._collectors import object_limit
    from cremore_aws_provider.collectors.s3 import S3Collector

    if s3_client_factory is None:
        raise ValueError("scope job with an S3 root requires an s3 client factory")
    partition = s3_partition_factory(job) if s3_partition_factory is not None else "aws"
    if root.get("inventory"):
        from cremore_aws_provider.collectors.inventory import S3InventoryCollector

        pointer = root["inventory"]
        return S3InventoryCollector(
            s3_client_factory(job), bucket=root["provider_resource_id"],
            manifest_bucket=pointer["manifest_bucket"], manifest_key=pointer["manifest_key"],
            prior_manifest_key=pointer.get("prior_manifest_key"),
            prefixes=[] if root.get("all_current_objects") else root.get("prefixes") or [],
            excluded_prefixes=root.get("excluded_prefixes") or [],
            known_finding_keys=root.get("watched_keys") or [], failed_keys=root.get("failed_keys") or [],
            region=root.get("region") or payload.get("region", ""),
            account_id=root.get("account_id") or payload.get("account_id", ""),
            partition=partition,
            max_object_bytes=object_limit(max_object_bytes), request_budget=request_budget)
    return S3Collector(
        s3_client_factory(job), bucket=root["provider_resource_id"],
        account_id=root.get("account_id") or payload.get("account_id", ""),
        region=root.get("region") or payload.get("region", ""),
        partition=partition,
        prefixes=[] if root.get("all_current_objects") else (root.get("prefixes") or []),
        excluded_prefixes=root.get("excluded_prefixes") or [], keys=root.get("exact_keys") or [],
        max_object_bytes=object_limit(max_object_bytes), request_budget=request_budget,
        lazy=bool(payload.get("_lazy")), watermark_since=root.get("watermark_since"),
        failed_keys=root.get("failed_keys"), watched_keys=root.get("watched_keys"),
        start_after=root.get("start_after", ""))


def list_resources(payload, kind, cid, *, s3_client=None, http_client=None, now, request_budget, s3_partition="aws"):
    from cremore.collectors.base import CollectorError
    from cremore_aws_provider.catalog import _aws

    if s3_client is None:
        raise CollectorError("NEEDS_CONFIGURATION", "no S3 client")
    return _aws(payload, kind, cid, s3_client(), now, request_budget, partition=s3_partition)


def check_credential(payload, *, http_client_factory=None, s3_client_factory=None, sts_client_factory=None):
    from cremore_aws_provider.credential_check import check_s3

    if s3_client_factory is None or sts_client_factory is None:
        raise ValueError("aws credential check requires s3 and sts client factories")
    return check_s3(sts_client_factory(), s3_client_factory(payload), str(payload.get("bucket", "")))
