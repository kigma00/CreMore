"""Bounded, secret-free contracts for coverage collection and submission."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_BATCH = 250
VERSION = 1
SCHEME = "cremore-credential-fingerprint-v1/hmac-sha256"
V1_PURPOSE = {"aws_iam": "issuer_inventory", "aws_cloudtrail": "usage",
              "aws_secrets_manager": "vault_metadata", "aws_ssm": "vault_metadata",
              "vault": "vault_metadata", "openbao": "vault_metadata", "gcp_secret_manager": "vault_metadata",
              "external_vault": "vault_metadata"}
# Schema 1 issuers whose credential_owner(issued) names who owns an issued key
# (the departed-owner check, cremore.identity.leavers). Schema 2 providers
# register theirs with their adapter (cremore.coverage.providers).
V1_OWNERS = {"aws_iam": "cremore_aws_provider.leavers"}
# How a finished run knows it saw the whole declared scope, strongest first. A
# built-in collector lists through the vault's API; an installed reader plugin
# reports its own listing; a JSON Lines export, or a run over the secrets an
# operator named (references), is complete only because the operator said so.
# "Not in the vault" carries the weakest basis in scope.
COMPLETENESS = ("API_LISTING", "READER_REPORTED", "OPERATOR_DECLARED")
Code = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,95}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_MARKER = re.compile(r"(?:gh[pousr]_|github_pat_|ntn_|glpat-|-----BEGIN .*PRIVATE KEY)")


def safe_label(value: str) -> str:
    if _CONTROL.search(value) or _SECRET_MARKER.search(value):
        raise ValueError("UNSAFE_METADATA")
    return value


def scope_path(value: str) -> str:
    safe_label(value)
    if "\\" in value or any(part in (".", "..") for part in value.split("/")):
        raise ValueError("INVALID_SCOPE_PATH")
    return value.strip("/")


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _timestamp(value: str) -> str:
    if value and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:  # noqa: FURB162
        raise ValueError("TIMEZONE_REQUIRED")
    return value


Timestamp = Annotated[str, Field(max_length=40), AfterValidator(_timestamp)]
ReportFieldState = Literal["AVAILABLE", "NOT_APPLICABLE", "NO_INFORMATION", "NOT_SUPPORTED", "NOT_RETURNED", "INVALID"]


class IAMReportKeySlot(StrictModel):
    slot: Literal[1, 2]
    active: bool | None = None
    last_rotated_at: Timestamp = ""
    last_used_at: Timestamp = ""
    last_used_region: str = Field(default="", pattern=r"^[a-z0-9-]{0,64}$")
    last_used_service: str = Field(default="", pattern=r"^[A-Za-z0-9.-]{0,128}$")
    field_status: dict[Literal["active", "last_rotated_at", "last_used_at", "last_used_region", "last_used_service"], ReportFieldState] = Field(default_factory=dict)


class IAMReportCertificateSlot(StrictModel):
    slot: Literal[1, 2]
    active: bool | None = None
    last_rotated_at: Timestamp = ""
    field_status: dict[Literal["active", "last_rotated_at"], ReportFieldState] = Field(default_factory=dict)


class IAMCredentialReport(StrictModel):
    generated_at: Timestamp
    user_created_at: Timestamp = ""
    password_last_used_at: Timestamp = ""
    password_last_changed_at: Timestamp = ""
    password_next_rotation_at: Timestamp = ""
    field_status: dict[Literal["user_created_at", "password_enabled", "mfa_active", "password_last_used_at", "password_last_changed_at", "password_next_rotation_at"], ReportFieldState] = Field(default_factory=dict)
    access_keys: list[IAMReportKeySlot] = Field(default_factory=list, max_length=2)
    certificates: list[IAMReportCertificateSlot] = Field(default_factory=list, max_length=2)


class IAMLastUsed(StrictModel):
    status: Literal["AVAILABLE", "NO_INFORMATION", "DENIED", "FAILED", "NOT_REQUESTED"]
    checked_at: Timestamp
    service: str = Field(default="", pattern=r"^[A-Za-z0-9.-]{0,128}$")
    region: str = Field(default="", pattern=r"^[a-z0-9-]{0,64}$")
    reason: Code | None = None


class CollectionOperation(StrictModel):
    name: Literal["LIST_USERS", "LIST_ACCESS_KEYS", "LIST_SERVICE_CREDENTIALS", "CREDENTIAL_REPORT", "GET_ACCESS_KEY_LAST_USED", "IAM_IDENTITY_POLICIES", "LOOKUP_EVENTS", "READ_TRAIL_LOGS"]
    status: Literal["COMPLETE", "PARTIAL", "FAILED", "NOT_REQUESTED"]
    requests: int = Field(ge=0, le=100000)
    records: int = Field(ge=0, le=250000)
    reason: Code | None = None


class AWSSession(StrictModel):
    """Only public identity/time facts from a CloudTrail event, never credentials."""

    issuer_account_id: str = Field(default="", pattern=r"^(?:[0-9]{12})?$")
    recipient_account_id: str = Field(default="", pattern=r"^(?:[0-9]{12})?$")
    issuer_arn: str = Field(default="", max_length=2048)
    session_arn: str = Field(default="", max_length=2048)
    caller_arn: str = Field(default="", max_length=2048)
    caller_access_key_id: str = Field(default="", pattern=r"^(?:(?:AKIA|ASIA)[A-Z0-9]{16})?$")
    source_identity: str = Field(default="", max_length=64)
    session_name: str = Field(default="", max_length=64)
    issued_at: Timestamp = ""
    expires_at: Timestamp = ""
    first_used_at: Timestamp = ""
    last_used_at: Timestamp = ""
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9-]+$")
    event_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9]+$")
    event_source: str = Field(default="", pattern=r"^[A-Za-z0-9.-]{0,128}$")
    event_category: Literal["Management", "Data", "NetworkActivity", "Unknown"] = "Unknown"
    evidence_source: Literal["EVENT_HISTORY", "TRAIL_S3"] = "EVENT_HISTORY"
    outcome: Literal["SUCCEEDED", "DENIED", "UNKNOWN"] = "UNKNOWN"

    @field_validator("issuer_arn", "session_arn", "caller_arn", "source_identity", "session_name")
    @classmethod
    def safe_metadata(cls, value):
        return safe_label(value)


class Mount(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    kv_version: Literal[1, 2] = 2
    prefixes: list[str] = Field(min_length=1, max_length=100)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        result = scope_path(value)
        if not result:
            raise ValueError("MOUNT_REQUIRED")
        return result

    @field_validator("prefixes")
    @classmethod
    def valid_prefixes(cls, values):
        return list(dict.fromkeys(scope_path(value) for value in values))


class VaultManagedEvidence(StrictModel):
    """Issuer management evidence, distinct from a secret stored in a KV item."""

    kind: Literal["SERVICE_TOKEN", "DYNAMIC_LEASE"]
    lookup_status: Literal["COMPLETE", "FAILED"] = "COMPLETE"
    issued_at: Timestamp = ""
    expires_at: Timestamp = ""
    last_renewal_at: Timestamp = ""
    ttl_seconds: int | None = Field(default=None, ge=0, le=9223372036854775807)
    renewable: bool | None = None
    policies: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("policies")
    @classmethod
    def policy_names(cls, values):
        if any(not re.fullmatch(r"[A-Za-z0-9_.@/-]{1,256}", safe_label(v)) for v in values):
            raise ValueError("INVALID_VAULT_POLICY_NAME")
        return values

    @model_validator(mode="after")
    def failure_has_no_invented_metadata(self):
        if self.lookup_status == "FAILED" and (self.issued_at or self.expires_at or self.last_renewal_at
                or self.ttl_seconds is not None or self.renewable is not None or self.policies):
            raise ValueError("FAILED_VAULT_LOOKUP_HAS_NO_METADATA")
        return self


SERVER_VAULTS = ("aws_secrets_manager", "aws_ssm", "vault", "openbao")
_PEM_CERT = re.compile(r"(?:-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+")


class VaultServerAuth(StrictModel):
    """A connection's own Vault/OpenBao login for a server-side read.

    It is never the installation's secret-store identity. Kubernetes and JWT
    logins read a token file the deployment mounted for this connection under
    ``VAULT_CONNECTION_TOKEN_DIR``; a token login uses a value sealed on arrival.
    """

    method: Literal["kubernetes", "jwt", "token"]
    mount: str = Field(default="", max_length=256)
    # The Vault Enterprise namespace that holds the auth mount, if any.
    namespace: str = Field(default="", max_length=512)
    role: str = Field(default="", pattern=r"^[A-Za-z0-9_.@-]{0,128}$")
    token_file: str = Field(default="", pattern=r"^(?:[A-Za-z0-9_-][A-Za-z0-9._-]{0,127})?$")

    @field_validator("mount", "namespace")
    @classmethod
    def valid_mount(cls, value):
        return scope_path(value) if value else value

    @model_validator(mode="after")
    def complete_login(self):
        if self.method == "token":
            if self.role or self.token_file or self.mount or self.namespace:
                raise ValueError("TOKEN_LOGIN_TAKES_NO_ROLE")
            return self
        if not self.role or not self.token_file:
            raise ValueError("VAULT_LOGIN_ROLE_AND_TOKEN_FILE_REQUIRED")
        if not self.mount:
            self.mount = self.method
        return self


def worker_collected(spec) -> bool:
    """AWS inventory, or an AWS secret store an administrator moved to the worker."""
    return spec.provider in ("aws_iam", "aws_cloudtrail") or bool(getattr(spec, "server_collection", False))


class ConnectionSpec(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    provider: Literal["aws_iam", "aws_cloudtrail", "aws_secrets_manager", "vault", "openbao", "gcp_secret_manager", "aws_ssm",
                      "external_vault"]
    account_id: str = Field(default="", pattern=r"^(?:[0-9]{12})?$")
    regions: list[str] = Field(default_factory=list, max_length=50)
    references: list[str] = Field(default_factory=list, max_length=1000)
    prefixes: list[str] = Field(default_factory=list, max_length=100)
    endpoint: str = Field(default="", max_length=2048)
    namespaces: list[str] = Field(default_factory=lambda: [""], min_length=1, max_length=100)
    mounts: list[Mount] = Field(default_factory=list, max_length=100)
    project: str = Field(default="", max_length=128)
    version_selector: str = Field(default="latest", pattern=r"^[A-Za-z0-9_-]{1,63}$")
    include_previous_versions: bool = False
    max_versions_per_secret: int = Field(default=20, ge=1, le=1000)
    include_token_accessors: bool = False
    lease_prefixes: list[str] = Field(default_factory=list, max_length=100)
    service_credentials: bool = False
    credential_report: bool = False
    last_used: bool = False
    # None preserves the legacy installation switch until the connection is edited.
    iam_policy_metadata: bool | None = None
    schedule_minutes: int = Field(default=0, ge=0, le=10080)
    # Legacy AWS connections follow the installation switch. New onboarding
    # explicitly opts in to a schedule owned by this connection.
    schedule_source: Literal["installation", "connection"] = "installation"
    # Opt-in: the CreMore worker reads this secret store instead of the
    # customer-side CLI -- AWS with the account's approved scanner access, Vault
    # and OpenBao only when it is the installation's own secret store.
    server_collection: bool = False
    # AWS server collection only: the account's value-reader role reads every value, chained
    # from the scanner session (cremore_aws_provider.aws_sessions). Empty: the scanner reads.
    value_reader_role: str = Field(default="", pattern=r"^(?:[A-Za-z0-9+=,.@_-]{1,64})?$")
    # A server read of a Vault/OpenBao cluster other than the installation's
    # own secret store, with this connection's login (design decision 10).
    server_auth: VaultServerAuth | None = None
    # A public CA certificate for that cluster's TLS. Never a private key.
    tls_ca_pem: str = Field(default="", max_length=16384)
    # Sealed on arrival through the token endpoint; the API never returns it.
    secret_refs: dict[Literal["vault_token"], str] = Field(default_factory=dict)
    # external_vault: the product the operator named, and the installed reader
    # that reads it directly (empty: the customer-side JSON Lines input).
    product: str = Field(default="", max_length=120)
    reader: str = Field(default="", pattern=r"^(?:[a-z][a-z0-9_-]{0,63})?$")
    cloudtrail_source: Literal["event_history", "s3"] = "event_history"
    cloudtrail_event_name: Literal["", "CreateAccessKey"] = ""
    trail_bucket: str = Field(default="", max_length=63, pattern=r"^(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])?$")
    trail_prefixes: list[str] = Field(default_factory=list, max_length=100)
    max_records: int = Field(default=50000, ge=1, le=250000)
    max_requests: int = Field(default=10000, ge=1, le=100000)
    max_value_bytes: int = Field(default=1048576, ge=1024, le=16777216)
    freshness_hours: int = Field(default=24, ge=1, le=168)
    window_days: int = Field(default=7, ge=1, le=3650)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        result = safe_label(value.strip())
        if not result:
            raise ValueError("NAME_REQUIRED")
        return result

    @field_validator("product")
    @classmethod
    def valid_product(cls, value):
        return safe_label(value.strip())

    @field_validator("tls_ca_pem")
    @classmethod
    def valid_ca(cls, value):
        value = value.strip()
        if value and (not _PEM_CERT.fullmatch(value + "\n") or "PRIVATE KEY" in value):
            raise ValueError("TLS_CA_MUST_BE_A_PEM_CERTIFICATE")
        return value

    @field_validator("regions")
    @classmethod
    def valid_regions(cls, values):
        if any(not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", value) for value in values):
            raise ValueError("INVALID_REGION")
        return list(dict.fromkeys(values))

    @field_validator("references", "prefixes", "namespaces", "trail_prefixes")
    @classmethod
    def valid_paths(cls, values):
        if any(len(value) > 2048 for value in values):
            raise ValueError("SCOPE_TOO_LONG")
        return list(dict.fromkeys(scope_path(value) for value in values))

    @field_validator("lease_prefixes")
    @classmethod
    def valid_lease_prefixes(cls, values):
        checked = [scope_path(v) for v in values]
        if any(not re.fullmatch(r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)+", v) or len(v) > 1024
               for v in checked):
            raise ValueError("EXPLICIT_LEASE_PREFIX_REQUIRED")
        return list(dict.fromkeys(checked))

    @field_validator("endpoint")
    @classmethod
    def valid_endpoint(cls, value):
        if not value:
            return value
        safe_label(value)
        parsed = urlsplit(value)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or (parsed.scheme != "https" and not
                    (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")))):
            raise ValueError("HTTPS_ENDPOINT_REQUIRED")
        return value.rstrip("/")

    @model_validator(mode="after")
    def complete_scope(self):
        if self.iam_policy_metadata is not None and self.provider != "aws_iam":
            raise ValueError("IAM_POLICY_METADATA_REQUIRES_IAM")
        if self.cloudtrail_event_name and self.provider != "aws_cloudtrail":
            raise ValueError("EVENT_FILTER_REQUIRES_CLOUDTRAIL")
        if self.provider.startswith("aws_") and not self.account_id:
            raise ValueError("ACCOUNT_REQUIRED")
        if self.provider in ("aws_secrets_manager", "aws_ssm", "aws_cloudtrail") and not self.regions:
            raise ValueError("REGIONS_REQUIRED")
        if self.provider in ("vault", "openbao") and (not self.endpoint or not (
                self.mounts or self.include_token_accessors or self.lease_prefixes)):
            raise ValueError("VAULT_ENDPOINT_AND_MOUNTS_REQUIRED")
        if self.provider not in ("vault", "openbao") and (self.include_token_accessors or self.lease_prefixes):
            raise ValueError("VAULT_MANAGEMENT_OPTIONS_REQUIRE_VAULT")
        if self.provider not in ("vault", "openbao", "aws_secrets_manager") and (
                self.include_previous_versions or self.max_versions_per_secret != 20):
            raise ValueError("VERSION_HISTORY_NOT_SUPPORTED")
        if self.include_previous_versions and self.version_selector != "latest":
            raise ValueError("VERSION_HISTORY_REQUIRES_LATEST_SELECTOR")
        if self.provider in ("vault", "openbao") and self.version_selector != "latest" and not re.fullmatch(
                r"[1-9][0-9]{0,9}", self.version_selector):
            raise ValueError("KV_VERSION_MUST_BE_POSITIVE_INTEGER")
        if self.provider in ("vault", "openbao") and not self.mounts and (
                self.include_previous_versions or self.version_selector != "latest"):
            raise ValueError("KV_VERSION_OPTIONS_REQUIRE_MOUNTS")
        if self.provider == "aws_ssm" and not self.prefixes:
            raise ValueError("PARAMETER_PREFIXES_REQUIRED")
        if self.provider == "gcp_secret_manager" and not re.fullmatch(r"[a-z0-9][a-z0-9-]{3,126}[a-z0-9]", self.project):
            raise ValueError("PROJECT_REQUIRED")
        if self.provider != "aws_iam" and (self.service_credentials or self.credential_report or self.last_used):
            raise ValueError("ISSUER_OPTIONS_REQUIRE_IAM")
        if self.server_collection and self.provider not in SERVER_VAULTS:
            raise ValueError("SERVER_COLLECTION_NOT_SUPPORTED")
        if self.value_reader_role and (self.provider not in ("aws_secrets_manager", "aws_ssm") or not self.server_collection):
            raise ValueError("VALUE_READER_REQUIRES_AWS_SERVER_COLLECTION")
        if self.value_reader_role and self.provider == "aws_secrets_manager" and not self.references:
            # The role reads only the secrets its stack names and lists none.
            raise ValueError("VALUE_READER_REQUIRES_SECRET_ARNS")
        if (self.server_auth or self.tls_ca_pem) and (self.provider not in ("vault", "openbao") or not self.server_collection):
            raise ValueError("VAULT_SERVER_LOGIN_REQUIRES_SERVER_COLLECTION")
        if self.secret_refs and (self.server_auth is None or self.server_auth.method != "token"):
            raise ValueError("VAULT_TOKEN_REQUIRES_TOKEN_LOGIN")
        if self.provider == "external_vault":
            if not self.product:
                raise ValueError("EXTERNAL_VAULT_PRODUCT_REQUIRED")
            if not self.prefixes:
                raise ValueError("EXTERNAL_VAULT_DECLARED_SCOPE_REQUIRED")
            if self.references or self.regions or self.account_id or self.endpoint or self.mounts:
                raise ValueError("EXTERNAL_VAULT_SCOPE_IS_PATH_PREFIXES")
        elif self.product or self.reader:
            raise ValueError("PRODUCT_AND_READER_REQUIRE_EXTERNAL_VAULT")
        if self.schedule_minutes and (self.schedule_minutes < 5 or not worker_collected(self)):
            raise ValueError("INVALID_AWS_INVENTORY_SCHEDULE")
        if self.schedule_source == "connection" and not (self.provider.startswith("aws_") and worker_collected(self)):
            raise ValueError("INVALID_AWS_INVENTORY_SCHEDULE")
        if self.cloudtrail_source == "s3":
            if self.provider != "aws_cloudtrail" or not self.trail_bucket or not self.trail_prefixes:
                raise ValueError("CLOUDTRAIL_LOG_SCOPE_REQUIRED")
            if any(not prefix for prefix in self.trail_prefixes):
                raise ValueError("CLOUDTRAIL_LOG_PREFIX_REQUIRED")
        elif self.trail_bucket or self.trail_prefixes or self.window_days > 90:
            raise ValueError("CLOUDTRAIL_LOG_SOURCE_REQUIRED")
        if self.provider == "aws_ssm" and self.references:
            raise ValueError("SSM_USES_EXPLICIT_PREFIX_SCOPE")
        if self.provider == "aws_secrets_manager":
            for reference in self.references:
                arn = reference.split(":", 5)
                if (len(arn) != 6 or arn[0] != "arn" or arn[1] not in ("aws", "aws-us-gov", "aws-cn", "aws-eusc")
                        or arn[2] != "secretsmanager" or arn[3] not in self.regions or arn[4] != self.account_id
                        or not re.fullmatch(r"secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}", arn[5])):
                    raise ValueError("SECRET_REFERENCE_OUTSIDE_SCOPE")
        if self.provider == "gcp_secret_manager" and any(not re.fullmatch(
                r"projects/" + re.escape(self.project) + r"/secrets/[A-Za-z0-9_-]{1,255}", ref) for ref in self.references):
            raise ValueError("GCP_REFERENCE_OUTSIDE_SCOPE")
        if self.provider in ("aws_iam", "aws_cloudtrail", "vault", "openbao") and self.references:
            raise ValueError("REFERENCES_NOT_SUPPORTED_FOR_PROVIDER")
        return self


class IAMPolicySummary(StrictModel):
    """Identity-policy statements, never an effective permission or token scope."""

    status: Literal["COMPLETE", "PARTIAL", "DENIED", "FAILED"]
    checked_at: Timestamp
    policy_names: list[Annotated[str, Field(max_length=128), AfterValidator(safe_label)]] = Field(default_factory=list, max_length=100)
    allow_actions: list[Annotated[str, Field(max_length=256, pattern=r"^(?:\*|[A-Za-z0-9*?-]+:[A-Za-z0-9*?]+)$")]] = Field(default_factory=list, max_length=200)
    deny_statements: int = Field(default=0, ge=0)
    conditional_statements: int = Field(default=0, ge=0)
    permissions_boundary: bool = False
    truncated: bool = False
    reason: Code | None = None


class Observation(StrictModel):
    reference: str = Field(min_length=1, max_length=2048)
    account_id: str = Field(default="", pattern=r"^(?:[0-9]{12})?$")
    region: str = Field(default="", max_length=64)
    namespace: str = Field(default="", max_length=512)
    mount: str = Field(default="", max_length=256)
    version: str = Field(default="", max_length=256)
    version_state: Literal["CURRENT", "PREVIOUS", "DELETED", "DESTROYED", "UNKNOWN"] = "CURRENT"
    evidence: Literal["VALUE", "IDENTIFIER", "UNRESOLVED", "ISSUED", "ROOT_STATUS", "USER_STATUS", "OPERATION", "SESSION_ISSUED", "KEY_CREATED", "USAGE", "MANAGED"]
    credential_type: Code = "UNKNOWN"
    fingerprint: Digest | None = None
    # Private HMAC comparison evidence; never the raw provider SHA256 digest.
    provider_digest: Digest | None = None
    issuer_identifier: str = Field(default="", max_length=512)
    identifier: str = Field(default="", pattern=r"^[A-Za-z0-9_+=,.@-]{0,128}$")
    principal_arn: str = Field(default="", max_length=2048)
    state: str = Field(default="UNKNOWN", pattern=r"^[A-Za-z_]{1,32}$")
    created_at: str = Field(default="", max_length=40)
    last_used_at: str = Field(default="", max_length=40)
    service: str = Field(default="", pattern=r"^[a-zA-Z0-9.-]{0,128}$")
    password_enabled: bool | None = None
    mfa_active: bool | None = None
    access_key_1_active: bool | None = None
    access_key_2_active: bool | None = None
    cert_1_active: bool | None = None
    cert_2_active: bool | None = None
    iam_report: IAMCredentialReport | None = None
    iam_last_used: IAMLastUsed | None = None
    iam_policies: IAMPolicySummary | None = None
    operation: CollectionOperation | None = None
    session: AWSSession | None = None
    session_fingerprint: Digest | None = None
    vault_managed: VaultManagedEvidence | None = None
    reason: Code | None = None

    @field_validator("created_at", "last_used_at")
    @classmethod
    def timestamp(cls, value):
        if value and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:  # noqa: FURB162 -- Preserve rejection of misplaced Z markers in the established timestamp contract.
            raise ValueError("TIMEZONE_REQUIRED")
        return value

    @field_validator("issuer_identifier")
    @classmethod
    def safe_issuer_identifier(cls, value):
        if value:
            safe_label(value)
            from cremore_gcp.linkage import is_service_account_key_identifier
            if not is_service_account_key_identifier(value):
                raise ValueError("INVALID_GCP_ISSUER_IDENTIFIER")
        return value

    @field_validator("reference", "namespace", "mount", "version", "principal_arn", "identifier")
    @classmethod
    def safe_metadata(cls, value):
        return safe_label(value)

    @model_validator(mode="after")
    def consistent_evidence(self):
        if self.issuer_identifier and (self.evidence != "VALUE" or self.credential_type != "GCP_SERVICE_ACCOUNT"):
            raise ValueError("ISSUER_IDENTIFIER_REQUIRES_GCP_VALUE")
        if self.provider_digest is not None and (self.evidence != "VALUE" or self.credential_type != "GITHUB_TOKEN"):
            raise ValueError("PROVIDER_DIGEST_REQUIRES_GITHUB_VALUE")
        if (self.evidence == "MANAGED") != (self.vault_managed is not None):
            raise ValueError("VAULT_MANAGED_EVIDENCE_REQUIRED")
        if self.evidence == "MANAGED" and (self.identifier or self.version or self.state != "UNKNOWN"
                                          or self.version_state != "UNKNOWN" or self.principal_arn):
            raise ValueError("VAULT_MANAGEMENT_IS_NOT_VALUE_OR_VALIDITY_EVIDENCE")
        if self.vault_managed is not None and self.credential_type != "VAULT_" + self.vault_managed.kind:
            raise ValueError("VAULT_MANAGEMENT_TYPE_MISMATCH")
        if self.vault_managed is not None and self.vault_managed.lookup_status == "FAILED" and not self.reason:
            raise ValueError("FAILED_VAULT_LOOKUP_REASON_REQUIRED")
        if (self.evidence == "VALUE") != (self.fingerprint is not None):
            raise ValueError("VALUE_FINGERPRINT_REQUIRED")
        if self.evidence in ("IDENTIFIER", "ISSUED", "SESSION_ISSUED", "KEY_CREATED", "USAGE") and not self.identifier:
            raise ValueError("IDENTIFIER_REQUIRED")
        if self.evidence == "UNRESOLVED" and not self.reason:
            raise ValueError("UNRESOLVED_REASON_REQUIRED")
        if (self.evidence == "OPERATION") != (self.operation is not None):
            raise ValueError("OPERATION_EVIDENCE_REQUIRED")
        if self.iam_report is not None and self.evidence not in ("USER_STATUS", "ROOT_STATUS"):
            raise ValueError("IAM_REPORT_EVIDENCE_REQUIRED")
        if self.iam_last_used is not None and self.evidence != "ISSUED":
            raise ValueError("IAM_LAST_USED_EVIDENCE_REQUIRED")
        if self.iam_policies is not None and (self.evidence != "ISSUED" or self.credential_type != "AWS_ACCESS_KEY"):
            raise ValueError("IAM_POLICIES_REQUIRE_ISSUED_ACCESS_KEY")
        if self.evidence == "SESSION_ISSUED" and (self.session is None or not self.identifier.startswith("ASIA")):
            raise ValueError("TEMPORARY_SESSION_REQUIRED")
        if self.evidence == "KEY_CREATED" and (self.session is None
                or not re.fullmatch(r"AKIA[A-Z0-9]{16}", self.identifier)
                or self.credential_type != "AWS_ACCESS_KEY" or self.state != "OBSERVED"
                or self.last_used_at or not self.created_at
                or self.session.event_source != "iam.amazonaws.com" or self.session.event_name != "CreateAccessKey"
                or self.session.outcome != "SUCCEEDED" or not self.session.caller_arn
                or self.session.recipient_account_id != self.account_id
                or not re.fullmatch(r"arn:aws(?:-us-gov|-cn|-eusc)?:(?:iam|sts)::[0-9]{12}:[A-Za-z0-9/+=,.@_-]+", self.session.caller_arn)
                or self.session.issued_at != self.created_at or self.session.expires_at
                or self.session.first_used_at or self.session.last_used_at):
            raise ValueError("KEY_CREATION_EVENT_REQUIRED")
        if self.session is not None and self.evidence not in ("SESSION_ISSUED", "KEY_CREATED", "USAGE"):
            raise ValueError("SESSION_EVIDENCE_REQUIRED")
        if self.session_fingerprint is not None and (self.evidence != "VALUE" or self.credential_type != "AWS_ACCESS_KEY"
                                                    or not re.fullmatch(r"ASIA[A-Z0-9]{16}", self.identifier)):
            raise ValueError("SESSION_VALUE_EVIDENCE_REQUIRED")
        return self


class Contract(StrictModel):
    schema_version: Literal[1] = VERSION
    tool_version: Literal["0.1.0"] = "0.1.0"
    scheme: Literal["cremore-credential-fingerprint-v1/hmac-sha256"] = SCHEME
    engine_digest: Digest
    policy_digest: Digest | None = None

    @model_validator(mode="after")
    def default_policy(self):
        if self.policy_digest is None:
            self.policy_digest = digest([self.engine_digest, {}])
        return self


class Start(StrictModel):
    revision: int = Field(ge=1)
    request_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    contract: Contract


class Batch(StrictModel):
    index: int = Field(ge=0, le=100000)
    items: list[Observation] = Field(min_length=1, max_length=MAX_BATCH)


class Finish(StrictModel):
    batch_count: int = Field(ge=0, le=100000)
    item_count: int = Field(ge=0, le=250000)
    status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    reasons: list[Code] = Field(default_factory=list, max_length=100)
    # Only an external vault's collector says how it knows the run was whole.
    completeness: Literal["READER_REPORTED", "OPERATOR_DECLARED"] | None = None


def weakest_completeness(values):
    """The basis a "not in the vault" verdict can claim across every store in scope."""
    known = [value for value in values if value in COMPLETENESS]
    return max(known, key=COMPLETENESS.index) if known else None


def in_scope(spec: ConnectionSpec, item: Observation) -> bool:
    if item.evidence == "MANAGED":
        if spec.provider not in ("vault", "openbao") or item.namespace not in spec.namespaces or item.vault_managed is None:
            return False
        if item.vault_managed.kind == "SERVICE_TOKEN":
            return bool(spec.include_token_accessors and item.mount == "auth/token" and re.fullmatch(
                r"auth/token/accessors/[A-Za-z0-9_-]{1,128}(?:\.[A-Za-z0-9_-]{1,128})?", item.reference))
        try:
            if scope_path(item.reference) != item.reference or not re.fullmatch(
                    r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)+", item.reference):
                return False
        except ValueError:
            return False
        return (item.mount == item.reference.split("/")[0] and any(
            item.reference.startswith(prefix + "/") for prefix in spec.lease_prefixes))
    if spec.provider == "aws_cloudtrail":
        if item.evidence == "OPERATION":
            return (item.account_id == spec.account_id and item.operation is not None and
                    ((item.operation.name == "LOOKUP_EVENTS" and spec.cloudtrail_source == "event_history"
                      and item.region in spec.regions and item.reference == "region/" + item.region)
                     or (item.operation.name == "READ_TRAIL_LOGS" and spec.cloudtrail_source == "s3"
                         and not item.region and item.reference == "account/" + spec.account_id)))
        prefix = "event-history" if spec.cloudtrail_source == "event_history" else "trail-s3"
        if spec.cloudtrail_event_name and (item.session is None or item.session.event_name != spec.cloudtrail_event_name):
            return False
        if item.session is not None:
            source = "EVENT_HISTORY" if spec.cloudtrail_source == "event_history" else "TRAIL_S3"
            # Legacy usage rows need no session object. When these new facts are
            # supplied, their provenance must agree with the approved scope.
            if ((item.session.recipient_account_id and item.session.recipient_account_id != spec.account_id)
                    or item.session.evidence_source != source or item.reference != prefix + "/" + item.session.event_id):
                return False
        return (item.account_id == spec.account_id and item.region in spec.regions and item.evidence in ("USAGE", "SESSION_ISSUED", "KEY_CREATED")
                and bool(re.fullmatch(prefix + r"/[A-Za-z0-9-]{1,128}", item.reference))
                and bool(re.fullmatch(r"(?:AKIA|ASIA)[A-Z0-9]{16}", item.identifier)))
    if spec.provider == "aws_iam":
        if item.evidence == "OPERATION":
            return (item.account_id == spec.account_id and item.reference == "account/" + spec.account_id
                    and not item.principal_arn and item.operation is not None
                    and item.operation.name not in ("LOOKUP_EVENTS", "READ_TRAIL_LOGS"))
        return (item.account_id == spec.account_id and item.evidence in ("ISSUED", "ROOT_STATUS", "USER_STATUS", "UNRESOLVED")
                and bool(re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn|aws-eusc):iam::" + spec.account_id + r":(?:user/[A-Za-z0-9/+=,.@_-]+|root)", item.reference))
                and (not item.principal_arn or item.principal_arn == item.reference))
    if item.evidence not in ("VALUE", "IDENTIFIER", "UNRESOLVED"):
        return False
    if spec.provider in ("aws_secrets_manager", "aws_ssm"):
        service = "secretsmanager" if spec.provider == "aws_secrets_manager" else "ssm"
        arn = item.reference.split(":", 5)
        if (len(arn) != 6 or arn[0] != "arn" or arn[1] not in ("aws", "aws-us-gov", "aws-cn", "aws-eusc")
                or arn[2] != service or arn[3] not in spec.regions
                or arn[4] != spec.account_id or item.account_id != spec.account_id or item.region != arn[3]):
            return False
        if spec.references and item.reference not in spec.references:
            return False
        kind = "secret:" if service == "secretsmanager" else "parameter/"
        if not arn[5].startswith(kind):
            return False
        name = arn[5][len(kind):]
        if service == "secretsmanager":
            # SM appends six random characters to the name in the ARN.
            name = re.sub(r"-[A-Za-z0-9]{6}$", "", name)
        return not spec.prefixes or any(name == prefix or name.startswith(prefix.rstrip("/") + "/") for prefix in spec.prefixes)
    if spec.provider == "external_vault":
        # The declared scope is path prefixes; "" declares the whole export.
        try:
            if not item.reference or scope_path(item.reference) != item.reference:
                return False
        except ValueError:
            return False
        return (not item.account_id and not item.region and not item.namespace and not item.mount
                and any(not prefix or item.reference == prefix or item.reference.startswith(prefix + "/")
                        for prefix in spec.prefixes))
    if spec.provider in ("vault", "openbao"):
        try:
            if scope_path(item.reference) != item.reference:
                return False
        except ValueError:
            return False
        return item.namespace in spec.namespaces and any(
            item.mount == mount.name and any(not prefix or item.reference == prefix or
                item.reference.startswith(prefix + "/") for prefix in mount.prefixes) for mount in spec.mounts)
    return bool(re.fullmatch(r"projects/" + re.escape(spec.project) + r"/secrets/[A-Za-z0-9_-]{1,255}", item.reference)) and (
        not spec.references or item.reference in spec.references)
