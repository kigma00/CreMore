"""Application configuration (environment variables).

Start-up checks cover only what CreMore itself is responsible for: keyed
fingerprints, no built-in credentials and well-formed values. Network, TLS,
database transport and identity provider design are the installing
organization's choice. Provider verification is on by default and switched from
the dashboard; credential-mutating actions stay off unless explicitly enabled.
"""

from __future__ import annotations

import logging
import math
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Variables that used to switch a feature on and no longer exist. A leftover
# line in an upgraded .env is ignored silently, so a queue consumer or an
# investigation an installation was relying on would just stop. Each is named at
# start-up with the setting that replaced it.
RETIRED_ENV = {
    "SCAN_SCHEDULES_ENABLED": "the schedules switch in the dashboard (/settings/scan-triggers)",
    "SCAN_SQS_ENABLED": "the queue switch in the dashboard (/settings/scan-triggers)",
    "SCAN_EVENTS_ENABLED": "nothing: the signed event webhook was removed. Use the dedicated queue or a schedule",
    "SCAN_EVENTS_MODE": "nothing: the signed event webhook was removed",
    "SCAN_EVENTS_SIGNING_KEY": "nothing: the signed event webhook was removed",
    "SCAN_EVENTS_PROFILE_ID": "nothing: the signed event webhook was removed",
    "IAM_POTENTIAL_ACCESS_ENABLED": "IAM_POTENTIAL_ACCESS_MODE plus the switch in the dashboard (/settings/aws-investigations)",
    "AWS_USAGE_LOOKUP_ENABLED": "AWS_USAGE_LOOKUP_MODE plus the switch in the dashboard (/settings/aws-investigations)",
    "AWS_SECRETS_INVENTORY_ENABLED": "AWS_SECRETS_INVENTORY_MODE plus the switch in the dashboard (/settings/aws-investigations)",
    "LEARNED_FP_ENABLED": "LEARNED_FP_MODE plus the switch in the dashboard (/settings/learned-false-positives)",
    "CREDENTIAL_VERIFICATION_ACKNOWLEDGED": "CREDENTIAL_VERIFICATION_MODE plus the switch in the dashboard",
}


def retired_env_in_use(environ=None) -> list[str]:
    """Retired variables actually present, so start-up can name them."""
    return sorted(name for name in RETIRED_ENV if name in (os.environ if environ is None else environ))


def _cgroup_cpus() -> float | None:
    """The container's CPU limit in CPUs (cgroup v2 cpu.max, else v1 CFS quota); None where there is none."""
    try:
        quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()[:2]
    except (OSError, ValueError):
        try:
            quota = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text().strip()
            period = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text().strip()
        except OSError:
            return None
    try:
        return int(quota) / int(period) if quota not in ("max", "-1") else None
    except (ValueError, ZeroDivisionError):
        return None


def _usable_cpus() -> int:
    """CPUs this process may really use: os.cpu_count() reports a container's whole host."""
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 2)
    limit = _cgroup_cpus()
    return max(1, min(cpus, math.ceil(limit))) if limit else cpus


_IAM_ROLE_ARN = re.compile(r"^arn:aws(?:-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore", case_sensitive=False)

    # --- deployment ---------------------------------------------------------
    profile: Literal["local", "alpha", "live"] = Field(default="local", alias="PROFILE")
    auth_mode: str = Field(default="local", alias="AUTH_MODE")  # local (test) | oidc
    # No built-in value: a default shared admin token would be public knowledge.
    api_token: str = Field(default="", alias="API_TOKEN")
    api_bind: str = Field(default="127.0.0.1:8080", alias="API_BIND")
    isolated_deployment: bool = Field(default=False, alias="ISOLATED_DEPLOYMENT")
    worker_execution_role: Literal["mixed", "collector", "remediator", "control"] = Field(
        default="mixed", alias="WORKER_EXECUTION_ROLE")
    remediation_approval_public_key_file: str = Field(default="", alias="REMEDIATION_APPROVAL_PUBLIC_KEY_FILE")
    # Optional in-process TLS for the API (the Helm chart mounts an internal
    # PKI certificate here so every in-cluster hop stays encrypted).
    api_tls_cert_file: str = Field(default="", alias="TLS_CERT_FILE")
    api_tls_key_file: str = Field(default="", alias="TLS_KEY_FILE")

    # --- OIDC (AUTH_MODE=oidc) -----------------------------------------------
    # The API independently validates issuer, signature (JWKS), audience,
    # expiry and subject, then maps the groups claim onto platform roles.
    oidc_issuer_url: str = Field(default="", alias="OIDC_ISSUER_URL")
    oidc_jwks_url: str = Field(default="", alias="OIDC_JWKS_URL")
    oidc_audience: str = Field(default="", alias="OIDC_AUDIENCE")
    oidc_groups_claim: str = Field(default="groups", alias="OIDC_GROUPS_CLAIM")
    oidc_viewer_group: str = Field(default="", alias="OIDC_VIEWER_GROUP")
    oidc_analyst_group: str = Field(default="", alias="OIDC_ANALYST_GROUP")
    oidc_remediator_group: str = Field(default="", alias="OIDC_REMEDIATOR_GROUP")
    oidc_admin_group: str = Field(default="", alias="OIDC_ADMIN_GROUP")

    # --- fingerprinting ---------------------------------------------------------
    # Hex-encoded HMAC key. When set, fingerprints are keyed so a fingerprint
    # from one installation cannot be matched against another's.
    fingerprint_key: str = Field(default="", alias="FINGERPRINT_KEY")
    # The audit trail's MAC key (cremore/db/audit_chain.py), 32+ random bytes as hex. Empty derives it from
    # FINGERPRINT_KEY; set it where FINGERPRINT_KEY also goes to hosts outside the API and worker (an external
    # vault's hasher). Keep it for the life of the trail: another key reads every sealed row as changed.
    audit_chain_key: str = Field(default="", alias="AUDIT_CHAIN_KEY")

    # --- sealing (connection credentials stored by CreMore) ------------------
    # The master that seals stored connection credentials. Empty means "derive
    # it from FINGERPRINT_KEY", which is what every installation did before this
    # existed, so leaving it unset changes nothing. Setting it separates the two
    # jobs one key used to do: FINGERPRINT_KEY then only keys fingerprints, which
    # must never rotate, and this one can.
    sealing_key: str = Field(default="", alias="SEALING_KEY")
    # Keys that may still open stored credentials but never seal a new one.
    # Comma separated, which is how an installation holds the key it is moving
    # away from while the credentials sealed under it are re-entered or re-sealed.
    sealing_key_previous: str = Field(default="", alias="SEALING_KEY_PREVIOUS")
    # The same master, held by AWS KMS instead of by this disk: what is set here
    # is a ciphertext, and opening it needs kms:Decrypt on the named CMK rather
    # than a copy of this file. See cremore_aws_provider.kms.
    sealing_kms_key_id: str = Field(default="", alias="SEALING_KMS_KEY_ID")
    sealing_key_ciphertext: str = Field(default="", alias="SEALING_KEY_CIPHERTEXT")
    sealing_key_ciphertext_previous: str = Field(default="", alias="SEALING_KEY_CIPHERTEXT_PREVIOUS")
    # The same master, held in the Vault/OpenBao this installation already runs:
    # a KV v2 path whose field holds it hex encoded. Needs the secret store
    # configured for THIS process, which for the API means a token scoped to
    # this one path -- not the worker's, which reads connection references.
    sealing_key_vault_path: str = Field(default="", alias="SEALING_KEY_VAULT_PATH")
    sealing_key_vault_path_previous: str = Field(default="", alias="SEALING_KEY_VAULT_PATH_PREVIOUS")
    sealing_key_vault_field: str = Field(default="key", alias="SEALING_KEY_VAULT_FIELD")
    # The same master derived from a supplied phrase. Process configuration
    # cannot prove disk absence; Docker retains injected environment across
    # restarts. See cremore.secretstore.passphrase.
    sealing_passphrase: str = Field(default="", alias="SEALING_PASSPHRASE")
    sealing_passphrase_previous: str = Field(default="", alias="SEALING_PASSPHRASE_PREVIOUS")
    sealing_public_keys_file: str = Field(default="", alias="SEALING_PUBLIC_KEYS_FILE")
    sealing_private_keys_file: str = Field(default="", alias="SEALING_PRIVATE_KEYS_FILE")
    control_sealing_key: str = Field(default="", alias="CONTROL_SEALING_KEY", repr=False)

    @property
    def credential_sealing_keys(self):
        if not self.isolated_deployment:
            return self.sealing_keys
        from cremore.secretstore.isolation import RecipientKeys

        return RecipientKeys.from_files(self.sealing_public_keys_file, self.sealing_private_keys_file)

    @property
    def control_sealing_keys(self):
        from cremore.secretstore.sealed import SealingKeys

        if not self.isolated_deployment:
            return self.sealing_keys
        return SealingKeys(self._key_bytes(self.control_sealing_key, "CONTROL_SEALING_KEY"))

    @staticmethod
    def _key_bytes(value: str, name: str) -> bytes | None:
        value = value.strip()
        if not value:
            return None
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be strict hexadecimal") from exc
        if len(decoded) < 32:
            raise ValueError(f"{name} must decode to at least 32 bytes")
        return decoded

    def _vault_masters(self, paths: str) -> list[bytes]:
        """Every master held at the given KV paths, in order. One client, closed after."""
        wanted = [part.strip() for part in paths.split(",") if part.strip()]
        if not wanted:
            return []
        import httpx

        from cremore.secretstore.vault import kv_from_settings, sealing_master

        client = httpx.Client(timeout=10.0)
        try:
            kv = kv_from_settings(self, client)
            return [sealing_master(kv, path, self.sealing_key_vault_field) for path in wanted]
        finally:
            client.close()

    def _typed_master(self, value: str) -> bytes | None:
        """A master derived from a typed passphrase, or None when none was typed."""
        if not value.strip():
            return None
        from cremore.secretstore.passphrase import master

        return master(value, self.fingerprint_key_bytes)

    def _kms_master(self, ciphertext: str) -> bytes | None:
        """One KMS-held master, or None where this installation keeps none there."""
        if not ciphertext.strip():
            return None
        from cremore_aws_provider import kms

        return kms.master(ciphertext, self.sealing_kms_key_id,
                          kms.region_of(self.sealing_kms_key_id, self.aws_region))

    @property
    def sealing_keys(self):
        """Which key seals new credentials, and every key that can open one.

        A master held somewhere other than this disk wins over one held on it,
        because an installation that moved its key out should not silently fall
        back to the copy it was moving away from. Vault comes before KMS only
        because an installation that configured both said something about which
        it trusts; either way the displaced key stays able to open.

        The store is reached here rather than at start-up: a worker whose
        connections are all ``vault://`` needs no sealing key at all, and should
        not fail to boot because Vault or KMS is briefly unreachable.
        """
        from cremore.secretstore.sealed import SealingKeys

        if self.isolated_deployment:
            return self.control_sealing_keys

        legacy = self.fingerprint_key_bytes
        in_vault = self._vault_masters(self.sealing_key_vault_path)
        in_kms = self._kms_master(self.sealing_key_ciphertext)
        # Preserve source precedence. A passphrase is still configured secret
        # material; settings cannot tell whether its source was persisted.
        typed = self._typed_master(self.sealing_passphrase)
        on_disk = self._key_bytes(self.sealing_key, "SEALING_KEY")
        current = (in_vault[0] if in_vault else None) or in_kms or typed or on_disk or legacy
        # Everything configured stays in the ring even when displaced, or moving
        # the master out would orphan every credential sealed before the move.
        previous = tuple(key for key in (
            on_disk, in_kms, typed, *in_vault,
            *(self._typed_master(part) for part in self.sealing_passphrase_previous.split(",")),
            *self._vault_masters(self.sealing_key_vault_path_previous),
            *(self._kms_master(part) for part in self.sealing_key_ciphertext_previous.split(",")),
            *(self._key_bytes(part, "SEALING_KEY_PREVIOUS") for part in self.sealing_key_previous.split(",")),
        ) if key)
        return SealingKeys(current, legacy, previous)

    def validate_sealing(self) -> None:
        """The sealing settings are well formed. Makes no AWS call."""
        from cremore_aws_provider import kms

        self._key_bytes(self.control_sealing_key, "CONTROL_SEALING_KEY")
        if self.isolated_deployment:
            if not self.sealing_public_keys_file.strip():
                raise ValueError("ISOLATED_DEPLOYMENT requires SEALING_PUBLIC_KEYS_FILE")
            if any(value.strip() for value in (self.sealing_key, self.sealing_key_previous,
                    self.sealing_passphrase, self.sealing_passphrase_previous, self.sealing_key_ciphertext,
                    self.sealing_key_ciphertext_previous, self.sealing_key_vault_path, self.sealing_key_vault_path_previous)):
                raise ValueError("ISOLATED_DEPLOYMENT cannot retain legacy sealing keys; migrate offline first")

        self._key_bytes(self.sealing_key, "SEALING_KEY")
        for part in self.sealing_key_previous.split(","):
            self._key_bytes(part, "SEALING_KEY_PREVIOUS")
        held = [self.sealing_key_ciphertext, *self.sealing_key_ciphertext_previous.split(",")]
        stored = [part for part in held if part.strip()]
        if stored and not self.sealing_kms_key_id.strip():
            raise ValueError("SEALING_KEY_CIPHERTEXT requires SEALING_KMS_KEY_ID naming the CMK that opens it")
        for part in stored:
            kms.decode(part)
        # A sealing path needs the store wired for THIS process, API included.
        # Left unsaid, the first credential written would fail instead.
        paths = [self.sealing_key_vault_path, *self.sealing_key_vault_path_previous.split(",")]
        if any(part.strip() for part in paths) and not self.secret_store_enabled:
            raise ValueError("SEALING_KEY_VAULT_PATH requires SECRET_STORE_URL and its credential in this process")
        if not self.sealing_key_vault_field.strip():
            raise ValueError("SEALING_KEY_VAULT_FIELD must name a field in the stored secret")
        # Length is checked at start-up so a too-short passphrase is refused
        # while somebody is still there to type a longer one.
        from cremore.secretstore.passphrase import MIN_LENGTH

        for name, value in (("SEALING_PASSPHRASE", self.sealing_passphrase),
                            *(("SEALING_PASSPHRASE_PREVIOUS", part)
                              for part in self.sealing_passphrase_previous.split(","))):
            if value.strip() and len(value.strip()) < MIN_LENGTH:
                raise ValueError(f"{name} must be at least {MIN_LENGTH} characters")

    @property
    def audit_chain_key_bytes(self) -> bytes | None:
        return self._key_bytes(self.audit_chain_key, "AUDIT_CHAIN_KEY")

    @property
    def fingerprint_key_bytes(self) -> bytes | None:
        value = self.fingerprint_key.strip()
        if not value:
            return None
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("FINGERPRINT_KEY must be strict hexadecimal") from exc
        if decoded.hex() != value.lower():
            raise ValueError("FINGERPRINT_KEY must be strict hexadecimal")
        return decoded

    # --- worker ----------------------------------------------------------------
    # The worker has no HTTP port; it touches this file every poll so a
    # liveness probe can check its freshness.
    worker_heartbeat_file: str = Field(
        default="/tmp/cremore-worker.heartbeat", alias="WORKER_HEARTBEAT_FILE"
    )
    # Task-runner processes of one scanning worker (cremore.worker.supervisor), each running one task at a time.
    # 0 picks for the database: PostgreSQL min(4, usable CPUs), SQLite 1 (one file takes one writer at a time).
    worker_concurrency: int = Field(default=0, ge=0, le=32, alias="WORKER_CONCURRENCY")

    @property
    def effective_worker_concurrency(self) -> int:
        if self.worker_concurrency:
            return self.worker_concurrency
        return min(4, _usable_cpus()) if self.sqlalchemy_url.startswith("postgresql") else 1

    # How often one worker queues platform.heartbeat for the SIEM; a SIEM rule
    # alerts when it stops arriving (docs/SIEM_INTEGRATION.md).
    operations_heartbeat_minutes: int = Field(default=5, ge=1, le=60, alias="OPERATIONS_HEARTBEAT_MINUTES")
    # Days a delivered SIEM event is kept; 0 keeps findings and connection events.
    # Heartbeats and test events always go a week after every destination got them.
    siem_event_retention_days: int = Field(default=0, ge=0, le=3650, alias="SIEM_EVENT_RETENTION_DAYS")
    # Departed people, their account links and verdicts are deleted this long after departure.
    leaver_retention_days: int = Field(default=365, ge=30, le=3650, alias="LEAVER_RETENTION_DAYS")

    # --- database -----------------------------------------------------------
    database_url: str = Field(
        default="postgresql+psycopg://cremore:cremore@localhost:5432/cremore",
        alias="DATABASE_URL",
    )

    @property
    def sqlalchemy_url(self) -> str:
        """Normalize a bare or async DSN to the sync psycopg driver SQLAlchemy uses."""

        url = self.database_url
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://") :]
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://") :]
        return url.replace("+asyncpg", "+psycopg")

    # --- scanning -----------------------------------------------------------
    max_input_bytes: int = Field(default=8 << 20, alias="MAX_INPUT_BYTES")
    max_object_size_mb: int = Field(default=50, alias="MAX_OBJECT_SIZE_MB")

    # Triggers are bound to administrator-approved scope profiles and switched in
    # the dashboard: schedules and change feeds are on unless an Admin switches
    # them off, queues off until an Admin binds one. A schedule is already the
    # Admin's decision (schedule_minutes on the profile), so a second decision
    # here would only let the installation ignore it silently. These modes ALLOW
    # a trigger (the default) or hard-lock it off; the switch and the binding are
    # in cremore/scanning/trigger_settings.py.
    scan_schedules_mode: str = Field(default="enabled", alias="SCAN_SCHEDULES_MODE")
    scan_sqs_mode: str = Field(default="enabled", alias="SCAN_SQS_MODE")
    # The customer's own Pub/Sub subscription and Service Bus queue, read like SQS.
    # Change feeds (cremore.scanning.changes): allowed by default, and on unless an Admin switches them off.
    scan_change_feeds_mode: str = Field(default="enabled", alias="SCAN_CHANGE_FEEDS_MODE")
    # Optional pins. Set one and the dashboard shows that field as fixed.
    scan_sqs_queue_url: str = Field(default="", alias="SCAN_SQS_QUEUE_URL")
    scan_sqs_profile_id: str = Field(default="", alias="SCAN_SQS_PROFILE_ID")
    scan_sqs_dedicated_acknowledged: bool = Field(default=False, alias="SCAN_SQS_DEDICATED_ACKNOWLEDGED")

    @property
    def scan_schedules_allowed(self) -> bool:
        return self.scan_schedules_mode == "enabled"

    @property
    def scan_sqs_allowed(self) -> bool:
        return self.scan_sqs_mode == "enabled"

    @property
    def scan_change_feeds_allowed(self) -> bool:
        return self.scan_change_feeds_mode == "enabled"

    # Existing S3 Inventory reports, as connectionUUID/bucket -> report pointer.
    # Optional: set it and the dashboard shows the bindings as fixed.
    scan_inventory_manifests: str = Field(default="{}", alias="SCAN_INVENTORY_MANIFESTS")

    @property
    def inventory_manifest_bindings(self) -> dict[str, dict[str, str]]:
        """The bindings configuration pins, if any; otherwise an Admin sets them
        in the dashboard (cremore/scanning/inventory_manifests.py)."""
        from cremore.scanning import inventory_manifests

        return inventory_manifests.pinned(self) or {}

    # --- verification (sends discovered credentials to their providers) -----
    # On by default and switched on/off by an Admin in the dashboard; `disabled`
    # locks it off for the whole installation regardless of the dashboard.
    verification_mode: str = Field(
        default="enabled", alias="CREDENTIAL_VERIFICATION_MODE"
    )  # enabled | disabled
    # After a credential verifies, make a few read-only calls with it to record
    # what it can reach — the empirical permissions for types whose provider does
    # not report them (a GitHub fine-grained PAT, a Notion integration). Off by
    # default; requires verification to be enabled. It uses the discovered token,
    # so it is a separate, deliberate opt-in.
    capability_probe_mode: str = Field(
        default="enabled", alias="CREDENTIAL_CAPABILITY_PROBE_MODE"
    )  # enabled (allowed) | disabled (hard lock)
    # When a GitHub token is rejected by the host it was found on, also try the
    # other registered GitHub hosts, so a token that belongs to a different
    # GitHub is confirmed rather than falsely called inactive. It sends the token
    # to an extra server, so it is OFF by default.
    cross_host_verification_mode: str = Field(
        default="enabled", alias="CREDENTIAL_CROSS_HOST_VERIFICATION"
    )  # enabled (allowed) | disabled (hard lock)
    # Bare GitHub Enterprise Server hostnames this installation uses, comma
    # separated (github.com is always known). Verification and capability probes
    # of a discovered GitHub token are directed at these hosts.
    github_enterprise_hosts: str = Field(default="", alias="GITHUB_ENTERPRISE_HOSTS")
    # --- actions (all default-off) -----------------------------------------
    action_execution_enabled: bool = Field(default=False, alias="ACTION_EXECUTION_ENABLED")
    rotation_execution_enabled: bool = Field(default=False, alias="ACTION_ROTATION_ENABLED")
    # Permanent IAM key deletion has its own gate on top of ACTION_EXECUTION_ENABLED.
    action_deletion_enabled: bool = Field(default=False, alias="ACTION_DELETION_ENABLED")
    # Comma-separated Secrets Manager ARNs a rotation plan may bind to. An
    # allowlist entry is not a permission grant; the executor role still decides.
    rotation_secret_arns: str = Field(default="", alias="ROTATION_SECRET_ARNS")
    # How long an unapproved / unexecuted plan stays actionable.
    action_plan_ttl_hours: int = Field(default=24, alias="ACTION_PLAN_TTL_HOURS")

    @property
    def rotation_secret_arn_list(self) -> list[str]:
        return [a.strip() for a in self.rotation_secret_arns.split(",") if a.strip()]

    # --- secret manager mapping (metadata only) ----------------------------
    # Comma-separated Secrets Manager ARNs an administrator may map a discovered
    # credential to. A mapping is a declaration ("possibly stored here"), never
    # proof of value equivalence; metadata reads need the secrets inventory switched on.
    secret_manager_allowed_references: str = Field(
        default="", alias="SECRET_MANAGER_ALLOWED_REFERENCES"
    )

    @property
    def secret_manager_reference_list(self) -> list[str]:
        return [a.strip() for a in self.secret_manager_allowed_references.split(",") if a.strip()]

    # --- learned false-positive profiles (docs/LEARNED_FALSE_POSITIVES.md) --
    # Confirmed false positives become per-scope samples; an active profile
    # auto-triages repeats of the same redacted context. Off by default.
    # Auto-triage is switched on in the dashboard, where the policy it applies is
    # also visible and audited (cremore/scanning/learned_fp_settings.py). This ALLOWS
    # it (default) or hard-locks it off, like the other scan toggles.
    learned_fp_mode: str = Field(
        default="enabled", alias="LEARNED_FP_MODE"
    )  # enabled (allowed) | disabled (hard lock)
    # Optional pin; 0 or empty leaves the value to the dashboard.
    learned_fp_min_samples_pin: int = Field(default=0, alias="LEARNED_FP_MIN_SAMPLES")
    # Optional pin; 0.0 or empty leaves the value to the dashboard.
    learned_fp_threshold_pin: float = Field(default=0.0, alias="LEARNED_FP_THRESHOLD")
    # Highest detector confidence tier a profile may auto-triage (low|medium|high).
    # Optional pin; "" or empty leaves the value to the dashboard.
    learned_fp_max_confidence_pin: str = Field(default="", alias="LEARNED_FP_MAX_CONFIDENCE")

    # --- secret store (optional; resolves connection secret_ref at scan time) -
    secret_store_url: str = Field(default="", alias="SECRET_STORE_URL")
    secret_store_token: str = Field(default="", alias="SECRET_STORE_TOKEN")
    secret_store_mount: str = Field(default="secret", alias="SECRET_STORE_MOUNT")
    secret_store_auth_mode: str = Field(default="token", alias="SECRET_STORE_AUTH_MODE")
    secret_store_kubernetes_role: str = Field(
        default="", alias="SECRET_STORE_KUBERNETES_ROLE"
    )
    secret_store_kubernetes_auth_mount: str = Field(
        default="kubernetes", alias="SECRET_STORE_KUBERNETES_AUTH_MOUNT"
    )
    secret_store_kubernetes_token_file: str = Field(
        default="/run/cremore-vault/token", alias="SECRET_STORE_KUBERNETES_TOKEN_FILE"
    )
    # Where the deployment mounts one login token per external Vault/OpenBao
    # connection (a projected token with that cluster's audience, or a file a
    # token refresher keeps current). Connections name a file here, never a path.

    @property
    def secret_store_enabled(self) -> bool:
        credential = (
            self.secret_store_token
            if self.secret_store_auth_mode == "token"
            else self.secret_store_kubernetes_role
        )
        return bool(self.secret_store_url and credential)

    # --- aws ----------------------------------------------------------------
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    # Optional: pins the scanner's IAM role ARN for server installs instead of
    # approving the runtime AWS identity in the dashboard. A dashboard approval wins.
    scanner_principal_arn: str = Field(default="", alias="AWS_SCANNER_PRINCIPAL_ARN")
    # Optional AWS CLI profile the API uses for approved key actions, so the
    # remediation identity can differ from the scanning identity.
    aws_remediation_profile: str = Field(default="", alias="AWS_REMEDIATION_PROFILE")
    # Optional S3 URL of deploy/cloudformation/member-account-role.yaml. When set,
    # onboarding also offers a CloudFormation quick-create link next to the CLI command.
    aws_onboarding_template_url: str = Field(default="", alias="AWS_ONBOARDING_TEMPLATE_URL")
    # Evaluate a discovered AWS principal's curated IAM potential-access so the
    # risk model can score its privilege. Read-only (SimulatePrincipalPolicy, and the
    # bucket, secret and key policies of the resources the principal's policies name),
    # but calls AWS with the scanner's own credentials, so it is opt-in.
    # Each of the three ALLOWS its investigation (the default) or hard-locks it
    # off. The switch itself is an Admin's and lives in the dashboard, where an
    # analyst can turn one on during an investigation rather than filing a
    # deployment change (cremore/investigation/investigation_switches.py). All three
    # default off there, so nothing new calls AWS until somebody asks.
    iam_potential_access_mode: str = Field(
        default="enabled", alias="IAM_POTENTIAL_ACCESS_MODE"
    )  # enabled (allowed) | disabled (hard lock)
    aws_secrets_inventory_mode: str = Field(
        default="enabled", alias="AWS_SECRETS_INVENTORY_MODE"
    )
    aws_usage_lookup_mode: str = Field(
        default="enabled", alias="AWS_USAGE_LOOKUP_MODE"
    )

    # --- AWS Organizations account discovery (opt-in) ----------------------
    # When on, the worker periodically lists the organization's accounts (read
    # only) from a delegated-administrator account and registers new ACTIVE ones,
    # so accounts do not have to be added by hand. Discovered accounts are reached
    # through the member scanner role the org-wide StackSet deploys, so they share
    # the ExternalId that StackSet baked into every role's trust policy. Accounts
    # already known that are no longer ACTIVE are disabled, never deleted.
    # The sweep itself is switched on in the dashboard (cremore/aws_org_settings.py);
    # this ALLOWS it (default) or hard-locks it off, like the scan toggles.
    aws_org_discovery_mode: str = Field(
        default="enabled", alias="AWS_ORG_DISCOVERY_MODE"
    )  # enabled (allowed) | disabled (hard lock)
    # The shared STS ExternalId the org-wide StackSet set on every member scanner
    # role. Discovery cannot register assumable accounts without it, but an
    # administrator normally pastes it into the dashboard; setting it here pins
    # it so the dashboard cannot change it.
    aws_org_discovery_external_id: str = Field(default="", alias="AWS_ORG_DISCOVERY_EXTERNAL_ID")
    aws_org_discovery_interval_minutes: int = Field(default=60, alias="AWS_ORG_DISCOVERY_INTERVAL_MINUTES")
    # Account ids to never auto-register (comma separated), e.g. the management account.
    aws_org_discovery_excludes: str = Field(default="", alias="AWS_ORG_DISCOVERY_EXCLUDE_ACCOUNTS")
    # Optional: limit discovery to these organizational units (comma separated OU
    # ids; nested OUs are included). Accounts outside them are not registered, and
    # a registered account that moves out is marked OUT_OF_DEPLOYMENT_SCOPE.
    aws_org_discovery_ou_ids: str = Field(default="", alias="AWS_ORG_DISCOVERY_OU_IDS")
    # Opt-in: immediately queue a discovered account's scanner-role validation so
    # it becomes READY without waiting for the maintenance sweep. This is the
    # account-level "scan on discovery"; S3 content scans still need an explicit
    # bucket scope (targets are never selected automatically).
    # Reaching accounts through this computer's IAM Identity Center assignments
    # instead of a member role (cremore/aws_sso.py). Both the permission set and the
    # sweep are chosen in the dashboard (cremore/aws_sso_settings.py), because the
    # operator who runs this deployment often cannot re-configure it. The env
    # ALLOWS the sweep (default) or hard-locks it off, as the scan toggles do.
    # It needs a writable token cache seeded by interactive `aws sso login`,
    # with human re-login when registration expires. Helm defaults this off;
    # server installs must explicitly provision that cache before opting in.
    aws_sso_discovery_mode: str = Field(
        default="enabled", alias="AWS_SSO_DISCOVERY_MODE"
    )  # enabled (allowed) | disabled (hard lock)
    # Optional pin for installations that do want the permission set fixed in
    # configuration. Empty (the default) leaves the choice to an Admin.
    aws_sso_discovery_permission_set: str = Field(default="", alias="AWS_SSO_DISCOVERY_PERMISSION_SET")
    aws_sso_discovery_interval_minutes: int = Field(default=60, alias="AWS_SSO_DISCOVERY_INTERVAL_MINUTES")
    # Account ids to never auto-register from Identity Center (comma separated).
    # Registered accounts can also simply be disabled from the dashboard.
    aws_sso_discovery_excludes: str = Field(default="", alias="AWS_SSO_DISCOVERY_EXCLUDE_ACCOUNTS")

    @property
    def org_discovery_allowed(self) -> bool:
        return self.aws_org_discovery_mode == "enabled"

    @property
    def aws_org_discovery_exclude_set(self) -> frozenset[str]:
        return frozenset(a.strip() for a in self.aws_org_discovery_excludes.split(",") if a.strip())

    @property
    def aws_org_discovery_ou_id_set(self) -> frozenset[str]:
        return frozenset(a.strip() for a in self.aws_org_discovery_ou_ids.split(",") if a.strip())

    @property
    def iam_potential_access_allowed(self) -> bool:
        return self.iam_potential_access_mode == "enabled"

    @property
    def aws_secrets_inventory_allowed(self) -> bool:
        return self.aws_secrets_inventory_mode == "enabled"

    @property
    def aws_usage_lookup_allowed(self) -> bool:
        return self.aws_usage_lookup_mode == "enabled"

    @property
    def learned_fp_allowed(self) -> bool:
        return self.learned_fp_mode == "enabled"

    @property
    def sso_discovery_allowed(self) -> bool:
        return self.aws_sso_discovery_mode == "enabled"

    @property
    def aws_sso_discovery_exclude_set(self) -> frozenset[str]:
        return frozenset(a.strip() for a in self.aws_sso_discovery_excludes.split(",") if a.strip())

    @property
    def verification_enabled(self) -> bool:
        return self.verification_mode == "enabled"

    @property
    def known_github_hosts(self) -> tuple[str, ...]:
        from cremore_github_provider.github_hosts import normalize_host
        out: list[str] = []
        for raw in self.github_enterprise_hosts.split(","):
            try:
                host = normalize_host(raw)
            except ValueError:
                continue
            if host and host not in out:
                out.append(host)
        return tuple(out)

    @property
    def cross_host_verification_allowed(self) -> bool:
        return self.verification_enabled and self.cross_host_verification_mode == "enabled"

    @property
    def capability_probe_allowed(self) -> bool:
        # Probing sends the discovered token to the provider, so it is only
        # available when verification is on and the env allows it.
        return self.verification_enabled and self.capability_probe_mode == "enabled"

    def validate_safety(self, component: str = "api") -> None:
        """Refuse unsafe combinations at start-up (fail closed)."""

        if component not in ("api", "worker"):
            raise ValueError("component must be 'api' or 'worker'")
        # A warning, not a refusal: a stale line in an .env should not stop a
        # deployment from booting. It must not pass unsaid either -- what it used
        # to switch now follows the dashboard switch's own default: off, except
        # schedules, which are on unless switched off.
        for name in retired_env_in_use():
            logging.getLogger("cremore.config").warning(
                "%s is set but no longer does anything; it was replaced by %s. Whatever it enabled is %s.",
                name, RETIRED_ENV[name], "ON unless it is switched off there" if name == "SCAN_SCHEDULES_ENABLED"
                else "OFF until it is turned on there")
        if self.auth_mode not in ("local", "oidc"):
            raise ValueError("AUTH_MODE must be 'local' or 'oidc'")
        if self.verification_mode not in ("disabled", "enabled"):
            raise ValueError("CREDENTIAL_VERIFICATION_MODE must be 'disabled' or 'enabled'")
        if self.capability_probe_mode not in ("disabled", "enabled"):
            raise ValueError("CREDENTIAL_CAPABILITY_PROBE_MODE must be 'disabled' or 'enabled'")
        if self.cross_host_verification_mode not in ("disabled", "enabled"):
            raise ValueError("CREDENTIAL_CROSS_HOST_VERIFICATION must be 'disabled' or 'enabled'")
        if self.secret_store_auth_mode not in ("token", "kubernetes"):
            raise ValueError("SECRET_STORE_AUTH_MODE must be 'token' or 'kubernetes'")
        if self.max_input_bytes <= 0:
            raise ValueError("MAX_INPUT_BYTES must be positive")
        if self.max_object_size_mb <= 0:
            raise ValueError("MAX_OBJECT_SIZE_MB must be positive")
        self.validate_scan_triggers()
        _ = self.inventory_manifest_bindings
        # Keyed fingerprints are ours: without the key a leaked database lets anyone
        # confirm a guessed secret, and adding one later orphans every stored match.
        key = self.fingerprint_key_bytes
        if key is None or len(key) < 32:
            raise ValueError("FINGERPRINT_KEY requires at least 32 random bytes as hex")
        self.validate_sealing()
        _ = self.audit_chain_key_bytes  # a malformed AUDIT_CHAIN_KEY stops start-up, not the first audit row
        if component == "api" and self.auth_mode == "local" and len(self.api_token) < 32:
            raise ValueError("AUTH_MODE=local requires API_TOKEN of at least 32 characters")
        if self.aws_remediation_profile and not re.fullmatch(r"[A-Za-z0-9._@+=,-]{1,64}", self.aws_remediation_profile):
            raise ValueError("AWS_REMEDIATION_PROFILE must be an AWS CLI profile name")
        if self.scanner_principal_arn and not _IAM_ROLE_ARN.fullmatch(self.scanner_principal_arn):
            raise ValueError("AWS_SCANNER_PRINCIPAL_ARN must be an exact IAM role ARN")
        if self.aws_sso_discovery_permission_set and not re.fullmatch(
                r"[A-Za-z0-9+=,.@_-]{1,32}", self.aws_sso_discovery_permission_set):
            raise ValueError("AWS_SSO_DISCOVERY_PERMISSION_SET must be an IAM Identity Center permission set name")
        for name in ("aws_sso_discovery_mode", "aws_org_discovery_mode", "learned_fp_mode",
                     "iam_potential_access_mode", "aws_usage_lookup_mode", "aws_secrets_inventory_mode",
                     "scan_schedules_mode", "scan_sqs_mode",
                     "scan_change_feeds_mode"):
            if getattr(self, name) not in ("enabled", "disabled"):
                raise ValueError(f"{name.upper()} must be 'enabled' or 'disabled'")
        if component == "api" and bool(self.api_tls_cert_file) != bool(self.api_tls_key_file):
            raise ValueError("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
        if component == "worker":
            secret_store_configured = bool(
                self.secret_store_url
                or self.secret_store_token
                or self.secret_store_kubernetes_role
                or self.secret_store_auth_mode == "kubernetes"
            )
            if secret_store_configured and not self.secret_store_url:
                raise ValueError("secret store authentication requires SECRET_STORE_URL")
            if self.secret_store_url:
                store_url = urlsplit(self.secret_store_url)
                if not store_url.hostname or store_url.scheme not in ("http", "https"):
                    raise ValueError("SECRET_STORE_URL must be an HTTP(S) URL")
                if not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
                    self.secret_store_mount.strip("/"),
                ):
                    raise ValueError("SECRET_STORE_MOUNT must be a single safe path segment")
                if self.secret_store_auth_mode == "token" and not self.secret_store_token:
                    raise ValueError("SECRET_STORE_AUTH_MODE=token requires SECRET_STORE_TOKEN")
                if self.secret_store_auth_mode == "kubernetes":
                    if self.secret_store_token:
                        raise ValueError(
                            "SECRET_STORE_AUTH_MODE=kubernetes requires SECRET_STORE_TOKEN to be unset"
                        )
                    if not self.secret_store_kubernetes_role:
                        raise ValueError(
                            "SECRET_STORE_AUTH_MODE=kubernetes requires SECRET_STORE_KUBERNETES_ROLE"
                        )
                    if not re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
                        self.secret_store_kubernetes_auth_mount.strip("/"),
                    ):
                        raise ValueError(
                            "SECRET_STORE_KUBERNETES_AUTH_MOUNT must be a single safe path segment"
                        )
                    if not self.secret_store_kubernetes_token_file.startswith("/"):
                        raise ValueError("SECRET_STORE_KUBERNETES_TOKEN_FILE must be absolute")
        # Only what OIDC token validation cannot work without; transport, IdP and
        # group design belong to the installing organization.
        if component == "api" and self.auth_mode == "oidc" and not (self.oidc_issuer_url and self.oidc_audience):
            raise ValueError("AUTH_MODE=oidc requires OIDC_ISSUER_URL and OIDC_AUDIENCE")
        # Onboarding needs neither setting: the scanner identity is approved in the
        # dashboard. A template URL only adds a CloudFormation quick-create link.
        if component == "api" and self.aws_onboarding_template_url:
            template = urlsplit(self.aws_onboarding_template_url)
            if template.scheme != "https" or not template.hostname:
                raise ValueError("AWS_ONBOARDING_TEMPLATE_URL must be HTTPS")

    def validate_scan_triggers(self) -> None:
        """Refuse a malformed pin at start-up, before a trigger could use it.

        Only the values configuration still owns are checked here. What an Admin
        sets in the dashboard is validated when it is written, and a trigger that
        is not fully bound reads as off rather than failing on the event that
        finally arrives (cremore/scanning/trigger_settings.py).
        """
        from cremore.scanning import trigger_settings

        try:
            trigger_settings.profile_uuid(self.scan_sqs_profile_id)
        except ValueError as exc:
            raise ValueError("SCAN_SQS_PROFILE_ID must be one approved profile UUID") from exc
        try:
            trigger_settings.queue_url(self.scan_sqs_queue_url)
        except ValueError as exc:
            raise ValueError("SCAN_SQS_QUEUE_URL must be an explicit HTTPS AWS queue URL") from exc


@lru_cache
def get_settings(component: str = "api") -> Settings:
    # 로컬 실행에서만 파일 설정을 허용해 배포 환경의 값 출처를 명확히 한다.
    profile = os.environ.get("PROFILE", "local").lower()
    if profile not in ("local", "alpha", "live"):
        raise ValueError("PROFILE must be 'local', 'alpha' or 'live'")
    settings = Settings(PROFILE=profile, _env_file=".env" if profile == "local" else None)
    settings.validate_safety(component)
    return settings
