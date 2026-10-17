"""The installation's machine identity from the organization's IdP, set in the dashboard.

An administrator registers one client-credentials app of the IdP and configures
an AWS IAM role that trusts it (``AssumeRoleWithWebIdentity``). API and worker processes keep its token current
itself, in files only it reads, and points the cloud SDKs at them the way the deployment files did
(docs/MACHINE_IDENTITY.md). No refresher runs beside it and nothing is typed into the deployment; the
AWS connections keep their own sign-in methods and reach AWS as this identity.

The client secret is sealed like a connection credential and never returned. A process reports back its
state and the non-secret claims of the tokens it holds (issuer, subject, audience, lifetime); the setup steps
for each cloud are written from those claims.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from cremore.cli.token_refresher import Token, refresh_due
from cremore.oauth_client import ClientCredentialsGrant

logger = logging.getLogger("cremore.machine_identity")

KEY = "machine_identity"
STATUS_PREFIX = "machine_identity.status."
# The last "fetch a token now" an Admin ran from the API, kept apart from the processes' own reports.
TEST_KEY = "machine_identity.test"
ACTOR = "system:machine-identity"
CLOUDS = ("aws",)
AUTH_METHODS = ("client_secret_post", "client_secret_basic")
TOKEN_FIELDS = ("access_token", "id_token")
AUDIT_TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:machine-identity")

_ROLE_ARN = re.compile(r"arn:aws(?:-[a-z]+)*:iam::\d{12}:role/[\w+=,.@/-]{1,512}\Z")
# AWS SDK 환경을 기존 값으로 되돌리기 위해 관리할 변수 목록.
ENV_KEYS = ("AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME", "AWS_PROFILE", "AWS_ACCESS_KEY_ID",
             "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
             "AWS_EC2_METADATA_DISABLED", "AWS_ROLES_ANYWHERE_CONFIG")



class MachineIdentityError(ValueError):
    """A refused setting, with a fixed code the dashboard names."""


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _text(value, code: str, pattern: re.Pattern | None = None, *, required: bool = True) -> str:
    if value in (None, ""):
        if required:
            raise MachineIdentityError(code)
        return ""
    if not isinstance(value, str) or len(value) > 1024 or (pattern is not None and not pattern.fullmatch(value.strip())):
        raise MachineIdentityError(code)
    return value.strip()


def _optional(value, code: str) -> str | None:
    """A scope or audience, as the OAuth client accepts it."""
    if value in (None, ""):
        return None
    try:
        ClientCredentialsGrant(token_url="https://idp.invalid/token", client_id="check", client_secret="check", scope=value)
    except ValueError:
        raise MachineIdentityError(code) from None
    return value


def _grant(idp: dict, secret, *, scope=None, audience=None) -> ClientCredentialsGrant:
    return ClientCredentialsGrant(token_url=idp["token_url"], client_id=idp["client_id"], client_secret=secret,
                                  scope=scope or idp.get("scope"), audience=audience or idp.get("audience"),
                                  auth_method=idp.get("auth_method", "client_secret_post"),
                                  token_field=idp.get("token_field", "access_token"))


def validate(body: dict, current: dict | None) -> dict:
    """The setting an Admin sent, normalized; a secret travels separately and is never part of it."""
    if not isinstance(body, dict):
        raise MachineIdentityError("MACHINE_IDENTITY_INVALID")
    idp_in = body.get("idp") if isinstance(body.get("idp"), dict) else {}
    idp = {"token_url": idp_in.get("token_url"), "client_id": idp_in.get("client_id"),
           "auth_method": idp_in.get("auth_method") or "client_secret_post",
           "token_field": idp_in.get("token_field") or "access_token",
           "scope": _optional(idp_in.get("scope"), "MACHINE_IDENTITY_SCOPE_INVALID"),
           "audience": _optional(idp_in.get("audience"), "MACHINE_IDENTITY_AUDIENCE_INVALID")}
    if idp["auth_method"] not in AUTH_METHODS:
        raise MachineIdentityError("MACHINE_IDENTITY_AUTH_METHOD_INVALID")
    if idp["token_field"] not in TOKEN_FIELDS:
        raise MachineIdentityError("MACHINE_IDENTITY_TOKEN_FIELD_INVALID")
    try:
        _grant(idp, "check")
    except ValueError as exc:
        code = str(exc)
        raise MachineIdentityError("MACHINE_IDENTITY_TOKEN_URL_INVALID" if "URL" in code else "MACHINE_IDENTITY_CLIENT_ID_INVALID") from None

    def binding(name: str) -> dict:
        raw = body.get(name) if isinstance(body.get(name), dict) else {}
        return {"enabled": raw.get("enabled") is True, "scope": _optional(raw.get("scope"), "MACHINE_IDENTITY_SCOPE_INVALID"),
                "audience": _optional(raw.get("audience"), "MACHINE_IDENTITY_AUDIENCE_INVALID"), "raw": raw}

    if any(body.get(name) for name in ("gcp", "azure", "vault")):
        raise MachineIdentityError("MACHINE_IDENTITY_UNSUPPORTED_PROVIDER")
    aws = binding("aws")
    out = {"idp": idp}
    out["aws"] = {"enabled": aws["enabled"], "scope": aws["scope"], "audience": aws["audience"],
                  "role_arn": _text(aws["raw"].get("role_arn"), "MACHINE_IDENTITY_AWS_ROLE_ARN_INVALID", _ROLE_ARN, required=aws["enabled"])}
    out["secret"] = (current or {}).get("secret")
    return out


def revision_of(row: dict | None) -> int:
    """A revisioned setting keeps its revision inside the value."""
    return int((row or {}).get("value", {}).get("revision") or 0)


def in_use(record: dict | None) -> bool:
    return bool(record) and bool(record.get("aws", {}).get("enabled"))


def machine_binding(record: dict) -> dict:
    """Deployment recipient for this IdP client, independent of requested cloud scopes."""
    idp = record["idp"]
    parts = urlsplit(idp["token_url"])
    host = parts.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    authority = host + (f":{parts.port}" if parts.port and parts.port != 443 else "")
    url = urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, ""))
    return {"purpose": "collector", "provider": "machine_identity",
            "authority": {"token_url": url, "client_id": idp["client_id"]}}


def save(repo, settings, body: dict, actor: str) -> dict:
    """Store the setting (sealing a new client secret) and audit who changed which clouds."""
    from cremore.domain.models import FindingEvent
    from cremore.secretstore.sealed import seal_fields

    current_row = repo.get_setting(KEY)
    current = dict(current_row["value"]) if current_row else None
    expected = body.get("expected_revision") if isinstance(body, dict) else None
    if expected is not None and expected != revision_of(current_row):
        raise MachineIdentityError("MACHINE_IDENTITY_CHANGED")
    record = validate(body, current)
    secret = body.get("client_secret")
    if secret not in (None, ""):
        if not isinstance(secret, str) or len(secret) > 8192 or any(not 33 <= ord(c) <= 126 for c in secret):
            raise MachineIdentityError("MACHINE_IDENTITY_SECRET_INVALID")
        if getattr(settings, "isolated_deployment", False):
            from cremore.secretstore.isolation import seal_credential
            from cremore.secretstore.sealed import SealedSecretError

            try:
                record["secret"] = seal_credential(settings, {"client_secret": secret}, machine_binding(record))
            except SealedSecretError:
                raise MachineIdentityError("MACHINE_IDENTITY_RECIPIENT_NOT_CONFIGURED") from None
        else:
            record["secret"] = seal_fields(settings.sealing_keys, {"client_secret": secret})
    elif (record.get("secret") and str(record["secret"]).startswith("sealed:v3:")
          and machine_binding(record) != machine_binding(current)):
        raise MachineIdentityError("MACHINE_IDENTITY_NEW_SECRET_REQUIRED")
    if in_use(record) and not record.get("secret"):
        raise MachineIdentityError("MACHINE_IDENTITY_SECRET_REQUIRED")
    saved = repo.put_revisioned_setting(KEY, record, actor)
    clouds = [cloud for cloud in CLOUDS if record[cloud]["enabled"]]
    repo.record_finding_event(FindingEvent(target_type="machine_identity", target_id=AUDIT_TARGET, actor=actor,
                                           event_type="MACHINE_IDENTITY_CHANGED",
                                           note=f"{record['idp']['client_id']} -> {', '.join(clouds) or 'none'}"
                                                + (" (new secret)" if secret else "")))
    return {**saved, "value": record}


def public(row: dict | None) -> dict:
    """The setting as the dashboard reads it: which secret exists, never the secret."""
    if not row:
        return {"configured": False, "revision": 0, "idp": None, "aws": None,
                "secret_saved": False}
    value = row["value"]
    return {"configured": True, "revision": revision_of(row), "idp": value.get("idp"), "aws": value.get("aws"),
            "secret_saved": bool(value.get("secret")), "updated_by": row.get("updated_by"),
            "updated_at": row["updated_at"].isoformat() if isinstance(row.get("updated_at"), _dt.datetime) else row.get("updated_at")}


def claims(token: str) -> dict:
    """The non-secret claims of a JWT (issuer, subject, audience, expiry); nothing for an opaque token.

    Read to name the token in setup steps, never to trust it: the clouds verify the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    out = {}
    for key in ("iss", "sub"):
        if isinstance(payload.get(key), str) and len(payload[key]) <= 512:
            out[key] = payload[key]
    aud = payload.get("aud")
    if isinstance(aud, str) and len(aud) <= 512:
        out["aud"] = aud
    elif isinstance(aud, list) and aud and all(isinstance(item, str) and len(item) <= 512 for item in aud[:8]):
        out["aud"] = aud[:8]
    if isinstance(payload.get("exp"), int):
        out["exp"] = payload["exp"]
    return out


def environment(record: dict, directory: Path) -> dict[str, str | None]:
    """What each enabled cloud's SDK is pointed at (None clears a variable that would win over it)."""
    env: dict[str, str | None] = {}
    if record.get("aws", {}).get("enabled"):
        env.update({"AWS_ROLE_ARN": record["aws"]["role_arn"], "AWS_WEB_IDENTITY_TOKEN_FILE": str(directory / "aws"),
                    "AWS_ROLE_SESSION_NAME": "cremore", "AWS_PROFILE": None, "AWS_ACCESS_KEY_ID": None,
                    "AWS_SECRET_ACCESS_KEY": None, "AWS_SESSION_TOKEN": None, "AWS_CONFIG_FILE": os.devnull,
                    "AWS_SHARED_CREDENTIALS_FILE": os.devnull, "AWS_EC2_METADATA_DISABLED": "true",
                    "AWS_ROLES_ANYWHERE_CONFIG": None})
    return env


def default_directory() -> Path:
    return Path(os.environ.get("CREMORE_MACHINE_IDENTITY_DIR") or Path(tempfile.gettempdir()) / "cremore-identity")


class Keeper:
    """Keeps the configured tokens current in this process and points the SDKs at them."""

    def __init__(self, repo, settings, process: str, *, directory: Path | None = None, client=None, environ=None) -> None:
        self.repo, self.settings, self.process = repo, settings, process
        self.directory = directory or default_directory()
        self.client = client
        self.environ = os.environ if environ is None else environ
        # This process's own values, given back when a cloud is turned off.
        self.original = {key: self.environ.get(key) for key in ENV_KEYS}
        self.revision: int | None = None
        self.tokens: list[Token] = []
        self.targets: dict[str, str] = {}
        self.applied: set[str] = set()
        self.reported, self.reported_at = "", 0.0
        self.config: dict | None = None
        self.error: str | None = None
        self.reset_pending = False

    def _secret(self, record: dict):
        from cremore.secretstore.sealed import unseal

        ref = record.get("secret")
        if getattr(self.settings, "isolated_deployment", False) or str(ref).startswith("sealed:v3:"):
            if self.process.split(":", 1)[0] not in {"worker", "collector", "test"}:
                raise MachineIdentityError("MACHINE_IDENTITY_COLLECTOR_ONLY")
            return lambda: unseal(self.settings.credential_sealing_keys, ref,
                                  binding=machine_binding(record)).get("client_secret", "") if ref else ""
        return lambda: (unseal(self.settings.sealing_keys, ref).get("client_secret", "") if ref else "")

    def _load(self, row: dict | None) -> None:
        """Rebuild the tokens when an Admin saved a new revision."""
        record = dict(row["value"]) if row else None
        self.config, self.tokens, self.targets, self.error = record, [], {}, None
        if not in_use(record):
            return
        secret = self._secret(record)
        idp = record["idp"]
        try:
            for cloud in CLOUDS:
                binding = record[cloud]
                if binding.get("enabled"):
                    self.tokens.append(Token(cloud, _grant(idp, secret, scope=binding.get("scope"), audience=binding.get("audience")),
                                             self.directory))
                    self.targets[cloud] = cloud
        except ValueError:
            self.tokens, self.targets, self.error = [], {}, "MACHINE_IDENTITY_INVALID"

    def _apply_env(self, *, blocked=False) -> None:
        """Bind configured identities before any file/network I/O; never fall back."""
        record = self.config or {}
        # A configured identity must fail closed while its first token is pending.
        # Falling back to the host's unrelated ADC/instance/key identity could
        # collect from a different tenant after a restart or IdP outage.
        wanted = environment(record, self.directory)
        if blocked:
            for key in ("AWS_WEB_IDENTITY_TOKEN_FILE",):
                if key in wanted:
                    wanted[key] = os.devnull
        for key in ENV_KEYS:
            if key in wanted:
                value = wanted[key]
                if value is None:
                    self.environ.pop(key, None)
                else:
                    self.environ[key] = value
            elif key in self.applied:
                if self.original.get(key) is None:
                    self.environ.pop(key, None)
                else:
                    self.environ[key] = self.original[key]
        self.applied = set(wanted)
    def _status(self, now: float) -> dict:
        out = {}
        for token in self.tokens:
            entry = {"state": "READY" if token.expires and not token.failures else "FAILED" if token.failures else "PENDING",
                     "code": token.last_code or None}
            if token.expires:
                entry["expires_in"] = max(0, int(token.expires - now))
                path = (token.directory or self.directory) / token.name
                try:
                    entry["claims"] = claims(path.read_text(encoding="ascii", errors="replace"))
                except OSError:
                    entry["claims"] = {}
            out[self.targets[token.name]] = entry
        return out

    def _report(self, now: float) -> None:
        status = self._status(now)
        body = {"process": self.process, "revision": self.revision, "error": self.error, "tokens": status}
        # Written when something changed, and at least every ten minutes so a stopped process shows its age.
        stable = json.dumps({"revision": self.revision, "error": self.error,
                             "tokens": {k: {"state": v["state"], "code": v["code"]} for k, v in status.items()}}, sort_keys=True)
        if stable != self.reported or now - self.reported_at > 600:
            self.repo.put_setting(STATUS_PREFIX + self.process, {**body, "reported_at": _now().isoformat()}, ACTOR)
            # A process that stopped a week ago (a worker is a new id each start) no longer reports.
            self.repo.delete_settings_before(STATUS_PREFIX, _now() - _dt.timedelta(days=7))
            self.reported, self.reported_at = stable, now

    def tick(self, now: float | None = None) -> float:
        """One pass: reload a changed setting, refresh what is due, point the SDKs, report. Returns the wait."""
        now = time.monotonic() if now is None else now
        row = self.repo.get_setting(KEY)
        revision = revision_of(row)
        if revision != self.revision:
            self.revision = revision
            self._load(row)
            self.reset_pending = True
        if self.reset_pending:
            self._apply_env(blocked=True)
            # Do not reuse a file minted for a prior configuration when the
            # newly selected IdP is unavailable. These are our auth files only.
            from cremore.cli.token_refresher import write_token

            try:
                for token in self.tokens:
                    write_token(token.directory or self.directory, token.name, "")
            except OSError:
                self.error = "TOKEN_WRITE_FAILED"
                self._report(now)
                return 5.0
            self.reset_pending = False
            if self.error == "TOKEN_WRITE_FAILED":
                self.error = None
        self._apply_env()
        wait = 60.0
        if self.tokens:
            owned = self.client is None
            client = self.client or httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False)
            try:
                wait = min(wait, refresh_due(self.tokens, self.directory, client, now=now))
            finally:
                if owned:
                    client.close()
        self._apply_env()
        try:
            self._report(now)
        except Exception as exc:  # noqa: BLE001 -- a status write never stops the tokens
            logger.warning("machine identity status not recorded: %s", type(exc).__name__)
        return max(1.0, wait)

    def test(self) -> dict:
        """Fetch every configured token once now (the API process), reporting claims and codes, never a token."""
        row = self.repo.get_setting(KEY)
        record = dict(row["value"]) if row else None
        if not in_use(record):
            raise MachineIdentityError("MACHINE_IDENTITY_NOT_CONFIGURED")
        secret = self._secret(record)
        idp = record["idp"]
        wanted = [(cloud, record[cloud]) for cloud in CLOUDS if record[cloud].get("enabled")]
        out = {}
        owned = self.client is None
        client = self.client or httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False)
        try:
            for name, binding in wanted:
                try:
                    token, lifetime = _grant(idp, secret, scope=binding.get("scope"), audience=binding.get("audience")).fetch(client)
                except ValueError as exc:
                    out[name] = {"state": "FAILED", "code": str(exc).split(":")[0]}
                    continue
                out[name] = {"state": "READY", "code": None, "expires_in": lifetime, "claims": claims(token)}
        finally:
            if owned:
                client.close()
        return out

    def run(self, stop: threading.Event | None = None) -> None:  # pragma: no cover -- exercised through tick
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                wait = self.tick()
            except Exception as exc:  # noqa: BLE001 -- the next pass tries again
                logger.warning("machine identity pass failed: %s", type(exc).__name__)
                wait = 30.0
            stop.wait(min(wait, 30.0))


def start_keeper(repo, settings, process: str) -> threading.Thread:  # pragma: no cover -- process wiring
    """Run the keeper beside the API or worker; it idles until an Admin configures an identity."""
    if getattr(settings, "isolated_deployment", False) and (
            process.split(":", 1)[0] not in {"worker", "collector"} or settings.worker_execution_role != "collector"):
        raise MachineIdentityError("MACHINE_IDENTITY_COLLECTOR_ONLY")
    keeper = Keeper(repo, settings, process)
    try:
        keeper.tick()  # the SDKs see the identity before the first request or job
    except Exception as exc:  # noqa: BLE001 -- the loop tries again
        logger.warning("machine identity first pass failed: %s", type(exc).__name__)
    thread = threading.Thread(target=keeper.run, name="machine-identity", daemon=True)
    thread.start()
    return thread


def setup_steps(record: dict | None, observed: dict, partition_policy: dict | None = None) -> dict[str, str]:
    """For each enabled cloud, the commands that make it trust the IdP token, with the observed claims filled in."""
    if not record:
        return {}
    out: dict[str, str] = {}

    def claim(name: str, key: str, fallback: str) -> str:
        value = (observed.get(name) or {}).get("claims", {}).get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        return str(value) if value else fallback

    if record.get("aws", {}).get("enabled"):
        iss, aud, sub = claim("aws", "iss", "<issuer>"), claim("aws", "aud", "<audience>"), claim("aws", "sub", "<subject>")
        host = iss.removeprefix("https://")
        role = record["aws"]["role_arn"]
        account = role.split(":")[4]
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                 "Principal": {"Federated": f"arn:aws:iam::{account}:oidc-provider/{host}"},
                 "Action": "sts:AssumeRoleWithWebIdentity",
                 "Condition": {"StringEquals": {f"{host}:aud": aud, f"{host}:sub": sub}}}]}
        name = role.rsplit("/", 1)[-1]
        path = role.split(":role/", 1)[1].removesuffix(name)
        lines = [f"aws iam create-open-id-connect-provider --url {iss} --client-id-list {aud}",
                 f"aws iam create-role --role-name {name}{' --path /' + path if path else ''} --assume-role-policy-document '{json.dumps(trust)}'"]
        policy = {"Version": "2012-10-17", "Statement": [*(partition_policy or {}).get("Statement", []),
                  {"Effect": "Allow", "Action": "iam:GetRole", "Resource": role}]}
        lines.append(f"aws iam put-role-policy --role-name {name} --policy-name CreMoreScanner "
                     f"--policy-document '{json.dumps(policy)}'")
        out["aws"] = "\n".join(lines)
    return out
