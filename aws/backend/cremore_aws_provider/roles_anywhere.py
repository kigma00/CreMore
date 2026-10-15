"""Bounded credential_process bridge to an operator-pinned AWS signing helper.

Only the SDK receives temporary credentials on stdout. Configuration, certificates
and keys belong to deployment administrators, never a dashboard request. Nothing
from the helper's output or stderr is logged or persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

CONFIG_ENV = "AWS_ROLES_ANYWHERE_CONFIG"
SOURCE = "roles-anywhere"
MAX_OUTPUT = 32768
TIMEOUT = 30
_ARN = re.compile(r"arn:(aws(?:-[a-z]+)*):rolesanywhere:([a-z0-9-]+):(\d{12}):(trust-anchor|profile)/([a-f0-9-]{36})\Z")
_ROLE = re.compile(r"arn:(aws(?:-[a-z]+)*):iam::(\d{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")


class RolesAnywhereError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _file(path, *, private=False):
    if not isinstance(path, str) or not Path(path).is_absolute() or any(ord(c) < 32 for c in path):
        raise RolesAnywhereError("AWS_ROLES_ANYWHERE_PATH_INVALID")
    result = Path(path).resolve(strict=True)
    info = result.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RolesAnywhereError("AWS_ROLES_ANYWHERE_FILE_INVALID")
    if os.name == "posix" and (info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022
                               or private and info.st_mode & 0o007):
        raise RolesAnywhereError("AWS_ROLES_ANYWHERE_FILE_PERMISSIONS")
    return result


def load(path):
    """Re-read mounted files on each renewal, including Kubernetes Secret rotation."""
    try:
        config_path = _file(path)
        with config_path.open("rb") as handle:
            raw = handle.read(16385)
        if len(raw) > 16384:
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_CONFIG_INVALID")
        config = json.loads(raw)
        fields = {"helper", "helper_sha256", "certificate", "private_key", "trust_anchor_arn", "profile_arn", "role_arn"}
        if not isinstance(config, dict) or set(config) != fields:
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_CONFIG_INVALID")
        anchor, profile, role = (_ARN.fullmatch(config["trust_anchor_arn"]),
                                 _ARN.fullmatch(config["profile_arn"]), _ROLE.fullmatch(config["role_arn"]))
        if (not anchor or not profile or not role or anchor[4] != "trust-anchor" or profile[4] != "profile"
                or anchor.groups()[:3] != profile.groups()[:3] or (role[1], role[2]) != (anchor[1], anchor[3])):
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_TARGET_INVALID")
        helper = _file(config["helper"])
        digest = config["helper_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or helper.stat().st_size > 256 << 20:
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_INVALID")
        with helper.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != digest:
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_CHANGED")
        certificate = _file(config["certificate"])
        key = _file(config["private_key"], private=True)
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        with certificate.open("rb") as handle:
            cert_bytes = handle.read(65537)
        with key.open("rb") as handle:
            key_bytes = handle.read(65537)
        if max(len(cert_bytes), len(key_bytes)) > 65536:
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_CERTIFICATE_INVALID")
        cert = x509.load_pem_x509_certificate(cert_bytes)
        private = serialization.load_pem_private_key(key_bytes, password=None)
        public_args = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if private.public_key().public_bytes(*public_args) != cert.public_key().public_bytes(*public_args):
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_KEY_MISMATCH")
        now = datetime.now(UTC)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise RolesAnywhereError("AWS_ROLES_ANYWHERE_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID")
        # Use original mount paths so atomic certificate rotation is picked up.
        args = [str(helper), "credential-process", "--certificate", config["certificate"],
                "--private-key", config["private_key"], "--trust-anchor-arn", config["trust_anchor_arn"],
                "--profile-arn", config["profile_arn"], "--role-arn", config["role_arn"],
                "--region", anchor[2], "--session-duration", "3600"]
        return args, cert.not_valid_after_utc
    except RolesAnywhereError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise RolesAnywhereError("AWS_ROLES_ANYWHERE_CONFIG_INVALID") from None


def _run(args):
    """No shell, stdin or stderr propagation; bounded time and stdout in memory."""
    try:
        with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              shell=False, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) as process:
            output = []

            def read():
                value = process.stdout.read(MAX_OUTPUT + 1)
                output.append(value)
                if len(value) > MAX_OUTPUT:
                    process.kill()

            reader = threading.Thread(target=read, daemon=True)
            reader.start()
            try:
                process.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_TIMEOUT") from None
            finally:
                reader.join(timeout=1)
            if not output or len(output[0]) > MAX_OUTPUT:
                raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_OUTPUT_INVALID")
            if process.returncode:
                raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_FAILED")
            return output[0]
    except OSError:
        raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_UNAVAILABLE") from None


def credentials(path):
    args, _expires = load(path)
    try:
        result = json.loads(_run(args))
        if not isinstance(result, dict) or result.get("Version") != 1:
            raise ValueError
        out = {name: result[name] for name in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")}
        if any(not isinstance(value, str) or not value or len(value) > 16384
               or any(ord(c) < 33 or ord(c) > 126 for c in value) for value in out.values()):
            raise ValueError
        expiration = datetime.fromisoformat(out["Expiration"])
        if expiration.tzinfo is None or not datetime.now(UTC) + timedelta(seconds=60) < expiration <= datetime.now(UTC) + timedelta(hours=12):
            raise ValueError
        return {"Version": 1, **out}
    except RolesAnywhereError:
        raise
    except (ValueError, TypeError, KeyError):
        raise RolesAnywhereError("AWS_ROLES_ANYWHERE_HELPER_OUTPUT_INVALID") from None


def trusted_process(command):
    """Recognize our fixed bridge, not arbitrary programs with temporary output."""
    path = os.environ.get(CONFIG_ENV)
    if not path or not isinstance(command, str):
        return False
    try:
        from botocore.compat import compat_shell_split

        args = compat_shell_split(command)
        expected = ["-m", "cremore_aws_provider.roles_anywhere", "--config", path]
        interpreter = bool(args) and Path(args[0]).is_absolute() and os.path.normcase(os.path.realpath(args[0])) == os.path.normcase(os.path.realpath(sys.executable))
        return interpreter and args[1:] == expected and bool(load(path))
    except (ValueError, OSError):
        return False


def diagnostic(identity=None):
    path = os.environ.get(CONFIG_ENV)
    if not path:
        return None
    try:
        _, expires = load(path)
        if identity and identity.get("state") in {"ERROR", "LOGIN_REQUIRED", "NO_CREDENTIALS"}:
            return {"state": "ERROR", "error_code": "AWS_ROLES_ANYWHERE_RENEWAL_FAILED",
                    "certificate_expires_at": expires.isoformat()}
        return {"state": "EXPIRING" if expires < datetime.now(UTC) + timedelta(days=30) else "READY",
                "certificate_expires_at": expires.isoformat(), "renewal": "SDK_CREDENTIAL_PROCESS"}
    except RolesAnywhereError as exc:
        return {"state": "ERROR", "error_code": exc.code}


def main(argv=None):
    parser = argparse.ArgumentParser(description="CreMore Roles Anywhere credential_process bridge")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        value = credentials(args.config)
    except RolesAnywhereError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    print(json.dumps(value, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
