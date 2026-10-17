"""Keep workload identity tokens current outside Kubernetes.

On Kubernetes the kubelet refreshes projected service-account tokens. On one
server (Docker Compose) nothing does, so this process takes an OAuth 2.0
client-credentials token from the organization's IdP and keeps it in a file
that the AWS SDK reads through ``AWS_WEB_IDENTITY_TOKEN_FILE``.

Configuration is a JSON file; secrets are environment variable names or file
paths, never values. Each token is written atomically (a temporary file renamed
over the old one, mode 0600) and refreshed at half its lifetime. A failed
refresh keeps the previous token until it would have expired and retries with a
growing delay. Logs name the token and a fixed code, never a token or secret.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from cremore.oauth_client import ClientCredentialsGrant

logger = logging.getLogger("cremore.token_refresher")
_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\Z")
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_FIELDS = {"name", "directory", "token_url", "client_id", "client_secret_env", "client_secret_file", "scope",
           "audience", "auth_method", "token_field"}
MAX_CONFIG_BYTES = 64 << 10


@dataclass
class Token:
    name: str
    grant: ClientCredentialsGrant
    # Tokens for different audiences live in different directories, so a Vault
    # connection pointed at its directory can never name a cloud token.
    directory: Path | None = None
    due: float = 0.0
    expires: float = 0.0
    failures: int = 0
    last_code: str = field(default="")


def _secret_source(item: dict):
    env, path = item.get("client_secret_env"), item.get("client_secret_file")
    if bool(env) == bool(path):
        raise ValueError("REFRESHER_SECRET_SOURCE_INVALID")
    if env:
        if not isinstance(env, str) or not _ENV.fullmatch(env):
            raise ValueError("REFRESHER_SECRET_SOURCE_INVALID")
        return lambda: os.environ.get(env, "")
    if not isinstance(path, str) or not path or any(ord(c) < 32 for c in path):
        raise ValueError("REFRESHER_SECRET_SOURCE_INVALID")

    def read():
        # Read on every refresh, so a rotated secret file needs no restart.
        try:
            with open(path, "rb") as handle:
                raw = handle.read(8193)
        except OSError:
            return ""
        return raw.decode("ascii", errors="replace").strip() if len(raw) <= 8192 else ""
    return read


def load_config(path: str) -> tuple[Path, list[Token]]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError
        config = json.loads(raw)
    except (OSError, ValueError):
        raise ValueError("REFRESHER_CONFIG_INVALID") from None
    if not isinstance(config, dict) or set(config) - {"directory", "tokens"}:
        raise ValueError("REFRESHER_CONFIG_INVALID")
    directory = config.get("directory")
    items = config.get("tokens")
    if not isinstance(directory, str) or not directory or not isinstance(items, list) or not 1 <= len(items) <= 32:
        raise ValueError("REFRESHER_CONFIG_INVALID")
    tokens, names = [], set()
    for item in items:
        if not isinstance(item, dict) or set(item) - _FIELDS or not isinstance(item.get("name"), str) \
                or not _NAME.fullmatch(item["name"]) or item["name"] in names:
            raise ValueError("REFRESHER_CONFIG_INVALID")
        names.add(item["name"])
        try:
            grant = ClientCredentialsGrant(token_url=item.get("token_url"), client_id=item.get("client_id"),
                                           client_secret=_secret_source(item), scope=item.get("scope"),
                                           audience=item.get("audience"),
                                           auth_method=item.get("auth_method", "client_secret_post"),
                                           token_field=item.get("token_field", "access_token"))
        except ValueError as exc:
            raise ValueError("REFRESHER_CONFIG_INVALID: " + item["name"] + " " + str(exc)) from None
        own = item.get("directory")
        if own is not None and (not isinstance(own, str) or not own or any(ord(c) < 32 for c in own)):
            raise ValueError("REFRESHER_CONFIG_INVALID")
        tokens.append(Token(item["name"], grant, Path(own) if own else None))
    return Path(directory), tokens


def write_token(directory: Path, name: str, value: str) -> None:
    """Replace the file in one step, so a reader never sees half a token."""
    directory.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file readable and writable by this user only (0600).
    handle, temporary = tempfile.mkstemp(prefix="." + name + ".", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="ascii") as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, directory / name)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def refresh_due(tokens: list[Token], directory: Path, client, *, now: float) -> float:
    """Refresh every due token; return seconds until the next one is due."""
    for token in tokens:
        if now < token.due:
            continue
        try:
            value, lifetime = token.grant.fetch(client)
            write_token(token.directory or directory, token.name, value)
        except ValueError as exc:
            token.failures += 1
            token.last_code = str(exc).split(":")[0]
            # Back off, but try again before the file on disk runs out.
            delay = min(300.0, 5.0 * 2 ** min(token.failures - 1, 6))
            if token.expires > now:
                delay = max(1.0, min(delay, token.expires - now - 1))
            token.due = now + delay
            logger.warning("TOKEN_REFRESH_FAILED name=%s code=%s failures=%d", token.name, token.last_code, token.failures)
            continue
        except OSError:
            token.failures += 1
            token.last_code = "TOKEN_WRITE_FAILED"
            token.due = now + 5.0
            logger.warning("TOKEN_REFRESH_FAILED name=%s code=TOKEN_WRITE_FAILED", token.name)
            continue
        token.failures, token.last_code = 0, ""
        token.expires = now + lifetime
        token.due = now + max(1.0, lifetime / 2)
        logger.info("TOKEN_REFRESHED name=%s lifetime=%d", token.name, lifetime)
    return max(1.0, min(token.due for token in tokens) - now)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Keep workload identity tokens current in files outside Kubernetes.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true", help="refresh every token once, then exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        directory, tokens = load_config(args.config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    heartbeat = os.environ.get("CREMORE_REFRESHER_HEARTBEAT_FILE", "/tmp/cremore-token-refresher.heartbeat")
    with httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False) as client:
        while True:
            wait = refresh_due(tokens, directory, client, now=time.monotonic())
            if args.once:
                return 0 if all(token.failures == 0 for token in tokens) else 2
            try:
                Path(heartbeat).touch()
            except OSError:
                pass
            time.sleep(min(wait, 30.0))


if __name__ == "__main__":
    sys.exit(main())
