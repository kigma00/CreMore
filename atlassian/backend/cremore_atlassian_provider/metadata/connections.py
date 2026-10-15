# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/connections.py).
"""Private named connections, shared by the package and setup commands."""

import errno
import json
import os
import re
import stat
import uuid
from pathlib import Path

from .jsonio import loads


def connection_filename(profile=None):
    if profile is None:
        return "connection.json"
    profile_argument(profile)
    return "connection-" + profile + ".json"


def profile_argument(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value):
        raise ValueError("Invalid connection profile")
    return value


def valid_workspace(value):
    return isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", value) is not None


def filename(profile):
    return "bitbucket-" + profile_argument(profile) + ".json"


def validate_token(token):
    if (
        not isinstance(token, str)
        or not 1 <= len(token) <= 16384
        or not token.isascii()
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in token)
    ):
        raise ValueError("Invalid authentication configuration")


def validate(workspace, token):
    if not valid_workspace(workspace):
        raise ValueError("Invalid workspace")
    validate_token(token)


def _directory_fd(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        os.close(fd)
        raise ValueError("Expected owner-only private directory")
    return fd


def check_directory(directory):
    os.close(_directory_fd(directory))


def _load(directory, name):
    directory_fd = _directory_fd(directory)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ValueError("Invalid private connection file") from None
            raise
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid()
                or info.st_size > 65536
            ):
                raise ValueError("Invalid private connection file")
            raw = handle.read(65537)
            if len(raw) > 65536:
                raise ValueError("Invalid private connection file")
            return loads(raw)
    finally:
        os.close(directory_fd)


def load_cloud(directory, profile=None):
    config = _load(directory, connection_filename(profile))
    org_id = str(uuid.UUID(config["org_id"]))
    validate_token(config["api_key"])
    return org_id, config["api_key"]


def load_bitbucket(directory, profile):
    try:
        config = _load(directory, filename(profile))
    except FileNotFoundError:
        raise ValueError("Missing Bitbucket connection") from None
    if config.get("provider") != "bitbucket":
        raise ValueError("Wrong provider connection")
    validate(config["workspace"], config["api_token"])
    return config["workspace"], config["api_token"]


def _save(directory, name, value):
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    directory_fd = _directory_fd(directory)
    temporary = ".connection-" + uuid.uuid4().hex + ".tmp"
    created = False
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(
            temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False
        )
        os.fsync(directory_fd)
        return name
    finally:
        try:
            if created:
                os.unlink(temporary, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)


def save_connection(directory, profile, workspace, token):
    validate(workspace, token)
    return _save(
        directory,
        filename(profile),
        {"provider": "bitbucket", "workspace": workspace, "api_token": token},
    )


def save_cloud(directory, profile, org_id, key):
    validate_token(key)
    return _save(
        directory,
        connection_filename(profile),
        {"org_id": str(uuid.UUID(str(org_id))), "api_key": key},
    )
