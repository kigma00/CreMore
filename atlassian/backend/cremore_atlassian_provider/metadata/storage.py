# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/storage.py).
"""Atomic local metadata output; private directory and owner-only files."""

import hashlib
import os
import re
import stat
import uuid

from .jsonio import read_json, write_json


def private_artifact(directory, filename):
    """Open and validate the exact file descriptor used by the consumer."""
    if not isinstance(filename, str) or not re.fullmatch(
        r"(?:inventory|diagnostic|recollection-part)-[0-9a-f]{32}\.json", filename
    ):
        raise ValueError("Invalid output reference")
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory_fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError("Invalid private directory")
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        handle = os.fdopen(fd, "rb")
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid()
        ):
            handle.close()
            raise ValueError("Invalid private artifact")
        return handle
    finally:
        os.close(directory_fd)


def load_private(directory, filename):
    with private_artifact(directory, filename) as handle:
        return read_json(handle)


def output_digest(directory, filename):
    """Hash a published private artifact without loading its metadata into memory."""
    with private_artifact(directory, filename) as handle:
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_private(directory, result, *, prefix="inventory"):
    if prefix not in (
        "inventory",
        "comparison",
        "manifest",
        "recollection",
        "recollection-part",
        "diagnostic",
    ):
        raise ValueError("Unsupported output type")
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp_name = "." + prefix + "-" + uuid.uuid4().hex + ".tmp"
    name = prefix + "-" + uuid.uuid4().hex + ".json"
    created = False
    try:
        info = os.fstat(directory_fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError("Output directory must be private and owned by the current user")
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        with os.fdopen(fd, "wb") as handle:
            write_json(handle, result)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is atomic and cannot replace an existing file.
        os.link(
            temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False
        )
        os.fsync(directory_fd)
        return name
    finally:
        try:
            if created:
                os.unlink(temp_name, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
