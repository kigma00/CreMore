"""Compatibility import for existing Bitbucket setup commands."""

if not __package__:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cremore_atlassian_provider.metadata.connections import (
    check_directory,
    filename,
    profile_argument,
    save_connection,
    valid_workspace,
    validate,
)
from cremore_atlassian_provider.metadata.connections import (
    load_bitbucket as load_connection,
)

__all__ = [
    "check_directory",
    "filename",
    "load_connection",
    "profile_argument",
    "save_connection",
    "valid_workspace",
    "validate",
]
