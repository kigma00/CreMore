"""Compatibility import for the original setup/diagnostic commands."""

if not __package__:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cremore_atlassian_provider.metadata.connections import connection_filename, profile_argument

__all__ = ["connection_filename", "profile_argument"]
