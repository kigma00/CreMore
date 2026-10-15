"""Save a lab connection locally without echoing the API key or making requests."""

import argparse
import getpass
import sys
import uuid
import warnings
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cremore_atlassian_provider.metadata.connections import (
    connection_filename,
    profile_argument,
    save_cloud,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org-id", required=True, type=uuid.UUID)
    parser.add_argument(
        "--profile",
        type=profile_argument,
        help="Explicit local connection name; omission keeps the original connection.",
    )
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.exit(2, "Run this command in an interactive terminal.\n")

    directory = Path.cwd() / ".local"
    if directory.is_symlink():
        parser.exit(2, "Refusing a symlink for the local connection directory.\n")
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / connection_filename(args.profile)
    if destination.exists() or destination.is_symlink():
        parser.exit(2, "A local connection already exists; it was not changed.\n")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            api_key = getpass.getpass("Atlassian admin API key (hidden input): ")
        if (
            not api_key
            or not api_key.isascii()
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in api_key)
        ):
            parser.exit(2, "Expected one non-empty API key without whitespace.\n")
        save_cloud(directory, args.profile, args.org_id, api_key)
    except (EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        parser.exit(2, "\nInput cancelled or hidden input unavailable.\n")
    except (OSError, ValueError):
        parser.exit(2, "Could not save the local connection.\n")
    print("Saved .local/" + destination.name + " (owner-only access; ignored by Git).")
    print("No API request was made. Do not upload this file.")


if __name__ == "__main__":
    main()
