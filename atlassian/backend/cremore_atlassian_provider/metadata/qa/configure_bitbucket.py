"""Save one Bitbucket workspace connection using hidden interactive input."""

import argparse
import getpass
import sys
import warnings
from pathlib import Path

if __package__:
    from .bitbucket_connection import profile_argument, save_connection, valid_workspace
else:
    from bitbucket_connection import profile_argument, save_connection, valid_workspace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=profile_argument)
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()
    if not sys.stdin.isatty() or not valid_workspace(args.workspace):
        parser.exit(2, "Use an interactive terminal and a valid workspace ID.\n")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = getpass.getpass("Bitbucket scoped API token (hidden input): ")
        name = save_connection(Path.cwd() / ".local", args.profile, args.workspace, token)
    except (EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        parser.exit(2, "\nInput cancelled or hidden input unavailable.\n")
    except (ValueError, OSError):
        parser.exit(2, "Connection not saved; existing files were not replaced.\n")
    print("Saved .local/" + name + " (owner-only; ignored by Git). No request made.")


if __name__ == "__main__":
    main()
