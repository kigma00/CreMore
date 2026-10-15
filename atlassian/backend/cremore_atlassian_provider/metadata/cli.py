# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/cli.py).
"""Run the Cloud metadata collector using an existing private connection."""

import argparse
import json
from pathlib import Path

from .collector import collect, safe_summary
from .connections import load_cloud as load_connection
from .connections import profile_argument
from .discovery import collect_accounts, collect_discovery, discovery_summary
from .http import CloudClient, Limits
from .specs import DEFAULT_SOURCES, SOURCES
from .storage import save_private


def main(argv=None, *, directory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        type=profile_argument,
        help="Explicit connection profile; never falls back to another organization.",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--sources",
        nargs="+",
        choices=SOURCES,
        help="Default: keys and API tokens. OAuth sources are opt-in.",
    )
    modes.add_argument(
        "--discovery",
        action="store_true",
        help="Collect broad provider metadata with bounded detail/count/account reads.",
    )
    modes.add_argument(
        "--accounts",
        action="store_true",
        help="Read only managed accounts, permissions, profiles and tokens; requires an explicit profile.",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=50,
        help="Discovery fan-out bound per account/client type (1-500).",
    )
    parser.add_argument(
        "--skip-account-reads",
        action="store_true",
        help="Discovery only: explicitly delegate managed-account/profile/token reads to a separate --accounts profile.",
    )
    parser.add_argument(
        "--token-page-size",
        type=int,
        help="Discovery mode only: organization API token page size (1-1000; default 20).",
    )
    for option in ("max_pages", "max_records", "max_requests", "retries"):
        parser.add_argument(
            "--" + option.replace("_", "-"), type=int, default=getattr(Limits(), option)
        )
    for option in ("max_seconds", "timeout", "max_retry_wait"):
        parser.add_argument(
            "--" + option.replace("_", "-"), type=float, default=getattr(Limits(), option)
        )
    args = parser.parse_args(argv)
    sources = args.sources if args.sources is not None else list(DEFAULT_SOURCES)
    directory = directory if directory is not None else Path.cwd() / ".local"
    try:
        limits = Limits(**{name: getattr(args, name) for name in Limits.__dataclass_fields__})
        if len(sources) != len(set(sources)):
            raise ValueError("Duplicate sources")
        if args.accounts and args.profile is None:
            raise ValueError("Account discovery requires an explicit connection profile")
        if args.skip_account_reads and not args.discovery:
            raise ValueError("Account read selection requires discovery mode")
        if not 1 <= args.max_targets <= 500:
            raise ValueError("Invalid target limit")
        if args.token_page_size is not None and (
            not args.discovery or not 1 <= args.token_page_size <= 1000
        ):
            raise ValueError("Token page size requires discovery mode and a value from 1 to 1000")
        org_id, key = load_connection(directory, args.profile)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.exit(2, "Invalid limits or private connection. No request made.\n")
    try:
        client = CloudClient(
            org_id,
            key,
            limits,
            **(
                {"token_page_size": args.token_page_size}
                if args.token_page_size is not None
                else {}
            ),
        )
        if args.accounts:
            result = collect_accounts(client, max_targets=args.max_targets)
        elif args.discovery:
            result = collect_discovery(
                client,
                max_targets=args.max_targets,
                include_account_reads=not args.skip_account_reads,
            )
        else:
            result = collect(client, sources)
        result["connection_profile"] = args.profile
        filename = save_private(directory, result)
        summary = (
            discovery_summary(result) if args.discovery or args.accounts else safe_summary(result)
        )
        summary["output_file"] = ".local/" + filename
        print(json.dumps(summary, indent=2))
    except KeyboardInterrupt:
        parser.exit(130, "Collection interrupted; no completion claim.\n")
    except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
        parser.exit(
            2, "Collection or private output failed. No completion claim; details suppressed.\n"
        )
    return 0 if result["run_status"] == "complete" else 1
