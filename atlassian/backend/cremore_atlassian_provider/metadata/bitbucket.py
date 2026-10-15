# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/bitbucket.py).
"""Bounded, metadata-only Bitbucket reads within one configured workspace."""

import argparse
import base64
import json
import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote, urlencode

from .connections import load_bitbucket as load_connection
from .connections import profile_argument, valid_workspace
from .discovery import collection_records, iter_operation
from .http import BearerReadClient, Limits
from .identities import BITBUCKET_IDS
from .jsonio import loads
from .metadata import utc_now
from .read_operations import validate_next_url
from .runner_pagination import RunnerIdentities
from .snapshot import REDACTED, metadata_snapshot
from .steps import consume
from .storage import save_private

ORIGIN = "https://api.bitbucket.org/2.0"
OPERATIONS = {
    "current-user": {"path": "/user", "shape": "object"},
    "workspace": {"path": "/workspaces/{workspace}", "shape": "object"},
    "workspace-gpg-key": {
        "path": "/workspaces/{workspace}/settings/gpg/public-key",
        "shape": "public_key_bundle",
        "pager": "top_url",
    },
    "workspace-oidc-configuration": {
        "path": "/workspaces/{workspace}/pipelines-config/identity/oidc/.well-known/openid-configuration",
        "shape": "object",
        "public": True,
    },
    "workspace-oidc-keys": {
        "path": "/workspaces/{workspace}/pipelines-config/identity/oidc/keys.json",
        "shape": "jwks",
        "public": True,
    },
    "workspace-members": {"path": "/workspaces/{workspace}/members", "shape": "values"},
    "projects": {"path": "/workspaces/{workspace}/projects", "shape": "values"},
    "repositories": {"path": "/repositories/{workspace}", "shape": "values"},
    "user-profile": {"path": "/users/{target}", "shape": "object"},
    "user-ssh-keys": {"path": "/users/{target}/ssh-keys", "shape": "values"},
    "user-ssh-key-detail": {"path": "/users/{target}/ssh-keys/{key_id}", "shape": "object"},
    "user-gpg-keys": {
        "path": "/users/{target}/gpg-keys",
        "shape": "values",
        "query": {"fields": "+values.key,+values.subkeys"},
    },
    "user-gpg-key-detail": {
        "path": "/users/{target}/gpg-keys/{key_id}",
        "shape": "object",
        "query": {"fields": "+key,+subkeys"},
    },
    "project-detail": {"path": "/workspaces/{workspace}/projects/{target}", "shape": "object"},
    "project-deploy-keys": {
        "path": "/workspaces/{workspace}/projects/{target}/deploy-keys",
        "shape": "values",
    },
    "project-deploy-key-detail": {
        "path": "/workspaces/{workspace}/projects/{target}/deploy-keys/{key_id}",
        "shape": "object",
    },
    "repository-detail": {"path": "/repositories/{workspace}/{target}", "shape": "object"},
    "repository-deploy-keys": {
        "path": "/repositories/{workspace}/{target}/deploy-keys",
        "shape": "values",
    },
    "repository-deploy-key-detail": {
        "path": "/repositories/{workspace}/{target}/deploy-keys/{key_id}",
        "shape": "object",
    },
    "pipeline-ssh-key": {
        "path": "/repositories/{workspace}/{target}/pipelines_config/ssh/key_pair",
        "shape": "object",
    },
    "pipeline-known-hosts": {
        "path": "/repositories/{workspace}/{target}/pipelines_config/ssh/known_hosts",
        "shape": "values",
    },
    "pipeline-known-host-detail": {
        "path": "/repositories/{workspace}/{target}/pipelines_config/ssh/known_hosts/{key_id}",
        "shape": "object",
    },
    "workspace-runners": {
        "path": "/workspaces/{workspace}/pipelines-config/runners",
        "shape": "values",
    },
    "workspace-runner-detail": {
        "path": "/workspaces/{workspace}/pipelines-config/runners/{target}",
        "shape": "object",
    },
    "repository-runners": {
        "path": "/repositories/{workspace}/{target}/pipelines-config/runners",
        "shape": "values",
    },
    "repository-runner-detail": {
        "path": "/repositories/{workspace}/{target}/pipelines-config/runners/{key_id}",
        "shape": "object",
    },
    "repository-branch-restrictions": {
        "path": "/repositories/{workspace}/{target}/branch-restrictions",
        "shape": "values",
    },
    "repository-branch-restriction-detail": {
        "path": "/repositories/{workspace}/{target}/branch-restrictions/{key_id}",
        "shape": "object",
    },
}
RUNNER_OPERATIONS = (
    "workspace-runners",
    "workspace-runner-detail",
    "repository-runners",
    "repository-runner-detail",
)
for _operation, _fields in BITBUCKET_IDS.items():
    OPERATIONS[_operation]["identity_fields"] = _fields
BRANCH_OPERATIONS = ("repository-branch-restrictions", "repository-branch-restriction-detail")
CORE_OPERATIONS = tuple(op for op in OPERATIONS if op not in RUNNER_OPERATIONS + BRANCH_OPERATIONS)
for _spec in OPERATIONS.values():
    if _spec["shape"] == "values":
        _spec["pager"] = "top_url"
STATIC = (
    "current-user",
    "workspace",
    "workspace-members",
    "projects",
    "repositories",
    "workspace-gpg-key",
    "workspace-oidc-configuration",
    "workspace-oidc-keys",
)


def valid_target(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9{][A-Za-z0-9{}:_.-]{0,127}", value) is not None
    )


def public_ssh_key(value):
    """Recognize public SSH wire format, including its encoded algorithm name."""
    if not isinstance(value, str) or len(value) > 16384:
        return False
    parts = value.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        return False
    try:
        wire = base64.b64decode(parts[1], validate=True)
        size = int.from_bytes(wire[:4], "big")
        return 0 < size < len(wire) - 4 and wire[4 : 4 + size] == parts[0].encode("ascii")
    except (ValueError, UnicodeError):
        return False


def pipeline_public_ssh_key(record):
    """Known hosts return the public wire blob and algorithm in separate fields."""
    key, algorithm = record.get("key"), record.get("key_type")
    return (
        record.get("type") == "pipeline_ssh_public_key"
        and isinstance(key, str)
        and len(key) <= 16384
        and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", key) is not None
        and isinstance(algorithm, str)
        and re.fullmatch(r"[A-Za-z0-9@._+-]{1,128}", algorithm) is not None
        and public_ssh_key(algorithm + " " + key)
    )


def bitbucket_snapshot(body, token, *, sensitive_values=()):
    sensitive_values = (token, *sensitive_values)
    result, stats = metadata_snapshot(body, sensitive_values=sensitive_values)

    def restore_metadata(raw, saved):
        # The generic redactor omits `key`. Restore only recognized public SSH
        # material or the documented project key, never private/token values.
        if isinstance(raw, dict) and isinstance(saved, dict):
            key = raw.get("key")
            if (
                saved.get("key") == REDACTED
                and isinstance(key, str)
                and not any(value in key for value in sensitive_values)
                and "PRIVATE KEY" not in key
                and (
                    public_ssh_key(key)
                    or pipeline_public_ssh_key(raw)
                    or (
                        key.strip().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                        and key.strip().endswith("-----END PGP PUBLIC KEY BLOCK-----")
                    )
                    or (
                        raw.get("type") == "project" and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key)
                    )
                )
            ):
                saved["key"] = key
                stats["secret_fields_omitted"] -= 1
            for name, value in saved.items():
                if name in raw:
                    restore_metadata(raw[name], value)
        elif isinstance(raw, list) and isinstance(saved, list):
            for original, value in zip(raw, saved):
                restore_metadata(original, value)

    restore_metadata(body, result)
    return result, stats


class BitbucketClient(BearerReadClient):
    def __init__(
        self,
        workspace,
        token,
        limits=None,
        *,
        page_size=20,
        auth_type="bearer",
        email=None,
        **kwargs,
    ):
        if not valid_workspace(workspace):
            raise ValueError("Invalid workspace")
        if type(page_size) is not int or not 1 <= page_size <= 100:
            raise ValueError("Invalid Bitbucket page size")
        self.workspace = workspace
        # A bearer token is an access token (workspace, project or repository), not a user account: no /user.
        self.user_account = auth_type == "basic"
        self.page_size = page_size
        self.runner_identities = RunnerIdentities(workspace)
        self._last_list_urls = {}
        if auth_type not in ("bearer", "basic"):
            raise ValueError("Invalid Bitbucket authentication mode")
        if auth_type == "basic" and (
            not isinstance(email, str)
            or not email
            or len(email) > 320
            or ":" in email
            or "@" not in email
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in email
            )
        ):
            raise ValueError("Invalid Bitbucket authentication email")
        if auth_type == "bearer" and email is not None:
            raise ValueError("Email is only used by explicit Basic authentication")
        super().__init__(token, limits, **kwargs)
        self._basic = (
            base64.b64encode((email + ":" + token).encode()).decode()
            if auth_type == "basic"
            else None
        )

    def _authentication_header(self):
        return (
            "Basic " + self._basic if self._basic is not None else super()._authentication_header()
        )

    def snapshot(self, body):
        return bitbucket_snapshot(
            body, self._key, sensitive_values=(self._basic,) if self._basic else ()
        )

    def read_metadata(self, operation, *, identifier=None, body=None, cursor=None, next_url=None):
        spec = OPERATIONS[operation]
        if body is not None or cursor is not None:
            raise ValueError("Bitbucket metadata reads take no body or cursor")
        target, key_id = None, None
        if "{key_id}" in spec["path"]:
            if not isinstance(identifier, (tuple, list)) or len(identifier) != 2:
                raise ValueError("Expected observed parent and key identifiers")
            target, key_id = identifier
            if not valid_target(key_id):
                raise ValueError("Invalid key identifier")
        elif "{target}" in spec["path"]:
            target = identifier
        elif identifier is not None:
            raise ValueError("Unexpected identifier")
        if "{target}" in spec["path"] and not valid_target(target):
            raise ValueError("Invalid target identifier")
        url = ORIGIN + spec["path"].format(
            workspace=self.workspace,
            target=quote(target or "", safe=""),
            key_id=quote(key_id or "", safe=""),
        )
        list_key = (operation, target)
        if next_url is not None:
            if not spec.get("pager"):
                raise ValueError("Unexpected next URL")
            if operation in ("workspace-runners", "repository-runners"):
                url = self.runner_identities.next_url(
                    url, self._last_list_urls.get(list_key, url), operation, target, next_url
                )
            else:
                url = validate_next_url(url, next_url)
        else:
            query = dict(spec.get("query", {}))
            if spec["shape"] == "values":
                query["pagelen"] = self.page_size
            if query:
                url += "?" + urlencode(query)
        # OIDC discovery/JWKS are public verification metadata. Select this
        # mode by fixed operation, never as an authentication-error fallback.
        response = self._request(
            url,
            response_format="text" if operation == "workspace-gpg-key" else "json",
            authenticate=not spec.get("public", False),
        )
        if response.status == 200 and not response.reason:
            self.runner_identities.observe(operation, response.body)
            if spec.get("pager"):
                self._last_list_urls[list_key] = url
        if (
            operation == "workspace-gpg-key"
            and response.status == 200
            and isinstance(response.body, str)
        ):
            try:
                response.body = loads(response.body)
            except (ValueError, RecursionError):
                pass
        return response


def records(report):
    spec = OPERATIONS[report["operation"]]
    for page in report["pages"]:
        body = page["metadata"]
        values, _ = collection_records(spec, body)
        if values is not None:
            yield from (v for v in values if isinstance(v, dict))
        elif spec["shape"] == "object" and isinstance(body, dict):
            yield body


def collect_bitbucket(
    client, max_targets=50, now=utc_now, *, runners_only=False, branch_restrictions_only=False
):
    return consume(
        iter_bitbucket(
            client,
            max_targets,
            now,
            runners_only=runners_only,
            branch_restrictions_only=branch_restrictions_only,
        )
    )


def iter_bitbucket(
    client, max_targets=50, now=utc_now, *, runners_only=False, branch_restrictions_only=False
):
    if type(max_targets) is not int or not 1 <= max_targets <= 500:
        raise ValueError("Invalid target limit")
    if (
        type(runners_only) is not bool
        or type(branch_restrictions_only) is not bool
        or (runners_only and branch_restrictions_only)
    ):
        raise ValueError("Invalid collection mode")
    started = now()
    reports = []

    def run(op, identifier=None):
        report = yield from iter_operation(
            client, op, identifier=identifier, now=now, specs=OPERATIONS
        )
        reports.append(report)
        return report

    enabled = (
        ("repositories",) + RUNNER_OPERATIONS
        if runners_only
        else ("repositories",) + BRANCH_OPERATIONS
        if branch_restrictions_only
        else CORE_OPERATIONS
    )
    # Public repository metadata establishes UUID identities before a Runner
    # next link can switch to the provider's internal UUID route.
    base = {}
    for op in (
        ("repositories", "workspace-runners")
        if runners_only
        else ("repositories",)
        if branch_restrictions_only
        else tuple(op for op in STATIC if op != "current-user" or getattr(client, "user_account", True))
    ):
        base[op] = yield from run(op)
    candidates = {"users": set(), "projects": set(), "repositories": set()}
    invalid = 0

    def add(kind, value):
        nonlocal invalid
        if valid_target(value):
            candidates[kind].add(value)
        else:
            invalid += 1

    for user in records(base["current-user"]) if "current-user" in base else ():
        add("users", user.get("account_id") or user.get("uuid"))
    for member in records(base["workspace-members"]) if "workspace-members" in base else ():
        user = member.get("user")
        if isinstance(user, dict):
            add("users", user.get("account_id") or user.get("uuid"))
        else:
            invalid += 1
    for project in records(base["projects"]) if "projects" in base else ():
        add("projects", project.get("key"))
    for repo in records(base["repositories"]):
        add("repositories", repo.get("slug"))
    omitted = {k: max(0, len(v) - max_targets) for k, v in candidates.items()}
    targets = {k: sorted(v)[:max_targets] for k, v in candidates.items()}
    key_targets = set()
    key_omitted = 0

    def key_candidates(listing, detail_op):
        nonlocal invalid
        for key in records(listing):
            yield key
            if detail_op == "user-gpg-key-detail" and "subkeys" in key:
                subkeys = key["subkeys"]
                if not isinstance(subkeys, list):
                    invalid += 1
                    continue
                for subkey in subkeys:
                    if isinstance(subkey, dict):
                        yield subkey
                    else:
                        invalid += 1

    def details(listing, detail_op, parent):
        nonlocal invalid, key_omitted
        for key in key_candidates(listing, detail_op):
            field = (
                "fingerprint"
                if detail_op == "user-gpg-key-detail"
                else "uuid"
                if detail_op
                in (
                    "user-ssh-key-detail",
                    "pipeline-known-host-detail",
                    "workspace-runner-detail",
                    "repository-runner-detail",
                )
                else "id"
            )
            value = key.get(field)
            if type(value) is int and value >= 0:
                value = str(value)
            if not valid_target(value):
                invalid += 1
                continue
            target = (detail_op, parent, value)
            if target in key_targets:
                continue
            key_targets.add(target)
            if len(key_targets) > max_targets:
                key_omitted += 1
                continue
            yield from run(
                detail_op, value if detail_op == "workspace-runner-detail" else (parent, value)
            )

    if runners_only:
        yield from details(base["workspace-runners"], "workspace-runner-detail", client.workspace)
    for user in targets["users"]:
        yield from run("user-profile", user)
        yield from details((yield from run("user-ssh-keys", user)), "user-ssh-key-detail", user)
        yield from details((yield from run("user-gpg-keys", user)), "user-gpg-key-detail", user)
    for project in targets["projects"]:
        yield from run("project-detail", project)
        yield from details(
            (yield from run("project-deploy-keys", project)), "project-deploy-key-detail", project
        )
    for repo in targets["repositories"]:
        if runners_only:
            yield from details(
                (yield from run("repository-runners", repo)), "repository-runner-detail", repo
            )
            continue
        if branch_restrictions_only:
            yield from details(
                (yield from run("repository-branch-restrictions", repo)),
                "repository-branch-restriction-detail",
                repo,
            )
            continue
        yield from run("repository-detail", repo)
        yield from details(
            (yield from run("repository-deploy-keys", repo)), "repository-deploy-key-detail", repo
        )
        yield from run("pipeline-ssh-key", repo)
        yield from details(
            (yield from run("pipeline-known-hosts", repo)), "pipeline-known-host-detail", repo
        )
    states = [r["coverage"] for r in reports]
    status = "complete"
    if any(s in ("partial", "failed") for s in states):
        status = "partial" if any(r["pages"] for r in reports) else "failed"
    elif any(s != "complete" for s in states) or invalid or any(omitted.values()) or key_omitted:
        status = "unverified"
    return {
        "schema_version": 1,
        "report_type": "bitbucket_metadata_discovery",
        "collection_mode": "runners"
        if runners_only
        else "branch_restrictions"
        if branch_restrictions_only
        else "core",
        "provider": "atlassian",
        "environment": "bitbucket_cloud",
        "workspace": client.workspace,
        "started_at": started,
        "finished_at": now(),
        "run_status": status,
        "inventory_complete": False,
        "limits": {
            **asdict(client.limits),
            "max_targets": max_targets,
            "page_size": getattr(client, "page_size", 20),
        },
        "targets": targets,
        "targets_omitted_by_limit": omitted,
        "key_details_omitted_by_limit": 0 if runners_only else key_omitted,
        "runner_details_omitted_by_limit": key_omitted if runners_only else 0,
        "invalid_identifiers": invalid,
        "collections": reports,
        "not_requested_no_observed_targets": [
            kind
            for kind, ids in targets.items()
            if not ids
            and (not (runners_only or branch_restrictions_only) or kind == "repositories")
        ],
        "not_requested_operations": [
            op for op in enabled if not any(r["operation"] == op for r in reports)
        ],
        "not_requested_by_mode": [op for op in OPERATIONS if op not in enabled],
        "public_listing_contract_unverified": [
            "resource-access-tokens",
            "workspace-ssh-keys",
            "oauth-consumers",
        ],
    }


def safe_summary(result):
    operations = {}
    for report in result["collections"]:
        item = operations.setdefault(
            report["operation"],
            {
                "requests": 0,
                "pages": 0,
                "saved_records": 0,
                "coverage_counts": {},
                "http_status_counts": {},
                "reason_counts": {},
            },
        )
        item["requests"] += report["requests"]
        item["pages"] += len(report["pages"])
        item["saved_records"] += report["saved_records"]
        item["record_quality"] = dict(
            Counter(item.get("record_quality", {})) + Counter(report.get("record_quality", {}))
        )
        for field, value in (
            ("coverage_counts", report["coverage"]),
            ("http_status_counts", report["last_http_status"]),
            ("reason_counts", report["reason"]),
        ):
            if value is not None:
                item[field][str(value)] = item[field].get(str(value), 0) + 1
    return {
        "report_type": result["report_type"],
        "schema_version": result["schema_version"],
        "collection_mode": result.get("collection_mode", "core"),
        "run_status": result["run_status"],
        "inventory_complete": False,
        "request_count": sum(r["requests"] for r in result["collections"]),
        "target_counts": {k: len(v) for k, v in result["targets"].items()},
        "targets_omitted_by_limit": result["targets_omitted_by_limit"],
        "key_details_omitted_by_limit": result["key_details_omitted_by_limit"],
        "runner_details_omitted_by_limit": result.get("runner_details_omitted_by_limit", 0),
        "invalid_identifiers": result["invalid_identifiers"],
        "operations": operations,
        "not_requested_no_observed_targets": result["not_requested_no_observed_targets"],
        "not_requested_operations": result.get(
            "not_requested_operations",
            [
                op
                for op in OPERATIONS
                if not any(r["operation"] == op for r in result["collections"])
            ],
        ),
        "not_requested_by_mode": result.get("not_requested_by_mode", []),
        "public_listing_contract_unverified": result["public_listing_contract_unverified"],
    }


def main(argv=None, *, directory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=profile_argument)
    parser.add_argument("--max-targets", type=int, default=50)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--runners-only",
        action="store_true",
        help="Read only workspace/repository runners and discover repositories; requires read:runner and read:repository scopes.",
    )
    modes.add_argument(
        "--branch-restrictions-only",
        action="store_true",
        help="Read repository branch restriction metadata; requires admin:repository and read:repository scopes. Does not enumerate all access tokens.",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=20,
        help="Initial Bitbucket list page size (1-100). Server next URLs are followed unchanged.",
    )
    for name in Limits.__dataclass_fields__:
        default = getattr(Limits(), name)
        parser.add_argument(
            "--" + name.replace("_", "-"),
            type=int if name in ("max_pages", "max_records", "max_requests", "retries") else float,
            default=default,
        )
    args = parser.parse_args(argv)
    directory = Path(directory) if directory is not None else Path.cwd() / ".local"
    try:
        limits = Limits(**{k: getattr(args, k) for k in Limits.__dataclass_fields__})
        if not 1 <= args.max_targets <= 500:
            raise ValueError("Invalid target bound")
        if not 1 <= args.page_size <= 100:
            raise ValueError("Invalid page size")
        workspace, token = load_connection(directory, args.profile)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.exit(2, "Invalid Bitbucket limits or private connection. No request made.\n")
    try:
        result = collect_bitbucket(
            BitbucketClient(workspace, token, limits, page_size=args.page_size),
            args.max_targets,
            runners_only=args.runners_only,
            branch_restrictions_only=args.branch_restrictions_only,
        )
        result["connection_profile"] = args.profile
        filename = save_private(directory, result)
        summary = safe_summary(result)
        summary["output_file"] = ".local/" + filename
        print(json.dumps(summary, indent=2))
    except KeyboardInterrupt:
        parser.exit(130, "Collection interrupted; no completion claim.\n")
    except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
        parser.exit(2, "Bitbucket collection or private output failed; details suppressed.\n")
    return 0 if result["run_status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
