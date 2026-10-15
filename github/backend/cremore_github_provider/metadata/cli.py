"""GitHub metadata collection outside the product: check, collect, export and submit.

develop_github ran its collectors as a standalone CLI with its own JSON files.
This one runs the product's own GitHub adapter on the operator's machine -- the
same task graph, budgets, checkpoints and record contract -- so what it collects
is what the worker would have stored. A run directory holds records.jsonl,
checkpoint.json (the provider checkpoint and how many records it covers) and
run.json. ``export`` prints the native view; ``submit`` sends a finished run to a
CreMore connection through the schema 2 collector API, where the same record
validation runs again, and ``config`` fetches that connection's spec and contract.

It is not a separate contract: it has no output format of its own. Secrets come from files or the environment and are
never written to the run directory. Provider digests need the product's
fingerprint key and are refused here.

    python -m cremore_github_provider.metadata.cli check --spec spec.json --app-id Iv23... --private-key-file app.pem
    python -m cremore_github_provider.metadata.cli collect --spec spec.json --out run1 --private-key-file app.pem
    python -m cremore_github_provider.metadata.cli export --out run1
    CREMORE_COLLECTOR_TOKEN=... python -m cremore_github_provider.metadata.cli config --api-url https://cremore.example --connection-id <id> --output spec.json
    CREMORE_COLLECTOR_TOKEN=... python -m cremore_github_provider.metadata.cli submit --spec spec.json --out run1 --api-url https://cremore.example
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pydantic import TypeAdapter, ValidationError

from cremore.coverage.metadata_models import MetadataBatch, MetadataConnectionSpec, MetadataRecord
from cremore.coverage.models import MAX_BATCH, digest
from cremore.http_client import bounded_request
from cremore_github_provider.github_auth import (
    GitHubAppTokenSource,
    GitHubAuthError,
    app_assertion,
    app_issuer,
)
from cremore_github_provider.github_hosts import api_base, normalize_host

from . import adapter

TERMINAL = ("COMPLETE", "PARTIAL", "FAILED")
CONFIG_KEYS = {"connection_id", "revision", "spec", "auth_slots", "contract", "limitations"}
_RECORD = TypeAdapter(MetadataRecord)
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,95}")


class CliError(Exception):
    """A safe code for the operator; never a response body, token or key."""


def _code(exc):
    text = str(exc).upper()
    return text if _CODE.fullmatch(text) else "GITHUB_CLI_FAILED"


def _now():
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def _write_json(path, value):
    """Replace the file whole: a crash leaves the old or the new one, never half."""
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=1), encoding="utf-8")
    os.replace(temporary, path)


# -- the spec and the local secrets ----------------------------------------------


def load_spec(path):
    """A plain spec, or what ``config`` saved (the product's spec, revision and contract)."""
    data = _read_json(path)
    if data is None:
        raise CliError("GITHUB_CLI_SPEC_NOT_FOUND")
    config = None
    if isinstance(data, dict) and "spec" in data and set(data) <= CONFIG_KEYS:
        config, spec = data, dict(data["spec"])
        # The product returns no secret references; the slots it names are filled locally.
        spec["secret_refs"] = {slot: "vault://cremore-cli/" + slot for slot in data.get("auth_slots") or ("app_id", "private_key")}
        data = spec
    try:
        spec = MetadataConnectionSpec.model_validate(data)
        adapter.validate_spec(spec)
    except (ValidationError, ValueError) as exc:
        raise CliError(_code(exc) if not isinstance(exc, ValidationError) else "GITHUB_CLI_SPEC_INVALID") from None
    if spec.options.include_provider_hashes:
        raise CliError("GITHUB_CLI_PROVIDER_DIGESTS_NEED_THE_PRODUCT_KEY")
    return spec, config


def local_secrets(spec, *, app_id=None, private_key_file=None, installation_id=None, audit_token_file=None,
                  environ=os.environ):
    """App ID or Client ID, the App's PEM key, and the audit PAT when the spec reads the Enterprise audit log."""
    try:
        issuer = app_issuer(app_id or environ.get("GITHUB_APP_ID", ""))
        if private_key_file:
            pem = Path(private_key_file).read_bytes()
            if len(pem) > 64 << 10:
                raise CliError("GITHUB_CLI_PRIVATE_KEY_FILE_TOO_LARGE")
            key = base64.b64encode(pem).decode()
        else:
            key = environ.get("GITHUB_APP_PRIVATE_KEY_BASE64", "")
        app_assertion(issuer, key)  # decodes the PEM and signs once; the JWT is discarded
    except GitHubAuthError as exc:
        raise CliError(exc.code) from None
    secrets = {"app_id": issuer, "private_key": key}
    if installation_id:
        secrets["installation_id"] = str(installation_id)
    if "audit_token" in spec.secret_refs:
        if not audit_token_file:
            raise CliError("GITHUB_CLI_AUDIT_TOKEN_FILE_REQUIRED")
        secrets["audit_token"] = Path(audit_token_file).read_text(encoding="utf-8").strip()
    return secrets


def online_identity(spec, secrets, *, client):
    """GET /app with the App JWT on the spec's host: the one request ``check --online`` makes."""
    # identity() reads only the App; an installation id is required by the source but never used here.
    source = GitHubAppTokenSource(lambda: client, secrets["app_id"], secrets.get("installation_id") or "1",
                                  secrets["private_key"], base_url=api_base(normalize_host(spec.origin)),
                                  close_client=False)
    app = source.identity()
    return {key: app[key] for key in ("id", "slug", "name", "owner")}


# -- a run directory ---------------------------------------------------------------


def _records(directory, limit=None):
    path = Path(directory) / "records.jsonl"
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if limit is not None and len(rows) >= limit:
                break
            rows.append(json.loads(line))
    return rows


def _keep(directory, count):
    """Drop records a crash wrote after the last checkpoint; they will be read again."""
    path = Path(directory) / "records.jsonl"
    rows = _records(directory, count)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    return rows


def collect(spec, secrets, directory, *, wait=True, sleep=time.sleep, transport=None, broker=None, now=None):
    """Collect into ``directory``, resuming from its checkpoint; returns run.json.

    Records are appended and flushed before the checkpoint that covers them is
    replaced, so a crash re-reads at most one page instead of losing or doubling it.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    run = _read_json(directory / "run.json") or {}
    spec_digest = digest(spec.model_dump())
    if run.get("status") in TERMINAL:
        raise CliError("GITHUB_CLI_RUN_ALREADY_FINISHED")
    if run and run.get("spec_digest") != spec_digest:
        raise CliError("GITHUB_CLI_SPEC_CHANGED")
    run = {"request_id": str(uuid.uuid4()), "started_at": _now(), **run, "spec_digest": spec_digest}
    _write_json(directory / "run.json", run)
    saved = _read_json(directory / "checkpoint.json") or {"provider": {}, "records": 0}
    committed = _keep(directory, saved["records"])
    secret_values = [value for slot, value in secrets.items() if slot not in ("app_id", "installation_id") and len(value) >= 8]
    while True:
        pages = adapter.collect_pages(spec, secrets=secrets, checkpoint=saved["provider"], check=lambda: None,
                                      read_records=(lambda: iter(committed)) if saved["provider"] else None,
                                      transport=transport, broker=broker, now=now)
        waiting = None
        for page in pages:
            rows = [json.loads(record.model_dump_json()) for record in page.records]
            encoded = json.dumps(rows)
            if any(value in encoded for value in secret_values):
                raise CliError("PROVIDER_AUTH_VALUE_IN_METADATA")
            with (directory / "records.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
                handle.writelines(json.dumps(row, sort_keys=True) + "\n" for row in rows)
                handle.flush()
                os.fsync(handle.fileno())
            committed.extend(rows)
            saved = {"provider": page.checkpoint, "records": len(committed)}
            _write_json(directory / "checkpoint.json", saved)
            if page.status == "WAITING":
                waiting = page
                break
            if page.status in TERMINAL:
                run.update(status=page.status, reasons=page.reasons, finished_at=_now(), record_count=len(committed))
                run.pop("retry_after_seconds", None)
                _write_json(directory / "run.json", run)
                return run
        if waiting is None:
            raise CliError("GITHUB_CLI_TERMINAL_REPORT_REQUIRED")
        pages.close()
        run.update(status="WAITING", reasons=waiting.reasons, retry_after_seconds=waiting.retry_after_seconds)
        _write_json(directory / "run.json", run)
        if not wait:
            return run
        sleep(waiting.retry_after_seconds or 60)


def export(directory):
    """The native view (organizations, Enterprise inventory, audit links) of a run directory."""
    saved = _read_json(Path(directory) / "checkpoint.json")
    if saved is None:
        raise CliError("GITHUB_CLI_RUN_NOT_FOUND")
    return adapter.native_snapshots(_records(directory, saved["records"]))


# -- the product's collector API ----------------------------------------------------


def _api(api_url, connection_id, token, client, sleep=time.sleep):
    parsed = urlsplit(api_url or "")
    if ((parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")))
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise CliError("HTTPS_API_URL_REQUIRED")
    if not token:
        raise CliError("CREMORE_COLLECTOR_TOKEN_REQUIRED")
    try:
        base = api_url.rstrip("/") + "/api/v2/coverage/collector/" + str(uuid.UUID(str(connection_id)))
    except ValueError:
        raise CliError("GITHUB_CLI_CONNECTION_ID_INVALID") from None

    def request(method, suffix="", body=None):
        # Start (by request id), batches (by index) and finish are idempotent: a
        # lost response is retried as the same request, never as a new run.
        for attempt in range(3):
            try:
                response = bounded_request(client, method, base + suffix, json=body,
                                           headers={"X-Cremore-Collector-Token": token},
                                           follow_redirects=False, max_response_bytes=4 << 20)
            except Exception:  # noqa: BLE001 -- transport errors can carry the URL; keep a fixed code.
                response = None
            status = getattr(response, "status_code", 0)
            if status in (200, 201):
                return response.json()
            if response is not None and status not in (429, 500, 502, 503, 504):
                try:
                    error = response.json().get("error", "")
                except (ValueError, AttributeError):
                    error = ""
                raise CliError(error if isinstance(error, str) and _CODE.fullmatch(error) else f"COVERAGE_API_HTTP_{status}")
            if attempt < 2:
                sleep(2 ** attempt)
        raise CliError("COVERAGE_API_REQUEST_FAILED")

    return request


def config(api_url, connection_id, token, *, client):
    """The connection's spec (without secret references), revision, auth slots and contract."""
    value = _api(api_url, connection_id, token, client)("GET")
    return {key: value[key] for key in CONFIG_KEYS if key in value}


def _batches(records):
    pending, size = [], 100
    for record in records:
        count = len(record.model_dump_json().encode()) + 1
        if pending and (len(pending) == MAX_BATCH or size + count > 1_999_900):
            yield pending
            pending, size = [], 100
        pending.append(record)
        size += count
    if pending:
        yield pending


def submit(directory, spec_config, api_url, token, *, client, connection_id=None):
    """Send a finished run directory as one run of the configured connection."""
    directory = Path(directory)
    run = _read_json(directory / "run.json") or {}
    if run.get("status") not in TERMINAL:
        raise CliError("GITHUB_CLI_RUN_NOT_FINISHED")
    if not spec_config or not {"contract", "revision", "connection_id"} <= set(spec_config):
        raise CliError("GITHUB_CLI_SUBMIT_NEEDS_THE_CONNECTION_CONFIG")
    request = _api(api_url, connection_id or spec_config["connection_id"], token, client)
    records = [_RECORD.validate_python(row) for row in _records(directory, run["record_count"])]
    started = request("POST", "/runs", {"revision": spec_config["revision"], "request_id": run["request_id"],
                                        "contract": spec_config["contract"]})
    batches = list(_batches(records))
    for index, items in enumerate(batches):
        body = MetadataBatch(index=index, items=items).model_dump(mode="json")
        request("PUT", f"/runs/{started['id']}/batches", body)
    finished = request("POST", f"/runs/{started['id']}/finish", {
        "batch_count": len(batches), "item_count": len(records), "status": run["status"],
        "reasons": run.get("reasons") or []})
    run["submitted"] = {"run_id": started["id"], "status": finished.get("status"), "at": _now()}
    _write_json(directory / "run.json", run)
    return finished


# -- the command line -----------------------------------------------------------------


def _parser():
    parser = argparse.ArgumentParser(prog="python -m cremore_github_provider.metadata.cli",
                                     description="GitHub metadata collection with the product's own adapter.")
    commands = parser.add_subparsers(dest="command", required=True)

    def secrets_args(command):
        command.add_argument("--app-id", help="App ID or Client ID (default: GITHUB_APP_ID)")
        command.add_argument("--private-key-file", help="the App's .pem (default: GITHUB_APP_PRIVATE_KEY_BASE64)")
        command.add_argument("--installation-id")
        command.add_argument("--audit-token-file", help="classic PAT (read:audit_log) for the Enterprise audit log")

    check = commands.add_parser("check", help="validate a spec and the App key offline; --online confirms the App")
    check.add_argument("--spec", required=True)
    check.add_argument("--online", action="store_true", help="GET /app with the App JWT (one request)")
    secrets_args(check)
    run = commands.add_parser("collect", help="collect into a directory, resuming from its checkpoint")
    run.add_argument("--spec", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--no-wait", action="store_true", help="stop at a rate limit instead of sleeping")
    secrets_args(run)
    view = commands.add_parser("export", help="print the native view of a run directory")
    view.add_argument("--out", required=True)
    view.add_argument("--output", help="write it to this file instead of stdout")
    fetch = commands.add_parser("config", help="save a connection's spec and contract (CREMORE_COLLECTOR_TOKEN)")
    fetch.add_argument("--api-url", required=True)
    fetch.add_argument("--connection-id", required=True)
    fetch.add_argument("--output", required=True)
    send = commands.add_parser("submit", help="send a finished run to the connection (CREMORE_COLLECTOR_TOKEN)")
    send.add_argument("--spec", required=True, help="the file config saved")
    send.add_argument("--out", required=True)
    send.add_argument("--api-url", required=True)
    return parser


def main(argv=None, *, environ=os.environ, client=None, stdout=sys.stdout, stderr=sys.stderr):
    args = _parser().parse_args(argv)
    own = None
    try:
        if client is None and (args.command in ("config", "submit") or args.command == "check" and args.online):
            own = client = httpx.Client(timeout=30, follow_redirects=False)
        if args.command == "check":
            spec, _config = load_spec(args.spec)
            secrets = local_secrets(spec, app_id=args.app_id, private_key_file=args.private_key_file,
                                    installation_id=args.installation_id, audit_token_file=args.audit_token_file,
                                    environ=environ)
            result = {"ok": True, "provider": spec.provider, "mode": spec.options.mode,
                      "scopes": [f"{scope.kind}:{scope.id}" for scope in spec.scopes],
                      "sources": list(spec.options.sources), "audit": spec.options.include_audit_events}
            if args.online:
                result["app"] = online_identity(spec, secrets, client=client)
        elif args.command == "collect":
            spec, _config = load_spec(args.spec)
            secrets = local_secrets(spec, app_id=args.app_id, private_key_file=args.private_key_file,
                                    installation_id=args.installation_id, audit_token_file=args.audit_token_file,
                                    environ=environ)
            result = collect(spec, secrets, args.out, wait=not args.no_wait)
        elif args.command == "export":
            result = export(args.out)
            if args.output:
                _write_json(args.output, result)
                result = {"ok": True, "output": args.output}
        elif args.command == "config":
            result = config(args.api_url, args.connection_id, environ.get("CREMORE_COLLECTOR_TOKEN", ""), client=client)
            _write_json(args.output, result)
            result = {"ok": True, "output": args.output, "revision": result.get("revision")}
        else:
            _spec, spec_config = load_spec(args.spec)
            result = submit(args.out, spec_config, args.api_url, environ.get("CREMORE_COLLECTOR_TOKEN", ""),
                            client=client)
    except CliError as exc:
        stderr.write(json.dumps({"error": str(exc)}) + "\n")
        return 2
    except GitHubAuthError as exc:
        stderr.write(json.dumps({"error": exc.code}) + "\n")
        return 2
    finally:
        if own is not None:
            own.close()
    stdout.write(json.dumps(result, sort_keys=True, default=str) + "\n")
    return 3 if isinstance(result, dict) and result.get("status") == "WAITING" else 0


if __name__ == "__main__":
    sys.exit(main())
