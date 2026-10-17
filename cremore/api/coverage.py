"""Admin onboarding, scoped machine submissions, and read-only coverage views."""

import hashlib
import uuid
from typing import Literal

from fastapi import Depends, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import Field

from cremore.coverage.correlation import public_connection, report, scope_revision
from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Start, StrictModel
from cremore.coverage.store import CoverageError, CoverageStore

# Integration: the source_type filter accepts the registry's content sources instead of a
# copied literal; keep the order and values aligned with the web source list.
from cremore.sources.registry import SOURCE_TYPES


class Change(StrictModel):
    revision: int = Field(ge=1)
    spec: ConnectionSpec | None = None
    enabled: bool | None = None
    rotate_token: bool = False


class ScopeDeclaration(StrictModel):
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirmed: bool


AWS_COVERAGE_PROVIDERS = frozenset({"aws_iam", "aws_cloudtrail", "aws_secrets_manager", "aws_ssm"})


def register_coverage_routes(app, repo, orchestrator, require_auth, require_role, aws_sessions=None, settings=None,
                             require_principal=None):
    from cremore.api.storage_receipts import register_storage_receipt_routes

    register_storage_receipt_routes(app, repo, require_auth, require_role)
    settings = settings or getattr(app.state, "settings", None)
    store = CoverageStore(repo)
    require_admin = require_role("admin")
    require_analyst = require_role("analyst")
    reader = require_principal or require_auth

    def contract():
        orchestrator.refresh_rules()
        return Contract(engine_digest=orchestrator.engine.detection_digest, policy_digest=orchestrator.coverage_policy_digest).model_dump()

    def machine(connection_id: uuid.UUID, x_cremore_collector_token: str = Header(default="", max_length=1024)):
        row = store.get(connection_id)
        store.authorize(row, x_cremore_collector_token)
        require_v1(row)
        if row["spec"]["provider"] not in AWS_COVERAGE_PROVIDERS:
            raise CoverageError("COVERAGE_PROVIDER_UNAVAILABLE")
        return x_cremore_collector_token

    def require_v1(row):
        # A missing row keeps its existing per-route status: authorize reports
        # COLLECTOR_UNAUTHORIZED, change reports NOT_FOUND, enqueue reports
        # DISABLED_OR_MISSING. Only a schema 2 row is rejected here.
        if row is not None and row["spec"].get("schema_version", 1) != 1:
            raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
        return row

    def key_id():
        key = orchestrator.config.fingerprint_key
        return hashlib.sha256(key).hexdigest() if key else None

    @app.exception_handler(CoverageError)
    async def coverage_error(_request, exc):
        code = str(exc)
        status = 401 if code == "COLLECTOR_UNAUTHORIZED" else 404 if code.endswith("NOT_FOUND") else 409
        return JSONResponse({"error": code, "detail": code}, status_code=status)

    @app.get("/api/v1/coverage")
    def get_report(offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
                   state: Literal["", "MATCHED", "NO_VAULT_MATCH", "UNKNOWN", "IDENTIFIER_ONLY", "IDENTIFIER_NOT_OBSERVED", "OBSERVED_IN_VAULT", "PUBLIC_CERTIFICATE_MATCH", "PUBLIC_CERTIFICATE_NOT_OBSERVED"] = "",
                   source_type: Literal[("", *SOURCE_TYPES)] = "",
                   vault_provider: Literal["", "aws_secrets_manager", "aws_ssm"] = "",
                   origin: Literal["", "EXPOSURE", "ISSUANCE", "USAGE", "VAULT"] = "",
                   who=Depends(reader)):
        return report(repo, contract(), offset=offset, limit=limit, state=state, source_type=source_type,
                      vault_provider=vault_provider, origin=origin, fingerprint_key_id=key_id(), settings=settings)

    @app.put("/api/v1/coverage/scope")
    def declare_scope(body: ScopeDeclaration, actor=Depends(require_admin)):
        if body.revision != scope_revision(store.list_connections()):
            raise CoverageError("SCOPE_REVISION_CONFLICT")
        repo.put_setting("coverage_scope", body.model_dump(), actor)
        return body

    @app.get("/api/v1/findings/{finding_id}/coverage")
    def finding_coverage(finding_id: uuid.UUID, who=Depends(reader)):
        if repo.get_finding(finding_id) is None:
            raise HTTPException(404, "FINDING_NOT_FOUND")
        return report(repo, contract(), finding_id=finding_id, fingerprint_key_id=key_id(), settings=settings)

    @app.patch("/api/v1/coverage/connections/{connection_id}")
    def change(connection_id: uuid.UUID, body: Change, actor=Depends(require_admin)):
        current = require_v1(store.get(connection_id))
        spec = body.spec
        selected_provider = spec.provider if spec is not None else current["spec"]["provider"] if current else None
        if (spec is not None or body.enabled is True) and selected_provider not in AWS_COVERAGE_PROVIDERS:
            raise CoverageError("COVERAGE_PROVIDER_UNAVAILABLE")
        row, token = store.change(connection_id, body.revision, actor, spec=spec, enabled=body.enabled, rotate=body.rotate_token)
        return {**public_connection(row), "collector_token": token}

    @app.get("/api/v1/coverage/connections/{connection_id}/runs")
    def connection_runs(connection_id: uuid.UUID, limit: int = Query(default=50, ge=1, le=200), _actor=Depends(require_auth)):
        """A collection's runs, newest first: status, reasons, item count, completeness and times."""
        if require_v1(store.get(connection_id)) is None:
            raise CoverageError("CONNECTION_NOT_FOUND")
        rows = store.connection_runs(connection_id, limit=limit)
        return {"items": [{**row, "id": str(row["id"]), "connection_id": str(row["connection_id"]),
                           "started_at": row["started_at"].isoformat() if row["started_at"] else None,
                           "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None} for row in rows]}

    @app.post("/api/v1/coverage/connections/{connection_id}/collect", status_code=202)
    def collect(connection_id: uuid.UUID, _actor=Depends(require_admin)):
        return enqueue(connection_id, _actor)

    def enqueue(connection_id, actor="api"):
        from cremore_aws_provider import aws_access

        from cremore.coverage.aws_scheduling import enqueue_aws_inventory
        row = store.get(connection_id)
        require_v1(row)
        if row and row["spec"]["provider"] not in AWS_COVERAGE_PROVIDERS:
            raise CoverageError("COVERAGE_PROVIDER_UNAVAILABLE")
        if (row and row["enabled"] and row["spec"]["provider"] not in ("aws_iam", "aws_cloudtrail")
                and not row["spec"].get("server_collection")):
            raise HTTPException(409, "VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT")
        try:
            return enqueue_aws_inventory(repo, settings, aws_sessions, connection_id, actor=actor)
        except aws_access.AccessBlocked as exc:
            raise HTTPException(409, exc.code) from None

    def account_and_connections(account_id):
        account = repo.get_aws_account(account_id)
        if not account:
            raise HTTPException(404, "ACCOUNT_NOT_FOUND")
        rows = [row for row in store.list_connections() if row["spec"].get("schema_version", 1) == 1
                and row["spec"]["provider"] in ("aws_iam", "aws_cloudtrail") and row["spec"]["account_id"] == account.account_id]
        return account, rows

    @app.get("/api/v1/aws/accounts/{account_id}/credential-inventory")
    def aws_inventory(account_id: uuid.UUID, offset: int = Query(default=0, ge=0),
                      limit: int = Query(default=5000, ge=1, le=5000),
                      snapshot_revision: str = Query(default="", pattern=r"^(?:[a-f0-9]{64})?$"),
                      _actor=Depends(require_auth)):
        from cremore_aws_provider.inventory_view import inventory_response
        account, _ = account_and_connections(account_id)
        return inventory_response(repo, account, settings=settings, offset=offset, limit=limit,
                                  snapshot_revision=snapshot_revision)

    @app.post("/api/v1/aws/accounts/{account_id}/credential-inventory/refresh", status_code=202)
    def refresh_aws_inventory(account_id: uuid.UUID, actor=Depends(require_analyst)):
        from cremore_aws_provider import aws_access
        from cremore_aws_provider.inventory_view import inventory_response

        from cremore.coverage.aws_scheduling import ensure_aws_inventory_connections
        account, _ = account_and_connections(account_id)
        if aws_sessions is None:
            raise HTTPException(409, "AWS_SESSION_UNAVAILABLE")
        code, _, _ = aws_sessions.refusal(account.account_id, aws_access.SCANNER)
        if code:
            raise HTTPException(409, code)
        connections = ensure_aws_inventory_connections(repo, settings, account, actor)
        if any(not row["enabled"] for row in connections):
            raise CoverageError("CONNECTION_DISABLED_OR_MISSING")
        for connection in connections:
            enqueue(connection["id"], actor)
        return inventory_response(repo, account, settings=settings)

    @app.get("/api/v1/coverage/collector/{connection_id}")
    def collector_config(connection_id: uuid.UUID, _token=Depends(machine)):
        row = store.get(connection_id)
        expected = contract()
        # Only fields needed to compile detectors; no samples, notes or customer content.
        rules = [{key: getattr(rule, key) for key in ("id", "name", "pattern", "keywords", "severity", "scope_sources", "include_globs", "exclude_globs", "exclude_words")}
                 for rule in repo.list_rules() if rule.enabled]
        from cremore.detection import switches

        # The hasher compiles the same detectors the contract was computed from.
        return {"connection_id": connection_id, "spec": row["spec"], "revision": row["revision"], "contract": expected,
                "rules": rules, "disabled_detectors": sorted(switches.disabled(repo))}

    @app.post("/api/v1/coverage/collector/{connection_id}/runs")
    def start(connection_id: uuid.UUID, body: Start, token=Depends(machine)):
        if body.contract.model_dump() != contract():
            raise CoverageError("FINGERPRINT_CONTRACT_MISMATCH")
        try:
            return store.start(connection_id, body.revision, body.request_id, body.contract.model_dump(), token=token)
        except ValueError as exc:
            if isinstance(exc, CoverageError):
                raise
            raise HTTPException(422, "INVALID_REQUEST_ID") from None

    @app.put("/api/v1/coverage/collector/{connection_id}/runs/{run_id}/batches")
    def append(connection_id: uuid.UUID, run_id: uuid.UUID, body: Batch, token=Depends(machine)):
        store.append(connection_id, run_id, body, token=token)
        return {"accepted": True, "index": body.index}

    @app.post("/api/v1/coverage/collector/{connection_id}/runs/{run_id}/finish")
    def finish(connection_id: uuid.UUID, run_id: uuid.UUID, body: Finish, token=Depends(machine)):
        return store.finish(connection_id, run_id, body, token=token)
