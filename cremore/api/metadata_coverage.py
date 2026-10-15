"""Schema 2 metadata routes sharing the existing auth, audit, queue and store."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from itertools import chain

from fastapi import Depends, Header, HTTPException, Query
from pydantic import Field, model_validator

from cremore.api import connection_setup
from cremore.api.auth import role_at_least
from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.correlation import public_connection
from cremore.coverage.metadata_correlation import finding_links
from cremore.coverage.metadata_job import pause_key, paused
from cremore.coverage.metadata_models import (
    MetadataBatch,
    MetadataConnectionSpec,
    MetadataFinish,
    MetadataModel,
    MetadataStart,
    ObjectKind,
    Provider,
    Purpose,
    metadata_contract,
    same_contract,
    scope_matches,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.providers import adapter_for, collector_for, validate_spec
from cremore.coverage.providers.catalog import catalog
from cremore.coverage.scheduling import connection_job
from cremore.coverage.store import CoverageError
from cremore.db.task_store import TaskStore
from cremore.domain.models import FindingEvent, ScanJob


class MetadataChange(MetadataModel):
    revision: int = Field(ge=1)
    spec: MetadataConnectionSpec | None = None
    enabled: bool | None = None
    rotate_token: bool = False

    @model_validator(mode="before")
    @classmethod
    def reject_retired_value_storage(cls, value):
        if isinstance(value, dict) and isinstance(value.get("spec"), dict):
            options = value["spec"].get("options")
            if isinstance(options, dict) and "store_values" in options:
                raise ValueError("RAW_VALUE_STORAGE_REMOVED")
        return value


class CollectRequest(MetadataModel):
    retry_from_run: str | None = Field(default=None, pattern=r"^[0-9a-fA-F-]{36}$")
    operations: list[str] = Field(default_factory=list, max_length=100)
    include_unverified: bool = False
    scope_id: str | None = Field(default=None, max_length=512)


class GitHubEnterpriseConnection(MetadataModel):
    source_connection_id: uuid.UUID = Field(strict=False)
    enterprise: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,99}$")


class GitHubAuditToken(MetadataModel):
    token: str = Field(min_length=1, max_length=512)


class GitHubInstallationCheck(MetadataModel):
    org: str | None = Field(default=None, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")


def _iso(value):
    """A stored timestamp as the dashboard reads one, or None."""
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else value.astimezone(UTC).isoformat()


def bounded_records(store, rid):
    """Native compatibility exports are bounded; canonical exports are paged."""
    result, size = [], 0
    for record in store.iter_records(rid):
        size += len(json.dumps(record, ensure_ascii=True).encode())
        if len(result) >= 10000 or size > 8_000_000:
            raise CoverageError("NATIVE_EXPORT_LIMIT_USE_RECORD_PAGES")
        result.append(record)
    return result


GITHUB_HISTORY_RUN_LIMIT = 100
GITHUB_CHECK_RECORD_LIMIT = 10_000
GITHUB_CHECK_BYTE_LIMIT = 8_000_000


def github_check_records(store, checks):
    """Replay all checked evidence or explicitly refuse; never return a partial overlay as current."""
    result, count, size = [], 0, 0
    for run in reversed(checks):
        if run["status"] == "RUNNING":
            continue
        rows = []
        for record in store.iter_records(run["id"]):
            count += 1
            size += len(json.dumps(record, ensure_ascii=True))
            if count > GITHUB_CHECK_RECORD_LIMIT or size > GITHUB_CHECK_BYTE_LIMIT:
                raise CoverageError("GITHUB_INSTALLATION_HISTORY_LIMIT_USE_RUN_PAGES")
            rows.append(record)
        result.append(rows)
    return result


_PRIVATE = {"provider_digest", "session_fingerprint", "signed_fingerprints", "identity_keys", "identity_key_id", "payload_digest", "store_values"}


# A people-directory collection's records (cremore.identity.idp): who is employed, since when, and -- where profiles are
# kept -- their name, email, department and title. Analysts and above read them, as GET /api/v1/people and the
# departed-owner lists are; the reads below leave them out, refuse them or drop their facts for anyone else.
PEOPLE = ("identity_status",)


def public_metadata(value, people=False):
    """Private issuer/session/identity digests support internal equality, never exports.

    ``people`` says the caller is an Analyst or above. Without it a people-directory record or summary that still
    reaches here keeps no facts: on such a record every fact is a profile value (idp.user_record).
    """
    if isinstance(value, dict):
        out = {key: None if key == "value_match" and isinstance(item, dict)
               and item.get("evidence") == "PROVIDER_DIGEST" else public_metadata(item, people)
               for key, item in value.items() if key not in _PRIVATE}
        if "issuer_identifier" in out and out["issuer_identifier"] != "":
            from cremore_gcp.linkage import is_service_account_key_identifier

            from cremore.detection.safe_text import safe_fact_text

            identifier = out["issuer_identifier"]
            if not is_service_account_key_identifier(identifier) or safe_fact_text(identifier) is None:
                out.pop("issuer_identifier")
        if not people and value.get("purpose") in PEOPLE and isinstance(out.get("facts"), list):
            out["facts"] = []
        return out
    if isinstance(value, list):
        return [public_metadata(item, people) for item in value]
    return value


def register_metadata_routes(app, repo, require_auth, require_role, require_principal, settings=None):
    store = MetadataStore(repo)
    admin, analyst = require_role("admin"), require_role("analyst")

    def people(principal) -> bool:
        """Whether the caller may read a people-directory collection's records (see PEOPLE)."""
        return role_at_least(principal.role, "analyst")

    def hidden(principal):
        return () if people(principal) else PEOPLE

    def refuse_people():
        raise HTTPException(status_code=403, detail="requires role analyst")

    def raw_spec(run):
        return run["contract"].get("spec_snapshot") or store.require_connection(run["connection_id"])["spec"]

    def run_spec(run):
        return MetadataConnectionSpec.model_validate(raw_spec(run))

    def people_run(run, principal):
        """A people-directory collection's runs -- their records, exports and comparisons -- are refused below Analyst.
        Read from the stored spec as it is, so an older snapshot is judged without being validated again."""
        if "identity_status" in (raw_spec(run).get("capabilities") or ()) and not people(principal):
            refuse_people()

    def audit(bound, cid, actor, action, note=None):
        bound.record_finding_event(FindingEvent(target_type="coverage_connection", target_id=cid,
                                               actor=actor, event_type=action, note=note))

    def machine(connection_id: uuid.UUID, x_cremore_collector_token: str = Header(default="", max_length=1024)):
        store.authorize(store.get(connection_id), x_cremore_collector_token)
        store.require_connection(connection_id)
        return x_cremore_collector_token

    def connection_view(row, *, references=False):
        runs = store.connection_runs(row["id"], limit=1)
        job = connection_job(repo, row["id"])
        latest = next(iter(runs["items"]), None)
        extra = {}
        if row["spec"]["provider"] == "gcp":
            from cremore.api.gcp_coverage import authentication
            from cremore.coverage.gcp_store import linked_source_disabled
            extra["connection_auth"] = authentication(store, row, latest, job)
            if linked_source_disabled(repo, row["id"]):
                extra["enabled"] = False
                extra["connection_auth"].update(state="DISABLED", reason_code="GCP_SOURCE_DISABLED")
        if row["spec"]["provider"] == "github":
            from cremore.coverage.github_exports import applicable, public_state

            if applicable(row["spec"]):
                extra["enterprise_export"] = public_state(repo, row["spec"])
        return {**public_connection(row, include_references=references), "latest_run": next(iter(runs["items"]), None),
                "latest_job": None if job is None else {"id": job.id, "status": job.status, "error": job.error,
                                                        "started_at": job.started_at, "finished_at": job.finished_at},
                "collection_paused": job is not None and job.status in ("QUEUED", "RUNNING")
                and paused(repo, row["id"], job.id), **extra}

    @app.get("/api/v2/coverage/providers")
    def providers(_actor=Depends(require_auth)):
        # What onboarding may offer. A provider whose adapter is not installed
        # is not listed, so the screen never proposes a connection the server
        # would refuse.
        return {"schema_version": 2, "items": catalog()}

    @app.get("/api/v2/coverage/connections")
    def connections(_actor=Depends(require_auth)):
        return {"schema_version": 2, "items": [connection_view(row) for row in store.list_connections()
                                                if row["spec"].get("schema_version") == 2]}

    @app.get("/api/v2/coverage/connections/{connection_id}")
    def connection(connection_id: uuid.UUID, _actor=Depends(admin)):
        return connection_view(store.require_connection(connection_id), references=True)

    class _Run:
        """One collection run in the shape the setup summary reads a run in."""

        def __init__(self, row):
            self.id = row["id"]
            self.status = {"COMPLETE": "SUCCEEDED", "PARTIAL": "SUCCEEDED", "RUNNING": "RUNNING",
                           "WAITING": "RUNNING", "FAILED": "FAILED",
                           "CANCELLED": "CANCELLED"}.get(row["status"], "QUEUED")
            self.payload = {}
            self.created_at = row["started_at"]
            self.finished_at = row["finished_at"]

    def _setup_evidence(row):
        """Setup progress for a metadata connection.

        There is no content catalog, no target selection and no approved scan
        scope here, so those steps are not applicable rather than unfinished.
        Authentication is proved by a run the provider answered -- this path has
        no separate identity call to offer.
        """
        runs = [_Run(item) for item in store.connection_runs(row["id"], limit=50)["items"]]
        success = store.latest_success(row["id"])
        recent, failure = connection_setup.runs_of(runs, _iso)
        spec = row["spec"]
        return connection_setup.evidence(
            kind="metadata", connection_id=row["id"], enabled=row["enabled"],
            declaration={"product_type": spec.get("provider", "UNKNOWN").upper(),
                         "declared_at": _iso(row.get("created_at")),
                         # The spec itself is the declaration: a v2 connection
                         # names its origin, edition and tenancy when it is made.
                         "environment": {"deployment_type": spec.get("edition", ""),
                                         "api_base_url": spec.get("origin", ""),
                                         "account_kind": spec.get("tenant", "") if spec.get("tenant_confirmed") else ""}},
            authenticated_at=_iso(success["finished_at"]) if success else None,
            management_only=True, catalog=None, known_count=0,
            catalog_job_status="NOT_REQUESTED", auth="", profiles=[],
            checkpoint=(repo.get_setting(connection_setup.checkpoint_key("metadata", row["id"])) or {}).get("value"),
            iso=_iso, recent_run=recent, recent_failure=failure,
            probe="NOT_AVAILABLE")

    @app.get("/api/v2/coverage/connections/{connection_id}/setup")
    def connection_setup_evidence(connection_id: uuid.UUID, _actor=Depends(require_auth)):
        return {"schema_version": 2, "connection_id": str(connection_id),
                "onboarding": _setup_evidence(store.require_connection(connection_id))}

    @app.post("/api/v2/coverage/connections/{connection_id}/setup")
    def save_connection_setup(connection_id: uuid.UUID, body: dict, actor=Depends(admin)):
        """Record the administrator's own note about setup progress. Runs nothing."""
        row = store.require_connection(connection_id)
        current = _setup_evidence(row)
        try:
            saved = connection_setup.validate_checkpoint(body, current, set())
        except ValueError as exc:
            raise CoverageError(str(exc)) from None
        saved["saved_by"] = actor
        saved["saved_at"] = datetime.now(UTC).isoformat()
        repo.put_setting(connection_setup.checkpoint_key("metadata", row["id"]), saved, actor)
        return {"schema_version": 2, "connection_id": str(connection_id),
                "onboarding": _setup_evidence(row)}

    @app.get("/api/v2/coverage/connections/{connection_id}/runs")
    def connection_runs(connection_id: uuid.UUID, offset: int = Query(default=0, ge=0),
                        limit: int = Query(default=50, ge=1, le=500), _actor=Depends(require_auth)):
        return store.connection_runs(connection_id, offset=offset, limit=limit)

    def github_collection_and_checks(connection_id, *, finished_only=False, inventory_only=False):
        """The latest GitHub collection run and the installation check runs after it, newest first.

        An installation check run reads only this App's installations; it is an
        overlay on the collection before it, never the organization list itself.
        """
        from cremore_github_provider.metadata.snapshot import installation_check_run

        checks = []
        runs, reports = store.recent_run_reports(connection_id, limit=GITHUB_HISTORY_RUN_LIMIT + 1)
        for index, run in enumerate(runs):
            if index >= GITHUB_HISTORY_RUN_LIMIT:
                raise CoverageError("GITHUB_INSTALLATION_HISTORY_LIMIT_USE_RUN_PAGES")
            if finished_only and run["status"] not in {"COMPLETE", "PARTIAL"}:
                continue
            if not run["item_count"]:
                continue
            if inventory_only and not any(item.get("provenance", {}).get("operation") == "github.inventory"
                                          for item in reports[run["id"]]):
                continue
            if not installation_check_run(reports[run["id"]]):
                return run, checks
            checks.append(run)
        return None, checks

    @app.get("/api/v2/coverage/connections/{connection_id}/github-export-rows")
    def github_export_rows(connection_id: uuid.UUID, offset: int = Query(default=0, ge=0),
                           limit: int = Query(default=50, ge=1, le=100),
                           credential_type: str | None = Query(default=None, pattern=r"^[a-z_]{1,40}$"),
                           run_id: uuid.UUID | None = None, _actor=Depends(require_auth)):
        """Snapshot observations without stable IDs, never unique credential totals.

        Paging pins a run so a concurrent collection cannot mix two snapshots.
        An older or changed scope remains labelled historical, never absent.
        """
        from cremore_github_provider.metadata.exports import CREDENTIAL_TYPES
        from cremore_github_provider.metadata.normalization import record_values

        row = store.require_connection(connection_id)
        if row["spec"]["provider"] != "github":
            raise CoverageError("GITHUB_PROVIDER_REQUIRED")
        if credential_type and credential_type not in CREDENTIAL_TYPES:
            raise HTTPException(422, "GITHUB_EXPORT_TYPE_INVALID")
        latest, _ = github_collection_and_checks(connection_id, finished_only=True, inventory_only=True)
        selected = latest
        if run_id is not None:
            selected = store.run_detail(run_id, limit=0)["run"]
            if selected["connection_id"] != connection_id:
                raise HTTPException(404, "RUN_NOT_FOUND")
            if selected["status"] not in {"COMPLETE", "PARTIAL"}:
                raise HTTPException(409, "RUN_NOT_FINISHED")
        page = {"items": [], "total": 0, "offset": offset, "limit": limit, "next_offset": None}
        if selected:
            page = store.record_page(run_id=selected["id"], record_type="entity_observation",
                object_prefix="inventory:export:" + (credential_type + ":" if credential_type else ""),
                offset=offset, limit=limit)
        items = [{"id": str(item["id"]), "kind": item["body"]["identity"]["kind"],
                  "as_of": item["body"]["provenance"].get("provider_generated_at"),
                  "permissions": item["body"].get("permissions", []),
                  "metadata": {key: value for key, value in record_values(item["body"]).items()
                               if key != "inventory_id"}} for item in page["items"]]
        full = store.run_detail(selected["id"], limit=0)["run"] if selected else None
        current = bool(selected and latest and selected["id"] == latest["id"]
                       and selected["revision"] == row["revision"] and row["enabled"]
                       and scope_matches(full["contract"], row["spec"]))
        public_run = {key: selected[key] for key in ("id", "connection_id", "revision", "sequence", "status",
                      "reasons", "item_count", "started_at", "finished_at")} if selected else None
        return {**page, "items": items, "run": public_run, "current_revision": current,
                "count_basis": "SNAPSHOT_ROWS_NOT_UNIQUE_CREDENTIALS"}

    @app.get("/api/v2/coverage/connections/{connection_id}/github-organizations")
    def github_organizations(connection_id: uuid.UUID, offset: int = Query(default=0, ge=0),
                             limit: int = Query(default=50, ge=1, le=100), _actor=Depends(require_auth)):
        from cremore_github_provider.metadata.snapshot import organization_roster

        row = store.require_connection(connection_id)
        if row["spec"]["provider"] != "github":
            raise CoverageError("GITHUB_PROVIDER_REQUIRED")
        latest, checks = github_collection_and_checks(connection_id)
        # The spec names the reads an organization not read yet would start with.
        roster = organization_roster(store.iter_records(latest["id"]) if latest else [],
                                     spec=MetadataConnectionSpec.model_validate(row["spec"]),
                                     checks=github_check_records(store, checks))
        total = len(roster["items"])
        return {"schema_version": 2, "connection_id": connection_id, "run": latest,
                "current_revision": latest is None or latest["revision"] == row["revision"],
                "installation_checks": checks, "discovery": roster["discovery"], "app": roster["app"],
                "items": roster["items"][offset:offset + limit],
                "total": total, "offset": offset, "limit": limit,
                "next_offset": offset + limit if offset + limit < total else None}

    def github_audit_sources(row):
        """Join only approved sibling jobs with the same origin and explicit scope.

        A shared App, Enterprise name or token is not permission to join other
        connections. Changed/stopped siblings are excluded on every request,
        including cache hits. Legacy mixed collections remain self-contained.
        """
        from cremore.onboarding.store import ProviderConnectionStore, active_plans

        parents = ProviderConnectionStore(repo)
        parent_id = parents.parent_of("metadata", row["id"])
        parent = parents.get(parent_id) if parent_id else None
        candidates = {row["id"]: row}
        spec = row["spec"]
        if (parent is not None and row["enabled"] and parent["status"] != "DISABLED"
                and "inventory" in active_plans(parent)):
            for child in parents.children(parent_id):
                if child["kind"] != "metadata" or child["purpose"] != "inventory":
                    continue
                sibling = store.get(uuid.UUID(child["child_id"]))
                if sibling is None or not sibling["enabled"]:
                    continue
                other = sibling["spec"]
                if (other.get("schema_version") == 2 and other["provider"] == "github"
                        and other["origin"] == spec["origin"] and other["scopes"] == spec["scopes"]
                        and other["tenant"] == spec["tenant"]):
                    candidates[sibling["id"]] = sibling
        sources, runs = [], []
        for cid, candidate in sorted(candidates.items(), key=lambda item: str(item[0])):
            latest, _checks = github_collection_and_checks(cid, finished_only=True)
            current = latest is None or latest["revision"] == candidate["revision"]
            if latest is not None and current:
                full = store.run_detail(latest["id"], limit=1)["run"]
                current = scope_matches(full["contract"], candidate["spec"])
            # The requested collection can still show its own historical
            # evidence, explicitly labelled. It cannot borrow current siblings.
            if cid != row["id"] and not current:
                latest = None
            sources.append({"connection_id": cid, "run": latest, "current_revision": current,
                            "inventory": candidate["spec"].get("options", {}).get("github_inventory", True),
                            "audit": bool(candidate["spec"].get("options", {}).get("include_audit_events"))})
            if latest is not None:
                runs.append(latest)
        own = next(source for source in sources if source["connection_id"] == row["id"])
        if not own["current_revision"]:
            sources, runs = [own], [own["run"]] if own["run"] else []
        return sources, runs

    # Cache one immutable set of source runs; a new inventory OR audit snapshot
    # changes the key. Current ownership and scope are checked before reuse.
    audit_link_cache = {}

    @app.get("/api/v2/coverage/connections/{connection_id}/github-audit-links")
    def github_audit_links(connection_id: uuid.UUID,
                           relation: str | None = Query(default=None, pattern=r"^(target|associated|unmatched)$"),
                           credential_type: str | None = Query(default=None, pattern=r"^[a-z_]{1,40}$"),
                           offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
                           _actor=Depends(require_auth)):
        """Finished inventory and audit snapshots of the same approved scope, joined exactly."""
        from cremore_github_provider.metadata.audit_links import (
            RELATIONS,
            audit_link_rows,
            audit_links,
            link_inputs,
            select_rows,
        )

        row = store.require_connection(connection_id)
        if row["spec"]["provider"] != "github":
            raise CoverageError("GITHUB_PROVIDER_REQUIRED")
        sources, runs = github_audit_sources(row)
        latest = next(source["run"] for source in sources if source["connection_id"] == row["id"])
        key = tuple((run["id"], run["revision"]) for run in runs)
        entry = audit_link_cache.get("entry")
        if entry is not None and entry[0] == key:
            counts, everything = entry[1]
        else:
            result = audit_links(link_inputs(chain.from_iterable(store.iter_records(run["id"]) for run in runs)))
            counts, everything = result["counts"], audit_link_rows(result)
            audit_link_cache["entry"] = (key, (counts, everything))
        rows = select_rows(everything, relation=relation, credential_type=credential_type)
        return {"schema_version": 2, "connection_id": connection_id, "run": latest, "sources": sources, "counts": counts,
                "relation_counts": {name: sum(item["relation"] == name for item in everything) for name in RELATIONS},
                "credential_types": sorted({item["credential_type"] for item in everything if item.get("credential_type")}),
                "items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit,
                "next_offset": offset + limit if offset + limit < len(rows) else None}

    @app.post("/api/v2/coverage/connections/{connection_id}/github-installation-check", status_code=202)
    def github_installation_check(connection_id: uuid.UUID, body: GitHubInstallationCheck, actor=Depends(analyst)):
        """Re-read this App's installation on one organization, or its installation list, collecting nothing else.

        The organizations are the ones the latest collection of this revision knew;
        an organization it did not observe is refused. The job is an ordinary
        metadata job with an installation-check plan (the GitHub recollection).
        """
        from cremore_github_provider.metadata.adapter import plan_recollection

        row = store.require_connection(connection_id)
        if row["spec"]["provider"] != "github":
            raise CoverageError("GITHUB_PROVIDER_REQUIRED")
        previous, _checks = github_collection_and_checks(connection_id)
        if previous is None or previous["status"] == "RUNNING" or previous["revision"] != row["revision"]:
            raise CoverageError("GITHUB_INSTALLATION_CHECK_NEEDS_A_FINISHED_COLLECTION")
        plan_recollection(store.iter_records(previous["id"]), scope_id=body.org, operations=["installation_check"])
        with store.transaction() as conn:
            bound = TaskStore(repo)._bound(conn)
            current = MetadataStore(bound)._get(conn, "connections", connection_id, lock=True)
            if not current or not current["enabled"]:
                raise CoverageError("CONNECTION_DISABLED_OR_MISSING")
            if current["revision"] != previous["revision"]:
                raise CoverageError("CONNECTION_REVISION_CONFLICT")
            existing = connection_job(bound, connection_id, active=True)
            if existing is not None:
                return {"job_id": existing.id, "status": existing.status}
            job = bound.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
                "provider": "github", "coverage_connection_id": str(connection_id),
                "coverage_revision": current["revision"], "retry_from_run": str(previous["id"]),
                "retry_operations": ["installation_check"], "include_unverified": False,
                "retry_scope_id": body.org}))
            audit(bound, connection_id, actor, "METADATA_COLLECTION_REQUESTED",
                  "GITHUB_INSTALLATION_CHECK " + str(job.id))
        return {"job_id": job.id, "status": job.status}

    @app.patch("/api/v2/coverage/connections/{connection_id}")
    def change(connection_id: uuid.UUID, body: MetadataChange, actor=Depends(admin)):
        from cremore.onboarding.store import ProviderConnectionStore

        # On a team install a people directory is the sign-in IdP its provider connection names
        # (cremore.onboarding.sign_in): the collection that reads its people is not pointed anywhere else.
        team = getattr(settings, "auth_mode", "local") == "oidc"
        parent = ProviderConnectionStore(repo).parent_of("metadata", connection_id) if team else None
        owned = parent is not None
        with store.transaction() as conn:
            bound = TaskStore(repo)._bound(conn)
            current = MetadataStore(bound).require_connection(connection_id)
            if owned and body.enabled is True and "identity_status" in (current["spec"].get("capabilities") or []):
                # Turned back on only through its provider connection, which holds it to the sign-in IdP.
                from cremore.onboarding import sign_in

                record = ProviderConnectionStore(repo).get(parent)
                if record is None or record["status"] == "DISABLED" or sign_in.problem(
                        settings, record["provider"], record["target"], ["identity"], repo=repo, excluding=record["id"]):
                    raise CoverageError("PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION")
            spec = body.spec
            if spec is not None:
                # The credential and how it signs in belong to the provider connection
                # that owns this collection (PUT /api/v1/provider-connections/{id}/credential);
                # an edit keeps the references and the auth type it has.
                if (("secret_refs" in spec.model_fields_set and spec.secret_refs != current["spec"]["secret_refs"])
                        or spec.auth_type != current["spec"]["auth_type"]):
                    raise CoverageError("CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION")
                was = MetadataConnectionSpec.model_validate(current["spec"])
                if owned and "identity_status" in was.capabilities and (
                        (spec.provider, spec.origin, spec.tenant, spec.scopes, spec.options.api_path)
                        != (was.provider, was.origin, was.tenant, was.scopes, was.options.api_path)):
                    raise CoverageError("PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION")
                spec = MetadataConnectionSpec.model_validate({**spec.model_dump(), "secret_refs": current["spec"]["secret_refs"]})
                validate_spec(spec)
            row, token = MetadataStore(bound).change(connection_id, body.revision, actor, spec=spec,
                                                     enabled=body.enabled, rotate=body.rotate_token)
            audit(bound, connection_id, actor, "METADATA_CONNECTION_CHANGED", "REVISION_" + str(row["revision"]))
        return {**public_connection(row, include_references=True), "collector_token": token}

    @app.post("/api/v2/coverage/connections/{connection_id}/collect", status_code=202)
    def collect(connection_id: uuid.UUID, body: CollectRequest | None = None, actor=Depends(analyst)):
        request = body or CollectRequest()
        with store.transaction() as conn:
            bound = TaskStore(repo)._bound(conn)
            current_store = MetadataStore(bound)
            row = current_store._get(conn, "connections", connection_id, lock=True)
            if not row or not row["enabled"]:
                raise CoverageError("CONNECTION_DISABLED_OR_MISSING")
            spec = MetadataConnectionSpec.model_validate(row["spec"])
            collector = collector_for(spec.provider)
            collector.validate_spec(spec)
            if spec.provider == "gcp":
                from cremore.coverage.gcp_store import linked_source_disabled
                if linked_source_disabled(bound, connection_id):
                    raise CoverageError("GCP_SOURCE_DISABLED")
            payload = {"provider": spec.provider, "coverage_connection_id": str(connection_id), "coverage_revision": row["revision"]}
            if request.retry_from_run:
                previous = current_store.run_detail(uuid.UUID(request.retry_from_run), limit=1)["run"]
                if (previous["connection_id"] != connection_id or previous["revision"] != row["revision"]
                        or previous["status"] == "RUNNING" or not scope_matches(previous["contract"], spec)):
                    raise CoverageError("INCOMPATIBLE_RECOLLECTION_RUN")
                # The native validated plan selects failed observed targets;
                # an entire completed collection is never queued as a retry.
                collector.plan_recollection(bounded_records(current_store, previous["id"]),
                    scope_id=request.scope_id, operations=request.operations or None,
                    include_unverified=request.include_unverified)
                payload.update(retry_from_run=request.retry_from_run, retry_operations=request.operations,
                               include_unverified=request.include_unverified, retry_scope_id=request.scope_id)
            elif request.operations or request.include_unverified or request.scope_id:
                raise CoverageError("RETRY_RUN_REQUIRED")
            existing = connection_job(bound, connection_id, active=True)
            if existing is not None:
                return {"job_id": existing.id, "status": existing.status}
            if not request.retry_from_run:
                from cremore.coverage.github_exports import request_refusal

                if refusal := request_refusal(bound, spec):
                    raise CoverageError(refusal)
            job = bound.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload=payload))
            audit(bound, connection_id, actor, "METADATA_COLLECTION_REQUESTED", str(job.id))
        return {"job_id": job.id, "status": job.status}

    def running_collection(connection_id):
        store.require_connection(connection_id)
        job = connection_job(repo, connection_id, active=True)
        if job is None or job.status == "CANCELLING":
            raise CoverageError("METADATA_COLLECTION_NOT_RUNNING")
        return job

    @app.post("/api/v2/coverage/connections/{connection_id}/collect/pause")
    def pause_collection(connection_id: uuid.UUID, actor=Depends(analyst)):
        """Hold the collection after its current request; its run and checkpoint stay open."""
        job = running_collection(connection_id)
        repo.put_setting(pause_key(connection_id), {"job_id": str(job.id)}, actor)
        audit(repo, connection_id, actor, "METADATA_COLLECTION_PAUSED", str(job.id))
        return {"job_id": job.id, "status": job.status, "paused": True}

    @app.post("/api/v2/coverage/connections/{connection_id}/collect/resume")
    def resume_collection(connection_id: uuid.UUID, actor=Depends(analyst)):
        """Let a paused collection continue the same run from its last committed page."""
        job = running_collection(connection_id)
        repo.put_setting(pause_key(connection_id), {"job_id": None}, actor)
        audit(repo, connection_id, actor, "METADATA_COLLECTION_RESUMED", str(job.id))
        return {"job_id": job.id, "status": job.status, "paused": False}

    @app.post("/api/v2/coverage/connections/{connection_id}/collect/stop")
    def stop_collection(connection_id: uuid.UUID, actor=Depends(analyst)):
        """End the collection at its next request; its run closes as stopped, keeping what it committed."""
        job = running_collection(connection_id)
        stopped = repo.request_job_cancel(job.id) or job
        repo.put_setting(pause_key(connection_id), {"job_id": None}, actor)
        audit(repo, connection_id, actor, "METADATA_COLLECTION_STOP_REQUESTED", str(job.id))
        return {"job_id": stopped.id, "status": stopped.status}

    @app.get("/api/v2/coverage/collector/{connection_id}")
    def config(connection_id: uuid.UUID, _token=Depends(machine)):
        row = store.require_connection(connection_id)
        return {"connection_id": connection_id, "revision": row["revision"],
                "spec": {**MetadataConnectionSpec.model_validate(row["spec"]).model_dump(), "secret_refs": {}}, "auth_slots": sorted(row["spec"]["secret_refs"]),
                "contract": metadata_contract(MetadataConnectionSpec.model_validate(row["spec"])),
                "limitations": ["MACHINE_REQUIRES_EXPLICIT_RESOURCE_SCOPES"]}

    @app.post("/api/v2/coverage/collector/{connection_id}/runs")
    def start(connection_id: uuid.UUID, body: MetadataStart, token=Depends(machine)):
        return store.start(connection_id, body.revision, body.request_id, body.contract.model_dump(), token=token)

    @app.put("/api/v2/coverage/collector/{connection_id}/runs/{run_id}/batches")
    def append(connection_id: uuid.UUID, run_id: uuid.UUID, body: MetadataBatch, token=Depends(machine)):
        store.append(connection_id, run_id, body, token=token)
        return {"accepted": True, "index": body.index}

    @app.post("/api/v2/coverage/collector/{connection_id}/runs/{run_id}/finish")
    def finish(connection_id: uuid.UUID, run_id: uuid.UUID, body: MetadataFinish, token=Depends(machine)):
        return store.finish(connection_id, run_id, body, token=token)

    @app.get("/api/v2/coverage/inventory")
    def inventory(offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
                  provider: Provider | None = None, object_kind: ObjectKind | None = None, purpose: Purpose | None = None,
                  connection_id: uuid.UUID | None = None, q: str = Query(default="", max_length=256), principal=Depends(require_principal)):
        return public_metadata(store.inventory(offset=offset, limit=limit, provider=provider or "", object_kind=object_kind or "",
                               purpose=purpose or "", connection_id=connection_id, q=q, exclude_purposes=hidden(principal)),
                               people(principal))

    @app.get("/api/v2/coverage/inventory/{entity_id}")
    def detail(entity_id: uuid.UUID, offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
               principal=Depends(require_principal)):
        result = store.entity_detail(entity_id, offset=offset, limit=limit)
        if result["entity"]["purpose"] in hidden(principal):
            # An entity id can be computed from what it names: hidden reads as absent, never as refused.
            raise CoverageError("ENTITY_NOT_FOUND")
        return public_metadata(result, people(principal))

    @app.get("/api/v2/coverage/events")
    def events(offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
               provider: Provider | None = None, connection_id: uuid.UUID | None = None,
               event_type: str = Query(default="", max_length=128), principal=Depends(require_principal)):
        # A provider's own event history, kept apart from CreMore's audit log:
        # nobody here performed these, and the provider's retention bounds them.
        return store.provider_events(offset=offset, limit=limit, provider=provider or "", event_type=event_type,
                                     connection_id=connection_id, exclude_purposes=hidden(principal))

    @app.get("/api/v2/coverage/findings/{finding_id}")
    def finding(finding_id: uuid.UUID, offset: int = Query(default=0, ge=0),
                limit: int = Query(default=50, ge=1, le=500), _actor=Depends(require_auth)):
        # Issuer evidence is separate from the finding's vault-storage report.
        # The response contains evidence labels, never private comparison data.
        return finding_links(store, repo, finding_id, offset=offset, limit=limit)

    @app.get("/api/v2/coverage/runs/{run_id}")
    def run(run_id: uuid.UUID, offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
            record_type: str = Query(default="", pattern=r"^(?:entity_observation|relation|provider_event|operation_report)?$"),
            principal=Depends(require_principal)):
        result = store.run_detail(run_id, offset=offset, limit=limit, record_type=record_type)
        people_run(result["run"], principal)
        return public_metadata(result, people(principal))

    @app.get("/api/v2/coverage/runs/{run_id}/export")
    def export(run_id: uuid.UUID, offset: int = Query(default=0, ge=0), limit: int = Query(default=250, ge=1, le=500),
               format: str = Query(default="records", pattern=r"^(records|native)$"), principal=Depends(require_principal)):
        result = store.run_detail(run_id, offset=offset, limit=limit)
        people_run(result["run"], principal)
        if format == "records":
            return public_metadata(result, people(principal))
        spec = run_spec(result["run"])
        adapter = adapter_for(spec.provider)
        records = bounded_records(store, run_id)
        if callable(getattr(adapter, "native_snapshots", None)):
            return public_metadata({"schema_version": 2, "run": result["run"], "snapshots": adapter.native_snapshots(records)}, people(principal))
        if callable(getattr(adapter, "export_records", None)):
            return public_metadata({"schema_version": 2, "run": result["run"], "snapshot": adapter.export_records(records, spec=spec)}, people(principal))
        raise CoverageError("NATIVE_EXPORT_UNSUPPORTED")

    @app.get("/api/v2/coverage/runs/{run_id}/compare/{other_id}")
    def compare(run_id: uuid.UUID, other_id: uuid.UUID, scope_id: str | None = Query(default=None, max_length=512),
                principal=Depends(require_principal)):
        before, after = [store.run_detail(rid, limit=1)["run"] for rid in (run_id, other_id)]
        people_run(before, principal)
        spec = run_spec(before)
        if (before["connection_id"] != after["connection_id"] or before["revision"] != after["revision"]
                or not same_contract(before["contract"], after["contract"]) or before["sequence"] >= after["sequence"]
                or not before["finished_at"] or not after["finished_at"]):
            raise CoverageError("INCOMPATIBLE_COMPARISON_RUNS")
        collector = collector_for(spec.provider)
        if not collector.supports_comparison:
            raise CoverageError("METADATA_COMPARISON_UNSUPPORTED")
        result = collector.compare_records(
            bounded_records(store, run_id), bounded_records(store, other_id), spec=spec, scope_id=scope_id)
        return public_metadata({"schema_version": 2, "before_run_id": run_id, "after_run_id": other_id, "comparison": result},
                               people(principal))
