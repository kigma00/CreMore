"""What the host of a finding's exposed files says about them: the owners CODEOWNERS names, who last
changed each file or page and which collaborators or members its provider reports.

A worker job (``finding-context``) reads it for up to MAX_LOCATIONS current exposures of the finding in a
host whose source module offers ``exposure_context`` (provider capabilities: docs/EXPOSURE_ACCESS.md),
with that source connection's own credential or approved account scanner,
and keeps one context per finding. The worker's maintenance queues the open findings that
have none or an old one (SWEEP_BATCH every SWEEP_SECONDS); an analyst can ask for one at once. Nothing is
written to the code host. What is kept: the owners CODEOWNERS names for each file (never the file), one
author per file (name, email, login, time, commit) and the people each repository lists (login, name,
role) and typed bounded grant/restriction metadata -- at most MAX_PEOPLE principals.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import re
import uuid

from sqlalchemy import JSON, Column, DateTime, Table, Text, Uuid, select

from cremore.governance.codeowners import owners_for, parse

JOB_KIND = "finding-context"
MAX_LOCATIONS = 5
MAX_LOCATION_RECORDS = 100
MAX_PEOPLE = 300
MAX_PAGED_PEOPLE = 10_000
MAX_CONTEXT_REQUESTS = 700
MAX_OWNERS = 50
SWEEP_KEY = "governance:finding-context"
SWEEP_SECONDS = 600
SWEEP_BATCH = 20
MAX_AGE = _dt.timedelta(days=7)
_OPEN = ("OPEN", "ACKNOWLEDGED")
_GONE = ("REMOVED", "FALSE_POSITIVE")
_STATUS = re.compile(r"[A-Z_]{2,40}")
_BASIS = re.compile(r"[A-Z][A-Z0-9_]{1,60}")
_ROLE = re.compile(r"[a-z_]{2,20}")
_SHA = re.compile(r"[0-9a-f]{40,64}")
_PAGE = re.compile(r"[0-9a-f]{32}")
_VERSION = re.compile(r"[0-9]{1,12}")


def register_tables(metadata):
    if "finding_contexts" in metadata.tables:
        return metadata.tables["finding_contexts"]
    return Table(
        "finding_contexts", metadata,
        Column("finding_id", Uuid, primary_key=True),
        # COMPLETE / PARTIAL: read; UNSUPPORTED: no exposure in a host that can say; FAILED: nothing read.
        Column("status", Text, nullable=False),
        Column("body", JSON, nullable=False),
        # What a credential row shows (summary()), kept with the body so the list never reads the bodies.
        Column("summary", JSON, nullable=False),
        Column("collected_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))


def _now():
    return _dt.datetime.now(_dt.UTC)


class ContextStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "finding_contexts"):
                    repo.finding_contexts = {}
        else:
            from cremore.db.schema import metadata

            self.table = register_tables(metadata)

    def _read(self, columns, finding_ids=None) -> dict:
        """``{finding_id: {column: value}}`` for these findings (every finding when None), 500 ids a query."""
        wanted = None if finding_ids is None else list({uuid.UUID(str(value)) for value in finding_ids})
        if self.engine is None:
            with self.repo._lock:
                return {key: {name: copy.deepcopy(row[name]) for name in columns} for key, row in self.repo.finding_contexts.items()
                        if wanted is None or key in wanted}
        statement = select(self.table.c.finding_id, *(self.table.c[name] for name in columns))
        out = {}
        with self.engine.connect() as conn:
            for chunk in [None] if wanted is None else [wanted[start:start + 500] for start in range(0, len(wanted), 500)]:
                query = statement if chunk is None else statement.where(self.table.c.finding_id.in_(chunk))
                for row in conn.execute(query).mappings():
                    # SQLite gives back naive times; they were written in UTC.
                    out[row["finding_id"]] = {name: row[name].replace(tzinfo=_dt.UTC)
                                              if isinstance(row[name], _dt.datetime) and row[name].tzinfo is None else row[name]
                                              for name in columns}
        return out

    def get(self, finding_id):
        """The whole row for one finding, or None."""
        found = self._read(("status", "body", "summary", "collected_at", "updated_at"), [finding_id])
        row = found.get(uuid.UUID(str(finding_id)))
        return None if row is None else {"finding_id": uuid.UUID(str(finding_id)), **row}

    def summaries(self, finding_ids) -> dict:
        """``{finding_id: summary}``: what the credential rows show, without the bodies."""
        return {key: row["summary"] for key, row in self._read(("summary",), finding_ids).items()}

    def ages(self) -> dict:
        """``{finding_id: collected_at}`` for every kept context (the sweep reads no bodies)."""
        return {key: row["collected_at"] for key, row in self._read(("collected_at",)).items()}

    def save(self, finding_id, status, body, now=None) -> dict:
        now = now or _now()
        row = {"finding_id": uuid.UUID(str(finding_id)), "status": status, "body": body,
               "summary": summary({"body": body, "collected_at": now}), "collected_at": now, "updated_at": now}
        if self.engine is None:
            with self.repo._lock:
                self.repo.finding_contexts[row["finding_id"]] = copy.deepcopy(row)
            return row
        with self.engine.begin() as conn:
            statement = self.repo._insert(conn, self.table).values(**row)
            conn.execute(statement.on_conflict_do_update(
                index_elements=[self.table.c.finding_id],
                set_={name: value for name, value in row.items() if name != "finding_id"}))
        return row


# --- reading ------------------------------------------------------------------------------------------


def _text(value, limit=200):
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())[:limit]
    return value if value and value.isprintable() else None


def _places(exposures):
    """Bounded current locations, including sources whose access API is unsupported."""
    out, seen = [], set()
    for exposure in exposures:
        if exposure.status in _GONE:
            continue
        meta = exposure.metadata or {}
        commit = meta.get("commit_sha") or exposure.object_version or ""
        key = (exposure.source_type, str(exposure.source_connection_id), exposure.resource_name, exposure.location)
        if key in seen:
            continue
        seen.add(key)
        place = {"exposure_id": str(exposure.id), "source_type": exposure.source_type,
                 "connection_id": exposure.source_connection_id, "repository": exposure.resource_name,
                 "path": exposure.location, "commit": commit if _SHA.fullmatch(str(commit)) else ""}
        place["source_connection_id"] = str(exposure.source_connection_id) if exposure.source_connection_id else None
        place["object_version"] = _text(exposure.object_version, 1024)
        from cremore.sources.registry import BY_SOURCE

        module = BY_SOURCE.get(exposure.source_type)
        coordinate = exposure.resource_name + ("|" + exposure.location if getattr(module, "ACCESS_CONTEXT_SCOPE", "repository") == "location" else "")
        place["access_key"] = str(uuid.uuid5(uuid.NAMESPACE_URL,
            f"cremore:location-access:{exposure.source_type}|{exposure.source_connection_id}|{coordinate}"))
        # A page's own id (Notion), and a numbered version (a TFVC changeset, a Confluence page version).
        if _PAGE.fullmatch(str(meta.get("page_id") or "")):
            place["page_id"] = meta["page_id"]
        if _VERSION.fullmatch(str(exposure.object_version or "")):
            place["version"] = str(exposure.object_version)
        out.append(place)
        if len(out) >= MAX_LOCATION_RECORDS:
            break
    return out


def _codeowners(found, path):
    status = found.get("status") if isinstance(found, dict) else None
    out = {"status": status if isinstance(status, str) and _STATUS.fullmatch(status) else "UNAVAILABLE"}
    if isinstance(found, dict) and isinstance(found.get("path"), str):
        out["path"] = found["path"][:200]
    if out["status"] == "OBSERVED" and isinstance(found.get("text"), str):
        out["owners"] = owners_for(parse(found["text"]), path)[:MAX_OWNERS]
        if not out["owners"]:
            out["status"] = "NO_MATCH"
    return out


def _author(found):
    if not isinstance(found, dict) or found.get("status") != "OBSERVED":
        status = found.get("status") if isinstance(found, dict) else None
        return {"status": status if isinstance(status, str) and _STATUS.fullmatch(status) else "UNAVAILABLE"}
    email = _text(found.get("email"), 254)
    return {"status": "OBSERVED", "name": _text(found.get("name")), "login": _text(found.get("login"), 100),
            "email": email if email and "@" in email else None, "at": _text(found.get("at"), 40),
            "commit": found.get("commit") if _SHA.fullmatch(str(found.get("commit") or "")) else None}


def _members(found):
    status = found.get("status") if isinstance(found, dict) else None
    out = {"status": status if isinstance(status, str) and _STATUS.fullmatch(status) else "UNAVAILABLE",
           "basis": found.get("basis") if isinstance(found, dict) and isinstance(found.get("basis"), str)
           and _BASIS.fullmatch(found["basis"]) else None}
    if out["status"] == "OBSERVED" or isinstance(found, dict) and found.get("people"):
        people = []
        rows = found.get("people") if isinstance(found.get("people"), list) else []
        malformed = False
        for row in rows[:MAX_PEOPLE]:
            login = _text(row.get("login"), 100) if isinstance(row, dict) else None
            if login is None:
                malformed = True
                continue
            role = row.get("role")
            people.append({"login": login, "name": _text(row.get("name")),
                           "role": role if isinstance(role, str) and _ROLE.fullmatch(role) else None,
                           "principal_id": _text(row.get("principal_id"), 256),
                           "principal_kind": row.get("principal_kind") if row.get("principal_kind") in (
                               "USER", "GROUP", "SERVICE_PRINCIPAL", "PUBLIC", "AUTHENTICATED", "POLICY", "UNKNOWN") else "UNKNOWN",
                           "permission": _text(row.get("permission"), 256),
                           "effect": row.get("effect") if row.get("effect") in ("ALLOW", "DENY", "RESTRICT") else "UNKNOWN",
                           "read_access": row.get("read_access") if row.get("read_access") in ("REPORTED", "UNKNOWN") else "UNKNOWN"})
        out["people"] = people
        out["truncated"] = bool(found.get("truncated")) or len(rows) > MAX_PEOPLE or malformed
    return out


def _scope_reason(repo, finding, exposure, module, *, original=None):
    """Re-use the approved rescan boundary before reading location metadata."""
    from cremore.db.catalog_store import CatalogStore
    from cremore.onboarding.store import child_feature_enabled
    from cremore.scanning import scope
    from cremore.sources.registry import RESOURCE_SOURCE

    cid = exposure.source_connection_id
    connection = repo.get_connection(cid) if cid else None
    if connection is None:
        return "SOURCE_CONNECTION_GONE"
    if connection.provider != module.PROVIDER:
        return "SOURCE_CONNECTION_MISMATCH"
    if (connection.status == "DISABLED" or (connection.credential_evidence or {}).get("revoked_at")
            or not child_feature_enabled(repo, "source", cid, "exposure")):
        return "SOURCE_CONNECTION_PAUSED"
    auth = scope.auth_revision("source", connection)
    if original is not None and (auth != scope.auth_revision("source", original) or connection.config != original.config):
        return "SOURCE_AUTHORIZATION_CHANGED"
    types = [rt for rt, source in RESOURCE_SOURCE.items() if source == exposure.source_type]
    references = [exposure.resource_name]
    if exposure.source_type == "notion":
        page = scope._notion_id(exposure.location)
        references = [page]
        if _PAGE.fullmatch(page):
            references.append(str(uuid.UUID(page)))
    ids = [scope.resource_id("source", cid, rt, ref) for rt in types for ref in references]
    catalog = CatalogStore(repo).selected("source", cid, ids)
    if catalog is None or catalog.auth_revision != auth:
        return "SOURCE_SCOPE_NOT_APPROVED"
    for profile in repo.list_scope_profiles("source", cid):
        if (profile.state != "READY" or not profile.approved_at or not profile.approved_by
                or scope.profile_state(profile, auth=auth, enabled=True) != "READY"):
            continue
        try:
            root, _target = scope.rescan_target(finding, exposure, profile, catalog)
        except (scope.ScopeError, StopIteration):
            continue
        if any(item["id"] == root["resource_id"] and scope.selectable(item) for item in catalog.items):
            return None
        # Notion descendants are approved by their parent but resolved as pages.
        if exposure.source_type == "notion" and any(scope.selectable(item) for item in catalog.items):
            return None
    return "SOURCE_SCOPE_NOT_APPROVED"


class _ScopedClient:
    """Check current source authorization again at every provider HTTP request."""
    def __init__(self, client, check):
        self.client, self.check = client, check

    def __enter__(self):
        self.client.__enter__()
        return self

    def __exit__(self, *args):
        return self.client.__exit__(*args)

    def __getattr__(self, name):
        method = getattr(self.client, name)
        if name not in ("stream", "request"):
            return method
        def guarded(*args, **kwargs):
            self.check()
            return method(*args, **kwargs)
        return guarded


def _access(place, found, now, *, status=None):
    found = found if isinstance(found, dict) else {}
    members = _members(found)
    if status:
        members = {"status": status, "basis": None}
    basis = members.get("basis")
    evidence = {"GITHUB_REPOSITORY_COLLABORATORS": "PROVIDER_COLLABORATORS",
                "GITLAB_PROJECT_MEMBERS": "PROVIDER_MEMBERSHIP",
                "CONFLUENCE_PAGE_RESTRICTIONS": "PROVIDER_RESTRICTIONS",
                "BITBUCKET_REPOSITORY_PERMISSIONS": "PROVIDER_GRANTS",
                "AZURE_DEVOPS_REPOSITORY_ACL": "PROVIDER_GRANTS",
                "GCS_BUCKET_IAM_OBJECT_ACL": "PROVIDER_GRANTS",
                "AZURE_BLOB_CONTAINER_ACCESS": "PROVIDER_GRANTS",
                "AWS_S3_POLICY_ACL": "PROVIDER_GRANTS"}.get(basis, "UNSUPPORTED")
    observed = members["status"] == "OBSERVED" or bool(members.get("people"))
    limitations = ["NOT_ACCESS_HISTORY", "PUBLIC_OR_LINK_ACCESS_NOT_ENUMERATED", "TOKENS_AND_APPS_NOT_ENUMERATED"]
    if evidence == "PROVIDER_MEMBERSHIP":
        limitations.append("MEMBERSHIP_NOT_EFFECTIVE_READ_ACCESS")
    limitations.extend(code for code in (found.get("limitations") or []) if isinstance(found, dict)
                       and isinstance(code, str) and _STATUS.fullmatch(code))
    return {"access_key": place["access_key"], "source_connection_id": place["source_connection_id"],
            "source_label": place.get("source_label"),
            "source_type": place["source_type"], "repository": place["repository"], **members,
            "evidence_kind": evidence, "observed_at": now.isoformat() if observed else None,
            "visibility": found.get("visibility") if found.get("visibility") in ("PUBLIC", "INTERNAL", "PRIVATE") else "UNKNOWN",
            "completeness": "PARTIAL" if observed and (members.get("truncated") or members["status"] != "OBSERVED") else "COMPLETE" if observed
                else "UNSUPPORTED" if members["status"] == "UNSUPPORTED" else "UNKNOWN",
            "limitations": list(dict.fromkeys(limitations)),
            **({"next_page": found["next_page"]} if basis in ("GITHUB_REPOSITORY_COLLABORATORS", "GITLAB_PROJECT_MEMBERS")
               and type(found.get("next_page")) is int and 1 < found["next_page"] <= 100 else {})}


def _access_pin(connection):
    from cremore.scanning.scope import auth_revision

    return hashlib.sha256(json.dumps([auth_revision("source", connection), connection.config],
                                    sort_keys=True, default=str).encode()).hexdigest()


def _continued_access(previous, current):
    """Append normalized principals only within one authorized collection."""
    people = {person["login"].casefold(): person for person in previous.get("people", [])}
    people.update({person["login"].casefold(): person for person in current.get("people", [])})
    limits = set(previous.get("limitations", [])) - {"MEMBER_PAGE_LIMIT"}
    limits.update(current.get("limitations", []))
    limits.add("PAGED_LIST_NOT_ATOMIC")
    current["people"] = list(people.values())[:MAX_PAGED_PEOPLE]
    current["observed_at"] = current.get("observed_at") or previous.get("observed_at")
    if not current.get("basis"):
        for field in ("basis", "evidence_kind", "visibility"):
            current[field] = previous.get(field)
    if len(people) > MAX_PAGED_PEOPLE:
        limits.add("MEMBER_PAGE_LIMIT")
        current.pop("next_page", None)
    if (len(people) > MAX_PAGED_PEOPLE or "MALFORMED_MEMBER_ROWS" in limits
            or current.get("status") != "OBSERVED"):
        current.update(truncated=True, completeness="PARTIAL")
    current["limitations"] = sorted(limits)
    return current


def _same_location(left, right):
    return all(left.get(field) == right.get(field) for field in (
        "access_key", "source_connection_id", "source_type", "repository", "path", "commit", "object_version"))


def read(repo, finding_id, *, secret_resolver=None, http_client_factory=None, aws_sessions=None,
         previous=None, pins=None, before_request=None):
    """``(status, body)`` for one finding, read from its code hosts; None when the finding is gone."""
    from cremore.secretstore.resolver import inject_secret
    from cremore.sources.registry import BY_SOURCE

    rows = list(repo.findings_with_exposures([uuid.UUID(str(finding_id))]))
    if not rows:
        return None
    finding, _credential, exposures = rows[0]
    places = _places(exposures)
    by_id = {str(exposure.id): exposure for exposure in exposures}
    total = len({(e.source_type, str(e.source_connection_id), e.resource_name, e.location)
                 for e in exposures if e.status not in _GONE})
    queried = 0
    locations, repositories, reasons = [], {}, set()
    prior_locations = {row["exposure_id"]: row for row in (previous or {}).get("locations", [])}
    prior_access = {row["access_key"]: row for row in (previous or {}).get("repositories", [])}
    pins = pins if pins is not None else {}
    for place in places:
        module = BY_SOURCE.get(place["source_type"])
        connection = copy.deepcopy(repo.get_connection(place["connection_id"])) if place["connection_id"] else None
        place["source_label"] = _text(connection.name) if connection else None
        entry = {key: value for key, value in place.items() if key != "connection_id"}
        key = place["access_key"]
        now = _now()
        def unavailable(status, reason, *, prior=None, prior_location=None, entry=entry, key=key, place=place, now=now):
            reasons.add(reason)
            locations.append({**entry, "context_status": status,
                              "codeowners": prior_location["codeowners"] if prior_location else {"status": status},
                              "author": prior_location["author"] if prior_location else {"status": status}})
            if status == "BLOCKED" or key not in repositories:
                repositories[key] = _access(place, {}, now, status=status)
                if prior:
                    repositories[key] = _continued_access(prior, repositories[key])
        if module is None or not callable(getattr(module, "exposure_context", None)):
            unavailable("UNSUPPORTED", "SOURCE_ACCESS_UNSUPPORTED")
            continue
        exposure = by_id[place["exposure_id"]]
        if reason := _scope_reason(repo, finding, exposure, module, original=connection):
            unavailable("BLOCKED", reason)
            continue
        pin = _access_pin(connection)
        if key in pins and pins[key] != pin:
            unavailable("BLOCKED", "SOURCE_AUTHORIZATION_CHANGED")
            continue
        pins[key] = pin
        prior = prior_access.get(key)
        prior_location = prior_locations.get(place["exposure_id"])
        if prior_location and not _same_location(prior_location, entry):
            prior = prior_location = None
        if (prior and prior_location and not prior.get("next_page")
                and prior["status"] == "OBSERVED" and prior_location["context_status"] == "OBSERVED"):
            locations.append(prior_location)
            repositories[key] = prior
            queried += 1
            if prior.get("truncated"):
                reasons.add("CONTEXT_MEMBERS_PARTIAL")
            continue
        if queried >= MAX_LOCATIONS:
            unavailable("LIMIT_REACHED", "CONTEXT_LOCATION_LIMIT")
            continue
        def check_scope(exposure=exposure, module=module, connection=connection):
            if before_request is not None:
                before_request()
            if _scope_reason(repo, finding, exposure, module, original=connection):
                raise ValueError("SOURCE_SCOPE_NOT_APPROVED")
        def client_factory(check=check_scope):
            if http_client_factory:
                raw = http_client_factory()
            else:
                import httpx

                raw = httpx.Client(timeout=15, follow_redirects=False)
            return _ScopedClient(raw, check)
        try:
            payload = {**module.job_payload(connection.config), "secret_ref": connection.secret_ref,
                       "source_type": module.SOURCE_TYPE, "provider": module.PROVIDER}
            from cremore.onboarding.credential_access import resolver_for_child

            resolver = resolver_for_child(repo, "content", connection.id, secret_resolver, payload=payload,
                                          job_kind=module.job_kind(connection.config))
            payload = inject_secret(module.job_kind(connection.config), payload, resolver,
                                    github_client_factory=client_factory, http_client_factory=client_factory)
        except Exception:  # noqa: BLE001 -- a credential that cannot be read is a reason, never its text
            unavailable("UNAVAILABLE", "SOURCE_CREDENTIAL_UNAVAILABLE", prior=prior, prior_location=prior_location)
            continue
        client = client_factory()
        try:
            queried += 1
            found = module.exposure_context(payload, place, http_client=client,
                members=key not in repositories, **({"aws_sessions": aws_sessions, "check_scope": check_scope}
                    if getattr(module, "CONTEXT_AWS_SESSION", False) else {}),
                **({"member_page": prior["next_page"]}
                   if prior and prior.get("next_page") and getattr(module, "CONTEXT_MEMBER_PAGING", False) else {}))
            if not isinstance(found, dict):
                reasons.add("SOURCE_READ_FAILED")
                found = {}
        except Exception:  # noqa: BLE001 -- one host's failure leaves the others
            reasons.add("SOURCE_READ_FAILED")
            found = {}
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()
        if reason := _scope_reason(repo, finding, exposure, module, original=connection):
            unavailable("BLOCKED", reason)
            continue
        location = {**entry, "context_status": "OBSERVED" if found or prior_location else "UNAVAILABLE",
                    "codeowners": _codeowners(found.get("codeowners"), place["path"]) if "codeowners" in found or not prior_location
                        else prior_location["codeowners"],
                    "author": _author(found.get("author")) if "author" in found or not prior_location else prior_location["author"]}
        locations.append(location)
        if "members" in found:
            repositories[key] = _access(place, found["members"], _now())
            if prior and prior.get("next_page") and getattr(module, "CONTEXT_MEMBER_PAGING", False):
                repositories[key] = _continued_access(prior, repositories[key])
        elif key not in repositories:
            repositories[key] = _access(place, {}, now, status="UNSUPPORTED" if found else "UNAVAILABLE")
            if prior and prior.get("next_page") and getattr(module, "CONTEXT_MEMBER_PAGING", False):
                repositories[key] = _continued_access(prior, repositories[key])
        if repositories[key].get("truncated"):
            reasons.add("CONTEXT_MEMBERS_PARTIAL")
        if repositories[key]["status"] == "UNSUPPORTED":
            reasons.add("SOURCE_ACCESS_UNSUPPORTED")
        for part in (location["codeowners"], location["author"], repositories.get(key) or {}):
            if part.get("status") in ("FORBIDDEN", "UNAVAILABLE", "TRUNCATED"):
                reasons.add("CONTEXT_" + part["status"])
    if total > len(places):
        reasons.add("CONTEXT_LOCATION_LIMIT")
    if not places or all(location["context_status"] == "UNSUPPORTED" for location in locations):
        status = "UNSUPPORTED"
    elif not any(part.get("status") == "OBSERVED" or part.get("people") for location in locations
                 for part in (location["author"], location["codeowners"], repositories[location["access_key"]])):
        status = "FAILED"
    else:
        status = "PARTIAL" if reasons else "COMPLETE"
    return status, {"locations": locations, "repositories": list(repositories.values()), "reasons": sorted(reasons),
                    "location_count": total, "queried_locations": queried,
                    "unqueried_locations": total - queried, "omitted_locations": total - len(places)}


def collect(repo, finding_id, *, secret_resolver=None, http_client_factory=None, aws_sessions=None, now=None):
    """Read one finding's context and keep it; returns the saved row (None when the finding is gone)."""
    found = read(repo, finding_id, secret_resolver=secret_resolver, http_client_factory=http_client_factory, aws_sessions=aws_sessions)
    return None if found is None else ContextStore(repo).save(finding_id, *found, now)


def run(worker, job, task, write_context):
    """Commit a bounded chunk and its cursor together under the worker lease."""
    from cremore.collectors.base import CollectorError
    from cremore.db.task_store import TaskStore
    from cremore.sources.registry import BY_SOURCE

    finding_id = (job.payload or {}).get("finding_id")
    state = copy.deepcopy(task.get("checkpoint") or {})
    state.setdefault("started_at", _now().isoformat())
    previous = None
    if state.get("saved_at"):
        saved = ContextStore(worker.repo).get(finding_id)
        if saved is None or _iso(saved["collected_at"]) != state["saved_at"]:
            raise CollectorError("CONTEXT_COLLECTION_CHANGED")
        previous = saved["body"]

    def before_request():
        if (state.get("requests", 0) >= MAX_CONTEXT_REQUESTS
                or _now() - _dt.datetime.fromisoformat(state["started_at"]) > _dt.timedelta(hours=1)):
            state["limit_reached"] = True
            raise CollectorError("CONTEXT_BUDGET_REACHED")
        state["requests"] = state.get("requests", 0) + 1
        with write_context() as bound:
            TaskStore(bound).checkpoint(task["id"], task["token"], state)

    found = read(worker.repo, finding_id, secret_resolver=worker.metadata_secret_resolver,
                 http_client_factory=worker.http_client_factory, aws_sessions=getattr(worker, "aws_sessions", None),
                 previous=previous, pins=state.setdefault("pins", {}), before_request=before_request)
    pending = False
    with write_context() as repo:
        if found is not None:
            status, body = found
            # Recheck the source and approved location inside the final write,
            # including authorization changes after the last HTTP response.
            batches = list(repo.findings_with_exposures([uuid.UUID(str(finding_id))]))
            if not batches:
                raise CollectorError("CONTEXT_FINDING_GONE")
            finding, _, exposures = batches[0]
            by_id = {str(exposure.id): exposure for exposure in exposures if exposure.status not in _GONE}
            places = {place["exposure_id"]: place for place in _places(exposures)}
            access = {item["access_key"]: item for item in body["repositories"]}
            for location in body["locations"]:
                if (location["context_status"] != "OBSERVED"
                        and not access.get(location["access_key"], {}).get("people")):
                    continue
                exposure = by_id.get(location["exposure_id"])
                module = BY_SOURCE.get(location["source_type"])
                connection = repo.get_connection(exposure.source_connection_id) if exposure else None
                if (not connection or not module or not _same_location(location, places.get(location["exposure_id"], {}))
                        or _scope_reason(repo, finding, exposure, module)
                        or _access_pin(connection) != state["pins"].get(location["access_key"])):
                    raise CollectorError("SOURCE_AUTHORIZATION_CHANGED")
            if state.get("limit_reached"):
                status = "PARTIAL"
                body["reasons"] = sorted(set(body["reasons"]) | {"CONTEXT_BUDGET_REACHED"})
                for access in body["repositories"]:
                    access.pop("next_page", None)
            pending = any(access.get("next_page") for access in body["repositories"])
            saved = ContextStore(repo).save(finding_id, status, body)
            state["saved_at"] = _iso(saved["collected_at"])
            TaskStore(repo).checkpoint(task["id"], task["token"], state)
        if not pending:
            TaskStore(repo).finish(task["id"], task["token"], {"requests": state.get("requests", 0)})
    if pending:
        worker.runtime.tasks.defer(task["id"], task["token"], "CONTEXT_PAGINATION_PENDING", delay_seconds=1)


def _active(repo, finding_id):
    for job in repo.list_jobs(500):
        if job.kind == JOB_KIND and (job.payload or {}).get("finding_id") == str(finding_id) \
                and job.status in ("QUEUED", "RUNNING"):
            return job
    return None


def enqueue(repo, finding_id):
    """Queue a context read for this finding, or return the one already waiting or running."""
    from cremore.domain.models import ScanJob

    return _active(repo, finding_id) or repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"finding_id": str(finding_id)}))


def sweep(repo, *, now=None) -> int:
    """Queue reads for open findings in code hosts that have no context, or an old one; one replica a slot."""
    from cremore.sources.registry import BY_SOURCE

    now = now or _now()
    if not repo.claim_slot(SWEEP_KEY, int(now.timestamp()) // SWEEP_SECONDS, "worker"):
        return 0
    known = ContextStore(repo).ages()
    due = [finding.id for finding in repo.list_findings() if finding.workflow_status in _OPEN
           and (known.get(finding.id) is None or known[finding.id] < now - MAX_AGE)]
    queued = 0
    for finding, _credential, exposures in repo.findings_with_exposures(due[:SWEEP_BATCH * 5]):
        if queued >= SWEEP_BATCH:
            break
        if any(callable(getattr(BY_SOURCE.get(exposure.source_type), "exposure_context", None))
               and exposure.status not in _GONE for exposure in exposures):
            enqueue(repo, finding.id)
            queued += 1
    return queued


# --- what the API shows --------------------------------------------------------------------------------


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def review_context(row) -> dict:
    """The ownership review's CODEOWNERS part: the first location's owners."""
    if row is None:
        return {"status": "NOT_COLLECTED", "basis": "CODEOWNERS_DECLARATION", "file_match": False, "candidates": []}
    first = next(iter(row["body"].get("locations") or []), None)
    if first is None:
        return {"status": "UNSUPPORTED", "basis": "CODEOWNERS_DECLARATION", "file_match": False, "candidates": [],
                "collected_at": _iso(row["collected_at"])}
    codeowners = first.get("codeowners") or {}
    # A GitLab role (@@maintainer) is neither a team to assign nor a person.
    owners = [item for item in codeowners.get("owners") or [] if item["kind"] != "role"]
    status = codeowners.get("status") or "UNAVAILABLE"
    return {"status": "OBSERVED" if status in ("OBSERVED", "NO_MATCH") else status, "basis": "CODEOWNERS_DECLARATION",
            "file_match": bool(owners),
            "candidates": [{"owner": item["owner"], "kind": "TEAM" if item["kind"] == "team" else "USER", "line": item["line"]}
                           for item in owners],
            "repository": first.get("repository"), "codeowners_path": codeowners.get("path"),
            "collected_at": _iso(row["collected_at"])}


def public(row, job=None) -> dict:
    """The whole context for analysts: each location's owners and author, each repository's people."""
    running = {"job_id": str(job.id), "job_status": job.status} if job is not None else {}
    if row is None:
        return {"status": "NOT_COLLECTED", "locations": [], "repositories": [], "reasons": [], "collected_at": None,
                **running}
    return {"status": row["status"], **copy.deepcopy(row["body"]), "collected_at": _iso(row["collected_at"]), **running}


def summary(row) -> dict | None:
    """What a credential row carries (viewers read it): the CODEOWNERS owner, authors by file and the
    count of provider-listed people for the first repository -- names only, never an email. JSON-ready: the
    authors are ``[repository, path, name]`` rows."""
    if row is None:
        return None
    body = row["body"]
    # A person the file's CODEOWNERS names, else a team it names; with the file that says so.
    declared = [(location, owner) for location in body.get("locations") or []
                for owner in (location.get("codeowners") or {}).get("owners") or []]
    found = next((item for item in declared if item[1]["kind"] in ("account", "email")), None) \
        or next((item for item in declared if item[1]["kind"] == "team"), None)
    authors = [[location.get("repository"), location.get("path"),
                (location.get("author") or {}).get("name") or (location.get("author") or {}).get("login")]
               for location in body.get("locations") or [] if (location.get("author") or {}).get("status") == "OBSERVED"]
    author_sources = [[location.get("source_type"), location["source_connection_id"], location.get("repository"),
                       location.get("path"), (location.get("author") or {}).get("name") or (location.get("author") or {}).get("login")]
                      for location in body.get("locations") or []
                      if location.get("source_connection_id") and (location.get("author") or {}).get("status") == "OBSERVED"]
    repository = next(iter(body.get("repositories") or []), None)
    return {"owner": {"name": None if found[1]["kind"] == "team" else found[1]["owner"],
                      "team": found[1]["owner"] if found[1]["kind"] == "team" else None,
                      "where": f"{found[0].get('repository')} · {(found[0].get('codeowners') or {}).get('path')}"}
            if found else None,
            "authors": authors, **({"author_sources": author_sources} if author_sources else {}),
            "access": {"count": len(repository.get("people") or []), "truncated": bool(repository.get("truncated")),
                       "basis": repository.get("basis"), "repository": repository.get("repository"),
                       "access_key": repository.get("access_key"), "evidence_kind": repository.get("evidence_kind"),
                       "completeness": repository.get("completeness"), "status": repository.get("status"),
                       "collected_at": _iso(row["collected_at"])}
            if repository and (repository.get("status") == "OBSERVED" or repository.get("people")) else None}
