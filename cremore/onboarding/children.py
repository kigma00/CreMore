"""The records a provider connection owns, kept in the stores that already run them.

A provider module describes each record (``children``/``prepare``); this module creates
it where it belongs and links it:

* ``content`` -- a content source connection (scan scope catalog, profiles, scans), with
  ``source_type``, ``name`` and ``config``; its credential check is queued at once.
* ``aws_account`` -- an AWS account in an access mode (``account``: account_id, name,
  environment, access, sso_role_name), registered as the AWS onboarding always did.
* ``metadata`` -- a schema 2 collection (``spec`` without ``secret_refs``).
* ``coverage`` -- a schema 1 inventory or vault collection (``spec`` without ``secret_refs``).
* ``aws_inventory`` -- an AWS account's IAM (and, when the installation's AWS inventory
  settings say so, CloudTrail) collections, created or found by the same function the
  inventory scheduler uses (``account_id``); each is linked as ``coverage``.

``secret_slots`` maps the record's credential slots to the provider connection's roles
(``{"secret_ref": "credential"}`` for a content source). Every slot points at the same
sealed or ``vault://`` reference as the provider connection, so a new credential is
applied by re-pointing the slots, never by copying a secret.

A record is owned by one provider connection at a time. One that belongs to a
disabled provider connection (or to none) is taken over when a new connection
describes it -- the same content source by name, the same AWS account in the same
access mode -- so reconnecting keeps its history and, for AWS, its ExternalId. A
record another enabled connection owns is never taken.
"""

from __future__ import annotations

import json
import uuid

from cremore.onboarding.store import ProviderConnectionStore, active_plans


class ChildError(ValueError):
    """A record the provider described could not be created; ``code`` is stable."""

    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code, self.status = code, status


def _refs(connection, slots):
    refs = connection["secret_refs"]
    return {slot: refs[role] for slot, role in (slots or {}).items() if role in refs}


def _released(repo, kind, child_id, connection) -> bool:
    """Whether ``connection`` may take this record: nobody owns it, or its owner is disabled."""
    store = ProviderConnectionStore(repo)
    owner = store.parent_of(kind, child_id)
    if owner is None or str(owner) == str(connection["id"]):
        return True
    record = store.get(owner)
    return record is None or record["status"] == "DISABLED"


def _audit(repo, target_type, target_id, actor, action, note=None):
    from cremore.domain.models import FindingEvent

    repo.record_finding_event(FindingEvent(target_type=target_type, target_id=target_id, actor=actor,
                                           event_type=action, note=note))


def content_coordinate(module, config):
    """Providers may exclude only a redundant auth hint from their source's stable coordinates."""
    normalize = getattr(module, "onboarding_coordinate", None)
    return normalize(config) if callable(normalize) else dict(config)


def _content(repo, settings, connection, child, slots, actor):
    from cremore.api.http_support import actor_uuid
    from cremore.domain.connections import ConnectionError as Invalid
    from cremore.domain.connections import queue_credential_check, validate_connection
    from cremore.domain.models import Connection
    from cremore.sources.registry import BY_SOURCE

    module = BY_SOURCE.get(child.get("source_type"))
    if module is None:
        raise ChildError("CONTENT_SOURCE_UNKNOWN")
    conn = Connection(provider=module.PROVIDER, name=str(child.get("name") or connection["name"])[:120],
                      config=dict(child.get("config") or {}), secret_ref=_refs(connection, slots).get("secret_ref"))
    try:
        validate_connection(conn)
    except Invalid as exc:
        raise ChildError(str(exc)) from None
    names = {existing.name: existing for existing in repo.list_connections() if existing.provider == conn.provider}
    # A label may change or be shared by unrelated targets. Only the same
    # normalized provider configuration may retain source history and scope.
    coordinate = lambda config: {key: value for key, value in content_coordinate(module, config).items() if key != "auth_kind"}
    taken = next((existing for existing in sorted(repo.list_connections(), key=lambda row: (row.created_at, str(row.id)))
                  if existing.provider == conn.provider and coordinate(existing.config) == coordinate(conn.config)
                  and _released(repo, "content", existing.id, connection)), None)
    if taken is not None and _released(repo, "content", taken.id, connection):
        # The source a disabled connection scanned: its findings and scan history stay with it.
        created = repo.update_connection(taken.id, config=conn.config, secret_ref=conn.secret_ref, status="PENDING",
                                         credential_evidence=None, last_error=None, last_verified_at=None)
    else:
        if conn.name in names:
            # An enabled connection scans a source of this name; this one is numbered after it.
            base = conn.name[:112]
            free = next((f"{base} ({n})" for n in range(2, 100) if f"{base} ({n})" not in names), None)
            if free is None:
                raise ChildError("CONTENT_SOURCE_ALREADY_EXISTS", 409)
            conn = conn.model_copy(update={"name": free})
        try:
            created = repo.create_connection(conn)
        except ValueError:
            raise ChildError("CONTENT_SOURCE_ALREADY_EXISTS", 409) from None
    queue_credential_check(repo, created, actor_uuid(actor))
    return created.id, created.name, None


def _aws_account(repo, settings, connection, child, slots, actor):
    from cremore_aws_provider import aws_access

    from cremore.api.aws_support import AccountRefused, register_account

    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    body = dict(child.get("account") or {})
    role_draft = (connection["auth_method"] == "role" and not connection.get("plans")
                  and "role_accounts" in connection["target"].get("auth", {}))
    existing = next((a for a in repo.list_aws_accounts() if a.account_id == str(body.get("account_id", ""))), None)
    if role_draft and existing is not None:
        # Keep the row locked through the snapshot check and completion commit.
        # A later administrator disable must not be overwritten by this transfer.
        existing = repo.get_aws_account(existing.id, for_update=True)
    discovery = None
    if role_draft:
        from cremore_aws_provider.onboarding_roles import registration

        discovery = registration(connection, body.get("account_id"), repo, settings)
    if existing is not None:
        _aws_account_taken(repo, connection, existing, body)
        account = repo.get_aws_account(existing.id)
    else:
        try:
            account = register_account(repo, settings, approved, body, discovery=discovery)
        except AccountRefused as exc:
            raise ChildError(exc.detail.split(":", 1)[0].strip(), exc.status) from None
    checked_revision = connection["target"].get("auth", {}).get("scanner_approval_revision")
    if (account.access == aws_access.RUNTIME_IDENTITY or role_draft) and checked_revision is not None:
        from cremore.onboarding.permissions import require

        require(connection, connection["checks"]["requested_plans"])
        if not aws_access.record_validation(repo, account, aws_access.SCANNER, access_revision=account.access_revision,
                approval_revision=checked_revision, current_approval_revision=(approved or {}).get("revision"),
                status="VALID", detail="SCANNER_ROLE_ASSUMED" if role_draft else "RUNTIME_IDENTITY_CONFIRMED"):
            raise ChildError("AWS_SCANNER_IDENTITY_CHANGED", 409)
    # An Identity Center account has no stack to wait for, so it is proved at once.
    if (account.access == aws_access.SSO_PERMISSION_SET and approved is not None
            and aws_access.validation_refusal(account, aws_access.SCANNER, approved) is None):
        aws_access.queue_validation(repo, account, aws_access.SCANNER, approved["revision"],
                                    aws_access.pending_validations(repo))
    return account.id, account.name, None


def _aws_account_taken(repo, connection, account, body):
    """An account registered before: taken over in the same access mode, keeping its ExternalId."""
    from cremore_aws_provider import aws_access

    if not _released(repo, "aws_account", account.id, connection):
        raise ChildError("ACCOUNT_ALREADY_REGISTERED", 409)
    access = body.get("access") or aws_access.ROLE
    wanted = body.get("sso_role_name")
    if account.access != access or (wanted and account.sso_role_name != wanted):
        # A different access mode is a different trust; the account screen changes it deliberately.
        raise ChildError("ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS", 409)
    changes = {"enabled": True}
    if body.get("environment"):
        changes["environment"] = str(body["environment"])
    account = repo.update_aws_account(account.id, **changes)
    return account.id, account.name, None


def _collection(repo, connection, child, slots, actor, *, schema):
    from cremore.coverage.errors import CoverageError
    from cremore.db.task_store import TaskStore

    if schema == 2:
        from cremore.coverage.metadata_models import MetadataConnectionSpec as Spec
        from cremore.coverage.metadata_store import MetadataStore as Store
        from cremore.coverage.providers import validate_spec
    else:
        from cremore.coverage.models import ConnectionSpec as Spec
        from cremore.coverage.store import CoverageStore as Store

        def validate_spec(_spec):
            return None
    try:
        spec = Spec.model_validate({**dict(child.get("spec") or {}), "secret_refs": _refs(connection, slots)})
        validate_spec(spec)
    except (ValueError, CoverageError) as exc:
        raise ChildError(getattr(exc, "code", None) or "COLLECTION_SPEC_INVALID") from None
    store = Store(repo)
    with store.transaction() as conn:
        bound = TaskStore(repo)._bound(conn)
        try:
            row, token = Store(bound).create(spec, actor)
        except CoverageError as exc:
            raise ChildError(str(exc), 409) from None
        _audit(bound, "coverage_connection", row["id"], actor,
               "METADATA_CONNECTION_CREATED" if schema == 2 else "COVERAGE_CONNECTION_CREATED",
               "PROVIDER_CONNECTION " + str(connection["id"]))
    return row["id"], spec.name, token


def _aws_inventory(repo, settings, connection, child, slots, actor):
    from cremore.coverage.aws_scheduling import (
        ensure_aws_inventory_connections,
        ensure_iam_connection,
    )

    account = next((a for a in repo.list_aws_accounts() if a.account_id == child.get("account_id")), None)
    if account is None:
        raise ChildError("AWS_ACCOUNT_NOT_REGISTERED")
    rows = ([ensure_iam_connection(repo, account, actor)] if child.get("iam_only") else
            ensure_aws_inventory_connections(repo, settings, account, actor))
    return [(row["id"], row["spec"].get("name"), None, "coverage") for row in rows]


_CREATORS = {
    "content": _content,
    "aws_account": _aws_account,
    "metadata": lambda repo, settings, connection, child, slots, actor: _collection(
        repo, connection, child, slots, actor, schema=2),
    "coverage": lambda repo, settings, connection, child, slots, actor: _collection(
        repo, connection, child, slots, actor, schema=1),
    "aws_inventory": _aws_inventory,
}


def create(repo, settings, connection, purpose, child, actor) -> list[dict]:
    """Create the record(s) the provider described and link them to ``connection``.

    Each result names a record; ``collector_token`` is present once, for a
    collection whose runs arrive from the customer's own environment. A record a
    disabled provider connection owns moves to this one; one an enabled
    connection owns is refused.
    """
    kind = child.get("kind")
    creator = _CREATORS.get(kind)
    if creator is None:
        raise ChildError("CHILD_KIND_UNKNOWN")
    slots = dict(child.get("secret_slots") or {})
    made = creator(repo, settings, connection, child, slots, actor)
    store, out = ProviderConnectionStore(repo), []
    for child_id, name, token, *linked in made if isinstance(made, list) else [made]:
        link_kind = linked[0] if linked else kind
        owner = store.parent_of(link_kind, child_id)
        if owner is None:
            store.link(connection["id"], purpose, link_kind, child_id, slots)
        elif str(owner) != str(connection["id"]):
            if not _released(repo, link_kind, child_id, connection):
                raise ChildError("RECORD_OWNED_BY_ANOTHER_CONNECTION", 409)
            store.relink(connection["id"], purpose, link_kind, child_id, slots)
            _audit(repo, "provider_connection", connection["id"], actor, "PROVIDER_CONNECTION_RECORD_TAKEN_OVER",
                   f"{link_kind} {child_id} from {owner}")
        row = {"kind": link_kind, "id": str(child_id), "purpose": purpose, "name": name}
        if token and child.get("collector_token"):
            row["collector_token"] = token
        out.append(row)
    return out


def describe(repo, link) -> dict:
    """What an owned record is now: its name and whether it runs."""
    kind, child_id = link["kind"], link["child_id"]
    out = {"kind": kind, "id": child_id, "purpose": link["purpose"], "name": None, "state": "MISSING"}
    if kind == "content":
        conn = repo.get_connection(uuid.UUID(child_id))
        if conn is not None:
            out.update(name=conn.name, state=conn.status, source_type=_source_type(conn.provider))
    elif kind == "aws_account":
        account = repo.get_aws_account(uuid.UUID(child_id))
        if account is not None:
            out.update(name=account.name, state="ENABLED" if account.enabled else "DISABLED",
                       account_id=account.account_id, access=account.access,
                       validation=account.validation_status)
    else:
        from cremore.coverage.store import CoverageStore

        row = CoverageStore(repo).get(uuid.UUID(child_id))
        if row is not None:
            out.update(name=row["spec"].get("name"), state="ENABLED" if row["enabled"] else "DISABLED",
                       provider=row["spec"].get("provider"), revision=row["revision"])
    return out


def _source_type(provider):
    from cremore.sources.registry import PROVIDERS

    module = PROVIDERS.get(provider)
    return module.SOURCE_TYPE if module else provider


def points_at_credential(repo, connection, link) -> bool:
    """Whether an owned record already uses the provider connection's current credential."""
    from cremore.coverage.store import CoverageStore

    expected = _refs(connection, link["secret_slots"])
    if link["kind"] == "content":
        conn = repo.get_connection(uuid.UUID(link["child_id"]))
        return conn is None or conn.secret_ref == expected.get("secret_ref")
    if link["kind"] in ("metadata", "coverage"):
        row = CoverageStore(repo).get(uuid.UUID(link["child_id"]))
        return row is None or (row["spec"].get("secret_refs") or {}) == expected
    return True


def repoint(repo, connection, actor) -> list[str]:
    """Point every owned record at the provider connection's current credential.

    A content source goes back to PENDING with a new credential check queued, as when
    its credential was entered; collections take the new references at their next run.
    Returns the ids of records that could not be updated (changed concurrently).
    """
    from cremore.api.http_support import actor_uuid
    from cremore.coverage.errors import CoverageError
    from cremore.coverage.store import CoverageStore
    from cremore.domain.connections import queue_credential_check

    failed = []
    for link in ProviderConnectionStore(repo).children(connection["id"]):
        refs = _refs(connection, link["secret_slots"])
        if not link["secret_slots"]:
            continue
        child_id = uuid.UUID(link["child_id"])
        if link["kind"] == "content":
            source = repo.get_connection(child_id)
            if source is None:
                failed.append(link["child_id"])
                continue
            state = "DISABLED" if source.status == "DISABLED" else "PENDING"
            updated = repo.update_connection(child_id, expected_status=source.status,
                                             secret_ref=refs.get("secret_ref"), status=state,
                                             credential_evidence=None, last_error=None, last_verified_at=None)
            if updated is None:
                failed.append(link["child_id"])
            elif state != "DISABLED":
                queue_credential_check(repo, updated, actor_uuid(actor))
            continue
        store = CoverageStore(repo)
        row = store.get(child_id)
        if row is None:
            failed.append(link["child_id"])
            continue
        spec_type = _spec_type(row)
        try:
            spec = spec_type.model_validate({**row["spec"], "secret_refs": refs})
            store.change(child_id, row["revision"], actor, spec=spec)
        except (ValueError, CoverageError):
            failed.append(link["child_id"])
    return failed


def _identity(child, purpose):
    from cremore.onboarding import catalog

    spec = child.get("spec") or {}
    provider = spec.get("provider")
    if provider in catalog.providers():
        identity = getattr(catalog.module(provider), "collection_identity_purpose", None)
        if callable(identity):
            purpose = identity(spec, purpose)
    if spec.get("schema_version") == 2:
        target = {key: spec.get(key) for key in ("origin", "edition", "scopes")}
        target["scopes"] = sorted(target["scopes"] or [], key=lambda s: json.dumps(s, sort_keys=True))
        # IdP app inventories use their own collection beside the people directory.
        target["apps"] = spec.get("options", {}).get("sources") == ["apps"]
    else:
        target = {key: spec.get(key) or "" for key in ("account_id", "endpoint", "project", "product", "reader")}
        target["mounts"] = sorted(m.get("name", "") for m in spec.get("mounts") or [])
    return child.get("kind"), spec.get("provider"), purpose, json.dumps(target, sort_keys=True)


def _apply_change(stored, before, after):
    """``stored`` with what changed from ``before`` to ``after`` applied: a key the new plan drops is
    removed, one it adds or changes is set, and a key neither plan names (set later, such as a chosen
    organization) is kept. Objects (options) are compared one level down."""
    out = dict(stored)
    for key in set(before) | set(after):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if isinstance(old, dict) and isinstance(new, dict) and isinstance(out.get(key), dict):
            out[key] = _apply_change(out[key], old, new)
        elif key in after:
            out[key] = new
        else:
            out.pop(key, None)
    return out


_COLLECTIONS = ("metadata", "coverage")


def update(repo, settings, connection, before, after, actor) -> list[dict]:
    """Apply changed plans to the collections ``connection`` owns, from their next run.

    ``before`` and ``after`` are what ``children()`` describes for the old and the new plans. A
    collection both describe takes the change between them; its credential references, anything set
    after it was made and whether it runs are kept. One only the new plans describe is created, or
    turned back on with that description; one only the old plans describe is turned off, never
    deleted. Collections neither describes (an AWS account's inventory) and other records stay as
    they are. Collections are identified by provider and immutable target coordinates.
    """
    from cremore.coverage.errors import CoverageError
    from cremore.coverage.providers import validate_spec
    from cremore.coverage.store import CoverageStore

    collections = CoverageStore(repo)
    owned = {}
    for link in ProviderConnectionStore(repo).children(connection["id"]):
        if link["kind"] in _COLLECTIONS:
            row = collections.get(uuid.UUID(link["child_id"]))
            if row is not None:
                key = _identity({"kind": link["kind"], "spec": row["spec"]}, link["purpose"])
                if key in owned:
                    raise ChildError("COLLECTION_TARGET_AMBIGUOUS", 409)
                owned[key] = (link, row)
    old = {_identity(child, purpose): child for purpose, child in before if child.get("kind") in _COLLECTIONS}
    new = {_identity(child, purpose): (purpose, child) for purpose, child in after if child.get("kind") in _COLLECTIONS}
    changed = []

    def changed_one(link, row, action, **extra):
        _audit(repo, "coverage_connection", row["id"], actor, action, "PROVIDER_CONNECTION " + str(connection["id"]))
        changed.append({"kind": link["kind"], "id": str(row["id"]), "purpose": link["purpose"],
                        "name": row["spec"].get("name"), **extra})

    for key, (purpose, child) in new.items():
        if key not in owned:
            changed.extend(create(repo, settings, connection, purpose, child, actor))
            continue
        link, row = owned[key]
        if link["purpose"] != purpose:
            ProviderConnectionStore(repo).relink(connection["id"], purpose, link["kind"], row["id"], link["secret_slots"])
            link = {**link, "purpose": purpose}
        kept = _wanted_collection(link, row, before)  # includes legacy AWS inventory; preserve an explicit pause
        previous = old.get(key, {}).get("spec") or {}
        desired = child.get("spec") or {}
        spec = _apply_change(row["spec"], previous, desired)
        if desired.get("schedule_source") == "connection" and previous.get("schedule_minutes") != desired.get("schedule_minutes"):
            spec["schedule_source"] = "connection"
        try:
            typed = _spec_type(row).model_validate(spec)
        except ValueError:
            raise ChildError("COLLECTION_SPEC_INVALID") from None
        if typed.model_dump() == row["spec"] and (kept or row["enabled"]):
            continue
        try:
            if row["spec"].get("schema_version") == 2:
                validate_spec(typed)
            row, _token = collections.change(row["id"], row["revision"], actor, spec=typed,
                                             enabled=None if kept else True)
        except CoverageError as exc:
            raise ChildError(str(exc), 409) from None
        changed_one(link, row, "COLLECTION_PLAN_CHANGED", enabled=row["enabled"])
    for key, (link, row) in owned.items():
        if key in old and not _wanted_collection(link, row, after) and row["enabled"]:
            try:
                row, _token = collections.change(row["id"], row["revision"], actor, enabled=False)
            except CoverageError as exc:
                raise ChildError(str(exc), 409) from None
            changed_one(link, row, "COLLECTION_TURNED_OFF_BY_PLAN", enabled=False)
    return changed


def _spec_type(row):
    if row["spec"].get("schema_version") == 2:
        from cremore.coverage.metadata_models import MetadataConnectionSpec

        return MetadataConnectionSpec
    from cremore.coverage.models import ConnectionSpec

    return ConnectionSpec


def reconcile_features(repo, settings, before, after, actor):
    """Reconcile only the capabilities that an individual feature switch changed."""
    from cremore.coverage.store import CoverageStore
    from cremore.onboarding import catalog, service

    if after["status"] == "DISABLED":
        return []
    old, new = active_plans(before), active_plans(after)
    module = catalog.module(after["provider"])
    described_before = service._described(module, before, old)
    described_after = service._described(module, after, new)
    if after["provider"] != "aws":
        if ("exposure" in old) != ("exposure" in new):
            return reconcile_targets(repo, settings, after, described_before, described_after, actor)
        return update(repo, settings, after, described_before, described_after, actor)
    changed = update(repo, settings, after, described_before, described_after, actor)
    # One AWS account supplies the scanner identity to all three features. Stopping
    # exposure alone must not stop metadata/vault access through that account.
    for link in ProviderConnectionStore(repo).children(after["id"]):
        cid = uuid.UUID(link["child_id"])
        if link["kind"] == "aws_account":
            account = repo.get_aws_account(cid)
            if account is None:
                raise ChildError("AWS_ACCOUNT_NOT_REGISTERED", 409)
        elif link["purpose"] == "inventory" and ("inventory" in old) != ("inventory" in new):
            store = CoverageStore(repo)
            row = store.get(cid)
            if row is None:
                raise ChildError("COLLECTION_NOT_FOUND", 409)
            desired = "inventory" in new and _wanted_collection(link, row, described_after)
            if row["enabled"] != desired:
                store.change(cid, row["revision"], actor, enabled=desired)
                changed.append({"kind": link["kind"], "id": str(cid), "purpose": link["purpose"], "enabled": desired})
    return changed


def _wanted_collection(link, row, described):
    key = _identity({"kind": link["kind"], "spec": row["spec"]}, link["purpose"])
    if key in {_identity(child, purpose) for purpose, child in described if child["kind"] in _COLLECTIONS}:
        return True
    return any(child["kind"] == "aws_inventory" and child["account_id"] == row["spec"].get("account_id")
               and row["spec"].get("provider") in ({"aws_iam"} if child.get("iam_only") else {"aws_iam", "aws_cloudtrail"})
               for _purpose, child in described)


def reconcile_targets(repo, settings, connection, before, after, actor):
    """Reconcile selected roots without deleting source history or approval records."""
    from cremore.api.http_support import actor_uuid
    from cremore.coverage.errors import CoverageError
    from cremore.coverage.store import CoverageStore
    from cremore.domain.connections import queue_credential_check
    from cremore.sources.registry import BY_SOURCE, PROVIDERS

    changed = update(repo, settings, connection, before, after, actor)
    wanted_collections = {_identity(child, purpose) for purpose, child in after if child["kind"] in _COLLECTIONS}
    collections = CoverageStore(repo)
    for link in ProviderConnectionStore(repo).children(connection["id"]):
        if link["kind"] not in _COLLECTIONS:
            continue
        row = collections.get(uuid.UUID(link["child_id"]))
        # The existing collection API can edit coordinates independently. An
        # edited row outside the final selection must stop even if it no longer
        # matches the previous provider target; its observations remain intact.
        if row and row["enabled"] and _identity({"kind": link["kind"], "spec": row["spec"]}, link["purpose"]) not in wanted_collections:
            try:
                row, _token = collections.change(row["id"], row["revision"], actor, enabled=False)
            except CoverageError as exc:
                raise ChildError(str(exc), 409) from None
            _audit(repo, "coverage_connection", row["id"], actor, "COLLECTION_TURNED_OFF_BY_PLAN",
                   "PROVIDER_CONNECTION " + str(connection["id"]))
            changed.append({"kind": link["kind"], "id": str(row["id"]), "purpose": link["purpose"],
                            "name": row["spec"].get("name"), "enabled": False})
    wanted = []
    links = ProviderConnectionStore(repo).children(connection["id"])
    for purpose, child in after:
        if child["kind"] == "content":
            provider = BY_SOURCE[child["source_type"]]
            config = provider.validate_config(dict(child.get("config") or {}))
            kept = next((source for link in links if link["kind"] == "content"
                         and (source := repo.get_connection(uuid.UUID(link["child_id"]))) is not None
                         and source.provider == provider.PROVIDER
                         and content_coordinate(provider, source.config) == content_coordinate(provider, config)), None)
            if kept is not None:
                if kept.status == "DISABLED" or kept.config != config:
                    # Pausing does not change the authorized identity or invalidate
                    # its retained scope. Only a changed config needs new evidence.
                    evidence = {"credential_evidence": None, "last_verified_at": None} if kept.config != config else {}
                    kept = repo.update_connection(kept.id, config=config, status="PENDING", last_error=None,
                                                  **evidence)
                    queue_credential_check(repo, kept, actor_uuid(actor))
                wanted.append(str(kept.id))
                continue
            made = create(repo, settings, connection, purpose, child, actor)
            wanted.extend(item["id"] for item in made)
            changed.extend(made)
        elif child["kind"] not in _COLLECTIONS:
            raise ChildError("TARGET_EDIT_NOT_SUPPORTED")
    old = {(BY_SOURCE[child["source_type"]].PROVIDER,
            json.dumps(content_coordinate(BY_SOURCE[child["source_type"]],
                BY_SOURCE[child["source_type"]].validate_config(dict(child.get("config") or {}))), sort_keys=True))
           for _purpose, child in before if child["kind"] == "content"}
    for link in ProviderConnectionStore(repo).children(connection["id"]):
        if link["kind"] != "content" or link["child_id"] in wanted:
            continue
        source = repo.get_connection(uuid.UUID(link["child_id"]))
        if source and (source.provider, json.dumps(content_coordinate(PROVIDERS[source.provider], source.config), sort_keys=True)) in old:
            repo.update_connection(source.id, status="DISABLED")
            _audit(repo, "source", source.id, actor, "SOURCE_REMOVED_FROM_PROVIDER_TARGETS")
    return changed


def set_enabled(repo, connection, enabled: bool, actor) -> list[str]:
    """Stop or restart every owned record; returns the ids that could not be changed."""
    from cremore.api.http_support import actor_uuid
    from cremore.coverage.errors import CoverageError
    from cremore.coverage.store import CoverageStore
    from cremore.domain.connections import queue_credential_check

    # Removed roots/options remain owned for history and renewal, but resuming
    # the connection must not quietly approve them again.
    active_sources = None
    active = None
    if enabled:
        from cremore.onboarding import catalog, service
        from cremore.sources.registry import BY_SOURCE, PROVIDERS

        active = service._described(catalog.module(connection["provider"]), connection, active_plans(connection))
        active_sources = {(BY_SOURCE[child["source_type"]].PROVIDER,
            json.dumps(content_coordinate(BY_SOURCE[child["source_type"]],
                BY_SOURCE[child["source_type"]].validate_config(dict(child.get("config") or {}))), sort_keys=True))
            for _purpose, child in active if child["kind"] == "content"}
    failed = []
    for link in ProviderConnectionStore(repo).children(connection["id"]):
        child_id = uuid.UUID(link["child_id"])
        if (enabled and connection["provider"] == "aws" and link["kind"] != "aws_account"
                and link["purpose"] not in active_plans(connection)):
            continue
        if link["kind"] == "content":
            conn = repo.get_connection(child_id)
            if conn and active_sources is not None and (conn.provider, json.dumps(content_coordinate(
                    PROVIDERS[conn.provider], conn.config), sort_keys=True)) not in active_sources:
                continue
            if conn is None:
                failed.append(link["child_id"])
            elif not enabled and conn.status != "DISABLED":
                repo.update_connection(child_id, status="DISABLED")
            elif enabled and conn.status == "DISABLED":
                updated = repo.update_connection(child_id, status="PENDING", last_error=None)
                queue_credential_check(repo, updated, actor_uuid(actor))
        elif link["kind"] == "aws_account":
            if repo.update_aws_account(child_id, enabled=enabled) is None:
                failed.append(link["child_id"])
        else:
            store = CoverageStore(repo)
            row = store.get(child_id)
            if row and active is not None and not _wanted_collection(link, row, active):
                continue
            if row is None:
                failed.append(link["child_id"])
            elif row["enabled"] != enabled:
                try:
                    store.change(child_id, row["revision"], actor, enabled=enabled)
                except CoverageError:
                    failed.append(link["child_id"])
    return failed
