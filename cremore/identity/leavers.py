"""Credentials departed people leave behind (design 4.2; decisions 4 and 13).

People come from IdP collections (okta, keycloak, entra_id). A provider account comes
from the issued-credential inventory, through each provider's ``credential_owner``
function, and for GitHub also from the organization's SAML/SCIM directory
(github_identity). An account links to a person only when both name the same value
on an exact basis: an IdP-issued external id, the IdP's object id, or an email the
IdP asserted or the provider verified. Weaker matches (a public email, a login) are
candidates an administrator confirms or rejects. A GitHub directory identity is a
person of the IdP that provisions the organization, which the directory does not
name, and so is the IdP identity GitLab keeps for a user (extern_uid): it links on
its own only while its values reach one human -- people of several IdPs count as one
only when they share an email. An exact link is kept once made (a
leaver's SAML identity usually disappears with the account it named); when the
identity later also reaches someone else who is active, its verdicts say the IdPs
disagree.

Every listing the check reads is read whole, page by page within a budget, and so is
the coverage comparison that carries the schema 1 inventory. One past the budget, or
one that changed while it was paged, decides no link or verdict (``PARTIAL``): a cut
list never shows a credential gone. People listings read whole are still saved, so a
departure is not lost while another listing stays cut; retention waits for the next
complete evaluation.

For every credential of an account linked to a departed person:

* ``USED_AFTER_DEPARTURE`` -- last used after the departure time,
* ``REVOKED_OR_EXPIRED`` -- already off,
* ``ACTIVE`` -- the provider still reports it on,
* ``UNKNOWN`` -- the provider gives no status, the observation is not current, or the
  provider does not list every credential a user holds (one row per account).

A departure time is the IdP's own when it reports one (Okta ``statusChanged``, an
Entra deletion, a Keycloak admin event); otherwise the first collection that saw the
account disabled or gone, which is never earlier than the real departure, so
"used after departure" is never claimed on a guess. Verdict changes become
``identity.credential_orphaned`` events and a governance ticket per credential that
needs action. Leaver data is deleted ``LEAVER_RETENTION_DAYS`` after departure;
identity collection history older than ``IDENTITY_RUN_HISTORY_DAYS`` is deleted too.
"""

from __future__ import annotations

import copy
import datetime as _dt
import uuid
from dataclasses import dataclass, field
from importlib import import_module
from itertools import combinations

from sqlalchemy import JSON, Column, DateTime, Integer, Table, Text, Uuid, delete, select

from cremore.identity.keys import EXACT_BASES, KINDS, Digester

SLOT_KEY = "identity:leavers"
RESULT_KEY = "identity:leavers:last"
MAX_CANDIDATES = 500
INTERVAL_SECONDS = 300
MAX_EVENTS = 500
MAX_TICKETS = 200
MAX_ROWS = 10000  # rows one store read returns
# ponytail: a listing is held in memory whole and one past MAX_PAGES reads makes the evaluation PARTIAL; read per
# account if an installation outgrows it.
MAX_PAGES = 10
IDENTITY_RUN_HISTORY_DAYS = 30
VERDICTS = ("USED_AFTER_DEPARTURE", "ACTIVE", "REVOKED_OR_EXPIRED", "UNKNOWN")
NEEDS_ACTION = ("USED_AFTER_DEPARTURE", "ACTIVE")
DEPARTED = "DEPARTED"
_PERSON_STATE = {"ACTIVE": "ACTIVE", "DISABLED": DEPARTED, "DELETED": DEPARTED, "PENDING": "PENDING"}
_NS = uuid.NAMESPACE_URL


def _now():
    return _dt.datetime.now(_dt.UTC)


def _time(value):
    """An aware datetime from a stored datetime or ISO text; None for anything else."""
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.UTC)
    if isinstance(value, str) and value:
        try:
            parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162 -- providers send Z
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)
    return None


def person_ref(provider, origin, tenant, user_id) -> uuid.UUID:
    return uuid.uuid5(_NS, f"cremore:identity-person:{provider}|{origin}|{tenant}|{user_id}")


def account_ref(provider, origin, account) -> str:
    return f"{provider}|{origin}|{account}"


def orphan_ref(person, credential_key) -> uuid.UUID:
    return uuid.uuid5(_NS, f"cremore:identity-orphan:{person}|{credential_key}")


# --- storage ---------------------------------------------------------------------------


def register_tables(metadata):
    names = ("identity_people", "identity_links", "identity_orphans")
    if names[0] in metadata.tables:
        return tuple(metadata.tables[name] for name in names)
    people = Table(
        "identity_people", metadata,
        Column("person_ref", Uuid, primary_key=True),
        Column("provider", Text, nullable=False), Column("origin", Text, nullable=False),
        Column("tenant", Text, nullable=False), Column("idp_user_id", Text),
        Column("connection_id", Uuid), Column("entity_id", Uuid),
        Column("state", Text, nullable=False), Column("idp_state", Text, nullable=False),
        Column("departed_at", DateTime(timezone=True)), Column("departure_basis", Text),
        Column("keys", JSON, nullable=False), Column("key_id", Text),
        Column("first_seen_at", DateTime(timezone=True), nullable=False),
        Column("last_seen_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
        Column("purged_at", DateTime(timezone=True)))
    links = Table(
        "identity_links", metadata,
        Column("account_ref", Text, primary_key=True), Column("person_ref", Uuid, primary_key=True),
        # MATCHED: an exact match the engine made; CONFIRMED / REJECTED: an administrator's decision.
        Column("decision", Text, nullable=False), Column("basis", Text, nullable=False),
        Column("actor_ref", Text), Column("decided_at", DateTime(timezone=True), nullable=False))
    orphans = Table(
        "identity_orphans", metadata,
        Column("orphan_ref", Uuid, primary_key=True), Column("person_ref", Uuid, nullable=False),
        Column("account_ref", Text, nullable=False), Column("provider", Text, nullable=False),
        Column("verdict", Text, nullable=False), Column("published_verdict", Text),
        Column("sequence", Integer, nullable=False), Column("body", JSON, nullable=False),
        Column("ticket_id", Uuid),
        Column("first_seen_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))
    return people, links, orphans


class LeaverStore:
    """identity_people / identity_links / identity_orphans, in memory or in the database."""

    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "identity_state"):
                    repo.identity_state = {"people": {}, "links": {}, "orphans": {}}
            self.memory = repo.identity_state
        else:
            from cremore.db.schema import metadata

            self.people_t, self.links_t, self.orphans_t = register_tables(metadata)

    def _rows(self, name, table, key):
        if self.engine is None:
            with self.repo._lock:
                return copy.deepcopy(self.memory[name])
        with self.engine.connect() as conn:
            return {key(row): dict(row) for row in conn.execute(select(table)).mappings()}

    def people(self) -> dict:
        return self._rows("people", getattr(self, "people_t", None), lambda row: row["person_ref"])

    def links(self) -> dict:
        return self._rows("links", getattr(self, "links_t", None), lambda row: (row["account_ref"], row["person_ref"]))

    def links_for(self, accounts) -> dict:
        """Decisions for the bounded accounts of one exposed credential."""
        accounts = set(accounts)
        if not accounts:
            return {}
        if self.engine is None:
            with self.repo._lock:
                return {key: copy.deepcopy(row) for key, row in self.memory["links"].items() if key[0] in accounts}
        with self.engine.connect() as conn:
            return {(row["account_ref"], row["person_ref"]): dict(row) for row in conn.execute(
                select(self.links_t).where(self.links_t.c.account_ref.in_(accounts))).mappings()}

    def orphans(self) -> dict:
        return self._rows("orphans", getattr(self, "orphans_t", None), lambda row: row["orphan_ref"])

    def states(self, refs) -> dict:
        """{person ref: state} of these people only."""
        refs = list(refs)
        if not refs:
            return {}
        if self.engine is None:
            with self.repo._lock:
                return {ref: self.memory["people"][ref]["state"] for ref in refs if ref in self.memory["people"]}
        with self.engine.connect() as conn:
            return dict(conn.execute(select(self.people_t.c.person_ref, self.people_t.c.state)
                                     .where(self.people_t.c.person_ref.in_(refs))).all())

    def _upsert(self, conn, table, row, keys):
        statement = self.repo._insert(conn, table).values(**row)
        conn.execute(statement.on_conflict_do_update(
            index_elements=[table.c[name] for name in keys],
            set_={name: value for name, value in row.items() if name not in keys}))

    def save(self, *, people=(), links=(), orphans=(), removed_orphans=(), removed_links=()) -> None:
        if self.engine is None:
            with self.repo._lock:
                for row in people:
                    self.memory["people"][row["person_ref"]] = copy.deepcopy(row)
                for row in links:
                    self.memory["links"][(row["account_ref"], row["person_ref"])] = copy.deepcopy(row)
                for key in removed_links:
                    self.memory["links"].pop(key, None)
                for key in removed_orphans:
                    self.memory["orphans"].pop(key, None)
                for row in orphans:
                    self.memory["orphans"][row["orphan_ref"]] = copy.deepcopy(row)
            return
        with self.engine.begin() as conn:
            for row in people:
                self._upsert(conn, self.people_t, row, ("person_ref",))
            for row in links:
                self._upsert(conn, self.links_t, row, ("account_ref", "person_ref"))
            for account, person in removed_links:
                conn.execute(delete(self.links_t).where(self.links_t.c.account_ref == account,
                                                        self.links_t.c.person_ref == person))
            if removed_orphans:
                conn.execute(delete(self.orphans_t).where(self.orphans_t.c.orphan_ref.in_(list(removed_orphans))))
            for row in orphans:
                self._upsert(conn, self.orphans_t, row, ("orphan_ref",))

    def delete_people(self, refs) -> None:
        refs = list(refs)
        if not refs:
            return
        if self.engine is None:
            with self.repo._lock:
                for ref in refs:
                    self.memory["people"].pop(ref, None)
            return
        with self.engine.begin() as conn:
            conn.execute(delete(self.people_t).where(self.people_t.c.person_ref.in_(refs)))


# --- what the collections hold --------------------------------------------------------


def identity_providers():
    """(IdP providers, {directory provider: provider whose accounts it names})."""
    from cremore.coverage.providers import _ADAPTERS

    idps, directories = set(), {}
    for provider, registration in _ADAPTERS.items():
        role = registration.descriptor.get("identity_role")
        if role == "idp":
            idps.add(provider)
        elif role == "directory":
            directories[provider] = registration.descriptor["identity_accounts_of"]
    return idps, directories


def _owner_modules():
    from cremore.coverage.models import V1_OWNERS
    from cremore.coverage.providers import _ADAPTERS

    schema2 = {provider: registration.owners for provider, registration in _ADAPTERS.items() if registration.owners}
    return schema2, dict(V1_OWNERS)


class IncompleteListing(Exception):
    """A listing ran past MAX_PAGES reads or changed between them; the code says which listing and how."""


def _every(name, read, **query):
    """Every row of one store listing, MAX_ROWS a read and at most MAX_PAGES reads.

    The store pages by offset, so a listing that changes between reads (a collection storing a run meanwhile) can
    skip a row: a total that moves or a row read twice shows it. That, or a listing past the budget, raises
    IncompleteListing: the rows read are not the listing, and a row missing from them is no evidence of anything.
    """
    rows, total = [], None
    for _ in range(MAX_PAGES):
        page = read(offset=len(rows), limit=MAX_ROWS, **query)
        if total not in (None, page["total"]):
            raise IncompleteListing(name + "_CHANGED_WHILE_READ")
        total = page["total"]
        if total > MAX_ROWS * MAX_PAGES:
            raise IncompleteListing(name + "_LIMIT_REACHED")
        rows += page["items"]
        if len(rows) >= total or not page["items"]:
            break
    else:
        raise IncompleteListing(name + "_LIMIT_REACHED")
    if len({row["id"] for row in rows}) != total:
        raise IncompleteListing(name + "_CHANGED_WHILE_READ")
    return rows


def _latest_finished(store, cid):
    for run in store.connection_runs(cid, limit=10)["items"]:
        if run["finished_at"] is not None and run["status"] in ("COMPLETE", "PARTIAL"):
            return run
    return None


def _run_ids(store, cid):
    """Every kept run of a collection. Newest first, so a run started while paging repeats a row, never skips one."""
    ids, offset = set(), 0
    while True:
        found = store.connection_runs(cid, offset=offset, limit=2000)
        ids.update(run["id"] for run in found["items"])
        offset += len(found["items"])
        if offset >= found["total"] or not found["items"]:
            return ids


def _listed_everyone(store, run) -> bool:
    """Whether a run's user listing named everyone the directory holds: the run is COMPLETE and its users report
    proves it. A run of the IdP's app list -- a collection switched to it included -- lists no people."""
    if run["status"] != "COMPLETE":
        return False
    reports = store.record_page(run_id=run["id"], record_type="operation_report", limit=100)["items"]
    return any((report.get("body") or {}).get("proves_completeness") is True for report in reports)


def _status_events(store, idps, connections):
    """({(provider, origin, tenant, user id): [(time, change)]} from IdP status events, reasons).

    Every run stores the events of its whole look-back window again, so only each collection's latest finished run is
    read, and only when it is complete. A collection whose events cannot be read whole dates no departure by them: a
    cut history (a partial run's, or an older run's beside a newer partial one) can miss a later enable and date a
    departure too early.
    """
    found, reasons = {}, set()
    for cid, connection in connections.items():
        spec = connection["spec"]
        if (spec.get("provider") not in idps or not connection["enabled"]
                or not (spec.get("options") or {}).get("include_audit_events")):
            continue  # a collection that reads no status events (Okta, Entra, an app list) dates nothing by them
        latest = _latest_finished(store, cid)
        if latest is None:
            continue
        if latest["status"] != "COMPLETE":
            reasons.add("IDP_EVENTS_NOT_CURRENT")
            continue
        try:
            items = [item for kind in ("user.disabled", "user.deleted", "user.enabled")
                     for item in _every("IDP_EVENTS", store.provider_events, provider=spec["provider"],
                                        event_type=kind, connection_id=cid, run_id=latest["id"])]
        except IncompleteListing as exc:
            reasons.add(str(exc))
            continue
        for item in items:
            subject, at = item.get("subject") or {}, _time(item.get("occurred_at"))
            if at is None or not str(subject.get("object_id", "")).startswith("user:"):
                continue
            key = (spec["provider"], spec["origin"], spec.get("tenant", ""), subject["object_id"][5:])
            found.setdefault(key, []).append((at, item["event_type"].removeprefix("user.").upper()))
    return found, reasons


def _departure_event(events):
    """The first disable or delete after the last enable (when the current departure began), or None."""
    latest = None
    for at, change in sorted(events):
        latest = None if change == "ENABLED" else latest or at
    return latest


def sync_people(store, connections, stored, key_id, now):
    """(People rows as the IdP collections show them now, keyed by person ref; reasons some events were not used;
    the codes of people listings that could not be read whole, whose people keep their stored rows).

    A purged person stays purged: an IdP that still lists them only shows its own
    current directory, which the identity collection history keeps for at most
    IDENTITY_RUN_HISTORY_DAYS.
    """
    idps, _directories = identity_providers()
    events, reasons = _status_events(store, idps, connections)
    rows, cut = {}, set()
    for connection in connections.values():
        spec = connection["spec"]
        if spec.get("schema_version") != 2 or spec.get("provider") not in idps or not connection["enabled"]:
            continue
        latest = _latest_finished(store, connection["id"])
        if latest is None:
            continue
        listed_everyone = _listed_everyone(store, latest)
        # Two collections of one tenant share its people rows: only the collection that made a row's newest
        # observation may read that row's absence from its own complete listing as a departure. Every run the history
        # keeps counts: a collection failing for a week can make thousands before its next complete listing.
        own_runs = _run_ids(store, connection["id"]) if listed_everyone else set()
        try:
            entities = _every("IDP_PEOPLE", store.inventory, provider=spec["provider"], purpose="identity_status",
                              object_kind="principal", connection_id=connection["id"], details=False)
        except IncompleteListing as exc:
            cut.add(str(exc))  # this IdP's people keep their stored rows; the others' are still read
            continue
        for entity in entities:
            user_id = entity["object_id"].removeprefix("user:")
            ref = person_ref(spec["provider"], entity["origin"], entity["tenant"], user_id)
            before = rows.get(ref) or stored.get(ref)
            if before is not None and before["state"] == "PURGED":
                continue
            summary = entity["summary"] or {}
            in_latest = entity["latest_run_id"] == latest["id"]
            if in_latest:
                state = _PERSON_STATE.get(summary.get("normalized_state"), "UNKNOWN")
            elif (listed_everyone and entity["latest_run_id"] in own_runs
                  and (entity["origin"], entity["tenant"]) == (spec["origin"], spec.get("tenant", ""))):
                # This collection's own complete listing of the directory it reads now no longer names this user
                # (a collection pointed at another directory says nothing about the first one's people).
                state = DEPARTED
            else:
                state = before["state"] if before else "UNKNOWN"
            departed_at, basis = None, None
            if state == DEPARTED:
                candidates = []
                reported = _time(summary.get("effective_at"))
                if in_latest and reported and summary.get("normalized_state") in ("DISABLED", "DELETED"):
                    candidates.append((reported, "PROVIDER_REPORTED"))
                changes = events.get((spec["provider"], entity["origin"], entity["tenant"], user_id), [])
                event = _departure_event(changes)
                if event is not None:
                    candidates.append((event, "ADMIN_EVENT"))
                earlier = _time((before or {}).get("departed_at")) if (before or {}).get("state") == DEPARTED else None
                # An enable after that departure ended it: the person left again since.
                if earlier is not None and not any(change == "ENABLED" and at > earlier for at, change in changes):
                    candidates.append((earlier, before["departure_basis"]))
                if not candidates:
                    # Never earlier than the departure: a run that missed the user was over by its end, and one that
                    # saw them disabled saw it when it read them.
                    first = _time(entity["observed_at"]) if in_latest else _time(latest["finished_at"])
                    candidates.append((first or now, "FIRST_OBSERVED_DISABLED" if in_latest else "FIRST_OBSERVED_MISSING"))
                departed_at, basis = min(candidates, key=lambda item: item[0])
            keys = (summary.get("identity_keys") or []) if summary.get("identity_key_id") == key_id else \
                (before or {}).get("keys", []) if (before or {}).get("key_id") == key_id else []
            rows[ref] = {
                "person_ref": ref, "provider": spec["provider"], "origin": entity["origin"], "tenant": entity["tenant"],
                "idp_user_id": user_id, "connection_id": connection["id"], "entity_id": entity["id"],
                "state": state, "idp_state": summary.get("provider_state") or "UNKNOWN",
                "departed_at": departed_at, "departure_basis": basis,
                "keys": [{"kind": key["kind"], "digest": key["digest"]} for key in keys], "key_id": key_id,
                "first_seen_at": (before or {}).get("first_seen_at") or now,
                "last_seen_at": _time(entity["observed_at"]) or now if in_latest else
                (before or {}).get("last_seen_at") or now,
                "updated_at": now, "purged_at": None}
    return rows, reasons, sorted(cut)


@dataclass
class Account:
    ref: str
    provider: str
    label: str
    lists_every: bool
    keys: set = field(default_factory=set)
    credentials: list = field(default_factory=list)
    directory: bool = False


def _report_index(report_rows):
    """Issued schema 2 credentials of the coverage comparison, by entity id."""
    return {str(row["entity_id"]): row for row in report_rows or []
            if row.get("origin") == "ISSUANCE" and row.get("entity_id")}


def collect_accounts(store, connections, digester, report_rows, now):
    """Provider accounts with their identity digests and the credentials they own."""
    from cremore.coverage.metadata_correlation import current_issuer_observation

    schema2, schema1 = _owner_modules()
    _idps, directories = identity_providers()
    by_entity = _report_index(report_rows)
    accounts = {}

    def account(provider, origin, owner, lists_every):
        ref = account_ref(provider, origin, owner["account"])
        found = accounts.get(ref)
        if found is None:
            found = accounts[ref] = Account(ref=ref, provider=provider, label=str(owner.get("label") or owner["account"]),
                                            lists_every=lists_every)
        for basis, value in owner.get("keys") or ():
            hashed = digester(value)
            if hashed:
                found.keys.add((basis, hashed))
        return found

    def credential(owner, *, ref, credential_ref, current, report):
        return {"ref": ref, "credential_ref": str(credential_ref), "type": owner.get("credential_type") or "UNKNOWN",
                "name": str(owner.get("name") or "")[:200], "state": owner.get("state") or "UNKNOWN",
                "relation": owner.get("relation") or "owns",
                "last_used_at": _iso(_time(owner.get("last_used_at"))), "expires_at": _iso(_time(owner.get("expires_at"))),
                "current": bool(current), "exposed": report.get("exposed") if report else None,
                "vault_state": report.get("state") if report else None, "action": owner.get("action")}

    for provider, module_name in schema2.items():
        module = import_module(module_name)
        # SSH and deploy keys are `public_key` entities; a provider's credential_owner names a person only for keys
        # a person owns (a deploy key or an app's certificate names nobody).
        for row in (row for kind in ("credential", "public_key")
                    for row in _every("ISSUED_CREDENTIALS", store.inventory, provider=provider, object_kind=kind,
                                      purpose="issuer_inventory")):
            try:
                owner = module.credential_owner(row)
            except (KeyError, TypeError, ValueError, AttributeError):
                owner = None
            if not owner or not owner.get("account"):
                continue
            run = row.get("observation_run") or {}
            current = current_issuer_observation(row, connections.get(run.get("connection_id")), now=now)
            found = account(provider, row["origin"], owner, module.LISTS_EVERY_USER_CREDENTIAL)
            found.credentials.append(credential(owner, ref=str(row["id"]), credential_ref=row["id"], current=current,
                                                report=by_entity.get(str(row["id"]))))
    for provider, accounts_of in directories.items():
        module = import_module(schema2[accounts_of]) if accounts_of in schema2 else None
        for row in _every("DIRECTORY_ACCOUNTS", store.inventory, provider=provider, object_kind="principal",
                          purpose="identity_status", details=False):
            summary = row["summary"] or {}
            if summary.get("identity_key_id") != digester.key_id:
                continue
            found = account(accounts_of, row["origin"], {"account": row["object_id"].removeprefix("user:")},
                            module.LISTS_EVERY_USER_CREDENTIAL if module else True)
            found.directory = True
            found.keys |= {(key["kind"], key["digest"]) for key in summary.get("identity_keys") or []
                           if key["kind"] != "IDP_USER_ID"}
    for provider, module_name in schema1.items():
        module = import_module(module_name)
        for row in report_rows or []:
            issued = row.get("issued") or {}
            if row.get("origin") != "ISSUANCE" or issued.get("provider") != provider:
                continue
            try:
                owner = module.credential_owner(issued)
            except (KeyError, TypeError, ValueError, AttributeError):
                owner = None
            if not owner:
                continue
            key = f"{module.PROVIDER}|{issued.get('account_id', '')}|{issued.get('identifier')}"
            found = account(module.PROVIDER, module.PROVIDER, owner, module.LISTS_EVERY_USER_CREDENTIAL)
            if any(item["ref"] == key for item in found.credentials):
                continue
            found.credentials.append(credential(owner, ref=key, credential_ref=uuid.uuid5(_NS, "cremore:identity-credential:" + key),
                                                current=issued.get("current_evidence"), report=row))
    return accounts


def _iso(value):
    return value.isoformat() if isinstance(value, _dt.datetime) else None


# What a value an IdP sent can be on that IdP's side when no record names the IdP -- a GitHub directory identity's
# values, GitLab's extern_uid: a SAML NameID is whatever the IdP was set to send (its user id, login or email), as is
# the uid another external login (OIDC and the like) gave GitLab, an LDAP DN matching nothing; a SCIM user name is a
# login (an email-shaped one too), an email an email.
_IDP_VALUE_KINDS = {"SAML_NAME_ID": KINDS, "SCIM_EXTERNAL_ID": ("LOGIN", "EMAIL"), "VERIFIED_EMAIL": ("EMAIL",),
                    "EXTERNAL_UID": KINDS}


def idp_value_kinds(basis, *, directory):
    """The kinds of IdP value an account's identity value may match, or None for any: a directory identity's values
    and GitLab's extern_uid are IdP-sent (_IDP_VALUE_KINDS); a provider's own verified email or object id is not."""
    return _IDP_VALUE_KINDS.get(basis) if directory or basis == "EXTERNAL_UID" else None


def fits(basis, kind, *, directory):
    """Whether an account's identity value of ``basis`` may match a person's IdP value of ``kind``."""
    kinds = idp_value_kinds(basis, directory=directory)
    return kinds is None or kind in kinds


def _idp(person):
    return person["provider"], person["origin"], person["tenant"]


def _two_humans(reached, people):
    """Whether people of different IdPs that one account's IdP-sent values reach may be different humans: no email of
    theirs is the same (one person in two IdPs carries one work email in both)."""
    emails = {ref: {key["digest"] for key in people[ref].get("keys") or [] if key["kind"] == "EMAIL"} for ref in reached}
    return any(_idp(people[a]) != _idp(people[b]) and not emails[a] & emails[b]
               for a, b in combinations(sorted(reached, key=str), 2))


def link_accounts(accounts, people, stored_links, now):
    """(exact links {account: {person: basis}}, candidates [(account, person, basis)], new MATCHED links,
    {account: people its IdP-sent values reach though they may be different humans}).

    A directory identity (github_identity) is a person of the IdP that provisions its organization or enterprise, and
    no IdP issuer or tenant is collected to say which IdP that is; nor for GitLab's extern_uid. Such values link on
    their own only to the same kind of value (idp_value_kinds) and only while they reach one human -- people of several
    IdPs sharing an email are one; otherwise each person reached is a candidate, except one the account's own
    provider-verified value (an email GitLab confirmed) names exactly. A person an administrator rejected for the
    account reaches nothing.
    """
    index = {}
    for ref, person in people.items():
        if person["state"] == "PURGED":
            continue
        for key in person.get("keys") or []:
            index.setdefault(key["digest"], set()).add((ref, key["kind"]))
    decisions = {}
    for (account, person), row in stored_links.items():
        decisions.setdefault(account, {})[person] = row
    exact, candidates, new_links, contested = {}, [], [], {}
    for ref, account in accounts.items():
        decided = decisions.get(ref, {})
        rejected = {person for person, row in decided.items() if row["decision"] == "REJECTED"}
        hits, weak, reached, own = {}, {}, set(), {}
        for basis, digest in sorted(account.keys):
            idp_sent = idp_value_kinds(basis, directory=account.directory) is not None
            for person, kind in index.get(digest, ()):
                if person in rejected:
                    continue
                if idp_sent:
                    reached.add(person)
                exact_basis = basis in EXACT_BASES and fits(basis, kind, directory=account.directory)
                (hits if exact_basis else weak).setdefault(person, basis)
                if exact_basis and not idp_sent:
                    own.setdefault(person, basis)
        # Two people of one IdP naming the same value: nothing links on its own. Nor do IdP-sent values that reach
        # people of two IdPs who may be different humans: only the IdP that sent them could say -- a person the
        # account's own verified value names stays linked by it.
        groups = {}
        for person in hits:
            groups.setdefault(_idp(people[person]), set()).add(person)
        two_humans = _two_humans(reached, people)
        if two_humans:
            contested[ref] = reached
        if any(len(group) > 1 for group in groups.values()):
            weak.update(hits)
            hits = {}
        elif two_humans:
            weak.update({person: basis for person, basis in hits.items() if person not in own})
            hits = dict(own)
        linked = dict(hits)
        for person, row in decided.items():
            if row["decision"] in ("MATCHED", "CONFIRMED") and person in people:
                linked.setdefault(person, row["basis"])
        for person, basis in hits.items():
            if person not in decided:
                new_links.append({"account_ref": ref, "person_ref": person, "decision": "MATCHED", "basis": basis,
                                  "actor_ref": None, "decided_at": now})
        if linked:
            exact[ref] = linked
        for person, basis in weak.items():
            if person not in linked and person not in rejected:
                candidates.append((ref, person, basis))
    return exact, candidates, new_links, contested


def verdict_for(credential, departed_at, now):
    """(verdict, reasons) for one credential of a departed person."""
    last, expires = _time(credential.get("last_used_at")), _time(credential.get("expires_at"))
    if last is not None and departed_at is not None and last > departed_at:
        return "USED_AFTER_DEPARTURE", []
    if credential.get("state") == "REVOKED_OR_EXPIRED" or (expires is not None and expires <= now):
        return "REVOKED_OR_EXPIRED", []
    if not credential.get("current"):
        return "UNKNOWN", ["ISSUER_OBSERVATION_NOT_CURRENT"]
    if credential.get("state") == "ACTIVE":
        return "ACTIVE", [] if last is not None else ["NO_LAST_USE_REPORTED"]
    return "UNKNOWN", ["PROVIDER_STATE_UNKNOWN"]


def build_orphans(accounts, exact, people, now, contested=None):
    """The verdict rows (without publication state), keyed by orphan ref. ``contested``: link_accounts' people an
    account's IdP-sent values reach beside its kept links; an active one among them is a disagreement too."""
    out = {}
    for ref, linked in exact.items():
        account = accounts.get(ref)
        departed = [(person, people[person]) for person in linked if people.get(person, {}).get("state") == DEPARTED]
        if account is None or not departed:
            continue
        person, row = min(departed, key=lambda item: _time(item[1]["departed_at"]) or now)
        departed_at = _time(row["departed_at"])
        disagreement = any(people.get(other, {}).get("state") == "ACTIVE"
                           for other in set(linked) | (contested or {}).get(ref, set()))
        basis = linked[person]
        base = {"person": {"ref": str(person), "provider": row["provider"], "idp_user_id": row["idp_user_id"],
                           "idp_state": row["idp_state"], "departed_at": _iso(departed_at),
                           "departure_basis": row["departure_basis"], "idp_disagreement": disagreement},
                "account": {"ref": ref, "provider": account.provider, "label": account.label,
                            "link_basis": "OPERATOR_CONFIRMED" if basis not in EXACT_BASES else basis}}
        rows = list(account.credentials)
        for credential in rows:
            verdict, reasons = verdict_for(credential, departed_at, now)
            key = orphan_ref(person, credential["ref"])
            out[key] = {"orphan_ref": key, "person_ref": person, "account_ref": ref, "provider": account.provider,
                        "verdict": verdict, "body": {**copy.deepcopy(base), "credential": credential,
                                                     "reasons": sorted(reasons + (["IDP_STATES_DISAGREE"] if disagreement else []))}}
        if not account.lists_every:
            key = orphan_ref(person, "account:" + ref)
            out[key] = {"orphan_ref": key, "person_ref": person, "account_ref": ref, "provider": account.provider,
                        "verdict": "UNKNOWN", "body": {**copy.deepcopy(base), "credential": None,
                                                       "reasons": ["PROVIDER_DOES_NOT_LIST_EVERY_CREDENTIAL"]}}
    return out


# --- one evaluation --------------------------------------------------------------------


def _report_rows(repo, settings, orchestrator, now):
    """The coverage comparison's issued rows (exposure and vault state); [] without an engine. The schema 1
    inventory (AWS IAM keys) reaches the check only here, and the comparison shares one row budget with the vault
    snapshots: when that budget cut a schema 1 issuer's snapshot, or the issued rows outran the page, it is a cut
    listing like any other. A cut elsewhere in the comparison (findings, vaults) leaves these rows whole."""
    if orchestrator is None:
        return []
    import hashlib

    from cremore.coverage.correlation import REPORT_LIMIT, report
    from cremore.coverage.models import V1_OWNERS, Contract

    key = orchestrator.config.fingerprint_key
    contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                        policy_digest=orchestrator.coverage_policy_digest).model_dump()
    result = report(repo, contract, limit=REPORT_LIMIT, now=now, settings=settings, origin="ISSUANCE",
                    fingerprint_key_id=hashlib.sha256(key).hexdigest() if key else None)
    if result["total"] > len(result["items"]) or any(
            (state.get("spec") or {}).get("provider") in V1_OWNERS and state.get("truncated")
            for state in result["connections"]):
        raise IncompleteListing("COVERAGE_REPORT_LIMIT_REACHED")
    return result["items"]


def _partial(repo, store, state, connections, people_rows, reasons, now):
    """A cut listing decides no link, verdict or ticket: those and the published result stay as the last complete
    evaluation left them, and the next slot reads again. The people listings read whole are still saved: a departure
    missed now would be lost once collection history expires. Retention waits for a complete evaluation, as only one
    knows whether a departed person still left a credential on."""
    state.save(people=list(people_rows.values()))
    reasons = sorted(set(reasons))
    last = (repo.get_setting(RESULT_KEY) or {}).get("value") or {}
    repo.put_setting(RESULT_KEY, {**last, "status": "PARTIAL", "reasons": reasons}, "worker")
    return {"status": "PARTIAL", "reasons": reasons, "pruned_runs": _prune_history(store, connections, now)}


def evaluate(repo, settings, orchestrator=None, *, now=None, fingerprint_key=None, report_rows=None) -> dict:
    """Recompute people, links and verdicts, publish changes, apply retention. Returns counts with ``status``
    COMPLETE, or PARTIAL and the listing that could not be read whole (then no link or verdict was decided)."""
    from cremore.coverage.metadata_store import MetadataStore

    now = now or _now()
    key = fingerprint_key if fingerprint_key is not None else (
        orchestrator.config.fingerprint_key if orchestrator is not None else settings.fingerprint_key_bytes)
    digester = Digester(key)
    store, state = MetadataStore(repo), LeaverStore(repo)
    connections = {row["id"]: row for row in store.list_connections()}
    stored_people = state.people()
    people_rows, reasons, cut = sync_people(store, connections, stored_people, digester.key_id, now)
    # PARTIAL's reasons are the cut listings; events that could not date a departure are a COMPLETE evaluation's note.
    if cut:
        return _partial(repo, store, state, connections, people_rows, cut, now)
    try:
        if report_rows is None:
            report_rows = _report_rows(repo, settings, orchestrator, now)
        accounts = collect_accounts(store, connections, digester, report_rows, now)
    except IncompleteListing as exc:
        return _partial(repo, store, state, connections, people_rows, [str(exc)], now)
    people = {**stored_people, **people_rows}
    idps, _directories = identity_providers()
    live_connections = {cid for cid, row in connections.items() if row["spec"].get("provider") in idps}
    # People of a removed IdP connection stop counting; departed ones wait for retention.
    dropped = [ref for ref, row in people.items() if ref not in people_rows and row["state"] not in (DEPARTED, "PURGED")
               and row.get("connection_id") not in live_connections]
    for ref in dropped:
        people.pop(ref)
    stored_links = state.links()
    exact, candidates, new_links, contested = link_accounts(accounts, people, stored_links, now)
    current = build_orphans(accounts, exact, people, now, contested)
    purged = _expire(people, current, getattr(settings, "leaver_retention_days", 365), now)
    people_rows.update({ref: people[ref] for ref in purged})
    current = {ref: row for ref, row in current.items() if row["person_ref"] not in purged}
    candidates = [item for item in candidates if item[1] not in purged]
    new_links = [row for row in new_links if row["person_ref"] not in purged]
    stored = state.orphans()
    events, tickets = _publish(repo, current, stored, people, now)
    state.save(people=list(people_rows.values()), links=new_links, orphans=list(current.values()),
               removed_orphans=[ref for ref in stored if ref not in current],
               removed_links=[key for key in stored_links if key[1] in purged])
    state.delete_people(dropped)
    pruned = _prune_history(store, connections, now)
    summary = {"status": "COMPLETE", "reasons": sorted(reasons),
               "people": sum(row["state"] != "PURGED" for row in people.values()),
               "departed": sum(row["state"] == DEPARTED for row in people.values()),
               "accounts": len(accounts), "linked_accounts": len(exact), "candidates": len(candidates),
               "orphans": len(current), "events": events, "tickets": tickets, "purged_people": len(purged),
               "pruned_runs": pruned, "evaluated_at": now.isoformat()}
    repo.put_setting(RESULT_KEY, {**summary, "candidate_links": [
        {"account_ref": account, "person_ref": str(person), "basis": basis,
         "account_label": accounts[account].label, "account_provider": accounts[account].provider}
        for account, person, basis in candidates if people.get(person, {}).get("state") == DEPARTED][:MAX_CANDIDATES]},
        "worker")
    return summary


def _publish(repo, current, stored, people, now):
    """Carry publication state forward; queue events for new or changed verdicts; open tickets."""
    from cremore.siem.events import identity_credential_orphaned

    queued, opened, existing = 0, 0, None
    for ref in sorted(current, key=str):
        row, before = current[ref], stored.get(ref) or {}
        row["first_seen_at"] = before.get("first_seen_at") or now
        row["updated_at"] = now
        row["sequence"] = before.get("sequence", 0)
        row["published_verdict"] = before.get("published_verdict")
        row["ticket_id"] = before.get("ticket_id")
        verdict, previous = row["verdict"], row["published_verdict"]
        silent = previous is None and verdict == "REVOKED_OR_EXPIRED"  # nothing left to act on
        if verdict != previous and not silent and queued < MAX_EVENTS:
            credential = row["body"].get("credential") or {}
            person = people.get(row["person_ref"], {})
            event = identity_credential_orphaned(
                orphan_ref=ref, sequence=row["sequence"] + 1, verdict=verdict, previous_verdict=previous,
                credential_ref=credential.get("credential_ref") or uuid.uuid5(_NS, "cremore:identity-account:" + row["account_ref"]),
                person_ref=row["person_ref"], provider=row["provider"], credential_type=credential.get("type"),
                departed_at=_time(person.get("departed_at")), departure_basis=person.get("departure_basis"),
                link_basis=row["body"]["account"]["link_basis"], last_used_at=_time(credential.get("last_used_at")),
                exposed=credential.get("exposed"), vault_state=credential.get("vault_state"), now=now)
            repo.record_siem_event(event)
            queued += 1
            row["sequence"] += 1
            row["published_verdict"] = verdict
        elif silent:
            row["published_verdict"] = verdict
        if verdict in NEEDS_ACTION and row["ticket_id"] is None and opened < MAX_TICKETS:
            from cremore.governance.tickets import TicketService

            if existing is None:  # a pass that stopped before saving a ticket id must not open a second one
                existing = {ticket.orphan_ref: ticket for ticket in repo.list_tickets() if ticket.orphan_ref}
            ticket = TicketService(repo).create_for_orphan(row, now=now, existing=existing)
            row["ticket_id"] = ticket.id
            opened += 1
    return queued, opened


def _still_on(row, now):
    """An actionable verdict whose credential is not yet off (a key used after departure stays that verdict)."""
    credential = row["body"].get("credential") or {}
    expires = _time(credential.get("expires_at"))
    return (row["verdict"] in NEEDS_ACTION and credential.get("state") != "REVOKED_OR_EXPIRED"
            and not (expires is not None and expires <= now))


def _expire(people, orphans, days, now):
    """Departed people past the retention period become tombstones: a reference and when, nothing else.

    A person who still left a credential in use or on (USED_AFTER_DEPARTURE, ACTIVE) stays until it
    is dealt with: the data is what the open problem is about, and dropping it would hide the problem.
    """
    cutoff = now - _dt.timedelta(days=days)
    open_problem = {row["person_ref"] for row in orphans.values() if _still_on(row, now)}
    expired = {ref for ref, row in people.items() if row["state"] == DEPARTED and ref not in open_problem
               and (_time(row.get("departed_at")) or now) < cutoff}
    for ref in expired:
        people[ref] = {**people[ref], "state": "PURGED", "idp_user_id": None, "keys": [], "key_id": None,
                       "entity_id": None, "idp_state": "PURGED", "departed_at": None, "departure_basis": None,
                       "purged_at": now, "updated_at": now}
    return expired


def _prune_history(store, connections, now):
    """Delete identity collection runs older than IDENTITY_RUN_HISTORY_DAYS (each one's latest complete run stays)."""
    idps, directories = identity_providers()
    pruned, history = 0, now - _dt.timedelta(days=IDENTITY_RUN_HISTORY_DAYS)
    for cid, connection in connections.items():
        if connection["spec"].get("provider") in idps | set(directories):
            latest = store.latest_success(cid)
            pruned += store.prune_runs(cid, before=history, keep={latest["id"]} if latest else set())
    return pruned


def publish(repo, settings, orchestrator=None, *, now=None):
    """One replica per five-minute slot evaluates; returns counts, or None when another had the slot."""
    now = now or _now()
    if not repo.claim_slot(SLOT_KEY, int(now.timestamp()) // INTERVAL_SECONDS, "worker"):
        return None
    if not _has_identity_connections(repo):
        return {"status": "COMPLETE", "reasons": [], "people": 0}
    return evaluate(repo, settings, orchestrator, now=now)


def _has_identity_connections(repo):
    from cremore.coverage.metadata_store import MetadataStore

    idps, _directories = identity_providers()
    return any(row["spec"].get("provider") in idps for row in MetadataStore(repo).list_connections())
