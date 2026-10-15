"""Change feeds: find what changed under an approved root since the last look, scan only that.

A source module that can answer "what changed since this cursor" defines one of:

* ``changes_since(payload, root, cursor, *, http_client, request_budget) -> Changes``
  (code hosts. GitLab, Bitbucket and Azure DevOps Git: the cursor is a commit. GitHub:
  "<sha> <ETag>", the branch head and the ETag of the request that read it, so the next
  look is a conditional request whose 304 means unchanged; a plain "<sha>" still works.
  Azure DevOps TFVC: the latest changeset id), or
* ``changes_since_batch(payload, roots, states, *, http_client, request_budget)
  -> {resource_id: Changes}`` (Confluence: one search answers for a space's pages; Notion:
  one search walk, newest edits first, answers for a connection's approved pages and names
  them as page ids).

Sources without either keep their scheduled scans; object stores already scan
incrementally by version (S3 watermarks, GCS generation and Azure Blob ETag through the
detection cache).

The worker polls every enabled, approved scope whose events are on (design 4.3,
decision 5): every five minutes (Bitbucket every fifteen) unless an Admin sets a
provider's minutes. What changed becomes the same work a queued event does
(``enqueue_event``): only the changed files when the provider names them, the whole root
when it cannot (too many, a diff timeout, a directory change) and a baseline when history
was rewritten (a force push, a commit that no longer exists). No new job kind exists, so
the active-scan indexes and their migrations are untouched. What a feed misses is read by
the installation's full scan (daily by default, cremore/scanning/triggers.py poll_schedules);
with schedules off, or a scope whose full scan is set to 0, nothing reads it until it changes
again or someone scans.

A first look only records where the root is: the scan that established the root's
state already covers the present. A cursor moves only after the resulting job is
durably queued, so a failure is retried by the next poll. A pass reads the roots whose
last look is oldest first and starts none once PASS_SECONDS are spent, so a provider
that throttles every request cannot hold the worker's control loop; the roots left
lead the next pass. Only scopes whose source has a feed are planned at all.

A push notification from a customer's queue wakes a root's feed (``wake``) rather than
queueing work itself, so the feed's compare decides the files and spots a force push.

A failed look (a provider's rate limit or outage, any other collector code, a refused
queueing) keeps the cursor and records its code and ``failing_since``, the first failure
of the streak; a successful look drops both, and a root not looked at for longer than its
interval and LOOK_SLACK starts a new streak. ``failing_roots`` counts them per connection
and code, of the roots a pass still reads, for the operations status
(cremore/operations/health.feed_alerts).
"""

from __future__ import annotations

import datetime as _dt
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import JSON, Column, DateTime, String, Table, Uuid, and_, func, or_, select

from cremore.collectors.base import CollectorError, RequestBudget, RequestBudgetExceeded, path_under
from cremore.collectors.changes import (
    Changes,  # noqa: F401 -- the answer type, re-exported for callers
)

logger = logging.getLogger(__name__)

DEFAULT_MINUTES = 5
MAX_PROFILES = 1000
REQUESTS_PER_ROOT = 60
# A pass runs on the worker's control loop, which must keep polling and beating: once this much of a pass's reading
# is spent (a provider throttling every request), no further connection or root starts; the rest wait for the next
# pass, which takes them first because their last look is the oldest. Planning is not counted, so a pass always reads.
PASS_SECONDS = 20
# enqueue_event's refusals of the changed paths themselves; the root's whole incremental read is queued instead.
PATHS_REFUSED = frozenset({"EVENT_INVALID_PAYLOAD", "EVENT_OUT_OF_SCOPE"})
# A root not looked at within its provider's interval and this much more is not being read (feeds off, a paused scope, a
# root its scope no longer holds): its failure no longer counts, and its next failure starts a new streak.
LOOK_SLACK = _dt.timedelta(hours=1)
_WOKEN = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)


@dataclass
class PassBudget(RequestBudget):
    """A feed pass's request budget, which also says when the pass's time is up: ``read_changes`` then starts no
    further root, and the roots it did not start get no answer, so their cursors stay as they are. A walk in hand (a
    Notion batch pages through one search) is refused its next request then, as if its requests had run out."""

    stop: Callable[[], bool] = lambda: False

    def consume(self) -> None:
        if self.stop():
            raise RequestBudgetExceeded()
        super().consume()


def register_tables(metadata):
    if "scan_change_cursors" in metadata.tables:
        return metadata.tables["scan_change_cursors"]
    return Table("scan_change_cursors", metadata,
                 Column("id", String(64), primary_key=True),  # the root identity
                 Column("profile_id", Uuid, nullable=False), Column("connection_id", Uuid, nullable=False),
                 Column("state", JSON, nullable=False),
                 Column("checked_at", DateTime(timezone=True), nullable=False))


class CursorStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "change_cursors"):
                    repo.change_cursors = {}
        else:
            from cremore.db.schema import metadata

            self.table = register_tables(metadata)

    def get(self, root_id):
        if self.engine is None:
            with self.repo._lock:
                row = self.repo.change_cursors.get(root_id)
                return None if row is None else dict(row)
        with self.engine.connect() as conn:
            row = conn.execute(select(self.table).where(self.table.c.id == root_id)).mappings().first()
            return None if row is None else dict(row)

    def put(self, root_id, profile_id, connection_id, state, checked_at):
        row = {"id": root_id, "profile_id": profile_id, "connection_id": connection_id, "state": state,
               "checked_at": checked_at}
        if self.engine is None:
            with self.repo._lock:
                self.repo.change_cursors[root_id] = row
            return
        with self.engine.begin() as conn:
            statement = self.repo._insert(conn, self.table).values(**row)
            conn.execute(statement.on_conflict_do_update(
                index_elements=[self.table.c.id],
                set_={"profile_id": profile_id, "connection_id": connection_id, "state": state,
                      "checked_at": checked_at}))

    def failing(self, looked_since):
        """``(connection_id, error, roots, earliest failing_since)`` of the failing roots of the profiles in
        ``looked_since``, a row counting only when its last look came at its profile's time or later. One row per
        connection and code, however many roots fail."""
        if not looked_since:
            return []
        if self.engine is None:
            groups = {}
            with self.repo._lock:
                for row in self.repo.change_cursors.values():
                    state, since = row["state"] or {}, looked_since.get(row["profile_id"])
                    if since is None or not state.get("failing_since") or _now(row["checked_at"]) < since:
                        continue
                    key = (row["connection_id"], state.get("error"))
                    roots, first = groups.get(key, (0, state["failing_since"]))
                    groups[key] = (roots + 1, min(first, state["failing_since"]))
            return [(*key, roots, first) for key, (roots, first) in groups.items()]
        profiles = {}
        for profile_id, since in looked_since.items():
            profiles.setdefault(since, []).append(profile_id)
        table, failing_since = self.table, self.table.c.state["failing_since"].as_string()
        # Labelled in a subquery, so the outer GROUP BY names columns rather than repeating bound JSON paths.
        rows = select(table.c.connection_id, table.c.state["error"].as_string().label("error"),
                      failing_since.label("since")).where(failing_since.is_not(None), or_(*(
                          and_(table.c.profile_id.in_(ids), table.c.checked_at >= since)
                          for since, ids in profiles.items()))).subquery()
        with self.engine.connect() as conn:
            return [tuple(row) for row in conn.execute(select(rows.c.connection_id, rows.c.error, func.count(),
                    func.min(rows.c.since)).group_by(rows.c.connection_id, rows.c.error))]


def _module(resource_type):
    from cremore.sources.registry import BY_RESOURCE_TYPE

    return BY_RESOURCE_TYPE.get(resource_type)


def _feeds(module) -> bool:
    return callable(getattr(module, "changes_since", None)) or callable(getattr(module, "changes_since_batch", None))


def supports(resource_type) -> bool:
    return _feeds(_module(resource_type))


def read_changes(payload, roots, states, *, http_client, request_budget):
    """Ask each root's source module; ``{resource_id: Changes | CollectorError}``.

    One root's failure is its own answer, never the others'. ``states`` maps a root to
    ``{"cursor", "checked_at"}`` from the last look. A ``PassBudget`` whose time is up
    starts no further root or batch; those get no answer.
    """
    stop = getattr(request_budget, "stop", None) or (lambda: False)
    out, singles, batches = {}, [], {}
    for root in roots:
        module = _module(root["resource_type"])
        if callable(getattr(module, "changes_since_batch", None)):
            batches.setdefault(root["resource_type"], []).append(root)
        elif callable(getattr(module, "changes_since", None)):
            singles.append((module.changes_since, root))
    for function, root in singles:
        if stop():
            return out
        try:
            answer = function(payload, root, (states.get(root["resource_id"]) or {}).get("cursor"),
                              http_client=http_client, request_budget=request_budget)
        except CollectorError as exc:
            answer = exc
        if answer is not None:
            out[root["resource_id"]] = answer
    for resource_type, group in batches.items():
        if stop():
            return out
        try:
            answers = _module(resource_type).changes_since_batch(payload, group, states, http_client=http_client,
                                                                 request_budget=request_budget)
        except CollectorError as exc:
            answers = dict.fromkeys((root["resource_id"] for root in group), exc)
        out.update(answers)
    return out


def _in_scope(root, value):
    """The approved root's own include and exclude rules, as ``enqueue_event`` checks them."""
    if getattr(_module(root["resource_type"]), "SCOPE_KIND", "path") == "object":
        included = root.get("all_current_objects") or any(value.startswith(p) for p in root.get("prefixes") or [])
        return (bool(included) and len(value.encode()) <= 1024
                and not any(value.startswith(p) for p in root.get("excluded_prefixes") or []))
    included = not root.get("paths") or path_under(value, root["paths"])
    return included and not path_under(value, root.get("excluded_paths") or [])


def _now(value=None):
    value = value or _dt.datetime.now(_dt.UTC)
    return value.replace(tzinfo=_dt.UTC) if value.tzinfo is None else value.astimezone(_dt.UTC)


def _confirms_removals(root):
    """GitHub confirms a missing exact path (the file is gone); other collectors only skip it."""
    return root.get("resource_type") == "GITHUB_REPOSITORY"


def work_for(root, changes):
    """(mode, paths) a change asks for: BASELINE, DELTA (whole root), EVENT (these paths) or None."""
    from cremore.scanning.triggers import MAX_EVENT_KEYS

    if changes.rewritten:
        return "BASELINE", None
    if changes.paths is None or (changes.removals and not _confirms_removals(root)):
        return "DELTA", None
    paths = [value for value in dict.fromkeys(changes.paths) if _in_scope(root, value)]
    if not paths:
        return None, None  # the change was outside the approved paths
    if len(paths) > MAX_EVENT_KEYS:
        return "DELTA", None
    return "EVENT", paths


def wake(repo, profile, root) -> bool:
    """Read ``root``'s feed on the next poll, whatever its interval. False when the feed has
    no cursor for the root yet: its first look would only record the head, so the caller
    queues the work itself."""
    from cremore.scanning import scope

    if not supports(root["resource_type"]):
        return False
    cursors = CursorStore(repo)
    root_id = scope.root_identity(profile.connection_id, root)
    saved = cursors.get(root_id)
    if saved is None or not (saved.get("state") or {}).get("cursor"):
        return False
    cursors.put(root_id, profile.id, profile.connection_id, saved["state"], _WOKEN)
    return True


def _event_scopes(repo):
    """The scopes a pass plans: ready, events on, at most MAX_PROFILES read. An account's buckets have no feed (their
    changes come through a queue): such a scope is not planned at all."""
    page_cursor, seen = None, 0
    while seen < MAX_PROFILES:
        profiles, page_cursor = repo.list_scope_profiles_page(cursor=page_cursor, limit=100)
        seen += len(profiles)
        yield from (p for p in profiles if p.state == "READY" and p.event_mode == "ENABLED" and p.kind != "aws")
        if page_cursor is None:
            return


def failing_roots(repo, settings, *, now=None) -> list[tuple]:
    """``(connection_id, error, roots, earliest failing_since)`` of the roots whose last look failed, of the scopes a pass
    still reads, counting a root only while a pass still looks at it: within its provider's interval and LOOK_SLACK. A
    removed, paused or event-off scope's cursor, or a root its scope no longer holds, is not one; none while feeds are
    off."""
    from cremore.scanning import scope, trigger_settings

    if not trigger_settings.change_feeds_on(settings, repo):
        return []
    now, intervals = _now(now), trigger_settings.change_feed_minutes(settings, repo)
    connections = {connection.id: connection for connection in repo.list_connections()}
    looked_since = {}
    for profile in _event_scopes(repo):
        if (connection := connections.get(profile.connection_id)) is not None:
            minutes = int(intervals.get(scope.provider_of(profile.kind, connection), DEFAULT_MINUTES))
            looked_since[profile.id] = now - _dt.timedelta(minutes=minutes) - LOOK_SLACK
    return CursorStore(repo).failing(looked_since)


def poll_change_feeds(repo, settings, reader, *, now=None, minutes=None, clock=time.monotonic):
    """One bounded pass over event-enabled scopes.

    ``reader(payload, roots, states, request_budget)`` returns ``read_changes`` for one
    profile's due roots, with the connection's credential resolved as a scan resolves it.
    The due roots are read oldest last look first, and once PASS_SECONDS of ``clock`` are
    spent from the first read no further connection or root starts: those keep their cursors and
    lead the next pass. A root whose answer fails to apply records the error and its look.
    """
    from cremore.db.scan_store import stable_digest
    from cremore.scanning import scope, trigger_settings, triggers
    from cremore.sources.registry import PROVIDERS

    if not trigger_settings.change_feeds_on(settings, repo):
        return {"checked": 0, "enqueued": 0}
    now = _now(now)
    intervals = minutes if minutes is not None else trigger_settings.change_feed_minutes(settings, repo)
    cursors = CursorStore(repo)
    result = {"checked": 0, "enqueued": 0, "unchanged": 0, "failed": 0, "deferred": 0}
    feeds, work = {}, []  # whether a connection's source has a feed; (oldest last look, profile, base, due roots)
    for candidate in _event_scopes(repo):
        try:
            # The object stores have no feed either: their scopes are not planned.
            if candidate.connection_id not in feeds:
                connection = repo.get_connection(candidate.connection_id)
                feeds[candidate.connection_id] = connection is not None and _feeds(
                    PROVIDERS.get(scope.provider_of(candidate.kind, connection)))
            if not feeds[candidate.connection_id]:
                continue
            profile, plan, target, base, _source = triggers.prepare_trigger_plan(
                repo, settings, candidate.id, "EVENT", now=now)
            provider = scope.provider_of(profile.kind, target)
            interval = _dt.timedelta(minutes=int(intervals.get(provider, DEFAULT_MINUTES)))
            due = []
            for root in plan.roots:
                if not supports(root["resource_type"]):
                    continue
                root_id = scope.root_identity(profile.connection_id, root)
                saved = cursors.get(root_id)
                looked, state = (_now(saved["checked_at"]), dict(saved.get("state") or {})) if saved else (None, {})
                if looked is not None and looked + interval > now:
                    continue
                if looked not in (None, _WOKEN) and looked + interval + LOOK_SLACK < now:
                    state.pop("failing_since", None)  # not read for a while: a failure now starts a new streak
                due.append((looked, root, root_id, state))
        except scope.ScopeError:
            continue
        except Exception as exc:  # noqa: BLE001 -- one broken scope (a malformed catalog item) never stops the rest
            logger.warning("change feed plan for scope %s failed: %s", candidate.id, type(exc).__name__)
            continue
        if due:
            due.sort(key=_last_look)
            work.append((_last_look(due[0]), profile, base, due))
    deadline = clock() + PASS_SECONDS  # from the first read: a slow plan must not leave a pass that reads nothing
    for _oldest, profile, base, due in sorted(work, key=lambda item: item[0]):
        if clock() >= deadline:
            result["deferred"] += len(due)
            continue
        states = {root["resource_id"]: {"cursor": state.get("cursor"), "checked_at": looked}
                  for looked, root, _rid, state in due}
        budget = PassBudget(REQUESTS_PER_ROOT * len(due), stop=lambda: clock() >= deadline)
        try:
            answers = reader({**base, "connection_id": str(profile.connection_id)},
                             [root for _looked, root, _rid, _state in due], states, budget)
        except Exception:  # noqa: BLE001 -- a credential or client failure stops this profile only
            answers = {root["resource_id"]: CollectorError("CHANGE_FEED_FAILED") for _looked, root, _r, _s in due}
        for _looked, root, root_id, state in due:
            answer = answers.get(root["resource_id"])
            if answer is None:
                result["deferred"] += int(clock() >= deadline)  # not started in time: it leads the next pass
                continue
            result["checked"] += 1
            try:
                _apply(repo, settings, profile, root, root_id, state, answer, cursors, result, now, stable_digest,
                       scope, triggers)
            except Exception as exc:  # noqa: BLE001 -- one root's failure never ends the pass for the others
                # Its look counts, so a root that always fails goes to the back of the next pass, not to its front.
                logger.warning("change feed root %s failed to apply: %s", root_id, type(exc).__name__)
                result["failed"] += 1
                cursors.put(root_id, profile.id, profile.connection_id, _failed(state, "CHANGE_FEED_FAILED", now), now)
    return result


def _last_look(item):
    """Oldest first: never looked at, then woken, then by the time of the last look."""
    return (item[0] is not None, item[0] or _WOKEN)


def _failed(state, code, now):
    """A failed look's state: the cursor stays, and ``failing_since`` keeps the first failure of the streak."""
    return {**state, "error": code, "failing_since": state.get("failing_since") or now.isoformat()}


def _apply(repo, settings, profile, root, root_id, state, changes, cursors, result, now, stable_digest, scope, triggers):
    """Turn one root's answer into queued work and a moved cursor."""
    if changes is None:
        return
    if isinstance(changes, Exception):
        result["failed"] += 1
        code = changes.code if isinstance(changes, CollectorError) else "CHANGE_FEED_FAILED"
        cursors.put(root_id, profile.id, profile.connection_id, _failed(state, code, now), now)
        return
    if not state.get("cursor") or changes.head == state["cursor"]:
        # A first look records where the root is; the scan that set its state covers the present.
        result["unchanged"] += bool(state.get("cursor"))
        cursors.put(root_id, profile.id, profile.connection_id,
                    {"cursor": changes.head, "changed_at": state.get("changed_at")}, now)
        return
    mode, paths = work_for(root, changes)
    if mode is not None:
        whole = {"event_id": stable_digest(["change", root_id, state["cursor"], changes.head]),
                 "resource_id": root["resource_id"]}
        # Under the root's own exact field, as _event_root reads it: page_ids for Notion.
        event = {**whole, scope.EXACT_FIELDS[root["resource_type"]].removeprefix("exact_"): paths} if paths else whole
        reason = changes.reason
        try:
            try:
                triggers.enqueue_event(repo, settings, profile.id, event, origin="change-feed", now=now,
                                       mode=mode if mode == "BASELINE" else None)
            except scope.ScopeError as exc:
                if not paths or exc.code not in PATHS_REFUSED:
                    raise
                # A changed name the event check refuses (a control character, an over-long path): every later
                # look from this cursor would meet it again, so the root's own incremental read covers the change
                # and the cursor moves on.
                mode, reason = "DELTA", exc.code
                triggers.enqueue_event(repo, settings, profile.id, whole, origin="change-feed", now=now)
        except scope.ScopeError as exc:
            # The look counts (the cursor stays): a refusal that lasts (a paused or re-approved scope) waits the
            # root's interval instead of being read again on every pass.
            result["failed"] += 1
            cursors.put(root_id, profile.id, profile.connection_id, _failed(state, exc.code, now), now)
            return
        result["enqueued"] += 1
        recorded = {"changed_at": now.isoformat(), "last_mode": mode, "reason": reason}
    else:
        result["unchanged"] += 1
        # Nothing to read (a feed whose head is a time moves it every poll): the last change stays recorded.
        recorded = {key: state.get(key) for key in ("changed_at", "last_mode", "reason")}
    cursors.put(root_id, profile.id, profile.connection_id, {"cursor": changes.head, **recorded}, now)
