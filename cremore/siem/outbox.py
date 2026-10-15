"""Durable per-destination delivery leases for immutable SIEM observations.

No outbound I/O runs here. A successful delivery must be acknowledged with its
current, unexpired token; crashes and failed sends leave the snapshot retryable.
"""
from __future__ import annotations

import re
import uuid
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta


def _clock(conn=None):
    if conn is not None and conn.dialect.name == "postgresql":
        from sqlalchemy import func, select
        return conn.execute(select(func.clock_timestamp())).scalar_one()
    return datetime.now(UTC)


def _destination(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError("SIEM_INVALID_DESTINATION")
    return value


def _number(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("SIEM_INVALID_LIMIT")
    return value


def _id(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("SIEM_INVALID_ID") from None


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


# Error text, URLs and responses must never enter durable delivery state: only
# these fixed codes do, the rest become DELIVERY_FAILED. The second line holds
# the codes the built-in sinks raise; the last the Slack detection alerts'
# (cremore/alerts) setup and bot codes.
SAFE_CODES = frozenset({
    "DELIVERY_FAILED", "DELIVERY_TIMEOUT", "DELIVERY_REJECTED", "DELIVERY_RATE_LIMITED",
    "AUTH_FAILED", "INVALID_RESPONSE", "SINK_UNAVAILABLE",
    "HTTP_STATUS_REJECTED", "HEC_RESPONSE_REJECTED", "RESPONSE_TOO_LARGE", "HTTP_DELIVERY_FAILED",
    "STDOUT_DELIVERY_FAILED", "INVALID_EVENT", "INVALID_EVENT_TIME",
    "OAUTH_TOKEN_FAILED", "SYSLOG_CONNECT_FAILED", "SYSLOG_TLS_FAILED", "SYSLOG_DELIVERY_FAILED",
    "ALERTS_NOT_CONFIGURED", "ALERTS_SECRET_UNAVAILABLE", "ALERTS_WEBHOOK_INVALID", "CONTACT_CHANNEL_NOT_SET_UP",
    "CONTACT_RECIPIENT_NOT_ALLOWED", "CONTACT_SECRET_UNAVAILABLE", "SLACK_RATE_LIMITED", "SLACK_UNAVAILABLE",
    "SLACK_RESPONSE_LIMIT", "SLACK_REQUEST_REFUSED", "SLACK_INVALID_AUTH", "SLACK_NOT_AUTHED", "SLACK_TOKEN_REVOKED",
    "SLACK_ACCOUNT_INACTIVE", "SLACK_MISSING_SCOPE", "SLACK_CHANNEL_NOT_FOUND", "SLACK_NOT_IN_CHANNEL",
    "SLACK_IS_ARCHIVED", "SLACK_INVALID_BLOCKS", "SLACK_MSG_TOO_LONG", "SLACK_MSG_BLOCKS_TOO_LONG",
    "SLACK_INVALID_BLOCKS_FORMAT", "SLACK_INVALID_ARGUMENTS", "SLACK_NO_TEXT", "SLACK_TOO_MANY_ATTACHMENTS",
    "SLACK_RESTRICTED_ACTION", "SLACK_RATELIMITED", "SLACK_TEAM_ACCESS_NOT_GRANTED", "SLACK_INTERNAL_ERROR",
    "SLACK_FATAL_ERROR", "SLACK_SERVICE_UNAVAILABLE", "SLACK_REQUEST_TIMEOUT",
})
OUTCOMES = ("SUCCESS", "FAILURE", "IDLE")


def safe_code(value) -> str:
    return value if value in SAFE_CODES else "DELIVERY_FAILED"


# Destinations CreMore delivers to itself (cremore/alerts) share the outbox but are not SIEMs: SIEM status, the backlog
# evaluator and the forward count leave them out, while retention still waits for one that reports.
INTERNAL_PREFIX = "cremore."


def _time(value):
    """An optional time bound in UTC; anything else is ValueError."""
    if value is None:
        return None
    try:
        return _utc(value)
    except (AttributeError, TypeError):
        raise ValueError("SIEM_INVALID_TIME") from None


class SiemOutbox:
    def __init__(self, repo):
        self.repo = repo
        self.engine = getattr(repo, "engine", None)

    @staticmethod
    def clock() -> datetime:
        """This process's time, as a lease or a put-back delay counts it: a span measured with it compares to those."""
        return _clock()

    @contextmanager
    def _transaction(self):
        if self.engine is None:
            with self.repo._lock:
                yield None
            return
        with self.engine.begin() as conn:
            if conn.dialect.name == "sqlite" and not getattr(self.engine, "_task_bound", False):
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            yield conn

    def claim(self, destination: str, limit=100, lease_seconds=60) -> list[dict]:
        destination = _destination(destination)
        _number(limit, 1, 1000)
        _number(lease_seconds, 1, 86400)
        with self._transaction() as conn:
            now = _clock(conn)
            if conn is None:
                return self._claim_memory(destination, limit, lease_seconds, now)
            from sqlalchemy import and_, or_, select

            from cremore.db.schema import siem_deliveries as deliveries
            from cremore.db.schema import siem_events as events

            # Lock the immutable event row, not the nullable side of the join.
            # This also serializes first delivery creation for a destination.
            available = or_(deliveries.c.event_id.is_(None), and_(
                deliveries.c.delivered_at.is_(None), deliveries.c.held_at.is_(None),
                deliveries.c.available_at <= now,
                or_(deliveries.c.lease_until.is_(None), deliveries.c.lease_until <= now)))
            query = select(events.c.event_id, events.c.payload).select_from(events.outerjoin(
                deliveries, and_(events.c.event_id == deliveries.c.event_id,
                                 deliveries.c.destination == destination))).where(available).order_by(
                events.c.occurred_at, events.c.event_id).limit(limit).with_for_update(of=events, skip_locked=True)
            rows = conn.execute(query).mappings().all()
            claimed = []
            for row in rows:
                token = uuid.uuid4()
                statement = self.repo._insert(conn, deliveries).values(destination=destination,
                    event_id=row["event_id"], attempts=1, token=token,
                    lease_until=now + timedelta(seconds=lease_seconds), available_at=now)
                statement = statement.on_conflict_do_update(
                    index_elements=[deliveries.c.destination, deliveries.c.event_id],
                    set_={"attempts": deliveries.c.attempts + 1, "token": token,
                          "lease_until": now + timedelta(seconds=lease_seconds)},
                    where=and_(deliveries.c.delivered_at.is_(None), deliveries.c.held_at.is_(None),
                               deliveries.c.available_at <= now,
                               or_(deliveries.c.lease_until.is_(None), deliveries.c.lease_until <= now)))
                attempts = conn.execute(statement.returning(deliveries.c.attempts)).scalar_one_or_none()
                if attempts is not None:
                    claimed.append({"event": deepcopy(row["payload"]), "token": str(token), "attempts": attempts})
            return claimed

    def claim_owed(self, destination: str, limit=100, lease_seconds=60) -> list[dict]:
        """Lease up to ``limit`` events the destination already holds and has not received (a retry or a put-back now
        due, an event queued with ``skip(queue_kept=True)``), the earliest due first, then the oldest. Reads delivery
        rows, not the kept events: with the ``siem_deliveries_owed`` index (destination, available_at WHERE
        delivered_at IS NULL) this stays cheap however long the history is."""
        destination = _destination(destination)
        _number(limit, 1, 1000)
        _number(lease_seconds, 1, 86400)
        with self._transaction() as conn:
            now = _clock(conn)
            lease = now + timedelta(seconds=lease_seconds)
            if conn is None:
                events = self.repo.siem_events
                due = sorted(((row["available_at"], datetime.fromisoformat(events[event_id]["occurred_at"]), event_id)
                              for (name, event_id), row in self.repo.siem_deliveries.items()
                              if name == destination and row["delivered_at"] is None and row.get("held_at") is None
                              and row["available_at"] <= now
                              and (row["lease_until"] is None or row["lease_until"] <= now) and event_id in events),
                             key=lambda entry: entry[:2])
                claimed = []
                for _available, _occurred, event_id in due[:limit]:
                    row, token = self.repo.siem_deliveries[(destination, event_id)], str(uuid.uuid4())
                    row.update(token=token, lease_until=lease, attempts=row["attempts"] + 1)
                    claimed.append({"event": deepcopy(self.repo.siem_events[event_id]), "token": token,
                                    "attempts": row["attempts"]})
                return claimed
            from sqlalchemy import or_, select, update

            from cremore.db.schema import siem_deliveries as deliveries
            from cremore.db.schema import siem_events as events
            free = or_(deliveries.c.lease_until.is_(None), deliveries.c.lease_until <= now)
            rows = conn.execute(select(deliveries.c.event_id, events.c.payload).select_from(deliveries.join(
                events, events.c.event_id == deliveries.c.event_id)).where(
                deliveries.c.destination == destination, deliveries.c.delivered_at.is_(None),
                deliveries.c.held_at.is_(None), deliveries.c.available_at <= now, free).order_by(
                deliveries.c.available_at, events.c.occurred_at, events.c.event_id).limit(limit).with_for_update(
                of=deliveries, skip_locked=True)).mappings().all()
            claimed = []
            for row in rows:
                token = uuid.uuid4()
                attempts = conn.execute(update(deliveries).where(
                    deliveries.c.destination == destination, deliveries.c.event_id == row["event_id"],
                    deliveries.c.delivered_at.is_(None), deliveries.c.held_at.is_(None), free).values(
                    token=token, lease_until=lease, attempts=deliveries.c.attempts + 1).returning(
                    deliveries.c.attempts)).scalar_one_or_none()
                if attempts is not None:
                    claimed.append({"event": deepcopy(row["payload"]), "token": str(token), "attempts": attempts})
            return claimed

    def _claim_memory(self, destination, limit, lease_seconds, now):
        claimed = []
        for event_id, event in self.repo.siem_events.items():
            key = (destination, event_id)
            previous = self.repo.siem_deliveries.get(key)
            if previous and (previous["delivered_at"] is not None or previous.get("held_at") is not None
                             or previous["available_at"] > now
                             or previous["lease_until"] is not None and previous["lease_until"] > now):
                continue
            token = str(uuid.uuid4())
            delivery = {"attempts": 0, "available_at": now, "delivered_at": None, "error_code": None,
                        "held_at": None, **(previous or {}), "token": token,
                        "lease_until": now + timedelta(seconds=lease_seconds)}
            delivery["attempts"] += 1
            self.repo.siem_deliveries[key] = delivery
            claimed.append({"event": deepcopy(event), "token": token, "attempts": delivery["attempts"]})
            if len(claimed) == limit:
                break
        return claimed

    def acknowledge(self, destination, event_id, token) -> bool:
        return self._finish(destination, event_id, token, error_code=None, delay_seconds=None)

    def retry(self, destination, event_id, token, *, error_code="DELIVERY_FAILED", delay_seconds=30,
              hold=False) -> bool:
        """Schedule another attempt, or with ``hold`` stop retrying until an Admin releases it."""
        _number(delay_seconds, 0, 604800)
        return self._finish(destination, event_id, token, error_code=safe_code(error_code),
                            delay_seconds=delay_seconds, hold=hold)

    def defer(self, destination, event_id, token, *, delay_seconds) -> bool:
        """Put a claimed event back for ``delay_seconds`` without counting the attempt: it was not tried (its state
        was not settled yet, or the destination is cooling down). The last error code stays."""
        _number(delay_seconds, 0, 86400)
        return self._finish(destination, event_id, token, error_code=None, delay_seconds=delay_seconds, uncounted=True)

    def _finish(self, destination, event_id, token, *, error_code, delay_seconds, hold=False, uncounted=False):
        destination, event_id, token = _destination(destination), _id(event_id), _id(token)
        with self._transaction() as conn:
            now = _clock(conn)
            changes = {"token": None, "lease_until": None}
            if not uncounted:
                changes["error_code"] = error_code
            if delay_seconds is None:
                changes["delivered_at"] = now
            else:
                changes["available_at"] = now + timedelta(seconds=delay_seconds)
            if hold:
                changes["held_at"] = now
            if conn is None:
                delivery = self.repo.siem_deliveries.get((destination, str(event_id)))
                if delivery is None or delivery["token"] != str(token) or delivery["delivered_at"] is not None:
                    return False
                if delivery["lease_until"] is None or _utc(delivery["lease_until"]) <= now:
                    return False
                delivery.update(changes)
                if uncounted:
                    delivery["attempts"] = max(0, delivery["attempts"] - 1)
                return True
            from sqlalchemy import update

            from cremore.db.schema import siem_deliveries as deliveries
            if uncounted:
                changes["attempts"] = deliveries.c.attempts - 1
            result = conn.execute(update(deliveries).where(deliveries.c.destination == destination,
                deliveries.c.event_id == event_id, deliveries.c.token == token,
                deliveries.c.delivered_at.is_(None), deliveries.c.lease_until > now).values(**changes))
            return result.rowcount == 1

    def record_status(self, destination, outcome, *, error_code=None) -> None:
        """What one exporter pass saw for a destination: success, failure or nothing to send."""
        destination = _destination(destination)
        if outcome not in OUTCOMES:
            raise ValueError("SIEM_INVALID_OUTCOME")
        with self._transaction() as conn:
            now = _clock(conn)
            if conn is None:
                row = self.repo.siem_destination_status.setdefault(destination, {
                    "destination": destination, "last_seen_at": now, "last_success_at": None,
                    "last_failure_at": None, "last_error_code": None, "consecutive_failures": 0})
                row["last_seen_at"] = now
                if outcome == "SUCCESS":
                    row.update(last_success_at=now, consecutive_failures=0)
                elif outcome == "FAILURE":
                    row.update(last_failure_at=now, last_error_code=safe_code(error_code),
                               consecutive_failures=row["consecutive_failures"] + 1)
                return
            from cremore.db.schema import siem_destination_status as table
            values = {"destination": destination, "last_seen_at": now, "consecutive_failures": 0}
            changes = {"last_seen_at": now}
            if outcome == "SUCCESS":
                values["last_success_at"] = changes["last_success_at"] = now
                changes["consecutive_failures"] = 0
            elif outcome == "FAILURE":
                values.update(last_failure_at=now, last_error_code=safe_code(error_code), consecutive_failures=1)
                changes.update(last_failure_at=now, last_error_code=safe_code(error_code),
                               consecutive_failures=table.c.consecutive_failures + 1)
            conn.execute(self.repo._insert(conn, table).values(**values).on_conflict_do_update(
                index_elements=[table.c.destination], set_=changes))

    def status(self, *, include_internal=False) -> list[dict]:
        """Per SIEM destination: exporter status plus pending, held and oldest-pending, from delivery rows. CreMore's
        own destinations (``INTERNAL_PREFIX``) only with ``include_internal``."""
        if self.engine is None:
            with self.repo._lock:
                return self._status_memory(include_internal)
        from sqlalchemy import and_, func, or_, select

        from cremore.db.schema import siem_deliveries as deliveries
        from cremore.db.schema import siem_destination_status as table
        from cremore.db.schema import siem_events as events
        with self.engine.connect() as conn:
            total = conn.execute(select(func.count()).select_from(events)).scalar_one()
            counts = {row.destination: row for row in conn.execute(select(
                deliveries.c.destination,
                func.count().filter(deliveries.c.delivered_at.isnot(None)).label("delivered"),
                func.count().filter(and_(deliveries.c.delivered_at.is_(None),
                                         deliveries.c.held_at.isnot(None))).label("held"),
            ).group_by(deliveries.c.destination))}
            saved = {row["destination"]: dict(row) for row in conn.execute(select(table)).mappings()}
            out = []
            for name in sorted(name for name in set(counts) | set(saved)
                               if include_internal or not name.startswith(INTERNAL_PREFIX)):
                oldest = conn.execute(select(func.min(events.c.occurred_at)).select_from(events.outerjoin(
                    deliveries, and_(deliveries.c.event_id == events.c.event_id,
                                     deliveries.c.destination == name))).where(or_(
                    deliveries.c.event_id.is_(None),
                    and_(deliveries.c.delivered_at.is_(None), deliveries.c.held_at.is_(None))))).scalar_one()
                delivered, held = (counts[name].delivered, counts[name].held) if name in counts else (0, 0)
                out.append(self._status_row(name, saved.get(name), total - delivered - held, held, oldest))
        return out

    def seen_since(self, since, *, include_internal=False) -> list[str]:
        """SIEM destinations the exporter has reported on since ``since`` (one silent longer counts as removed): a
        light read of their status rows only. CreMore's own destinations only with ``include_internal``."""
        if self.engine is None:
            with self.repo._lock:
                names = [name for name, row in self.repo.siem_destination_status.items()
                         if _utc(row["last_seen_at"]) >= since]
        else:
            from sqlalchemy import select

            from cremore.db.schema import siem_destination_status as table
            with self.engine.connect() as conn:
                names = list(conn.execute(select(table.c.destination).where(table.c.last_seen_at >= since)).scalars())
        return sorted(name for name in names if include_internal or not name.startswith(INTERNAL_PREFIX))

    def _status_memory(self, include_internal=False):
        names = {name for name, _ in self.repo.siem_deliveries} | set(self.repo.siem_destination_status)
        names = {name for name in names if include_internal or not name.startswith(INTERNAL_PREFIX)}
        out = []
        for name in sorted(names):
            pending, held, oldest = 0, 0, None
            for event_id, event in self.repo.siem_events.items():
                delivery = self.repo.siem_deliveries.get((name, event_id)) or {}
                if delivery.get("delivered_at") is not None:
                    continue
                if delivery.get("held_at") is not None:
                    held += 1
                    continue
                pending += 1
                occurred = datetime.fromisoformat(event["occurred_at"])
                oldest = occurred if oldest is None or occurred < oldest else oldest
            out.append(self._status_row(name, self.repo.siem_destination_status.get(name), pending, held, oldest))
        return out

    @staticmethod
    def _status_row(name, saved, pending, held, oldest) -> dict:
        saved = saved or {}

        def stamp(value):
            return _utc(value).isoformat() if value is not None else None

        return {"destination": name, "pending": pending, "held": held, "oldest_pending_at": stamp(oldest),
                "last_seen_at": stamp(saved.get("last_seen_at")), "last_success_at": stamp(saved.get("last_success_at")),
                "last_failure_at": stamp(saved.get("last_failure_at")), "last_error_code": saved.get("last_error_code"),
                "consecutive_failures": saved.get("consecutive_failures", 0)}

    def release_held(self, destination) -> int:
        """Give every held delivery of one destination a fresh round of attempts."""
        destination = _destination(destination)
        with self._transaction() as conn:
            now = _clock(conn)
            changes = {"held_at": None, "available_at": now, "attempts": 0}
            if conn is None:
                held = [row for (name, _), row in self.repo.siem_deliveries.items()
                        if name == destination and row.get("held_at") is not None and row["delivered_at"] is None]
                for row in held:
                    row.update(changes)
                return len(held)
            from sqlalchemy import update

            from cremore.db.schema import siem_deliveries as deliveries
            released = conn.execute(update(deliveries).where(
                deliveries.c.destination == destination, deliveries.c.held_at.isnot(None),
                deliveries.c.delivered_at.is_(None)).values(**changes).returning(deliveries.c.event_id)).all()
            return len(released)

    def skip_before(self, destination, before, *, since=None) -> None:
        """Count every event that occurred before ``before`` (and from ``since``) as delivered to ``destination``,
        unsent: a destination turned on now starts from now instead of replaying the kept history."""
        if before is None:
            raise ValueError("SIEM_INVALID_TIME")
        self.skip(destination, before=before, since=since)

    def skip(self, destination, *, before=None, since=None, keep=(), queue_kept=False):
        """Count events as delivered to ``destination`` without sending them: those that occurred before ``before``
        and from ``since`` (either open), except those ``keep`` names as (event type, change or None) pairs. With
        ``queue_kept`` the kept ones get a row too, owed since they occurred, so ``claim_owed`` finds them without
        reading the events again. One INSERT ... SELECT; an event the destination already holds keeps its state.
        Returns when the newest event in that range occurred (None: none), read before the insert."""
        destination, before, since, keep = _destination(destination), _time(before), _time(since), tuple(keep)
        with self._transaction() as conn:
            now = _clock(conn)
            if conn is None:
                newest = None
                for event_id, event in self.repo.siem_events.items():
                    occurred = datetime.fromisoformat(event["occurred_at"])
                    if (before is not None and occurred >= before) or (since is not None and occurred < since):
                        continue
                    newest = occurred if newest is None or occurred > newest else newest
                    kept = any(event.get("event_type") == kind and change in (None, event.get("change"))
                               for kind, change in keep)
                    if kept and not queue_kept:
                        continue
                    self.repo.siem_deliveries.setdefault((destination, event_id), {
                        "attempts": 0, "token": None, "lease_until": None, "available_at": min(occurred, now),
                        "delivered_at": None if kept else now, "error_code": None, "held_at": None})
                return newest
            from sqlalchemy import (
                DateTime,
                Integer,
                String,
                and_,
                case,
                func,
                literal,
                not_,
                null,
                or_,
                select,
                true,
            )

            from cremore.db.schema import siem_deliveries as deliveries
            from cremore.db.schema import siem_events as events
            # SQLite reads ON CONFLICT after a SELECT without WHERE as a join constraint: there is always a WHERE.
            bounds = [true(), *([events.c.occurred_at < before] if before is not None else []),
                      *([events.c.occurred_at >= since] if since is not None else [])]
            newest = conn.execute(select(func.max(events.c.occurred_at)).where(*bounds)).scalar_one()
            stamp = literal(now, DateTime(timezone=True))
            delivered = stamp
            if keep:
                kind = events.c.payload["event_type"].as_string()
                change = func.coalesce(events.c.payload["change"].as_string(), "")
                kept = or_(*(kind == name if part is None else and_(kind == name, change == part) for name, part in keep))
                if queue_kept:
                    delivered = case((kept, null()), else_=stamp)
                else:
                    bounds.append(not_(kept))
            # In one order (the events' own index): writers whose ranges overlap take the row locks in the same order,
            # so on PostgreSQL two of them wait for each other instead of deadlocking.
            chosen = select(literal(destination, String(128)), events.c.event_id, literal(0, Integer),
                            case((events.c.occurred_at < stamp, events.c.occurred_at), else_=stamp), delivered).where(
                *bounds).order_by(events.c.occurred_at, events.c.event_id)
            conn.execute(self.repo._insert(conn, deliveries).from_select(
                ["destination", "event_id", "attempts", "available_at", "delivered_at"], chosen).on_conflict_do_nothing(
                index_elements=[deliveries.c.destination, deliveries.c.event_id]))
            return _utc(newest) if newest is not None else None

    def oldest_unclaimed(self, destination):
        """When the oldest event the destination holds no row for occurred, or None: an event written later than the
        destination's reader looked for it (the whole kept history is read)."""
        destination = _destination(destination)
        if self.engine is None:
            with self.repo._lock:
                times = [datetime.fromisoformat(event["occurred_at"]) for event_id, event in self.repo.siem_events.items()
                         if (destination, event_id) not in self.repo.siem_deliveries]
            return min(times) if times else None
        from sqlalchemy import and_, select

        from cremore.db.schema import siem_deliveries as deliveries
        from cremore.db.schema import siem_events as events
        query = select(events.c.occurred_at).select_from(events.outerjoin(deliveries, and_(
            deliveries.c.event_id == events.c.event_id, deliveries.c.destination == destination))).where(
            deliveries.c.event_id.is_(None)).order_by(events.c.occurred_at).limit(1)
        with self.engine.connect() as conn:
            value = conn.execute(query).scalar_one_or_none()
        return _utc(value) if value is not None else None

    def destination_status(self, destination, *, since=None) -> dict:
        """``status()``'s row for one destination without reading the whole kept history: the rows it holds and has
        not received (through the owed-rows index), plus the events from ``since`` it holds no row for yet."""
        destination, since = _destination(destination), _time(since)
        if self.engine is None:
            with self.repo._lock:
                pending, held, oldest = 0, 0, None
                for event_id, event in self.repo.siem_events.items():
                    occurred = datetime.fromisoformat(event["occurred_at"])
                    delivery = self.repo.siem_deliveries.get((destination, event_id))
                    if delivery is None and since is not None and occurred < since:
                        continue
                    if (delivery or {}).get("delivered_at") is not None:
                        continue
                    if (delivery or {}).get("held_at") is not None:
                        held += 1
                        continue
                    pending, oldest = pending + 1, occurred if oldest is None or occurred < oldest else oldest
                return self._status_row(destination, self.repo.siem_destination_status.get(destination), pending,
                                        held, oldest)
        from sqlalchemy import and_, func, select

        from cremore.db.schema import siem_deliveries as deliveries
        from cremore.db.schema import siem_destination_status as table
        from cremore.db.schema import siem_events as events
        waiting = deliveries.c.held_at.is_(None)
        with self.engine.connect() as conn:
            owed, held, owed_oldest = conn.execute(select(
                func.count().filter(waiting), func.count().filter(deliveries.c.held_at.isnot(None)),
                func.min(events.c.occurred_at).filter(waiting)).select_from(deliveries.join(
                events, events.c.event_id == deliveries.c.event_id)).where(
                deliveries.c.destination == destination, deliveries.c.delivered_at.is_(None))).one()
            fresh, fresh_oldest = conn.execute(select(func.count(), func.min(events.c.occurred_at)).select_from(
                events.outerjoin(deliveries, and_(deliveries.c.event_id == events.c.event_id,
                                                  deliveries.c.destination == destination))).where(
                deliveries.c.event_id.is_(None), *([events.c.occurred_at >= since] if since is not None else []))).one()
            saved = conn.execute(select(table).where(table.c.destination == destination)).mappings().first()
        times = [_utc(value) for value in (owed_oldest, fresh_oldest) if value is not None]
        return self._status_row(destination, dict(saved) if saved else None, owed + fresh, held,
                                min(times) if times else None)

    def deliveries(self, event_id) -> list[dict]:
        """Where one event stands at each destination that has tried it (e.g. a test event)."""
        event_id = _id(event_id)
        fields = ("attempts", "delivered_at", "held_at", "error_code", "available_at")
        if self.engine is None:
            with self.repo._lock:
                rows = [{"destination": name, **{key: row.get(key) for key in fields}}
                        for (name, eid), row in self.repo.siem_deliveries.items() if eid == str(event_id)]
        else:
            from sqlalchemy import select

            from cremore.db.schema import siem_deliveries as deliveries
            with self.engine.connect() as conn:
                rows = [dict(row) for row in conn.execute(select(
                    deliveries.c.destination, *(deliveries.c[key] for key in fields)).where(
                    deliveries.c.event_id == event_id)).mappings()]
        for row in rows:
            for key in ("delivered_at", "held_at", "available_at"):
                row[key] = _utc(row[key]).isoformat() if row[key] is not None else None
        return sorted(rows, key=lambda row: row["destination"])

    def prune(self, *, before, short_lived_before, short_lived_types, active_since, limit=5000) -> int:
        """Delete events past retention that every active destination has received.

        ``before`` (None = keep) applies to every event; ``short_lived_before`` only to
        ``short_lived_types``. A destination the exporter last saw before
        ``active_since`` counts as removed. With no active destination, age decides.
        """
        _number(limit, 1, 100000)
        with self._transaction() as conn:
            if conn is None:
                return self._prune_memory(before, short_lived_before, set(short_lived_types), active_since, limit)
            from sqlalchemy import and_, delete, false, func, or_, select

            from cremore.db.schema import siem_deliveries as deliveries
            from cremore.db.schema import siem_destination_status as table
            from cremore.db.schema import siem_events as events
            active = list(conn.execute(select(table.c.destination).where(
                table.c.last_seen_at >= active_since)).scalars())
            aged = or_(events.c.occurred_at < before if before is not None else false(), and_(
                events.c.payload["event_type"].as_string().in_(list(short_lived_types)),
                events.c.occurred_at < short_lived_before))
            if active:
                received = select(func.count()).where(
                    deliveries.c.event_id == events.c.event_id, deliveries.c.destination.in_(active),
                    deliveries.c.delivered_at.isnot(None)).scalar_subquery()
                aged = and_(aged, received == len(active))
            ids = list(conn.execute(select(events.c.event_id).where(aged).order_by(
                events.c.occurred_at).limit(limit)).scalars())
            if ids:
                conn.execute(delete(deliveries).where(deliveries.c.event_id.in_(ids)))
                conn.execute(delete(events).where(events.c.event_id.in_(ids)))
            return len(ids)

    def _prune_memory(self, before, short_lived_before, short_lived_types, active_since, limit):
        active = [name for name, row in self.repo.siem_destination_status.items()
                  if _utc(row["last_seen_at"]) >= active_since]
        chosen = []
        for event_id, event in sorted(self.repo.siem_events.items(), key=lambda item: item[1]["occurred_at"]):
            occurred = datetime.fromisoformat(event["occurred_at"])
            old = (before is not None and occurred < before) or (
                event.get("event_type") in short_lived_types and occurred < short_lived_before)
            received = all((self.repo.siem_deliveries.get((name, event_id)) or {}).get("delivered_at") is not None
                           for name in active)
            if old and received:
                chosen.append(event_id)
            if len(chosen) == limit:
                break
        for event_id in chosen:
            del self.repo.siem_events[event_id]
            for key in [key for key in self.repo.siem_deliveries if key[1] == event_id]:
                del self.repo.siem_deliveries[key]
        return len(chosen)
