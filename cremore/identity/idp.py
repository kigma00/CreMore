"""One checkpointed collector for identity listings: IdP users and account directories.

A provider folder supplies a small vendor module: how to authenticate and read one
page of a source, and how one row becomes a user (id, status, when it changed, the
identity values to digest), a status event, or an app the IdP lists for sign-in (its
name and whether it is on, to suggest services to connect; a separate collection of the
same IdP reads apps, so its failure never makes a people listing partial). This module does everything else the
schema 2 contract asks of a collector: budgets, pacing, waits on rate limits, cursor
cycles, record replay after a restart, per-source completeness reports and the
record checks the worker applies before storing anything.

Identity values leave the vendor module only as keyed digests (cremore.identity.keys);
the key never reaches it. Records a machine submits are refused: nothing outside the
worker can prove a digest was made from what the IdP returned. A collection that asks
for profiles (``options.keep_profiles``) also keeps what a person is called and where
they work -- display name, email, department, title -- as facts that name people in
owner, contact and access views; matching never uses them.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    EntityIdentity,
    EntityObservation,
    IdentityKey,
    MetadataConnectionSpec,
    MetadataFact,
    MetadataPage,
    MetadataProvenance,
    OperationReport,
    ProviderEvent,
    RecordQuality,
    checkpoint_json,
    in_metadata_scope,
    metadata_text,
)
from cremore.coverage.models import digest as spec_digest

STATES = ("ACTIVE", "DISABLED", "DELETED", "PENDING", "UNKNOWN")
CHANGES = ("DISABLED", "DELETED", "ENABLED")
_COUNTS = ("task", "requests", "pages", "records", "retries", "op_pages", "received", "saved", "invalid", "duplicates")
_HASH = re.compile(r"[0-9a-f]{64}")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,95}")
MAX_SEEN_CURSORS = 20000
PROFILE_FIELDS = ("display_name", "email", "department", "title")
PROFILE_LIMIT = 256
# What an app the IdP lists keeps: what people see it as, and what it was made from -- an Okta catalog name
# (``app_slug``) or a Keycloak client ID (``client_id``), the vendor's APP_KEY.
APP_FIELDS = ("display_name", "app_slug", "client_id")


def apps_only(spec) -> bool:
    """A collection of the IdP's app list alone (the wizard's app list option): it lists no people, so it never
    says who left. ``spec`` is a connection spec or its stored form."""
    options = (spec.get("options") or {}) if isinstance(spec, dict) else {"sources": spec.options.sources}
    return options.get("sources") == ["apps"]


class ReadError(Exception):
    """A sanitized read failure: a fixed code, never a response body, URL or token."""

    def __init__(self, code, *, retryable=False, retry_after=60):
        super().__init__(code)
        self.code, self.retryable, self.retry_after = code, retryable, max(1, min(3600, int(retry_after)))


@dataclass(frozen=True)
class Source:
    name: str
    kind: str  # "users", "events" or "apps"
    # A complete users listing names everyone the scope holds, so a person missing
    # from it is no longer there. Only such a listing may say so.
    completes: bool = False
    enabled: Callable[[MetadataConnectionSpec], bool] = field(default=lambda spec: True)
    # Offset pages over a sorted list: a row read twice means rows moved under the reader (a rename, an add), and one
    # may have moved past it unread, so such a listing names no one's absence.
    shifts: bool = False


@dataclass(frozen=True)
class User:
    id: str
    raw_state: str
    state: str
    changed_at: str | None = None
    keys: tuple[tuple[str, str], ...] = ()  # (kind, raw value); digested here
    profile: tuple[tuple[str, str], ...] = ()  # (PROFILE_FIELDS name, value); kept only with keep_profiles


@dataclass(frozen=True)
class Event:
    id: str
    user_id: str
    change: str
    at: str


@dataclass(frozen=True)
class App:
    """An app the IdP lists for sign-in (an Okta app integration, a Keycloak client): kept only to suggest the
    services to connect (cremore.onboarding.suggestions), never as a person or a credential."""
    id: str
    raw_state: str
    state: str  # ACTIVE or DISABLED
    name: str
    key: str = ""


def utc_text(value) -> str | None:
    """An aware ISO-8601 time in UTC, or None."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, UTC).isoformat()
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162 -- providers send Z
    except ValueError:
        return None
    return parsed.astimezone(UTC).isoformat() if parsed.tzinfo else None


def profile_facts(profile, fields=PROFILE_FIELDS) -> list:
    """Facts for the profile values that can be kept: the first of each field, whitespace folded and
    cut to PROFILE_LIMIT; a value shaped like a credential or holding control characters is dropped."""
    facts, seen = [], set()
    for name, value in profile:
        if name not in fields or name in seen or not isinstance(value, str):
            continue
        text = " ".join(value.split())[:PROFILE_LIMIT]
        try:
            metadata_text(text)
        except ValueError:
            continue
        if text:
            seen.add(name)
            facts.append(MetadataFact(name=name, value=text))
    return facts


def cursor_text(value) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 4096 or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError("IDENTITY_INVALID_CURSOR")
    return value


class Pacer:
    """Interruptible pacing shared by vendor readers: requests_per_second and the request budget."""

    def __init__(self, spec, check, *, requests=0, sleep=time.sleep):
        self.spec, self.check, self.requests, self.sleep, self.next_slot = spec, check, requests, sleep, 0.0

    def before(self):
        self.check()
        if self.requests >= self.spec.max_requests:
            raise ReadError("REQUEST_BUDGET_EXCEEDED")
        delay = self.next_slot - time.monotonic()
        while delay > 0:
            step = min(delay, 0.5)
            self.check()
            self.sleep(step)
            delay -= step
        self.next_slot = time.monotonic() + 1 / self.spec.options.requests_per_second
        self.check()
        self.requests += 1


def status_error(prefix, response):
    """ReadError for a non-200 answer; rate limits and outages are retryable."""
    code = response.status_code
    if code == 429:
        retry = 60
        try:
            retry = int(float(response.headers.get("retry-after", "60")))
        except (TypeError, ValueError, OverflowError):
            pass
        return ReadError(prefix + "_RATE_LIMITED", retryable=True, retry_after=retry)
    if code >= 500 or code == 408:
        return ReadError(prefix + "_UNAVAILABLE", retryable=True)
    if code in (401, 403):
        return ReadError(prefix + "_ACCESS_DENIED")
    return ReadError(prefix + "_HTTP_" + str(code))


class Collector:
    """The schema 2 entry points for one vendor module (see the module docstring)."""

    def __init__(self, vendor):
        self.vendor = vendor
        self.provider = vendor.PROVIDER
        self.sources = {source.name: source for source in vendor.SOURCES}

    # --- spec and records ----------------------------------------------------

    def validate_spec(self, spec):
        vendor = self.vendor
        if spec.provider != self.provider:
            raise ValueError("IDENTITY_PROVIDER_MISMATCH")
        caps = set(spec.capabilities)
        events = any(source.kind == "events" for source in vendor.SOURCES)
        if "identity_status" not in caps or caps - {"identity_status", "audit"}:
            raise ValueError("IDENTITY_STATUS_CAPABILITY_REQUIRED")
        if ("audit" in caps) != bool(spec.options.include_audit_events) or (spec.options.include_audit_events and not events):
            raise ValueError("IDENTITY_AUDIT_OPTION_MISMATCH")
        options = spec.options
        if (options.include_actions or options.locations
                or options.include_deleted or options.include_provider_hashes
                or spec.principal_pin is not None):
            raise ValueError("IDENTITY_COLLECTION_OPTION_NOT_SUPPORTED")
        if options.audit_created_after is not None:
            raise ValueError("IDENTITY_AUDIT_WINDOW_IS_LOOKBACK_DAYS")
        vendor.validate_spec(spec)

    def tasks(self, spec):
        return [(scope, source) for scope in spec.scopes for source in self.vendor.SOURCES]

    def enabled(self, spec, source):
        if source.kind == "events" and not spec.options.include_audit_events:
            return False
        return source.enabled(spec)

    def operation(self, source_name):
        return self.provider + "." + source_name

    @staticmethod
    def resource(scope, source_name):
        return scope.kind + ":" + scope.id + "/" + source_name

    def provenance(self, scope, source_name, stamp):
        return MetadataProvenance(operation=self.operation(source_name), observed_at=stamp,
                                  resource_id=self.resource(scope, source_name),
                                  contract_version=self.vendor.CONTRACT_VERSION)

    def identity(self, spec, user_id):
        return EntityIdentity(provider=self.provider, origin=spec.origin, tenant=spec.tenant,
                              tenant_confirmed=spec.tenant_confirmed, kind="principal", object_id="user:" + user_id)

    def _user_id(self, object_id):
        user_id = object_id.removeprefix("user:")
        return user_id if object_id.startswith("user:") and self.vendor.USER_ID.fullmatch(user_id) else None

    def _app_id(self, object_id):
        pattern, app_id = getattr(self.vendor, "APP_ID", None), object_id.removeprefix("app:")
        return app_id if object_id.startswith("app:") and pattern is not None and pattern.fullmatch(app_id) else None

    def app_record(self, spec, scope, source_name, app, stamp):
        """An app as an ``installation`` of the IdP: no person, no identity keys, never read as a departure."""
        if app.state not in ("ACTIVE", "DISABLED") or self._app_id("app:" + app.id) is None:
            raise ValueError("IDENTITY_INVALID_APP")
        facts = profile_facts((("display_name", app.name), (self.vendor.APP_KEY, app.key)), APP_FIELDS)
        if not any(fact.name == "display_name" for fact in facts):  # a name that reads like a secret: its key names it
            facts = profile_facts((("display_name", app.key), (self.vendor.APP_KEY, app.key)), APP_FIELDS)
        if not any(fact.name == "display_name" for fact in facts):
            raise ValueError("IDENTITY_INVALID_APP")
        return EntityObservation(
            scope=scope, purpose="identity_status", provenance=self.provenance(scope, source_name, stamp),
            identity=EntityIdentity(provider=self.provider, origin=spec.origin, tenant=spec.tenant,
                                    tenant_confirmed=spec.tenant_confirmed, kind="installation", object_id="app:" + app.id),
            provider_state=app.raw_state[:64] or "UNKNOWN", normalized_state=app.state, state_basis="PROVIDER_REPORTED",
            facts=facts)

    def user_record(self, spec, scope, source_name, user, stamp, digester):
        if user.state not in STATES or not self.vendor.USER_ID.fullmatch(user.id):
            raise ValueError("IDENTITY_INVALID_USER")
        keys, seen = [IdentityKey(kind="IDP_USER_ID", digest=digester(user.id))], set()
        for kind, value in user.keys:
            hashed = digester(value)
            if hashed is not None and (kind, hashed) not in seen:
                seen.add((kind, hashed))
                keys.append(IdentityKey(kind=kind, digest=hashed))
        if len(keys) > 16:
            raise ValueError("IDENTITY_TOO_MANY_KEYS")
        return EntityObservation(
            scope=scope, purpose="identity_status", provenance=self.provenance(scope, source_name, stamp),
            identity=self.identity(spec, user.id), provider_state=user.raw_state[:64] or "UNKNOWN",
            normalized_state=user.state, state_basis="PROVIDER_REPORTED" if user.state != "UNKNOWN" else "UNKNOWN",
            effective_at=user.changed_at, identity_keys=keys, identity_key_id=digester.key_id,
            facts=profile_facts(user.profile) if spec.options.keep_profiles else [])

    def event_record(self, spec, scope, source_name, event, stamp):
        if event.change not in CHANGES or not self.vendor.USER_ID.fullmatch(event.user_id):
            raise ValueError("IDENTITY_INVALID_EVENT")
        return ProviderEvent(
            scope=scope, purpose="identity_status", provenance=self.provenance(scope, source_name, stamp),
            event_id=event.id, event_type="user." + event.change.lower(), occurred_at=event.at,
            subject=self.identity(spec, event.user_id), match_basis="PROVIDER_ID", confidence="EXACT")

    def report(self, scope, source_name, stamp, status, state=None, *, complete=False):
        state = state or dict.fromkeys(_COUNTS, 0) | {"op_reasons": []}
        return OperationReport(
            scope=scope, purpose="identity_status", provenance=self.provenance(scope, source_name, stamp),
            status=status, reasons=list(state["op_reasons"]), pages=state["op_pages"],
            received_records=state["received"], saved_records=state["saved"], proves_completeness=complete,
            record_quality=RecordQuality(records=state["received"], identified=state["saved"],
                                         invalid_records=state["invalid"], duplicates=state["duplicates"]),
            shape="array", native_schema_version=self.vendor.API_VERSION,
            report_type=self.provider + "_" + source_name.replace("-", "_"), collection_mode="identity")

    def validate_record(self, spec, item):
        try:
            self.validate_spec(spec)
            if not in_metadata_scope(spec, item) or item.purpose != "identity_status":
                return False
            name = item.provenance.operation.removeprefix(self.provider + ".")
            source = self.sources.get(name)
            if (source is None or item.provenance.operation != self.operation(name)
                    or item.provenance.contract_version != self.vendor.CONTRACT_VERSION
                    or item.provenance.source_commit is not None
                    or item.provenance.resource_id != self.resource(item.scope, name)
                    or item.omissions or (item.facts and item.record_type != "entity_observation")):
                return False
            if item.record_type == "operation_report":
                return (item.report_type == self.provider + "_" + name.replace("-", "_")
                        and item.collection_mode == "identity" and item.native_schema_version == self.vendor.API_VERSION
                        and item.value_access == "NOT_REQUESTED" and item.value_contract is None
                        and item.saved_records <= item.received_records
                        and (self.enabled(spec, source) or item.status == "NOT_REQUESTED")
                        and (not item.proves_completeness or (source.completes and item.status == "COMPLETE"
                                                              and not item.reasons)))
            if not self.enabled(spec, source):
                return False
            if item.record_type == "entity_observation" and source.kind == "apps":
                return (item.identity.kind == "installation" and self._app_id(item.identity.object_id) is not None
                        and item.value_match is None and not item.permissions and not item.identity_keys
                        and item.identity_key_id is None and item.normalized_state in ("ACTIVE", "DISABLED")
                        and item.effective_at is None and item.state_basis == "PROVIDER_REPORTED"
                        and any(fact.name == "display_name" for fact in item.facts)
                        and all(fact.name in APP_FIELDS and fact.state == "PRESENT" and not fact.children
                                and isinstance(fact.value, str) and 0 < len(fact.value) <= PROFILE_LIMIT
                                for fact in item.facts))
            if item.record_type == "entity_observation":
                return (source.kind == "users" and self._user_id(item.identity.object_id) is not None
                        and item.value_match is None and not item.permissions and item.identity_key_id is not None
                        and item.normalized_state in STATES
                        and sum(key.kind == "IDP_USER_ID" for key in item.identity_keys) == 1
                        and all(key.kind in self.vendor.KEY_KINDS for key in item.identity_keys)
                        and (not item.facts or spec.options.keep_profiles)
                        and len({fact.name for fact in item.facts}) == len(item.facts)
                        and all(fact.name in PROFILE_FIELDS and fact.state == "PRESENT" and not fact.children
                                and isinstance(fact.value, str) and 0 < len(fact.value) <= PROFILE_LIMIT
                                for fact in item.facts))
            if item.record_type == "provider_event":
                return (source.kind == "events" and item.subject is not None and item.target is None
                        and self._user_id(item.subject.object_id) is not None and item.value_match is None
                        and item.event_type in {"user." + change.lower() for change in CHANGES}
                        and item.match_basis == "PROVIDER_ID" and item.confidence == "EXACT")
            return False
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def validate_machine_record(spec, item):
        return False

    # --- collection ------------------------------------------------------------

    def _initial(self, spec, key_id):
        return {"provider": self.provider, "version": 1, "config_hash": spec_digest(spec.model_dump()),
                "key_id": key_id, **dict.fromkeys(_COUNTS, 0), "cursor": "", "seen": [], "reasons": [],
                "op_reasons": []}

    def _state(self, spec, checkpoint, key_id):
        if not isinstance(checkpoint, dict):
            raise TypeError("IDENTITY_CHECKPOINT_MISMATCH")
        base = self._initial(spec, key_id)
        state = deepcopy(checkpoint) if checkpoint else base
        tasks = len(self.tasks(spec))
        if (set(state) != set(base) or state["provider"] != self.provider or state["version"] != 1
                or state["config_hash"] != base["config_hash"] or state["key_id"] != key_id
                or any(type(state[key]) is not int or state[key] < 0 for key in _COUNTS)
                or state["task"] > tasks or state["requests"] > spec.max_requests or state["pages"] > spec.max_pages
                or state["records"] > spec.max_records or state["saved"] > state["received"]
                or state["op_pages"] > state["pages"]
                or not isinstance(state["seen"], list) or len(state["seen"]) > MAX_SEEN_CURSORS
                or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in state["seen"])
                or any(not isinstance(state[key], list) or len(state[key]) > 100
                       or any(not isinstance(value, str) or not _CODE.fullmatch(value) for value in state[key])
                       for key in ("reasons", "op_reasons"))):
            raise ValueError("IDENTITY_CHECKPOINT_MISMATCH")
        if state["cursor"]:
            cursor_text(state["cursor"])
            if hashlib.sha256(state["cursor"].encode()).hexdigest() not in state["seen"]:
                raise ValueError("IDENTITY_CHECKPOINT_MISMATCH")
        elif state["seen"]:
            raise ValueError("IDENTITY_CHECKPOINT_MISMATCH")
        return checkpoint_json(state)

    def _replay(self, spec, read_records, state):
        seen, count, reports = set(), 0, set()
        for raw in read_records() if read_records is not None else ():
            count += 1
            item = RECORD_ADAPTER.validate_python(raw)
            if not self.validate_record(spec, item):
                raise ValueError("IDENTITY_REPLAY_RECORD_REJECTED")
            if item.record_type == "entity_observation":
                seen.add((item.scope.id, item.provenance.operation, item.identity.object_id))
            elif item.record_type == "provider_event":
                seen.add((item.scope.id, item.provenance.operation, "event:" + item.event_id))
            else:
                reports.add((item.scope.kind, item.scope.id, item.provenance.operation))
        if count != state["records"]:
            raise ValueError("IDENTITY_REPLAY_COUNT_MISMATCH")
        done = {(scope.kind, scope.id, self.operation(source.name)) for scope, source in self.tasks(spec)[:state["task"]]}
        if reports != done:
            raise ValueError("IDENTITY_REPLAY_PROGRESS_MISMATCH")
        return seen

    @staticmethod
    def _degrade(state, code):
        state["reasons"] = sorted({*state["reasons"], code})
        state["op_reasons"] = sorted({*state["op_reasons"], code})

    @staticmethod
    def _advance(state):
        state["task"] += 1
        for key in ("retries", "op_pages", "received", "saved", "invalid", "duplicates"):
            state[key] = 0
        state["cursor"], state["seen"], state["op_reasons"] = "", [], []

    def collect_pages(self, spec, *, secrets, checkpoint, check, read_records=None, identity_digest=None,
                      client=None, now=None, sleep=None):
        if not isinstance(spec, MetadataConnectionSpec):
            spec = MetadataConnectionSpec.model_validate(spec)
        self.validate_spec(spec)
        if identity_digest is None or not callable(identity_digest) or not getattr(identity_digest, "key_id", None):
            raise ValueError("IDENTITY_KEY_UNAVAILABLE")
        state = self._state(spec, checkpoint or {}, identity_digest.key_id)
        if checkpoint and read_records is None:
            raise ValueError("IDENTITY_RECORD_REPLAY_REQUIRED")
        seen = self._replay(spec, read_records, state)
        tasks = self.tasks(spec)
        own_client = client is None
        if own_client:
            import httpx

            client = httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
        pacer = Pacer(spec, check, requests=state["requests"], **({"sleep": sleep} if sleep else {}))
        reader = self.vendor.reader(spec, dict(secrets), client, pacer)
        try:
            while state["task"] < len(tasks):
                check()
                previous = deepcopy(state)
                scope, source = tasks[state["task"]]
                stamp = (now() if callable(now) else now or datetime.now(UTC)).isoformat()
                if not self.enabled(spec, source):
                    records, finished = [self.report(scope, source.name, stamp, "NOT_REQUESTED")], True
                else:
                    if state["pages"] >= spec.max_pages:
                        self._degrade(state, "PAGE_BUDGET_EXCEEDED")
                        break
                    try:
                        rows, next_cursor = reader.read(scope, source.name, state["cursor"])
                    except ReadError as exc:
                        state["requests"] = pacer.requests
                        if exc.retryable and state["retries"] < min(spec.options.max_retries,
                                                                    spec.options.max_consecutive_rate_limits):
                            state["retries"] += 1
                            yield MetadataPage(checkpoint=deepcopy(state), status="WAITING", reasons=[exc.code],
                                               retry_after_seconds=exc.retry_after)
                            return
                        self._degrade(state, exc.code)
                        if exc.retryable:
                            self._degrade(state, self.provider.upper() + "_RETRY_LIMIT")
                        records = [self.report(scope, source.name, stamp,
                                               "PARTIAL" if state["op_pages"] else "FAILED", state)]
                        finished = True
                    else:
                        state["requests"] = pacer.requests
                        state["pages"] += 1
                        state["op_pages"] += 1
                        state["received"] += len(rows)
                        state["retries"] = 0
                        records = []
                        for row in rows:
                            try:
                                if source.kind == "users":
                                    user = self.vendor.user(spec, source.name, row)
                                    if user is None:  # a row the vendor says is not a person (service account)
                                        continue
                                    item = self.user_record(spec, scope, source.name, user, stamp, identity_digest)
                                    key = (scope.id, item.provenance.operation, item.identity.object_id)
                                elif source.kind == "apps":
                                    app = self.vendor.app(spec, source.name, row)
                                    if app is None:  # a row the vendor says is none of the company's apps
                                        continue
                                    item = self.app_record(spec, scope, source.name, app, stamp)
                                    key = (scope.id, item.provenance.operation, item.identity.object_id)
                                else:
                                    event = self.vendor.event(spec, source.name, row)
                                    if event is None:
                                        continue
                                    item = self.event_record(spec, scope, source.name, event, stamp)
                                    key = (scope.id, item.provenance.operation, "event:" + item.event_id)
                            except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
                                state["invalid"] += 1
                                self._degrade(state, self.provider.upper() + "_INVALID_RECORD")
                                continue
                            if key in seen:
                                state["duplicates"] += 1
                                if source.shifts:
                                    self._degrade(state, self.provider.upper() + "_LISTING_SHIFTED")
                                continue
                            seen.add(key)
                            records.append(item)
                        state["saved"] += len(records)
                        finished = not next_cursor
                        if next_cursor:
                            try:
                                cursor_text(next_cursor)
                            except ValueError:
                                self._degrade(state, self.provider.upper() + "_INVALID_CURSOR")
                                finished = True
                            else:
                                marker = hashlib.sha256(next_cursor.encode()).hexdigest()
                                if marker in state["seen"]:
                                    self._degrade(state, self.provider.upper() + "_CURSOR_CYCLE")
                                    finished = True
                                elif len(state["seen"]) >= MAX_SEEN_CURSORS:
                                    self._degrade(state, self.provider.upper() + "_CURSOR_HISTORY_LIMIT")
                                    finished = True
                                else:
                                    state["cursor"] = next_cursor
                                    state["seen"].append(marker)
                        if finished:
                            complete = not state["op_reasons"]
                            records.append(self.report(scope, source.name, stamp, "COMPLETE" if complete else "PARTIAL",
                                                       state, complete=complete and source.completes))
                # Every record counts, a report of a source this collection does not read included: the store takes
                # no run of more than max_records items.
                if state["records"] + len(records) > spec.max_records:
                    requests, pages = state["requests"], state["pages"]
                    state = previous
                    state["requests"], state["pages"] = requests, pages
                    self._degrade(state, "RECORD_BUDGET_EXCEEDED")
                    break
                for item in records:
                    if not self.validate_record(spec, item):
                        raise ValueError("IDENTITY_RECORD_REJECTED")
                state["records"] += len(records)
                if finished:
                    self._advance(state)
                check()
                yield MetadataPage(records=records, checkpoint=deepcopy(state))
            status = "COMPLETE" if not state["reasons"] else "PARTIAL" if state["pages"] else "FAILED"
            yield MetadataPage(checkpoint=deepcopy(state), status=status, reasons=state["reasons"])
        finally:
            reader.close()
            if own_client:
                client.close()


def module_entry_points(vendor):
    """The functions a registered adapter module exposes, built for one vendor."""
    collector = Collector(vendor)
    return {"collect_pages": collector.collect_pages, "validate_spec": collector.validate_spec,
            "validate_record": collector.validate_record,
            "validate_machine_record": collector.validate_machine_record, "collector": collector}
