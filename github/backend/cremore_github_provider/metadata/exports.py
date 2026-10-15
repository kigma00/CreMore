"""Memory-only projection of GitHub's Enterprise credential CSV export.

The transport is an implementation detail: callers receive the same typed
records as other metadata collectors, never CSV, download URLs or raw hashes.
Rows are not necessarily adjacent for one credential. Credential identities
and organization authorizations are therefore deduplicated independently.
"""

from __future__ import annotations

import codecs
import csv
import hashlib
import json
import re
from datetime import UTC, datetime

from cremore.coverage.metadata_models import MetadataOmission

from .http import SourceError
from .normalization import (
    INVENTORY_ID_TYPES,
    fingerprint_key,
    identity,
    inventory_observation,
    observation,
    record_values,
    relation,
)

MAX_EXPORT_BYTES = 256 << 20
MAX_ROW_BYTES = 64 << 10
MAX_EXPORT_ROWS = 2_000_000
EXPORT_ID = re.compile(r"[A-Za-z0-9_-]{1,200}")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,256}")
_NUMBER = re.compile(r"(?:0|[1-9][0-9]{0,19})")
_NAME = re.compile(r"[A-Za-z0-9_./*-]{1,128}")
CREDENTIAL_TYPES = INVENTORY_ID_TYPES | {"ssh_key", "github_app_installation", "federated_jti"}
_REQUIRED = {"credential_type", "credential_id", "item_type", "fingerprint",
             "owner_id", "owner_type", "organization_id", "organization"}
_TEXT = {"display_name", "owner", "owner_type", "application", "credential_state",
         "expiry_status", "past_expiration_policy_basis", "repository_selection"}
_NUMBERS = {"owner_id", "application_id", "authorization_count", "age_days"}
_BOOLS = {"enterprise_authorized", "past_expiration_policy"}
_TIMES = {"created_at", "last_used_at", "expires_at"}


class ExportError(SourceError):
    """A fixed diagnostic code, with no cell content or signed URL."""


def export_id(value):
    if not isinstance(value, str) or not EXPORT_ID.fullmatch(value):
        raise ExportError("github_export_invalid_id")
    return value


def timestamp(value):
    """The export API's as_of also accepts its documented '... UTC' format."""
    try:
        if not isinstance(value, str) or len(value) > 80:
            raise ValueError
        parsed = datetime.fromisoformat(value.removesuffix(" UTC") + ("+00:00" if value.endswith(" UTC") else ""))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC).isoformat()
    except (ValueError, TypeError, OverflowError):
        raise ExportError("github_export_invalid_timestamp") from None


class _Lines:
    """Bound both a physical line and a CSV record, including quoted newlines."""

    def __init__(self, chunks, check, max_bytes):
        self.chunks, self.check = iter(chunks), check
        self.max_bytes, self.total, self.record_bytes = max_bytes, 0, 0
        self.decoder = codecs.getincrementaldecoder("utf-8-sig")("strict")
        self.buffer, self.finished = "", False

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            self.check()
            split = self.buffer.find("\n")
            if split >= 0 or self.finished:
                if not self.buffer:
                    raise StopIteration
                split = split + 1 if split >= 0 else len(self.buffer)
                line, self.buffer = self.buffer[:split], self.buffer[split:]
                self.record_bytes += len(line.encode("utf-8"))
                if self.record_bytes > MAX_ROW_BYTES:
                    raise ExportError("github_export_row_limit")
                return line
            if len(self.buffer.encode("utf-8")) > MAX_ROW_BYTES:
                raise ExportError("github_export_row_limit")
            try:
                data = next(self.chunks)
            except StopIteration:
                self.buffer += self.decoder.decode(b"", final=True)
                self.finished = True
                continue
            if not isinstance(data, bytes) or len(data) > 64 << 10:
                raise ExportError("github_export_invalid_chunk")
            self.total += len(data)
            if self.total > self.max_bytes:
                raise ExportError("github_export_size_limit")
            self.buffer += self.decoder.decode(data)


def rows(chunks, *, check, max_bytes=MAX_EXPORT_BYTES, max_rows=MAX_EXPORT_ROWS):
    """Yield one transient allowlisted row at a time; never write an export file."""
    if not 0 < max_bytes <= MAX_EXPORT_BYTES or not 0 < max_rows <= MAX_EXPORT_ROWS:
        raise ExportError("github_export_invalid_limits")
    lines = _Lines(chunks, check, max_bytes)
    reader = csv.reader(lines, strict=True)
    try:
        header = next(reader, None)
        if (not header or len(header) > 100 or len(set(header)) != len(header)
                or not _REQUIRED <= set(header) or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,80}", h) for h in header)):
            raise ExportError("github_export_invalid_header")
        known = _REQUIRED | _TEXT | _NUMBERS | _BOOLS | _TIMES | {"hashed_token", "scopes", "permissions"}
        index = 0
        while True:
            lines.record_bytes = 0
            values = next(reader, None)
            if values is None:
                return
            index += 1
            check()
            if index > max_rows:
                raise ExportError("github_export_row_count_limit")
            if len(values) != len(header):
                raise ExportError("github_export_invalid_row")
            yield index, {name: value for name, value in zip(header, values, strict=True) if name in known}
    except (csv.Error, UnicodeError):
        raise ExportError("github_export_invalid_csv") from None


def _number(value):
    if not _NUMBER.fullmatch(value):
        raise ExportError("github_export_invalid_number")
    return int(value)


def normalize(row, *, export, index):
    """Preserve blank as unavailable, including booleans and expiration."""
    if isinstance(index, bool) or not isinstance(index, int) or not 0 < index <= MAX_EXPORT_ROWS:
        raise ExportError("github_export_invalid_row_index")
    kind, item = row.get("credential_type"), row.get("item_type")
    if kind not in CREDENTIAL_TYPES or item not in {"credential", "token_issuer_principal"}:
        raise ExportError("github_export_unsupported_credential_type")
    if (kind == "github_app_installation") != (item == "token_issuer_principal"):
        raise ExportError("github_export_invalid_item_type")
    values = {"credential_type": kind, "item_type": item,
              "inventory_id": f"export:{export_id(export)}:row:{index}", "basis": "EXPORT_ROW_ONLY"}
    credential = row.get("credential_id")
    if kind in INVENTORY_ID_TYPES and credential:
        if not _ID.fullmatch(credential):
            raise ExportError("github_export_invalid_credential_id")
        values.update(credential_id=credential, basis="PROVIDER_ID")
    elif credential:
        raise ExportError("github_export_unexpected_credential_id")
    fingerprint = row.get("fingerprint")
    if fingerprint:
        canonical = fingerprint_key(fingerprint)
        if kind != "ssh_key" or not canonical:
            raise ExportError("github_export_invalid_fingerprint")
        values.update(fingerprint=canonical, basis="PROVIDER_FINGERPRINT")
    for name in _TEXT:
        if value := row.get(name):
            if len(value) > 4096 or any(ord(c) < 32 and c not in "\r\n\t" for c in value):
                raise ExportError("github_export_invalid_text")
            values[name] = value
    for name in _NUMBERS:
        if value := row.get(name):
            values[name] = _number(value)
    for name in _BOOLS:
        if value := row.get(name):
            if value.lower() not in {"true", "false"}:
                raise ExportError("github_export_invalid_boolean")
            values[name] = value.lower() == "true"
    for name in _TIMES:
        if value := row.get(name):
            values[name] = timestamp(value)
    # The CSV states "never" in expiry_status (expires|never|unknown), never by a blank expires_at.
    if values.get("expiry_status") == "never":
        values["never_expires"] = True
    if value := row.get("scopes"):
        scopes = value.split(";")
        if len(scopes) > 250 or any(not re.fullmatch(r"[A-Za-z0-9_:./*-]{1,256}", s.strip()) for s in scopes):
            raise ExportError("github_export_invalid_scopes")
        values["scopes"] = sorted({s.strip() for s in scopes})
    if value := row.get("permissions"):
        permissions = {}
        for entry in value.split(";"):
            name, separator, level = entry.strip().partition(":")
            if (not separator or not _NAME.fullmatch(name) or level not in {"read", "write", "admin"}
                    or name in permissions and permissions[name] != level):
                raise ExportError("github_export_invalid_permissions")
            permissions[name] = level
        if len(permissions) > 200:
            raise ExportError("github_export_permission_limit")
        values["permissions"] = permissions
    # inventory_observation immediately keys this value when opted in, then
    # its allowlist drops the original from every public or persisted field.
    if value := row.get("hashed_token"):
        values["hashed_token"] = value
    organization = None
    org_id, org = row.get("organization_id"), row.get("organization")
    if bool(org_id) != bool(org):
        raise ExportError("github_export_invalid_organization")
    if org_id:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", org):
            raise ExportError("github_export_invalid_organization")
        organization = {"id": _number(org_id), "login": org}
    return values, organization


def _signature(record):
    data = record.model_dump() if hasattr(record, "model_dump") else record
    stable = {key: data.get(key) for key in ("identity", "facts", "permissions", "normalized_state",
                                            "provider_state", "state_basis", "omissions")}
    # inventory_id is a source row locator, never a credential identity.
    stable["facts"] = sorted((f for f in stable["facts"] if f["name"] != "inventory_id"), key=lambda f: f["name"])
    stable["omissions"] = sorted(stable["omissions"], key=lambda o: (o["path"], o["reason"]))
    evidence = data.get("value_match") or {}
    stable["value_match"] = {k: evidence.get(k) for k in ("fingerprint", "scheme", "key_id")}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Projection:
    """Run-local deduplication reconstructed from committed, sanitized records."""

    def __init__(self, spec, *, export, generated_at, value_context=None, committed=()):
        self.spec, self.export = spec, export_id(export)
        self.generated_at = None if generated_at is None else timestamp(generated_at)
        self.value_context = value_context
        self.entities, self.grants = {}, set()
        for record in committed:
            if record.get("provenance", {}).get("operation") != "github.inventory":
                continue
            if record.get("scope") != spec.scopes[0].model_dump():
                raise ExportError("github_export_replay_scope_mismatch")
            if record["record_type"] == "entity_observation":
                if record["identity"]["object_id"].startswith("inventoryAuthorization:"):
                    values = record_values(record)
                    self.grants.add((values["source_scope"], "organization:" + str(values["organization_id"])))
                else:
                    self.entities[record["identity"]["object_id"]] = _signature(record)
            elif record["record_type"] == "relation":
                self.grants.add((record["subject"]["object_id"], record["target"]["object_id"]))

    def project(self, index, row):
        values, organization = normalize(row, export=self.export, index=index)
        item = inventory_observation(self.spec, self.spec.scopes[0], values,
            operation="github.inventory", generated_at=self.generated_at, value_context=self.value_context)
        if values["basis"] == "EXPORT_ROW_ONLY":
            item.omissions.append(MetadataOmission(path="credential_id", reason="NO_STABLE_PROVIDER_IDENTIFIER"))
        signature, key = _signature(item), item.identity.object_id
        previous = self.entities.get(key)
        if previous is not None and previous != signature:
            raise ExportError("github_export_conflicting_credential")
        records = []
        if previous is None:
            self.entities[key] = signature
            records.append(item)
        if organization:
            target = identity(self.spec, "resource", "organization:" + str(organization["id"]))
            grant = (key, target.object_id)
            if grant not in self.grants:
                self.grants.add(grant)
                facts = {"organization": organization["login"], "organization_id": organization["id"],
                         "basis": "PROVIDER_REPORTED_AUTHORIZATION", "source_scope": key}
                if "relations" in self.spec.capabilities:
                    records.append(relation(self.spec, self.spec.scopes[0], item.identity, target,
                        relation_kind="can_access", match_basis="PROVIDER_EXPLICIT", confidence="EXACT",
                        operation="github.inventory", resource_id=values["inventory_id"], facts=facts))
                else:
                    # Existing inventory-only connections keep grant metadata
                    # without silently enabling the relations capability.
                    grant_id = hashlib.sha256(json.dumps(grant).encode()).hexdigest()
                    records.append(observation(self.spec, self.spec.scopes[0], kind="context",
                        object_id="inventoryAuthorization:" + grant_id, operation="github.inventory",
                        resource_id=values["inventory_id"], row=facts, generated_at=self.generated_at))
        if len(self.entities) + len(self.grants) > self.spec.max_records:
            raise ExportError("github_export_record_limit")
        return records
