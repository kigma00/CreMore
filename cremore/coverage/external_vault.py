"""Vaults CreMore has no built-in collector for, read where the customer runs.

Two inputs share one path. A JSON Lines export -- one ``{"path", "value"}``
object per line, from whatever tool the vault ships -- and an installed reader
plugin that lists the vault itself. Either way every value is fingerprinted by
the same engine as a built-in collector before anything is sent, and only the
fingerprint leaves this process.

A JSON Lines file cannot show that it holds the whole vault, so its run is
complete only when the operator declares it; a reader reports its own listing.
Plugins are like SIEM output plugins: listed without executing them, imported
only when named in the allow-list, and not a sandbox for untrusted code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from importlib.metadata import entry_points
from typing import Literal

from cremore.coverage.collection import Collection, CollectionLimit
from cremore.coverage.models import ConnectionSpec, scope_path

ENTRY_POINT_GROUP = "cremore.vault_readers"
_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_BUILTINS = {"kubernetes_secrets": "cremore.coverage.readers.kubernetes_secrets"}
_FIELDS = {"path", "value", "version", "updated_at", "state"}


@dataclass(frozen=True)
class VaultEntry:
    path: str
    value: str | bytes | Mapping
    version: str = ""
    updated_at: str = ""
    state: Literal["CURRENT", "PREVIOUS"] = "CURRENT"


@dataclass(frozen=True)
class ReaderProvider:
    """What a ``cremore.vault_readers`` entry point exposes as ``PROVIDER``.

    ``build(options)`` returns an object with ``entries(prefixes)`` -- an
    iterator of :class:`VaultEntry` -- and, once exhausted, ``complete``: whether
    it listed every item under those prefixes.
    """

    id: str
    api_version: int
    build: Callable[[Mapping[str, str]], object]


def providers() -> dict:
    """Listing package metadata does not execute plugin code."""
    result = dict(_BUILTINS)
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        if not _ID.fullmatch(entry.name):
            raise ValueError("VAULT_READER_ID_INVALID")
        if entry.name in result:
            raise ValueError("VAULT_READER_ID_DUPLICATE")
        result[entry.name] = entry
    return result


def load_reader(identifier: str, *, allow_plugins: Iterable[str] = ()) -> ReaderProvider:
    registered = providers()
    if identifier not in registered:
        raise ValueError("VAULT_READER_UNAVAILABLE")
    if identifier not in _BUILTINS and identifier not in tuple(allow_plugins):
        raise ValueError("VAULT_READER_NOT_ENABLED")
    try:
        provider = (import_module(registered[identifier]).PROVIDER
                    if identifier in _BUILTINS else registered[identifier].load())
    except Exception:  # noqa: BLE001 -- an installed plugin's import error may carry credentials.
        raise ValueError("VAULT_READER_LOAD_FAILED") from None
    if (not isinstance(provider, ReaderProvider) or provider.id != identifier
            or type(provider.api_version) is not int or provider.api_version != 1 or not callable(provider.build)):
        raise ValueError("VAULT_READER_CONTRACT_INCOMPATIBLE")
    return provider


def jsonl_entries(stream, *, max_line_bytes: int, reasons: set) -> Iterator[VaultEntry]:
    """Parse a binary JSON Lines stream. A bad line is a reason, never an echo of it."""
    number = 0
    while True:
        line = stream.readline(max_line_bytes + 1)
        if not line:
            return
        number += 1
        if len(line) > max_line_bytes and not line.endswith(b"\n"):
            reasons.add("INPUT_LINE_TOO_LARGE")
            while line and not line.endswith(b"\n"):
                line = stream.readline(max_line_bytes + 1)
            continue
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except (ValueError, RecursionError):
            reasons.add("INPUT_LINE_INVALID")
            continue
        if not isinstance(row, dict) or not set(row) <= _FIELDS or not isinstance(row.get("path"), str):
            reasons.add("INPUT_LINE_INVALID")
            continue
        version, updated, state = row.get("version", ""), row.get("updated_at", ""), row.get("state", "CURRENT")
        if (not isinstance(version, str) or len(version) > 256 or not isinstance(updated, str)
                or state not in ("CURRENT", "PREVIOUS")):
            reasons.add("INPUT_LINE_INVALID")
            continue
        yield VaultEntry(path=row["path"], value=row.get("value"), version=version, updated_at=updated, state=state)


def _timestamp(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return ""
    return value if parsed.tzinfo is not None and len(value) <= 40 else ""


def collect_external(spec: ConnectionSpec, engine, entries: Iterable[VaultEntry], *, checkpoint=None) -> Collection:
    """Fingerprint entries under the declared scope, within the connection's budgets."""
    if spec.provider != "external_vault":
        raise ValueError("INPUT_REQUIRES_EXTERNAL_VAULT")
    out = Collection(spec, checkpoint=checkpoint)
    out.skipped = 0
    seen = set()
    try:
        for entry in entries:
            try:
                path = scope_path(entry.path) if isinstance(entry.path, str) else ""
            except ValueError:
                path = ""
            if not path or len(path) > 2048:
                out.reasons.add("INPUT_PATH_INVALID")
                continue
            if not any(not prefix or path == prefix or path.startswith(prefix + "/") for prefix in spec.prefixes):
                # Outside what the operator declared: not read, not sent, and
                # no gap in the declared scope either.
                out.skipped += 1
                continue
            location = {"reference": path, "version": entry.version,
                        "version_state": entry.state, "created_at": _timestamp(entry.updated_at)}
            if entry.updated_at and not location["created_at"]:
                out.reasons.add("INPUT_TIMESTAMP_INVALID")
            if (path, entry.version) in seen:
                # Two values for one item cannot both be what the vault holds.
                out.unresolved(location, "INPUT_DUPLICATE_ENTRY")
                continue
            seen.add((path, entry.version))
            value = entry.value
            if isinstance(value, Mapping):
                if not value or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
                    out.unresolved(location, "INPUT_VALUE_INVALID")
                    continue
                value = dict(value)
            elif not isinstance(value, (str, bytes)) or not value:
                out.unresolved(location, "INPUT_VALUE_INVALID")
                continue
            out.value(engine, value, location)
    except CollectionLimit as exc:
        out.reasons.add(str(exc))
    return out


def read_with(provider: ReaderProvider, spec: ConnectionSpec, engine, options: Mapping[str, str], *, checkpoint=None):
    """Run a reader plugin. Its failure text never leaves; only fixed codes do."""
    try:
        reader = provider.build(dict(options))
        entries = reader.entries(tuple(spec.prefixes))
    except Exception:  # noqa: BLE001 -- a reader's errors can contain vault responses.
        out = Collection(spec, checkpoint=checkpoint)
        out.reasons.add("READER_FAILED")
        return out, False

    def guarded():
        try:
            yield from entries
        except CollectionLimit:
            raise
        except Exception:  # noqa: BLE001 -- see above.
            failed.append(True)

    failed = []
    out = collect_external(spec, engine, guarded(), checkpoint=checkpoint)
    if failed:
        out.reasons.add("READER_FAILED")
    complete = not failed and getattr(reader, "complete", False) is True
    if not complete:
        out.reasons.add("READER_LISTING_INCOMPLETE")
    return out, complete
