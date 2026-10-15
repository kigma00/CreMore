"""The keyed MACs that make the audit trail tamper-evident.

Every audit row gets two MACs, keyed by AUDIT_CHAIN_KEY or, when that is not set, by a key derived from
FINGERPRINT_KEY. The database never holds either key:

* ``entry_mac`` is set when a CreMore process writes the row. A row someone inserts into the database directly
  has none, or a wrong one.
* ``chain_mac`` is set when one worker seals the row into the chain, in order. It covers the row's sequence
  number, its content and the previous row's ``chain_mac``, so changing, deleting or inserting a sealed row
  breaks the chain from there on.

The sealer also writes rows of its own into the chain, as ``system:audit-chain``:

* ``AUDIT_CHAIN_STARTED`` starts the chain after every row written before it. Rows sealed before it may lack an
  ``entry_mac``; rows after it may not.
* ``AUDIT_CHAIN_ANCHORED`` records the chain head each hour. Verification checks every such claim again, so
  re-sealing rows the database un-sealed shows even after the worker restarts.
* ``AUDIT_CHAIN_REWOUND`` records that the head the sealer sealed last lost its place. When no chain is left to
  seal it onto, one waits unsealed while the sealer runs, and is written again if it is removed.

An admin's ``AUDIT_CHAIN_ACKNOWLEDGED`` row accepts problems the admin has examined, each bound to what it was
when examined.
"""

from __future__ import annotations

import datetime as _dt
import enum
import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cremore.domain.models import FindingEvent

GENESIS_EVENT = "AUDIT_CHAIN_STARTED"
ANCHOR_EVENT = "AUDIT_CHAIN_ANCHORED"
REWOUND_EVENT = "AUDIT_CHAIN_REWOUND"
ACK_EVENT = "AUDIT_CHAIN_ACKNOWLEDGED"
# The sealer's own rows: their presence says a chain existed.
CHAIN_EVENTS = (GENESIS_EVENT, ANCHOR_EVENT, REWOUND_EVENT)
CHAIN_ACTOR = "system:audit-chain"
CHAIN_TARGET = "audit_chain"
TARGET_ID = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:audit-chain")
FIELDS = ("id", "finding_id", "target_type", "target_id", "actor", "event_type", "from_status", "to_status",
          "note", "created_at")
_INFO = b"cremore:audit-chain:v1"


def key(fingerprint_key: bytes | None, dedicated: bytes | None = None) -> bytes | None:
    """The audit MAC key: from AUDIT_CHAIN_KEY when set, else from FINGERPRINT_KEY; None without either."""
    root = dedicated or fingerprint_key
    if not root:
        return None
    return HKDF(hashes.SHA256(), 32, salt=None, info=_INFO).derive(root)


def key_id(secret: bytes) -> str:
    """A name for the key, stored with the chain's start, so a changed key reads as such."""
    return hmac.new(secret, b"key-id", hashlib.sha256).hexdigest()[:16]


def _value(name: str, value):
    if value is None:
        return None
    if isinstance(value, _dt.datetime) and name == "created_at":
        value = value.replace(tzinfo=_dt.UTC) if value.tzinfo is None else value.astimezone(_dt.UTC)
        return value.isoformat()
    if isinstance(value, enum.Enum):
        value = value.value
    if isinstance(value, uuid.UUID | str):
        return str(value)
    # Nothing CreMore writes: tagged, so the row reads as changed rather than stopping the sealer.
    return f"!{type(value).__name__}:{value!r}"[:4096]


def content(row) -> bytes:
    """One row's audited content, the same bytes whether it came from memory, SQLite or PostgreSQL."""
    get = row.get if isinstance(row, Mapping) else lambda name: getattr(row, name, None)
    return json.dumps({name: _value(name, get(name)) for name in FIELDS}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_of(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, b"entry\n" + body, hashlib.sha256).hexdigest()


def link_of(secret: bytes, previous: str, seq: int, body: bytes) -> str:
    return hmac.new(secret, f"link\n{seq}\n{previous}\n".encode() + body, hashlib.sha256).hexdigest()


def entry(secret: bytes, row) -> str:
    return entry_of(secret, content(row))


def link(secret: bytes, previous: str, seq: int, row) -> str:
    return link_of(secret, previous, seq, content(row))


def same(stored, expected: str) -> bool:
    """A stored MAC equals the expected one; anything a database could put there that is not a MAC does not."""
    return isinstance(stored, str) and stored.isascii() and hmac.compare_digest(stored, expected)


def authentic(secret: bytes, row, body: bytes | None = None) -> bool:
    mac = row.get("entry_mac") if isinstance(row, Mapping) else getattr(row, "entry_mac", None)
    return same(mac, entry_of(secret, content(row) if body is None else body))


def evidence(value: bytes | str) -> str:
    """What an acknowledgement binds to: a problem's row content, or its extent, hashed."""
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()[:32]


def chain_event(event_type: str, note: str) -> FindingEvent:
    """A row the sealer writes into the chain about the chain itself."""
    return FindingEvent(target_type=CHAIN_TARGET, target_id=TARGET_ID, actor=CHAIN_ACTOR, event_type=event_type, note=note)
