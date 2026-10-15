"""Tamper evidence for the audit trail: sealing, verification, acknowledgement and the hourly anchor.

A worker seals new audit rows into the keyed chain each maintenance tick (cremore/db/audit_chain.py).
``verify`` walks the whole chain and reports every problem it finds, not only the first:

* a missing position (a deleted row) or a MAC that no longer matches (a changed row);
* a row after the chain's start that no CreMore process wrote, and a row at a position no chain has;
* an anchor whose claim no longer holds, which shows rows that were un-sealed and sealed again;
* evidence the sealer recorded, and a chain whose positions are gone.

An admin may acknowledge a problem once they have examined it. The acknowledgement names the problem's kind,
place and content, is itself a chained row, and stops applying when the row or the extent it named changes.

Once an hour one replica verifies, writes an anchor row into the chain, queues ``audit.chain_anchor`` with the
result, the chain's start and its head, and logs the same line. A SIEM that keeps these catches what no check
inside the database can: a chain rewritten after its latest anchor, or from its start by someone who also removed
every anchor row.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import re

from cremore.db import audit_chain
from cremore.domain.models import FindingEvent
from cremore.operations.health import utc
from cremore.siem.events import audit_chain_anchor

logger = logging.getLogger(__name__)

SLOT_KEY = "operations:audit-anchor"
ANCHOR_SECONDS = 3600
PAGE = 2000
SEAL_BATCH = 1000
SEAL_BATCHES = 10  # at most 10,000 rows a tick; the rest wait for the next one
PENDING_CHECKED = 10000
LISTED = 100
KEPT = 10000  # problems held while walking; the count goes on
# Problems that say rows were changed, removed or re-placed; the rest say who wrote a row.
STRUCTURAL = frozenset({"SEQUENCE_GAP", "SEQUENCE_INVALID", "MAC_MISMATCH", "GENESIS_MISSING", "GENESIS_INVALID",
                        "GENESIS_MOVED", "CHAIN_RESET", "KEY_MISMATCH", "ANCHOR_CLAIM_MISMATCH", "ANCHOR_SEQUENCE_GAP",
                        "CHAIN_REWOUND"})
# Problems about the whole chain: nothing to point an acknowledgement at.
_WHOLE = frozenset({"GENESIS_MISSING", "CHAIN_RESET", "KEY_MISMATCH"})
_ANCHOR = re.compile(r"\Aanchor=(\d+) seq=(\d+) mac=([0-9a-f]{64})\b")
_ACK = re.compile(r"\Aitems=(\S+) reason=")
_KEY = re.compile(r"\bkey=([0-9a-f]{16})\b")
_LEGACY = re.compile(r"\blegacy_rows=(\d+)\b")
# KIND@seq:N#evidence or KIND@event:ID#evidence: one problem as it was when an admin examined it.
ITEM = re.compile(r"\A[A-Z_]{3,40}@(?:seq:[1-9][0-9]{0,17}|event:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
                  r"#[0-9a-f]{32}\Z")


def key(settings) -> bytes | None:
    # A process without FINGERPRINT_KEY (or a test's partial settings) seals nothing and writes unauthenticated rows.
    return audit_chain.key(getattr(settings, "fingerprint_key_bytes", None), getattr(settings, "audit_chain_key_bytes", None))


def attach(repo, settings) -> None:
    """Let this process's repository authenticate the audit rows it writes."""
    if getattr(repo, "audit_key", None) is None and key(settings) is not None:
        repo.audit_key = key(settings)


def seal(repo, settings) -> int:
    """Seal what is waiting. This process remembers the head it sealed, so it notices when that head is moved,
    and never starts a chain again while it runs."""
    secret = key(settings)
    if secret is None:
        return 0
    total = 0
    for _ in range(SEAL_BATCHES):
        done = repo.seal_audit(secret, SEAL_BATCH, getattr(repo, "_audit_sealed_head", None))
        if done["rewound"]:
            logger.warning("audit chain: the head this worker sealed lost its place; recorded in the chain")
        if done["reset"]:
            # The head stays remembered: removing the rewind row that waits cannot make this process start over.
            logger.warning("audit chain: its positions are gone while it existed; not sealing")
            return total
        if done["head"] is not None:
            repo._audit_sealed_head = done["head"]
        total += done["sealed"]
        if done["sealed"] < SEAL_BATCH:
            break
    return total


def _items(note) -> set[str]:
    found = _ACK.match(note or "")
    return {item for item in found.group(1).split(",") if ITEM.match(item)} if found else set()


def _state(problems: list[dict], anchor_state, seq: int) -> str:
    open_ = [item for item in problems if not item["acknowledged"]]
    return ("BROKEN" if any(item["kind"] in STRUCTURAL for item in open_) else
            "ANCHOR_MISMATCH" if anchor_state in ("MISMATCH", "MISSING") else
            "UNAUTHENTICATED" if open_ else
            "NOT_STARTED" if not seq else "INTACT")


def verify(repo, settings, *, anchor: tuple[int, str] | None = None, now=None) -> dict:
    """Walk the chain from its first row and report every problem, rows no CreMore process wrote, and the head.

    ``anchor`` is a (seq, chain_mac) pair kept outside CreMore, e.g. from an audit.chain_anchor event.
    """
    return with_anchor(repo, walk(repo, settings, now=now), anchor)


def walk(repo, settings, *, now=None) -> dict:
    """The whole report, with every problem held (``_problems``) for acknowledgements and anchor checks."""
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    secret = key(settings)
    if secret is None:
        raise ValueError("FINGERPRINT_KEY_REQUIRED")
    found: list[dict] = []
    total = 0

    def problem(kind: str, seq: int | None, row: dict | None = None, extent: str | None = None, body: bytes | None = None) -> None:
        nonlocal total
        total += 1
        if len(found) >= KEPT:
            return
        stamp = utc(row.get("created_at")) if row else None
        # Who wrote a row does not depend on where it sits: accepting one outlives its seal.
        where = (f"event:{row['id']}" if row and (kind == "UNAUTHENTICATED" or not seq) else f"seq:{seq}" if seq else None)
        proof = extent if extent is not None else body if body is not None else audit_chain.content(row) if row else None
        found.append({"kind": kind, "seq": seq, "event_id": str(row["id"]) if row else None,
                      "created_at": stamp.isoformat() if stamp else None,
                      "ack": f"{kind}@{where}#{audit_chain.evidence(proof)}" if where and proof is not None and kind not in _WHOLE else None})

    # Where the chain starts: its first authentic start row. A start that does not authenticate is itself a
    # problem (GENESIS_INVALID) and sets the boundary only when no start authenticates, so a damaged start never
    # moves it later and a fake one never moves it earlier.
    own = repo.audit_chain_rows()
    starts = [row for row in own if row["event_type"] == audit_chain.GENESIS_EVENT and row["chain_seq"]]
    real = [row["chain_seq"] for row in starts if audit_chain.authentic(secret, row)]
    boundary = (min(real) if real else min((row["chain_seq"] for row in starts), default=0)
                or min((row["chain_seq"] for row in own if row["chain_seq"] and audit_chain.authentic(secret, row)), default=0))
    expect, seq, previous, head_mac = 1, 0, "", None
    genesis, last_anchor = None, None
    links = entries = 0
    claims: list[tuple[int | None, int, str, dict]] = []
    acks: set[str] = set()
    after = 0
    # ponytail: a full walk each call (hourly in the worker's own thread, and on demand behind a one-minute cache);
    # resume from the last anchor if the trail grows to many millions of rows.
    while True:
        rows = repo.audit_chain_page(after, PAGE)
        for row in rows:
            at = row["chain_seq"]
            body = audit_chain.content(row)
            if at != expect:
                # Its extent and both sides of it: the MAC before the gap and the row after it, whose own link can
                # no longer be checked. Accepting the gap accepts these; changing or swapping that row opens it again.
                problem("SEQUENCE_GAP", expect, extent=f"to:{at}|prev:{previous}|mac:{row['chain_mac']}|row:{audit_chain.evidence(body)}")
                previous = None  # the row before this one is gone: its MAC is not there to check against
            linked = None if previous is None else audit_chain.same(row["chain_mac"], audit_chain.link_of(secret, previous, at, body))
            ok = audit_chain.authentic(secret, row, body)
            links += bool(linked)
            entries += ok
            previous = head_mac = row["chain_mac"] if isinstance(row["chain_mac"], str) else None
            seq, expect = at, at + 1
            if linked is False or (linked is None and row.get("entry_mac") is not None and not ok):
                # Changed after it was sealed; right after a gap, its own entry MAC is the only check left.
                problem("MAC_MISMATCH", at, row, body=body)
            elif not ok and row["actor"] == audit_chain.CHAIN_ACTOR and row["event_type"] == audit_chain.GENESIS_EVENT:
                problem("GENESIS_INVALID", at, row, body=body)  # claims to start the chain; the sealer did not write it
            elif at > boundary and not ok:
                problem("UNAUTHENTICATED", at, row, body=body)
            mine = ok and row["actor"] == audit_chain.CHAIN_ACTOR
            if mine and row["event_type"] == audit_chain.GENESIS_EVENT and genesis is None:
                genesis = {"seq": at, "mac": head_mac}
                named = _LEGACY.search(row["note"] or "")
                if named and at != int(named.group(1)) + 1:
                    # The start names how many rows came before it: rows sealed again in front of it moved it, and
                    # whatever landed there would pass as history written before the chain.
                    problem("GENESIS_MOVED", at, row, body=body)
            elif mine and row["event_type"] == audit_chain.ANCHOR_EVENT and (match := _ANCHOR.match(row["note"] or "")):
                number = int(match.group(1))
                if number != (last_anchor or {}).get("no", 0) + 1:
                    problem("ANCHOR_SEQUENCE_GAP", at, row, body=body)
                last_anchor = {"no": number, "seq": int(match.group(2)), "mac": match.group(3)}
                claims.append((at, int(match.group(2)), match.group(3), row))
            elif mine and row["event_type"] == audit_chain.REWOUND_EVENT:
                problem("CHAIN_REWOUND", at, row, body=body)
            elif ok and row["event_type"] == audit_chain.ACK_EVENT:
                acks |= _items(row["note"])
        if len(rows) < PAGE:
            break
        after = rows[-1]["chain_seq"]
    if seq and not links and not entries:
        # Nothing in the chain answers to this key: it was sealed with another one (AUDIT_CHAIN_KEY changed).
        found[:], total = [], 0
        problem("KEY_MISMATCH", None)
    elif seq and not starts:
        problem("GENESIS_MISSING", None)
    for row in repo.audit_rows_outside_chain(LISTED):
        problem("SEQUENCE_INVALID", None, row)
    pending = repo.unsealed_audit(PENDING_CHECKED)
    if not seq and any(row["actor"] == audit_chain.CHAIN_ACTOR and row["event_type"] in audit_chain.CHAIN_EVENTS
                       and audit_chain.authentic(secret, row) for row in pending):
        problem("CHAIN_RESET", None)
    started = bool(seq) or any(item["kind"] == "CHAIN_RESET" for item in found)
    for row in pending:
        if audit_chain.authentic(secret, row):
            if row["event_type"] == audit_chain.ACK_EVENT:
                acks |= _items(row["note"])
            elif (row["actor"] == audit_chain.CHAIN_ACTOR and row["event_type"] == audit_chain.ANCHOR_EVENT
                  and (match := _ANCHOR.match(row["note"] or ""))):
                # An anchor the sealer has not reached yet still claims a head, and still counts.
                claims.append((None, int(match.group(2)), match.group(3), row))
                if int(match.group(1)) > (last_anchor or {}).get("no", 0):
                    last_anchor = {"no": int(match.group(1)), "seq": int(match.group(2)), "mac": match.group(3)}
        elif started:
            problem("UNAUTHENTICATED", None, row)
    macs = repo.audit_macs_at([claimed for _at, claimed, _mac, _row in claims])
    for at, claimed, mac, row in claims:
        if not audit_chain.same(macs.get(claimed), mac):
            problem("ANCHOR_CLAIM_MISMATCH", at, row)
    for item in found:
        item["acknowledged"] = item["ack"] is not None and item["ack"] in acks
    open_count = sum(1 for item in found if not item["acknowledged"]) + (total - len(found))
    report = {
        "state": _state(found, None, seq), "checked_at": now.isoformat(), "verified_through": seq,
        "head": {"seq": seq, "mac": head_mac} if seq else None,
        "genesis": genesis, "legacy_rows": boundary - 1 if boundary else 0,
        "anchors": {"count": len(claims), "last": last_anchor},
        "pending": len(pending),
        "problem_count": total, "open_problems": open_count,
        "problems": sorted(found, key=lambda item: item["acknowledged"])[:LISTED],
        "unauthenticated": {"sealed_count": sum(1 for item in found if item["kind"] == "UNAUTHENTICATED" and item["seq"]),
                            "pending_count": sum(1 for item in found if item["kind"] == "UNAUTHENTICATED" and not item["seq"])},
        "anchor": None,
        "_problems": found,
    }
    return report


def with_anchor(repo, report: dict, anchor: tuple[int, str] | None) -> dict:
    """The report checked against a head kept outside CreMore: one lookup, not another walk."""
    out = {key: value for key, value in report.items() if key != "_problems"}
    if anchor is None:
        return out
    head = report["verified_through"]
    mac = repo.audit_macs_at([anchor[0]]).get(anchor[0]) if anchor[0] <= head else None
    state = "MISSING" if anchor[0] > head else "MATCHED" if audit_chain.same(mac, anchor[1]) else "MISMATCH"
    return {**out, "anchor": {"seq": anchor[0], "state": state},
            "state": _state(report.get("_problems") or report["problems"], state, head)}


def acknowledge(repo, settings, actor: str, items: list[str], reason: str) -> FindingEvent:
    """An admin accepts problems open now, each as it is now (``KIND@place#evidence``); a chained row itself."""
    if not items or any(not ITEM.match(item) for item in items):
        raise ValueError("AUDIT_ACK_INVALID")
    open_ = {item["ack"] for item in walk(repo, settings)["_problems"] if not item["acknowledged"] and item["ack"]}
    if set(items) - open_:
        raise ValueError("AUDIT_ACK_NOT_OPEN")
    return repo.record_finding_event(FindingEvent(
        target_type=audit_chain.CHAIN_TARGET, target_id=audit_chain.TARGET_ID, actor=actor,
        event_type=audit_chain.ACK_EVENT, note=f"items={','.join(items)} reason={' '.join(reason.split())}"))


def publish(repo, settings, *, now=None, actor: str = "worker") -> bool:
    """Once an hour across every replica: verify, anchor the head in the chain, and send the result out."""
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    slot = int(now.timestamp()) // ANCHOR_SECONDS
    if key(settings) is None or not repo.claim_slot(SLOT_KEY, slot, actor):
        return False
    last = getattr(repo, "_audit_last_anchor", None)
    try:
        report = verify(repo, settings, anchor=last, now=now)
    except Exception as exc:  # noqa: BLE001 -- an unreadable chain is itself the alarm; the slot must not go silent
        logger.warning("audit chain: verification failed: %s", type(exc).__name__)
        report = {"state": "UNKNOWN", "head": None, "genesis": None, "anchors": {"count": 0, "last": None}}
    if report["state"] == "NOT_STARTED":
        return False
    number = None
    if report["state"] != "UNKNOWN" and report["head"]:
        number = ((report["anchors"]["last"] or {}).get("no") or 0) + 1
        head = report["head"]
        repo.record_finding_event(audit_chain.chain_event(
            audit_chain.ANCHOR_EVENT, f"anchor={number} seq={head['seq']} mac={head['mac']} state={report['state']}"))
        repo._audit_last_anchor = (head["seq"], head["mac"])
    event = audit_chain_anchor(now=now, slot=slot, report=report, number=number)
    repo.record_siem_event(event)
    # The copy of record outside the database: the outbox above is only as safe as the database.
    log = logger.info if event["audit"]["chain_state"] == "INTACT" else logger.warning
    log("audit chain anchor %s", json.dumps(event["audit"], sort_keys=True))
    return True
