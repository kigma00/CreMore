"""Azure Storage SAS: its non-secret facts, and offline checks of which account key signed it.

The signature itself is never read or kept here. A key held in memory for an
approved storage account can recompute Microsoft's documented string-to-sign
and compare its keyed fingerprint with a discovered SAS; nothing is sent.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from itertools import product
from urllib.parse import parse_qsl, unquote, urlsplit

from cremore.detection.fingerprint import fingerprint
from cremore.detection.safe_text import safe_fact_text

_FIELDS = {"sv": "version", "ss": "services", "srt": "resource_types", "sr": "resource", "sp": "permissions",
           "st": "start", "se": "expiry", "sip": "ip", "spr": "protocol", "si": "policy",
           "skoid": "signer_object_id", "sktid": "signer_tenant_id", "ske": "signer_key_expiry",
           "ses": "encryption_scope", "snapshot": "snapshot", "sdd": "directory_depth",
           "rscc": "cache_control", "rscd": "content_disposition", "rsce": "content_encoding",
           "rscl": "content_language", "rsct": "content_type", "tn": "table",
           "spk": "start_partition_key", "srk": "start_row_key", "epk": "end_partition_key", "erk": "end_row_key"}
_SAFE = re.compile(r"[A-Za-z0-9:.,+/=_ -]{1,128}")
_PATH = re.compile(r"/[^\s?#\"'<>]{0,512}")
_ENDPOINT = re.compile(rb"AccountName=([a-z0-9]{3,24})|https?://([a-z0-9]{3,24})\.(blob|file|queue|table|dfs)\.core\.windows\.net")
_HEADERS = ("cache_control", "content_disposition", "content_encoding", "content_language", "content_type")


def sas_facts(query: bytes, *, account: bytes = b"", service: bytes = b"", before: bytes = b"",
              match: bytes = b"") -> dict[str, str]:
    """The signed fields, the storage account the SAS URL or its connection string names,
    and the URL path a service SAS signs."""
    facts: dict[str, str] = {}
    try:
        pairs = parse_qsl(query.decode("utf-8", "replace"), keep_blank_values=True, max_num_fields=64)
    except ValueError:
        pairs = []
    signatures = tuple(value for name, value in pairs if name == "sig" and value)
    for name, value in pairs:
        field = _FIELDS.get(name)
        if field and field not in facts and _SAFE.fullmatch(value):
            if safe_fact_text(value, secrets=signatures) is None:
                facts["redacted"] = "true"
            else:
                facts[field] = value
    if not account:
        # A connection string names its account before SharedAccessSignature=.
        found = list(_ENDPOINT.finditer(before[-2048:]))
        if found:
            account = found[-1].group(1) or found[-1].group(2) or b""
            service = service or found[-1].group(3) or b""
    if re.fullmatch(rb"[a-z0-9]{3,24}", account):
        facts["account"] = account.decode("ascii").lower()
    if service in (b"blob", b"file", b"queue", b"table", b"dfs"):
        facts["service"] = service.decode("ascii")
    if match.startswith((b"https://", b"http://")):
        path = urlsplit(match.decode("ascii", "replace")).path
        if _PATH.fullmatch(path):
            if safe_fact_text(path, secrets=signatures) is None:
                facts["redacted"] = "true"
            else:
                facts["path"] = path
    facts["kind"] = ("user_delegation" if "signer_object_id" in facts
                     else "account" if "services" in facts or "resource_types" in facts else "service")
    return facts


def _service(facts):
    return {"blob": "blob", "dfs": "blob", "file": "file", "queue": "queue", "table": "table"}.get(facts.get("service", ""))


def _resource(facts, version):
    """Microsoft's canonicalized resource for a service SAS, or None. Before 2015-02-21 it
    has no service name."""
    service = _service(facts)
    if service == "table":
        # A table SAS names its table in tn; the canonical name is lowercase.
        parts, keep = [facts.get("table", "").lower()], 1
        if not parts[0]:
            return None
    else:
        parts = [part for part in unquote(facts.get("path", "")).split("/") if part]
        if not service or not parts:
            return None
        # A container, share or queue SAS signs only its root; a directory SAS its signed depth.
        depth = facts.get("directory_depth", "")
        keep = 1 if service == "queue" else {"c": 1, "s": 1, "d": 1 + int(depth) if depth.isdigit() else 0}.get(
            facts.get("resource", ""), len(parts))
        if not 0 < keep <= len(parts):
            return None
    return "/".join(["", *([service] if version >= "2015-02-21" else []), facts["account"], *parts[:keep]])


def string_to_sign(facts: dict[str, str]) -> str | None:
    """The documented string-to-sign of an account SAS (2015-04-05 and later) or a Blob, Files,
    Queue or Table service SAS (2012-02-12 and later) signed with an account key; None otherwise."""
    version, account = facts.get("version", ""), facts.get("account", "")
    if facts.get("redacted") or not account or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", version) or version < "2012-02-12":
        return None
    get = facts.get
    if facts.get("kind") == "account":
        if version < "2015-04-05":
            return None
        fields = [account, get("permissions", ""), get("services", ""), get("resource_types", ""),
                  get("start", ""), get("expiry", ""), get("ip", ""), get("protocol", ""), version]
        if version >= "2020-12-06":
            fields.append(get("encryption_scope", ""))
        return "".join(field + "\n" for field in fields)
    service = _service(facts) if facts.get("kind") == "service" else None
    # Files SAS starts at 2015-02-21; before 2013-08-15 only blobs and containers are documented.
    if not service or service == "file" and version < "2015-02-21" or service != "blob" and version < "2013-08-15":
        return None
    resource = _resource(facts, version)
    if resource is None:
        return None
    fields = [get("permissions", ""), get("start", ""), get("expiry", ""), resource, get("policy", "")]
    if version >= "2015-04-05":
        fields += [get("ip", ""), get("protocol", "")]
    fields.append(version)
    if service == "queue":
        return "\n".join(fields)
    if service == "table":
        return "\n".join(fields + [get(name, "") for name in (
            "start_partition_key", "start_row_key", "end_partition_key", "end_row_key")])
    if version < "2013-08-15":
        return "\n".join(fields)
    if service == "blob" and version >= "2018-11-09":
        fields += [get("resource", ""), get("snapshot", "")]
        if version >= "2020-12-06":
            fields.append(get("encryption_scope", ""))
    return "\n".join(fields + [get(name, "") for name in _HEADERS])


def _encodings(signature):
    # The discovered sig is fingerprinted as written: raw Base64 or percent-encoded.
    for plus, slash, equals in product(("+", "%2B", "%2b"), ("/", "%2F", "%2f"), ("=", "%3D", "%3d")):
        yield "".join({"+": plus, "/": slash, "=": equals}.get(char, char) for char in signature)


def signed_fingerprints(account_key: str, account: str, candidates, fingerprint_key: bytes) -> list[str]:
    """Fingerprints of the candidate SAS this account key signed, recomputed in memory."""
    secret = base64.b64decode(account_key)
    found = set()
    for candidate in candidates:
        facts = candidate.get("sas") or {}
        text = string_to_sign(facts) if facts.get("account") == account else None
        if text is None or candidate.get("fingerprint") in found:
            continue
        signature = base64.b64encode(hmac.new(secret, text.encode("utf-8"), hashlib.sha256).digest()).decode()
        if candidate["fingerprint"] in {fingerprint(form.encode(), key=fingerprint_key) for form in _encodings(signature)}:
            found.add(candidate["fingerprint"])
    return sorted(found)
