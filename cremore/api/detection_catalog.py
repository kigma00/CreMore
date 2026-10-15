"""Read-only detector and credential lifecycle catalog projections."""

from __future__ import annotations

from cremore import detection
from cremore.detection.catalog import builtin_definitions

_ACCOUNT_WORDS = {"PASSWORD", "PASSCODE", "PASSWD"}
# Cloud providers whose keys the credential list groups as cloud keys.
_CLOUD_PROVIDERS = {"aws", "gcp", "azure", "alibaba", "tencent", "oracle", "ibm", "digitalocean", "scaleway",
                    "linode", "vultr", "hetzner", "cloudflare", "huaweicloud"}
_STRATEGIES = {"labelled value (config key adjacent)": "label", "documented prefix and bounded format": "prefix",
               "documented format": "format"}


def category(credential_type: str) -> str:
    """One of ``cremore.detection.custom.CATEGORIES`` for a detector's credential type (named after what it is)."""
    code = (credential_type or "").upper()
    words = set(code.split("_"))
    if code.endswith("WEBHOOK") or "WEBHOOK_URL" in code:
        return "webhook"
    if "CONNECTION_STRING" in code or code.endswith("_DSN") or code in ("DB_URL", "DATABASE_URL"):
        return "conn"
    if "PRIVATE_KEY" in code or code.endswith("CERTIFICATE"):
        return "privkey"
    if words & _ACCOUNT_WORDS or code.endswith("BASIC_AUTH") or code in ("BASIC_AUTH_URL", "NEO4J_AUTH"):
        return "account"
    if code.endswith("_TOKEN") or code == "JWT":
        return "token"
    if "SECRET" in words:
        return "secret"
    if "TOKEN" in words or "PAT" in words:
        return "token"
    if words & {"KEY", "APIKEY", "KEYSTRING", "ACCOUNT"}:
        return "apikey"
    return "other"


def kind(credential_type: str, provider: str = "") -> str:
    """The credential list's four kinds: token, apikey (API keys and secrets), cloud keys, other."""
    return kind_of(category(credential_type), provider)


def kind_of(found: str, provider: str = "") -> str:
    """``kind`` for a category already known (an operator rule declares its own)."""
    if (provider or "").lower() in _CLOUD_PROVIDERS and found in ("apikey", "secret", "privkey"):
        return "cloud"
    if found == "token":
        return "token"
    if found in ("apikey", "secret"):
        return "apikey"
    return "other"


def detector_catalog(disabled=frozenset()) -> list[dict]:
    out = []
    for d in builtin_definitions():
        c = d.catalog
        out.append({
            "id": c.id,
            "name": c.name,
            "provider": c.provider,
            "credential_type": c.credential_type,
            "category": category(c.credential_type),
            "description": c.description,
            "confidence": c.confidence,
            "keywords": list(c.keywords),
            "strategy": _STRATEGIES.get(c.match_strategy, c.match_strategy),
            "patterns": [pattern.expr for pattern in d.patterns],
            "enabled": c.id not in disabled,
            "verified_supported": False,
            "source_url": c.source_url,
            "provenance": c.provenance,
        })
    return out


def credential_types() -> list[dict]:
    seen: dict[str, dict] = {}
    for d in builtin_definitions():
        ct = d.catalog.credential_type
        if ct not in seen:
            seen[ct] = {"credential_type": ct, "provider": d.catalog.provider,
                        "detector_count": 0}
        seen[ct]["detector_count"] += 1
    return sorted(seen.values(), key=lambda x: x["credential_type"])


def reviewed_semantics() -> dict:
    """The reviewed credential-type lifecycle semantics (documentation review)."""
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "domain" / "credential_semantics" / "reviewed.json"
    return json.loads(path.read_text(encoding="utf-8"))


def credential_type_catalog() -> dict:
    """The lifecycle coverage catalog the dashboard's read-only panel renders.

    Types come from the reviewed semantics as written. Classification counts are
    computed per *current* detector (one mapping each), so retired detector ids in
    the semantics file never inflate support: ``detectors`` always equals
    ``reviewed + ambiguous + unclassified``. Adapter and live-action-roundtrip
    counts are deliberately omitted — there is no measured source for them, and a
    zero would itself assert "no support / zero tested".
    """

    semantics = reviewed_semantics()
    types = semantics.get("types", [])
    # ``rules`` classify groups of detector ids; some point at retired detectors.
    # Indexing by detector id lets us classify only the detectors that still exist.
    reviewed_by_detector: dict[str, dict] = {}
    for rule in semantics.get("rules", []):
        for detector_id in rule.get("detector_ids", []):
            reviewed_by_detector[detector_id] = rule

    engine, version = detection.NAME, detection.VERSION
    mappings: list[dict] = []
    tally = {"REVIEWED": 0, "AMBIGUOUS": 0, "UNCLASSIFIED": 0}
    for d in builtin_definitions():
        cat = d.catalog
        reviewed = reviewed_by_detector.get(cat.id)
        status = (reviewed or {}).get("classification_status", "UNCLASSIFIED")
        if status not in tally:
            status = "UNCLASSIFIED"
        tally[status] += 1
        mappings.append({
            "engine": engine, "engine_version": version, "detector_id": cat.id,
            "credential_type": cat.credential_type, "provider": cat.provider,
            "classification_status": status,
            "candidate_type_ids": (reviewed or {}).get("candidate_type_ids", []),
            "basis": (reviewed or {}).get("basis", "NO_REVIEWED_MAPPING"),
            "registration": "BUILT_IN",
        })

    reviewed_at = [s.get("reviewed_at") for t in types for s in t.get("sources", []) if s.get("reviewed_at")]
    evaluated_at = (max(reviewed_at) + "T00:00:00Z") if reviewed_at else None
    return {
        "revision": semantics.get("revision", ""),
        "mode": "SHADOW",
        "evaluated_at": evaluated_at,
        "coverage": "PARTIAL_SEMANTICS",
        "counts_scope": "SHARED_SEMANTICS_READ_PATH",
        "types": types,
        "mappings": mappings,
        "counts": {
            "detectors": len(mappings),
            "reviewed_mappings": tally["REVIEWED"],
            "ambiguous_mappings": tally["AMBIGUOUS"],
            "unclassified_mappings": tally["UNCLASSIFIED"],
            "reviewed_types": len(types),
        },
        "compatibility": {"engine": engine, "engine_version": version, "coverage": "NOT_ENUMERATED"},
    }
