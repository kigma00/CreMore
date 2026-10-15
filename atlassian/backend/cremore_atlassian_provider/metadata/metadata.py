# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/metadata.py).
"""Select metadata fields, preserve observations, and group token identities."""

from datetime import UTC, datetime, timedelta

from .specs import SOURCES

MISSING = object()
TIME_FIELDS = ("createdAt", "expiresAt", "lastActiveAt", "updatedAt", "clientRevocationTime")


def utc_now():
    return datetime.now(UTC).isoformat()


def lookup(record, field):
    for part in field.split("."):
        if not isinstance(record, dict) or part not in record:
            return MISSING
        record = record[part]
    return record


def iso_time(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value)
        return result.astimezone(UTC) if result.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def epoch_ms_time(value):
    if type(value) is not int:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=value)
    except (ValueError, OverflowError):
        return None


def normalize(source, record, observed_at, *, allow_service_oauth_variant=False):
    """None means an unidentifiable record. Raw unknown fields are never copied."""
    if not isinstance(record, dict):
        return None
    spec = SOURCES[source]
    variant_warnings = []
    if source == "org-oauth-clients" and allow_service_oauth_variant:
        service_markers = "clientName" in record and "serviceAccount" in record
        org_markers = any(name in record for name in ("name", "status", "updatedAt"))
        if service_markers and not org_markers:
            # Observed with matching IDs and fields on both endpoints in the lab.
            # Select by explicit field contract, never by timestamp magnitude/type.
            spec = SOURCES["service-account-oauth-clients"]
        elif service_markers and org_markers:
            variant_warnings.append("ambiguous_oauth_record_contract")
    identifier = record.get(spec["id_field"])
    if (
        not isinstance(identifier, str)
        or not identifier.strip()
        or any(ord(c) < 32 for c in identifier)
    ):
        return None
    fields, warnings = {}, variant_warnings
    for name in spec["fields"]:
        value = lookup(record, name)
        if value is MISSING:
            item = {"state": "missing"}
        elif value is None:
            item = {"state": "null"}
        elif (
            (
                name == "scopes"
                and isinstance(value, list)
                and all(isinstance(v, str) for v in value)
            )
            or (name in spec.get("epoch_ms", ()) and type(value) is int)
            or (name in spec.get("booleans", ()) and type(value) is bool)
            or (
                name != "scopes"
                and name not in spec.get("epoch_ms", ())
                and name not in spec.get("booleans", ())
                and name not in spec.get("null_only", ())
                and isinstance(value, str)
            )
        ):
            item = {"state": "present", "value": list(value) if name == "scopes" else value}
        else:
            item = {"state": "invalid_type"}
            warnings.append("invalid_type:" + name)
        if name in spec["required"] and item["state"] in ("missing", "null"):
            warnings.append("required_" + item["state"] + ":" + name)
        if name in TIME_FIELDS and item["state"] == "present":
            parsed = epoch_ms_time(value) if name in spec.get("epoch_ms", ()) else iso_time(value)
            if parsed is None:
                warnings.append("invalid_timestamp:" + name)
            else:
                item["normalized_utc"] = parsed.isoformat()
        fields[name] = item
    parent_states = {}
    for name, required in spec["parents"].items():
        parent = record.get(name, MISSING)
        state = (
            "missing"
            if parent is MISSING
            else "null"
            if parent is None
            else "present"
            if isinstance(parent, dict)
            else "invalid_type"
        )
        parent_states[name] = state
        if state == "invalid_type" or (required and state != "present"):
            warnings.append("parent_" + state + ":" + name)
        # Optional nullable TokenUser still requires id/name when an object exists.
        if (
            spec["kind"] == "service_account_oauth_client"
            and name == "createdBy"
            and state == "present"
        ):
            for child in ("id", "name"):
                child_state = fields[name + "." + child]["state"]
                if child_state in ("missing", "null"):
                    warnings.append("required_" + child_state + ":" + name + "." + child)
    if (
        spec["kind"] == "api_token"
        and fields["status"]["state"] == "present"
        and fields["status"]["value"] not in ("ALLOWED", "BLOCKED", "EXPIRED")
    ):
        warnings.append("unknown_status:status")
    if (
        spec["kind"] == "org_oauth_client"
        and fields["status"]["state"] == "present"
        and fields["status"]["value"] not in ("ACTIVE", "REVOKED", "EXPIRED")
    ):
        warnings.append("unknown_status:status")
    if source == "service-account-api-tokens" and fields["scopes"] == {
        "state": "present",
        "value": [],
    }:
        warnings.append("empty_service_account_scopes")
    expiry = iso_time(fields.get("expiresAt", {}).get("value"))
    observed = iso_time(observed_at)
    return {
        "source": source,
        "record_contract": spec["kind"],
        "observed_at": observed_at,
        "fields": fields,
        "parent_states": parent_states,
        "warnings": warnings,
        "derived": {"expired_at_observation": expiry <= observed if expiry and observed else None}
        if "expiresAt" in fields
        else {},
    }


def comparison_value(name, item):
    if name == "scopes" and item.get("state") == "present":
        return {"state": "present", "value": sorted(set(item["value"]))}
    return {k: v for k, v in item.items() if k != "normalized_utc"}


def group_inventory(observations):
    """Called for one organization only; metadata conflicts retain every version."""
    groups = {}
    for observation in observations:
        source = observation["source"]
        kind = observation["record_contract"]
        identifier = observation["fields"][SOURCES[source]["id_field"]]["value"]
        entry = groups.setdefault(
            (kind, identifier),
            {
                "kind": kind,
                "provider_id": identifier,
                "principal_kind": "unknown",
                "sources": [],
                "conflict_fields": [],
                "observations": [],
            },
        )
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if entry["observations"]:
            first = entry["observations"][0]
            for name, item in observation["fields"].items():
                if comparison_value(name, item) != comparison_value(name, first["fields"][name]):
                    entry["conflict_fields"].append(name)
            for name, state in observation["parent_states"].items():
                if state != first["parent_states"][name]:
                    entry["conflict_fields"].append(name)
        entry["observations"].append(observation)
    for entry in groups.values():
        entry["conflict_fields"] = sorted(set(entry["conflict_fields"]))
        subjects = [o["fields"].get("user.id", {}) for o in entry["observations"]]
        subject_verified = all(
            s.get("state") == "present" and s.get("value", "").strip() for s in subjects
        )
        if (
            "service-account-api-tokens" in entry["sources"]
            and subject_verified
            and "user.id" not in entry["conflict_fields"]
        ):
            entry["principal_kind"] = "service_account"
        if entry["kind"] == "service_account_oauth_client":
            subjects = [o["fields"]["serviceAccount.id"] for o in entry["observations"]]
            if (
                all(s.get("state") == "present" and s.get("value", "").strip() for s in subjects)
                and "serviceAccount.id" not in entry["conflict_fields"]
            ):
                entry["principal_kind"] = "service_account"
    return list(groups.values())


def oauth_link_candidates(inventory):
    """Same clientId is a candidate; do not merge different unverified contracts."""
    service_ids = {
        e["provider_id"] for e in inventory if e["kind"] == "service_account_oauth_client"
    }
    org_ids = {e["provider_id"] for e in inventory if e["kind"] == "org_oauth_client"}
    return [
        {
            "state": "unverified",
            "basis": "same_client_id",
            "provider_id": identifier,
            "kinds": ["service_account_oauth_client", "org_oauth_client"],
        }
        for identifier in sorted(service_ids & org_ids)
    ]
