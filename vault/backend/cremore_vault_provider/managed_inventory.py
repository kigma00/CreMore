"""Listed service-token accessors and dynamic leases are management, not KV storage."""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.coverage.collection import CollectionLimit
from cremore.coverage.models import Observation, VaultManagedEvidence, scope_path

from .inventory_http import ReadError


def _keys(data):
    keys = data.get("keys")
    if not isinstance(keys, list):
        raise TypeError("VAULT_LIST_MALFORMED")
    return keys


def _safe_component(value, sensitive, *, directory=False):
    if (not isinstance(value, str) or len(value) > 512 or not re.fullmatch(r"[A-Za-z0-9_.@+-]+/?" if directory
                                                      else r"[A-Za-z0-9_-]{1,128}(?:\.[A-Za-z0-9_-]{1,128})?", value)
            or not scope_path(value) or any(token and token in value for token in sensitive)):
        raise ValueError("VAULT_MANAGEMENT_IDENTIFIER_INVALID")
    return value


def _metadata(kind, data):
    selected = {"kind": kind}
    for original, normalized in (("issue_time", "issued_at"), ("expire_time", "expires_at"),
                                 ("last_renewal", "last_renewal_at"), ("ttl", "ttl_seconds"),
                                 ("renewable", "renewable")):
        if data.get(original) is not None:
            selected[normalized] = data[original]
    if kind == "SERVICE_TOKEN" and "policies" in data:
        selected["policies"] = data["policies"]
    return VaultManagedEvidence.model_validate(selected)


def _add(out, request, namespace, reference, mount, metadata, reason=None):
    row = Observation(reference=reference, namespace=namespace, mount=mount, evidence="MANAGED",
                      version_state="UNKNOWN", vault_managed=metadata, reason=reason,
                      credential_type="VAULT_" + metadata.kind)
    if any(len(token) >= 8 and token in row.model_dump_json() for token in request.sensitive):
        raise ValueError("VAULT_AUTH_METADATA_REJECTED")
    if reason:
        out.reasons.add("TOKEN_ACCESSOR_LOOKUP_FAILED" if metadata.kind == "SERVICE_TOKEN" else "LEASE_LOOKUP_FAILED")
    out.add(row)


def _token_accessors(namespace, request, out):
    # Batch tokens are not persisted and have no accessor listing. This is an
    # explicit incomplete-coverage reason, never evidence that none exist.
    out.reasons.add("BATCH_TOKEN_INVENTORY_UNSUPPORTED")
    try:
        data = request.data(namespace, "auth/token/accessors", method="LIST")
        seen = set()
        for accessor in _keys(data):
            accessor = _safe_component(accessor, request.sensitive)
            if accessor in seen:
                out.reasons.add("DUPLICATE_TOKEN_ACCESSOR")
                continue
            seen.add(accessor)
            if len(seen) > out.spec.max_records:
                raise CollectionLimit("RECORD_LIMIT")
            reason = None
            try:
                data = request.data(namespace, "auth/token/lookup-accessor", method="POST", body={"accessor": accessor})
                if data.get("accessor") != accessor or data.get("type", "service") != "service":
                    raise ValueError("TOKEN_ACCESSOR_RESPONSE_MISMATCH")
                metadata = _metadata("SERVICE_TOKEN", data)
                if any(len(token) >= 8 and token in metadata.model_dump_json() for token in request.sensitive):
                    raise ValueError("VAULT_AUTH_METADATA_REJECTED")
            except CollectionLimit:
                raise
            except ReadError as exc:
                reason = str(exc)
            except Exception:  # noqa: BLE001 -- No raw token or provider exception may escape.
                reason = "TOKEN_ACCESSOR_LOOKUP_FAILED"
            if reason:
                metadata = VaultManagedEvidence(kind="SERVICE_TOKEN", lookup_status="FAILED")
            _add(out, request, namespace, "auth/token/accessors/" + accessor, "auth/token", metadata, reason)
    except CollectionLimit:
        raise
    except Exception:  # noqa: BLE001 -- Preserve explicit incomplete-list coverage.
        out.reasons.add("TOKEN_ACCESSOR_LIST_FAILED")


def _leases(spec, namespace, request, out):
    pending, visited, leases = list(spec.lease_prefixes), set(), set()
    while pending:
        prefix = pending.pop()
        if prefix in visited:
            continue
        visited.add(prefix)
        try:
            data = request.data(namespace, "sys/leases/lookup/" + quote(prefix, safe="/"), method="LIST")
            for child in _keys(data):
                child = _safe_component(child, request.sensitive, directory=True)
                identifier = prefix + "/" + child.rstrip("/")
                if len(identifier) > 2048:
                    raise ValueError("VAULT_MANAGEMENT_IDENTIFIER_INVALID")
                if child.endswith("/"):
                    pending.append(identifier)
                else:
                    if identifier in leases:
                        out.reasons.add("DUPLICATE_LEASE_IDENTIFIER")
                    leases.add(identifier)
                if len(visited) + len(leases) + len(pending) > spec.max_records:
                    raise CollectionLimit("RECORD_LIMIT")
        except CollectionLimit:
            raise
        except Exception:  # noqa: BLE001 -- A denied prefix does not hide other approved prefixes.
            out.reasons.add("LEASE_LIST_FAILED")
    for identifier in sorted(leases):
        reason = None
        try:
            response = request(namespace, "sys/leases/lookup", method="POST", body={"lease_id": identifier})
            # Vault's official example is top-level; OpenBao documents data.
            data = response.get("data", response)
            if not isinstance(data, dict) or data.get("id") != identifier:
                raise ValueError("LEASE_RESPONSE_MISMATCH")
            metadata = _metadata("DYNAMIC_LEASE", data)
            if any(len(token) >= 8 and token in metadata.model_dump_json() for token in request.sensitive):
                raise ValueError("VAULT_AUTH_METADATA_REJECTED")
        except CollectionLimit:
            raise
        except ReadError as exc:
            reason = str(exc)
        except Exception:  # noqa: BLE001 -- Keep listed lease without fabricating its lifetime.
            reason = "LEASE_LOOKUP_FAILED"
        if reason:
            metadata = VaultManagedEvidence(kind="DYNAMIC_LEASE", lookup_status="FAILED")
        _add(out, request, namespace, identifier, identifier.split("/")[0], metadata, reason)


def collect_management(spec, namespace, request, out):
    if spec.include_token_accessors:
        _token_accessors(namespace, request, out)
    if spec.lease_prefixes:
        _leases(spec, namespace, request, out)
