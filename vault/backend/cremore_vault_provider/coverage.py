"""Vault/OpenBao scoped KV fingerprints and separate management evidence."""
from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote

from cremore.coverage.collection import Collection, CollectionLimit
from cremore.coverage.models import scope_path

from .inventory_http import InventoryHTTP, ReadError
from .managed_inventory import collect_management


def _child(prefix, key):
    if (not isinstance(key, str) or len(key) > 512 or "/" in key.rstrip("/") or not scope_path(key)
            or key.count("/") > 1 or "%" in key or "?" in key or "#" in key):
        raise ValueError("KV_PATH_INVALID")
    path = "/".join(p for p in (prefix, key.rstrip("/")) if p)
    if len(path) > 2048:
        raise ValueError("KV_PATH_INVALID")
    return path


def _unavailable(meta):
    if meta.get("destroyed") is True:
        return "DESTROYED"
    deletion = meta.get("deletion_time")
    # A scheduled future deletion does not prove that the value is gone now.
    if deletion and datetime.fromisoformat(deletion) <= datetime.now(UTC):
        return "DELETED"
    return None


def _version_read(out, request, spec, engine, namespace, mount, path, *, version=None, current=None):
    location = {"reference": path, "namespace": namespace, "mount": mount.name,
                "version_state": "UNKNOWN"}
    if version is not None:
        location["version"] = str(version)
    try:
        endpoint = quote(mount.name, safe="/") + ("/data/" if mount.kv_version == 2 else "/") + quote(path, safe="/")
        try:
            data = request.data(namespace, endpoint, {"version": version} if version is not None else None)
        except ReadError as exc:
            if mount.kv_version != 2 or not exc.metadata or not _unavailable(exc.metadata):
                raise
            data = {"metadata": exc.metadata}
        if mount.kv_version == 2:
            meta = data.get("metadata")
            if (not isinstance(meta, dict) or type(meta.get("version")) is not int or meta["version"] <= 0
                    or (version is not None and meta["version"] != version)):
                raise ValueError("KV_VERSION_RESPONSE_MISMATCH")
            location["version"] = str(meta["version"])
            if version is None:
                location["version_state"] = "CURRENT"
            if current is not None:
                location["version_state"] = "CURRENT" if meta["version"] == current else "PREVIOUS"
            unavailable = _unavailable(meta)
            if unavailable:
                location["version_state"] = unavailable
                out.unresolved(location, "VERSION_UNAVAILABLE")
                return
            data = data.get("data")
        else:
            location["version"] = "unversioned"
            location["version_state"] = "CURRENT"
        if not isinstance(data, dict):
            raise TypeError("KV_VALUE_MALFORMED")
        out.value(engine, data, location)
    except CollectionLimit:
        raise
    except ReadError as exc:
        out.reasons.add(str(exc))
        out.unresolved(location, "KV_VALUE_READ_FAILED")
    except Exception:  # noqa: BLE001 -- Never emit raw response or authentication exceptions.
        out.unresolved(location, "KV_VALUE_READ_FAILED")


def _history(out, request, spec, engine, namespace, mount, path):
    location = {"reference": path, "namespace": namespace, "mount": mount.name, "version_state": "UNKNOWN"}
    try:
        meta = request.data(namespace, quote(mount.name, safe="/") + "/metadata/" + quote(path, safe="/"))
        current, versions = meta.get("current_version"), meta.get("versions")
        if (type(current) is not int or current <= 0 or not isinstance(versions, dict)
                or str(current) not in versions
                or any(not isinstance(k, str) or not k.isdecimal() or not 0 < int(k) <= current
                       or not isinstance(v, dict) for k, v in versions.items())):
            raise ValueError("KV_METADATA_MALFORMED")
        ordered = sorted(versions, key=int, reverse=True)
        if len(ordered) > spec.max_versions_per_secret:
            out.reasons.add("KV_VERSION_LIMIT")
        for version in ordered[:spec.max_versions_per_secret]:
            unavailable = _unavailable(versions[version])
            if unavailable:
                out.unresolved({**location, "version": version, "version_state": unavailable}, "VERSION_UNAVAILABLE")
            else:
                _version_read(out, request, spec, engine, namespace, mount, path,
                              version=int(version), current=current)
    except CollectionLimit:
        raise
    except ReadError as exc:
        out.unresolved(location, str(exc))
    except Exception:  # noqa: BLE001 -- Failed lookup cannot prove absent versions.
        out.unresolved(location, "KV_VERSION_METADATA_FAILED")


def collect_kv(spec, client, token, engine, *, checkpoint=None):
    """Reuse one budget for explicit namespaces, mounts and management prefixes."""
    out = Collection(spec, checkpoint=checkpoint)
    request = InventoryHTTP(spec, client, token, out)
    for namespace in spec.namespaces:
        for mount in spec.mounts:
            if mount.kv_version == 1 and (spec.include_previous_versions or spec.version_selector != "latest"):
                out.reasons.add("KV1_VERSION_HISTORY_UNSUPPORTED")
                if spec.version_selector != "latest":
                    continue
            try:
                pending, visited, paths = list(mount.prefixes), set(), set()
                while pending:
                    prefix = pending.pop()
                    if prefix in visited:
                        continue
                    visited.add(prefix)
                    endpoint = quote(mount.name, safe="/") + ("/metadata/" if mount.kv_version == 2 else "/")
                    try:
                        listing = request.data(namespace, endpoint + quote(prefix, safe="/"), {"list": "true"})
                        if not isinstance(listing.get("keys"), list):
                            raise TypeError("KV_LIST_MALFORMED")
                        for key in listing["keys"]:
                            path = _child(prefix, key)
                            if key.endswith("/"):
                                pending.append(path)
                            else:
                                paths.add(path)
                            if len(paths) + len(visited) + len(pending) > spec.max_records:
                                raise CollectionLimit("RECORD_LIMIT")
                    except CollectionLimit:
                        raise
                    except ReadError as exc:
                        out.reasons.add(str(exc))
                    except Exception:  # noqa: BLE001 -- Preserve other approved prefixes.
                        out.reasons.add("KV_SCOPE_LIST_FAILED")
                for path in sorted(paths):
                    if mount.kv_version == 2 and spec.include_previous_versions:
                        _history(out, request, spec, engine, namespace, mount, path)
                    else:
                        version = None if spec.version_selector == "latest" else int(spec.version_selector)
                        _version_read(out, request, spec, engine, namespace, mount, path, version=version)
            except CollectionLimit as exc:
                out.reasons.add(str(exc))
                return out
        try:
            collect_management(spec, namespace, request, out)
        except CollectionLimit as exc:
            out.reasons.add(str(exc))
            return out
    return out
