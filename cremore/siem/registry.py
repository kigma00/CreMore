"""Discover installed output adapters; import only explicitly configured adapters."""

import re
from importlib import import_module
from importlib.metadata import entry_points

from cremore.siem.contract import SinkProvider

ENTRY_POINT_GROUP = "cremore.siem_sinks"
_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_BUILTINS = {name: f"cremore.siem.sinks.{name}" for name in (
    "jsonl", "http_json", "splunk_hec", "logscale", "syslog_tls",
)}


def providers() -> dict:
    """Listing package metadata does not execute plugin code."""
    result = dict(_BUILTINS)
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        if not _ID.fullmatch(entry.name):
            raise ValueError("SIEM_PLUGIN_ID_INVALID")
        if entry.name in result:
            raise ValueError("SIEM_PLUGIN_ID_DUPLICATE")
        result[entry.name] = entry
    return result


def load_provider(identifier: str, *, allow_plugins: tuple[str, ...] = ()) -> SinkProvider:
    registered = providers()
    if identifier not in registered:
        raise ValueError("SIEM_PROVIDER_UNAVAILABLE")
    if identifier not in _BUILTINS and identifier not in allow_plugins:
        raise ValueError("SIEM_PLUGIN_NOT_ENABLED")
    try:
        provider = (import_module(registered[identifier]).PROVIDER
                    if identifier in _BUILTINS else registered[identifier].load())
    except Exception:  # noqa: BLE001 -- installed plugin import failures may contain credentials.
        raise ValueError("SIEM_PLUGIN_LOAD_FAILED") from None
    if (not isinstance(provider, SinkProvider) or provider.id != identifier
            or type(provider.api_version) is not int or provider.api_version != 1
            or not isinstance(provider.event_schema_versions, tuple)
            or 1 not in provider.event_schema_versions
            or any(type(version) is not int or version < 1 for version in provider.event_schema_versions)
            or not callable(provider.build)):
        raise ValueError("SIEM_PLUGIN_CONTRACT_INCOMPATIBLE")
    return provider
