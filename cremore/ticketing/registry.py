"""The ticket systems CreMore can ask through: installed adapters the installation named. None is built in."""

import os
import re
from importlib import import_module
from importlib.metadata import entry_points

from cremore.ticketing.contract import Field, TicketSystemProvider

ENTRY_POINT_GROUP = "cremore.ticket_systems"
PLUGINS_ENV = "TICKET_SYSTEM_PLUGINS"  # comma-separated ids of installed adapters the installation allows
_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_BUILTINS: dict[str, str] = {}  # id -> module path of a built-in adapter (its ``PROVIDER``); none is built in


def allowed_plugins() -> tuple[str, ...]:
    return tuple(item.strip() for item in os.environ.get(PLUGINS_ENV, "").split(",") if item.strip())


def _registered() -> dict:
    """Listing package metadata runs no adapter code."""
    found = dict(_BUILTINS)
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        if _ID.fullmatch(entry.name) and entry.name not in found:
            found[entry.name] = entry
    return found


def available() -> list[str]:
    """The systems an admin can choose: every built-in one (none now), and the installed adapters the installation
    allows."""
    allowed = allowed_plugins()
    return [name for name in _registered() if name in _BUILTINS or name in allowed]


def load(identifier: str) -> TicketSystemProvider:
    if identifier not in available():
        raise ValueError("TICKET_SYSTEM_UNAVAILABLE")
    entry = _registered()[identifier]
    try:
        provider = import_module(entry).PROVIDER if identifier in _BUILTINS else entry.load()
    except Exception:  # noqa: BLE001 -- an installed adapter's import failure may quote its setup
        raise ValueError("TICKET_SYSTEM_LOAD_FAILED") from None
    if (not isinstance(provider, TicketSystemProvider) or provider.id != identifier
            or type(provider.api_version) is not int or provider.api_version != 1
            or not isinstance(provider.fields, tuple) or not provider.fields
            or not all(isinstance(field, Field) and _ID.fullmatch(field.name) for field in provider.fields)
            or len({field.name for field in provider.fields}) != len(provider.fields)
            or not callable(provider.build) or not callable(provider.validate)):
        raise ValueError("TICKET_SYSTEM_CONTRACT_INCOMPATIBLE")
    return provider
