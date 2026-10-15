"""Shared lock and append-only audit for installation settings."""

import uuid

_SETTING_TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:installation_setting")


def change_note(what: str, changes: dict, plain: tuple[str, ...] = ()) -> str:
    """The audit note of an Admin's settings change: which fields, never a value an address or identifier could be
    read from. Switches read on/off, numbers as given, lists and maps as their size, text as set or cleared.
    ``plain`` names the fields validated to closed values that are shown as chosen: a choice as itself, a map of
    them (the change feed's minutes per provider) as ``key:value`` pairs."""
    def shown(name, value) -> str:
        if isinstance(value, bool):
            return "on" if value else "off"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, dict) and name in plain:
            return ",".join(f"{key}:{item}" for key, item in sorted(value.items())) or "0"
        if isinstance(value, list | dict):
            return str(len(value))
        if name in plain and value:
            return str(value)
        return "set" if value else "cleared"
    return " ".join([what, *(f"{name}={shown(name, value)}" for name, value in changes.items())])[:500]


SETTINGS_LOCK = "installation-settings:lock"


def locked_installation_settings(repo):
    """The one lock an Admin's settings saves take: a row that always exists, so two first-ever saves of one setting
    wait for each other too (a row lock on a setting not stored yet locks nothing on PostgreSQL)."""
    from cremore.db.settings_store import locked_settings

    if repo.get_setting(SETTINGS_LOCK) is None:
        repo.claim_slot(SETTINGS_LOCK, 0, "system:settings")  # insert-if-absent: racing first writers both find it
    return locked_settings(repo, setting_key=SETTINGS_LOCK)


def setting_changed(bound, actor: str, what: str, changes: dict, plain: tuple[str, ...] = ()) -> None:
    """The audit row of an Admin's settings change, written in the transaction that stores the change."""
    from cremore.domain.models import FindingEvent

    bound.record_finding_event(FindingEvent(target_type="installation_setting", target_id=_SETTING_TARGET, actor=actor,
                                            event_type="INSTALLATION_SETTING_CHANGED",
                                            note=change_note(what, changes, plain)))
