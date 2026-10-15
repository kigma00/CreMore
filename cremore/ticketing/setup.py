"""The admin's setup of the ticket system, kept in installation settings with its secrets sealed.

A secret is sealed on arrival and never returned. Saving with a blank secret keeps the saved one only for the same
system at the same address with the same sign-in values (``url`` and ``text`` fields): a saved password never goes
to another server.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import NamedTuple

from cremore.domain.models import FindingEvent
from cremore.domain.text import unsafe_text
from cremore.secretstore.sealed import SealedSecretError, seal_fields, unseal
from cremore.ticketing import registry
from cremore.ticketing.contract import TicketError, safe_code

SETTING_KEY = "ticket_system"
LOCK_KEY = "ticket-system:lock"


class SetupError(Exception):
    def __init__(self, code: str, http_status: int = 422) -> None:
        super().__init__(code)
        self.code, self.http_status = code, http_status


def _saved(repo) -> dict:
    value = (repo.get_setting(SETTING_KEY) or {}).get("value")
    return value if isinstance(value, dict) else {}


def _provider(system):
    try:
        return registry.load(system)
    except ValueError as exc:
        raise SetupError(safe_code(exc)) from None


def configured(repo) -> str | None:
    """The system CreMore asks through, or None."""
    return _saved(repo).get("system") or None


def _binding(saved: dict) -> str:
    return hashlib.sha256(json.dumps([saved.get("system"), (saved.get("values") or {}).get("url")]).encode()).hexdigest()


def binding(repo) -> str:
    """Which server a request is asked on (the system and its address): a request asked on another one is not
    read from this one, whose ticket numbers can name other tickets."""
    return _binding(_saved(repo))


class Ready(NamedTuple):
    """A system built from one reading of the setup, with that reading's name and server binding."""

    system: object
    name: str
    binding: str


def _locked(repo):
    from cremore.db.settings_store import locked_settings

    if repo.get_setting(LOCK_KEY) is None:
        repo.claim_slot(LOCK_KEY, 0, "system:ticketing")  # insert-if-absent: racing first writers both find it after
    return locked_settings(repo, setting_key=LOCK_KEY)


def _audit(bound, actor: str, target, note: str) -> None:
    bound.record_finding_event(FindingEvent(target_type="ticket_system", target_id=target, actor=actor,
                                            event_type="TICKET_SYSTEM_SAVED", note=note))


def public(repo) -> dict:
    """The systems an admin can choose (with the values each takes) and the saved setup, never its secrets."""
    systems = []
    for name in registry.available():
        try:
            provider = registry.load(name)
        except ValueError:
            continue  # an allowed adapter that does not load is not offered
        systems.append({"id": provider.id, "label": provider.label, "fields": [asdict(item) for item in provider.fields]})
    saved = _saved(repo)
    current = {"system": saved["system"], "values": saved.get("values") or {},
               "secrets_saved": sorted(saved.get("secret_names") or [])} if saved.get("system") else None
    return {"systems": systems, "current": current}


def save(repo, settings, body, actor: str, target) -> tuple[dict, str]:
    """Replace the setup (or turn it off with ``system: null``), audited with it (``TICKET_SYSTEM_SAVED`` against
    ``target``, the plain values and which secrets were replaced, never a secret). (public view, audit note)."""
    if not isinstance(body, dict):
        raise SetupError("TICKET_SYSTEM_SETUP_INVALID")
    system = body.get("system")
    if system is None:
        with _locked(repo) as bound:
            note = f"system=off (was {_saved(bound).get('system') or 'off'})"
            bound.put_setting(SETTING_KEY, {}, actor)
            _audit(bound, actor, target, note)
        return public(repo), note
    provider = _provider(system)
    try:
        values = provider.validate(body.get("values") or {})
    except ValueError as exc:
        raise SetupError(safe_code(exc)) from None
    given = body.get("secrets") or {}
    if not isinstance(given, dict):
        raise SetupError("TICKET_SYSTEM_SECRET_INVALID")
    fields = [item.name for item in provider.fields if item.kind in ("url", "text")]
    # The setup it replaces is read under the lock: a save running at the same time cannot undo this one's secrets.
    with _locked(repo) as bound:
        before = _saved(bound)
        same = (before.get("system") == system and before.get("sealed")
                and all((before.get("values") or {}).get(name) == values.get(name) for name in fields))
        try:
            kept = unseal(settings.sealing_keys, before["sealed"]) if same else {}
        except SealedSecretError:
            kept = {}  # a key rotated away: every secret must be entered again
        except Exception:  # noqa: BLE001 -- the key store (Vault, KMS) did not answer: retry later, never a 500
            raise SetupError("TICKET_SYSTEM_SECRET_UNAVAILABLE", 503) from None
        secrets, changed = {}, []
        for item in provider.fields:
            if item.kind != "secret":
                continue
            value = given.get(item.name)
            if value:
                if not isinstance(value, str) or len(value) > 1024 or unsafe_text(value):
                    raise SetupError("TICKET_SYSTEM_SECRET_INVALID")
                secrets[item.name] = value
                changed.append(item.name)
            elif item.name in kept:
                secrets[item.name] = kept[item.name]
            elif item.required:
                raise SetupError("TICKET_SYSTEM_SECRET_REQUIRED")
        try:
            sealed = seal_fields(settings.sealing_keys, secrets) if secrets else None
        except Exception:  # noqa: BLE001 -- as above
            raise SetupError("TICKET_SYSTEM_SECRET_UNAVAILABLE", 503) from None
        shown = " ".join(f"{name}={value}" for name, value in values.items() if value is not None)
        note = f"system={system} {shown} secrets={','.join(changed) + ' replaced' if changed else 'kept'}"
        bound.put_setting(SETTING_KEY, {"system": system, "values": values, "sealed": sealed,
                                        "secret_names": sorted(secrets)}, actor)
        _audit(bound, actor, target, note)
    return public(repo), note


def open_system(repo, settings, client) -> Ready:
    """The configured system, ready to call, with the name and server binding of the same reading of the setup (a
    request is bound to the server it is actually asked on); TicketError when there is none or its secrets cannot be
    opened."""
    saved = _saved(repo)
    if not saved.get("system"):
        raise TicketError("TICKET_SYSTEM_NOT_SET_UP")
    try:
        provider = registry.load(saved["system"])
    except ValueError as exc:
        raise TicketError(safe_code(exc)) from None
    try:
        secrets = unseal(settings.sealing_keys, saved["sealed"]) if saved.get("sealed") else {}
    except Exception:  # noqa: BLE001 -- a sealed value never reaches an error message
        raise TicketError("TICKET_SYSTEM_SECRET_UNAVAILABLE", retryable=True) from None
    return Ready(provider.build(saved.get("values") or {}, secrets, client), saved["system"], _binding(saved))
