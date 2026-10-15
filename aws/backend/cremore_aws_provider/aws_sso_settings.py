"""Which IAM Identity Center permission set CreMore uses, and whether it sweeps.

CreMore is handed to an operator as a deployment they run but often may not
re-configure: editing the environment and restarting the stack is somebody
else's change request. So both choices live in ``installation_settings`` and an
Admin makes them from the dashboard, the same way credential verification and
the two scan toggles already work (``cremore/scanning/verification_switch.py``,
``cremore/scanning/scan_switches.py``).

The environment keeps the role it has everywhere else in CreMore:

* ``AWS_SSO_DISCOVERY_MODE=disabled`` hard-locks the assignment sweep off, which
  no dashboard switch can undo;
* ``AWS_SSO_DISCOVERY_PERMISSION_SET`` is an optional **pin** for installations
  that do want the permission set fixed in configuration. When it is set it
  wins, and the dashboard reports it as locked rather than pretending to offer a
  choice.

There is deliberately no default permission set. An operator commonly holds
``AdministratorAccess`` alongside a read-only set, so guessing would quietly
pick up far more than scanning needs; until one is chosen, the Identity Center
route offers nothing to select.
"""

from __future__ import annotations

PERMISSION_SET_KEY = "aws_sso_permission_set"
DISCOVERY_KEY = "aws_sso_discovery"


def permission_set(settings, repo) -> dict:
    """``{name, source, locked, updated_by, updated_at}``; the configured pin wins."""
    pinned = (getattr(settings, "aws_sso_discovery_permission_set", "") or "").strip()
    if pinned:
        return {"name": pinned, "source": "SETTING", "locked": True, "updated_by": None, "updated_at": None}
    record = repo.get_setting(PERMISSION_SET_KEY)
    value = (record or {}).get("value") or {}
    name = str(value.get("permission_set") or "").strip() or None
    return {"name": name, "source": "DASHBOARD" if name else None, "locked": False,
            "updated_by": (record or {}).get("updated_by") if name else None,
            "updated_at": (record or {}).get("updated_at") if name else None}


def discovery_switch(repo) -> dict:
    """The Admin's sweep choice. Off until someone turns it on, like every scan toggle."""
    record = repo.get_setting(DISCOVERY_KEY)
    value = (record or {}).get("value") or {}
    return {"enabled": value.get("enabled", False) is True,
            "updated_by": (record or {}).get("updated_by") or None,
            "updated_at": (record or {}).get("updated_at")}


def discovery_effective(settings, repo) -> bool:
    """Sweep now? Allowed by configuration, switched on, and a permission set chosen."""
    return (bool(getattr(settings, "sso_discovery_allowed", True))
            and discovery_switch(repo)["enabled"]
            and bool(permission_set(settings, repo)["name"]))
