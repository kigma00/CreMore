"""The dashboard switch for provider verification of discovered credentials.

Verification is on by default. ``CREDENTIAL_VERIFICATION_MODE=disabled`` in the
installation settings is a hard lock; otherwise an Admin turns it on or off from
the dashboard and every scan reads the current value when it starts.
"""

from __future__ import annotations

KEY = "credential_verification"


def switch(repo) -> dict:
    record = repo.get_setting(KEY)
    value = (record or {}).get("value") or {}
    return {
        "enabled": value.get("enabled", True) is not False,
        "updated_by": (record or {}).get("updated_by") or None,
        "updated_at": (record or {}).get("updated_at"),
    }


def effective(settings, repo) -> bool:
    return bool(settings.verification_enabled) and switch(repo)["enabled"]
