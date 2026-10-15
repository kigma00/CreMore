"""Test-wide safety: never send synthetic credentials to real providers.

Provider verification is on by default in real installations. Tests that need
the default or a live-looking switch opt in explicitly and inject fake clients.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_live_provider_verification(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_VERIFICATION_MODE", "disabled")
