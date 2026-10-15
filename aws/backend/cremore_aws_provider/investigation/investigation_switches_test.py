from types import SimpleNamespace

from cremore.db.repository import InMemoryRepository
from cremore_aws_provider.investigation import investigation_switches as s


def _settings(**allowed):
    return SimpleNamespace(aws_usage_lookup_allowed=allowed.get("usage", True),
                           iam_potential_access_allowed=allowed.get("potential", True),
                           aws_secrets_inventory_allowed=allowed.get("secrets", True))


def test_no_investigation_calls_aws_until_an_admin_asks():
    """Each one reads metadata in somebody's account, so none is on by default."""
    repo = InMemoryRepository()
    for key in s.KEYS:
        assert s.effective(_settings(), repo, key) is False
        assert s.switch(repo, key) == {"enabled": False, "updated_by": None, "updated_at": None}


def test_an_admin_switches_one_on_and_the_record_says_who():
    repo = InMemoryRepository()
    repo.put_setting(s.USAGE_LOOKUP, {"enabled": True}, "officer")
    current = s.switch(repo, s.USAGE_LOOKUP)
    assert current["enabled"] is True
    assert current["updated_by"] == "officer" and current["updated_at"] is not None
    assert s.effective(_settings(), repo, s.USAGE_LOOKUP) is True
    # One switch is one investigation; the other two stay off.
    assert not s.effective(_settings(), repo, s.POTENTIAL_ACCESS)
    assert not s.effective(_settings(), repo, s.SECRETS_INVENTORY)


def test_configuration_overrides_the_switch_but_does_not_erase_it():
    repo = InMemoryRepository()
    repo.put_setting(s.SECRETS_INVENTORY, {"enabled": True}, "officer")
    locked = _settings(secrets=False)
    assert s.allowed(locked, s.SECRETS_INVENTORY) is False
    assert s.effective(locked, repo, s.SECRETS_INVENTORY) is False
    # The Admin's choice is still readable, so the dashboard can say why it is off.
    assert s.switch(repo, s.SECRETS_INVENTORY)["enabled"] is True


def test_a_stored_value_that_is_not_a_true_boolean_leaves_it_off():
    repo = InMemoryRepository()
    for stored in ({"enabled": "true"}, {"enabled": 1}, {"enabled": None}, {}, {"on": True}):
        repo.put_setting(s.POTENTIAL_ACCESS, stored, "officer")
        assert s.effective(_settings(), repo, s.POTENTIAL_ACCESS) is False, stored


def test_every_key_names_a_configuration_property_that_exists():
    """A typo here would silently allow an investigation the installation locked."""
    from cremore.config import Settings

    for key in s.KEYS:
        assert hasattr(Settings(FINGERPRINT_KEY="0" * 64), s.ALLOWED_BY[key]), key


def test_the_worker_reads_the_switch_per_principal_not_once_at_start_up():
    """The worker wires the potential-access provider when configuration allows
    it and then scans for hours. If it captured the switch at start-up, turning
    the investigation off in the dashboard would not stop the IAM calls."""
    from cremore.risk.model import AWSPrivilegeSignal

    repo, calls = InMemoryRepository(), []
    settings = _settings()

    def evaluate(arn):
        calls.append(arn)
        return AWSPrivilegeSignal(evaluated=True)

    provider = s.switched_potential_access(evaluate, settings, repo)  # what cremore/cli/worker.py wires

    arn = "arn:aws:iam::123456789012:user/example"
    assert provider(arn).evaluated is False and not calls
    repo.put_setting(s.POTENTIAL_ACCESS, {"enabled": True}, "officer")
    assert provider(arn).evaluated is True and calls == [arn]
    # And off again without restarting anything.
    repo.put_setting(s.POTENTIAL_ACCESS, {"enabled": False}, "officer")
    assert provider(arn).evaluated is False and calls == [arn]


def test_the_worker_actually_wires_that_wrapper():
    """The test above proves the wrapper works; this proves the worker uses it.
    Nothing else drives cremore/cli/worker.py, so a direct call would go unnoticed."""
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[4] / "cremore" / "cli" / "worker.py").read_text(encoding="utf-8")
    assert "switched_potential_access(" in source
    # provider_from_sessions must not reach the orchestrator unwrapped.
    for line in source.splitlines():
        if "provider_from_sessions(" in line and "import" not in line:
            assert "switched_potential_access(" in line or line.strip().startswith(
                ("provider_from_sessions(", "#")), line
