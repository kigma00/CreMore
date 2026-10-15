from types import SimpleNamespace

from cremore.db.repository import InMemoryRepository
from cremore_aws_provider import aws_sso_settings as s


def _settings(pin="", allowed=True):
    return SimpleNamespace(aws_sso_discovery_permission_set=pin, sso_discovery_allowed=allowed)


def test_nothing_is_chosen_until_someone_chooses_it():
    """No default: an operator usually also holds AdministratorAccess, so a
    guess would quietly hand CreMore far more than scanning needs."""
    repo = InMemoryRepository()
    assert s.permission_set(_settings(), repo) == {
        "name": None, "source": None, "locked": False, "updated_by": None, "updated_at": None}
    assert s.discovery_switch(repo)["enabled"] is False
    assert s.discovery_effective(_settings(), repo) is False


def test_an_admin_can_choose_the_permission_set_without_touching_the_environment():
    repo = InMemoryRepository()
    repo.put_setting(s.PERMISSION_SET_KEY, {"permission_set": "CreMoreScanner"}, "admin")
    chosen = s.permission_set(_settings(), repo)
    assert chosen["name"] == "CreMoreScanner" and chosen["source"] == "DASHBOARD" and chosen["locked"] is False
    assert chosen["updated_by"] == "admin"


def test_a_configured_pin_wins_and_is_reported_as_locked():
    """Installations that do want it fixed in configuration still can."""
    repo = InMemoryRepository()
    repo.put_setting(s.PERMISSION_SET_KEY, {"permission_set": "SomethingElse"}, "admin")
    chosen = s.permission_set(_settings(pin="PinnedSet"), repo)
    assert chosen["name"] == "PinnedSet" and chosen["source"] == "SETTING" and chosen["locked"] is True
    # A pin with surrounding whitespace is still a pin.
    assert s.permission_set(_settings(pin="  PinnedSet  "), repo)["name"] == "PinnedSet"


def test_clearing_the_choice_returns_to_nothing_chosen():
    repo = InMemoryRepository()
    repo.put_setting(s.PERMISSION_SET_KEY, {"permission_set": "CreMoreScanner"}, "admin")
    repo.put_setting(s.PERMISSION_SET_KEY, {"permission_set": ""}, "admin")
    assert s.permission_set(_settings(), repo)["name"] is None
    assert s.discovery_effective(_settings(), repo) is False


def test_the_sweep_needs_configuration_the_switch_and_a_permission_set():
    repo = InMemoryRepository()
    repo.put_setting(s.PERMISSION_SET_KEY, {"permission_set": "CreMoreScanner"}, "admin")
    repo.put_setting(s.DISCOVERY_KEY, {"enabled": True}, "admin")
    assert s.discovery_effective(_settings(), repo) is True
    # Configuration can hard-lock it off, and no dashboard switch undoes that.
    assert s.discovery_effective(_settings(allowed=False), repo) is False
    # Turning the switch back off stops it without any configuration change.
    repo.put_setting(s.DISCOVERY_KEY, {"enabled": False}, "admin")
    assert s.discovery_effective(_settings(), repo) is False
