from types import SimpleNamespace

from cremore.db.repository import InMemoryRepository
from cremore_aws_provider import aws_org_settings as s

EXT = "ext-shared-0123456789"
OU = "ou-abcd-11111111"


def _settings(external_id="", ou_ids="", excludes="", allowed=True):
    return SimpleNamespace(aws_org_discovery_external_id=external_id, aws_org_discovery_ou_ids=ou_ids,
                           aws_org_discovery_excludes=excludes, org_discovery_allowed=allowed)


def test_nothing_is_configured_until_an_administrator_configures_it():
    repo = InMemoryRepository()
    current = s.config(_settings(), repo)
    assert current["enabled"] is False and current["external_id"] is None
    assert current["ou_ids"] == [] and current["excludes"] == [] and current["auto_validate"] is False
    assert current["installation_allows"] is True
    assert s.effective(_settings(), repo) is False


def test_an_administrator_can_set_everything_without_touching_the_environment():
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"enabled": True, "external_id": EXT, "ou_ids": [OU],
                             "excludes": ["111111111111"], "auto_validate": True}, "admin")
    current = s.config(_settings(), repo)
    assert current["external_id"] == EXT and current["ou_ids"] == [OU]
    assert current["excludes"] == ["111111111111"] and current["auto_validate"] is True
    assert all(current[k] is False for k in ("external_id_locked", "ou_ids_locked", "excludes_locked"))
    assert s.effective(_settings(), repo) is True


def test_the_sweep_cannot_run_without_the_shared_external_id():
    """A role deployed with a different ExternalId can never be assumed, so a
    sweep without one would only register records that always fail."""
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"enabled": True}, "admin")
    assert s.effective(_settings(), repo) is False
    repo.put_setting(s.KEY, {"enabled": True, "external_id": EXT}, "admin")
    assert s.effective(_settings(), repo) is True


def test_each_configured_value_pins_its_own_field():
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"enabled": True, "external_id": "dashboard-value",
                             "ou_ids": ["ou-zzzz-99999999"], "excludes": ["999999999999"]}, "admin")
    current = s.config(_settings(external_id=EXT, ou_ids=OU), repo)
    assert current["external_id"] == EXT and current["external_id_locked"] is True
    assert current["ou_ids"] == [OU] and current["ou_ids_locked"] is True
    # Not pinned, so the dashboard value still stands.
    assert current["excludes"] == ["999999999999"] and current["excludes_locked"] is False


def test_configuration_can_hard_lock_the_sweep_off():
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"enabled": True, "external_id": EXT}, "admin")
    assert s.effective(_settings(allowed=False), repo) is False
    assert s.config(_settings(allowed=False), repo)["installation_allows"] is False


def test_malformed_stored_or_pinned_values_are_dropped_not_used():
    """These reach AWS APIs, so anything that is not an id is discarded."""
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"external_id": "x", "ou_ids": ["not-an-ou", OU, ""],
                             "excludes": ["nope", "111111111111"]}, "admin")
    current = s.config(_settings(), repo)
    assert current["external_id"] is None  # one character fails the pattern
    assert current["ou_ids"] == [OU] and current["excludes"] == ["111111111111"]
    # A root id is a valid discovery target too.
    repo.put_setting(s.KEY, {"ou_ids": ["r-abcd"]}, "admin")
    assert s.config(_settings(), repo)["ou_ids"] == ["r-abcd"]


def test_a_comma_separated_pin_is_read_as_a_list():
    repo = InMemoryRepository()
    current = s.config(_settings(ou_ids=f"{OU}, ou-abcd-22222222 ,junk", excludes="111111111111,nope"), repo)
    assert current["ou_ids"] == [OU, "ou-abcd-22222222"]
    assert current["excludes"] == ["111111111111"]
