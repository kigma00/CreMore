from types import SimpleNamespace

from cremore.db.repository import InMemoryRepository
from cremore.scanning import learned_fp_settings as s


def _settings(allowed=True, threshold=0.0, min_samples=0, max_confidence=""):
    return SimpleNamespace(learned_fp_allowed=allowed, learned_fp_threshold_pin=threshold,
                           learned_fp_min_samples_pin=min_samples, learned_fp_max_confidence_pin=max_confidence)


def test_nothing_is_suppressed_until_an_admin_turns_it_on():
    """Auto-triage closes findings nobody reads, so it is never on by default."""
    current = s.config(_settings(), InMemoryRepository())
    assert current["enabled"] is False and current["switch"] is False
    assert (current["threshold"], current["min_samples"], current["max_confidence"]) == (0.85, 3, "medium")


def test_an_admin_sets_the_policy_and_the_record_says_who():
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"enabled": True, "threshold": 0.92, "min_samples": 5,
                             "max_confidence": "low"}, "officer")
    current = s.config(_settings(), repo)
    assert current["enabled"] is True and current["threshold"] == 0.92
    assert current["min_samples"] == 5 and current["max_confidence"] == "low"
    assert current["updated_by"] == "officer" and current["updated_at"] is not None
    assert not any(current[k] for k in ("threshold_locked", "min_samples_locked", "max_confidence_locked"))


def test_configuration_pins_a_field_or_locks_the_whole_thing():
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"enabled": True, "threshold": 0.92, "min_samples": 5}, "officer")
    pinned = s.config(_settings(threshold=0.7, min_samples=9), repo)
    assert pinned["threshold"] == 0.7 and pinned["threshold_locked"] is True
    assert pinned["min_samples"] == 9 and pinned["min_samples_locked"] is True
    # Not pinned, so the dashboard value still stands.
    assert pinned["max_confidence_locked"] is False

    locked = s.config(_settings(allowed=False), repo)
    assert locked["enabled"] is False and locked["installation_allows"] is False
    # The Admin's switch is still reported; configuration is what overrides it.
    assert locked["switch"] is True


def test_a_stored_policy_that_would_suppress_too_eagerly_is_refused():
    """These decide what closes unread, so an out-of-range value falls back to
    the default rather than being honoured."""
    repo = InMemoryRepository()
    for bad in ({"threshold": 0}, {"threshold": 1.5}, {"threshold": "high"}, {"threshold": True}):
        repo.put_setting(s.KEY, bad, "officer")
        assert s.config(_settings(), repo)["threshold"] == 0.85, bad
    for bad in ({"min_samples": 1}, {"min_samples": 0}, {"min_samples": -5}, {"min_samples": "many"}):
        repo.put_setting(s.KEY, bad, "officer")
        assert s.config(_settings(), repo)["min_samples"] == 3, bad
    for bad in ({"max_confidence": "certain"}, {"max_confidence": ""}, {"max_confidence": 3}):
        repo.put_setting(s.KEY, bad, "officer")
        assert s.config(_settings(), repo)["max_confidence"] == "medium", bad


def test_the_sample_floor_cannot_be_argued_below_two():
    """A profile also needs two distinct actors; one sample must never suppress."""
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"min_samples": 2}, "officer")
    assert s.config(_settings(), repo)["min_samples"] == s.MIN_SAMPLE_FLOOR == 2
    assert s.config(_settings(min_samples=1), repo)["min_samples"] == 2


def test_the_service_follows_the_policy_without_being_rebuilt():
    """An Admin's change has to take effect on a running worker."""
    from cremore.scanning.learned_fp import LearnedFPService

    repo = InMemoryRepository()
    svc = LearnedFPService(repo, _settings())
    svc._POLICY_TTL = 0  # read every time, so the change is visible at once
    assert svc.enabled is False and svc.threshold == 0.85

    repo.put_setting(s.KEY, {"enabled": True, "threshold": 0.95}, "officer")
    assert svc.enabled is True and svc.threshold == 0.95

    # An explicit assignment pins this instance over the installation.
    svc.threshold = 0.5
    assert svc.threshold == 0.5
