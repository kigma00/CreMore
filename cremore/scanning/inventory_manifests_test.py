import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.scanning import inventory_manifests as m

CONNECTION = "22222222-2222-4222-8222-222222222222"
IDENTITY = f"{CONNECTION}/approved-bucket"
POINTER = {"manifest_bucket": "existing-reports", "manifest_key": "reports/2026-09-15/manifest.json"}


def _settings(**env):
    return Settings(FINGERPRINT_KEY="ab" * 32, **env)


def _save(repo, bindings):
    repo.put_setting(m.KEY, {"bindings": bindings}, "admin")
    return repo


def test_nothing_is_bound_until_somebody_binds_it():
    repo, settings = InMemoryRepository(), _settings()
    assert m.bindings(settings, repo) == {}
    assert m.config(settings, repo) == {"bindings": {}, "locked": False,
                                        "updated_by": None, "updated_at": None}


def test_an_admin_binds_a_bucket_and_the_record_says_who():
    repo = _save(InMemoryRepository(), {IDENTITY: POINTER})
    settings = _settings()
    assert m.bindings(settings, repo) == {IDENTITY: POINTER}
    view = m.config(settings, repo)
    assert view["locked"] is False and view["updated_by"] == "admin" and view["updated_at"] is not None


def test_configuration_pins_the_bindings_and_the_dashboard_says_so():
    """An installation that wants these fixed keeps them fixed, and the dashboard
    does not pretend they can be edited."""
    import json

    repo = _save(InMemoryRepository(), {IDENTITY: POINTER})
    other = {"manifest_bucket": "fixed-reports", "manifest_key": "fixed/manifest.json"}
    pinned = _settings(SCAN_INVENTORY_MANIFESTS=json.dumps({IDENTITY: other}))
    assert m.bindings(pinned, repo) == {IDENTITY: other}
    view = m.config(pinned, repo)
    assert view["locked"] is True and view["bindings"] == {IDENTITY: other}
    # Configuration overrides, so the Admin's name would be the wrong attribution.
    assert view["updated_by"] is None


def test_a_pointer_that_is_not_an_exact_report_is_refused():
    """A binding is two exact S3 objects. Anything else would be a place to put a
    URL, and a report is never fetched over HTTP."""
    for bad in ({**POINTER, "url": "https://untrusted.invalid"},
                {**POINTER, "manifest_key": "https://untrusted.invalid/manifest.json"},
                {**POINTER, "manifest_key": "../manifest.json"},
                {**POINTER, "manifest_key": "reports/manifest.txt"},
                {**POINTER, "manifest_key": ""},
                {**POINTER, "manifest_key": "reports/\nx/manifest.json"},
                {**POINTER, "manifest_bucket": "Not A Bucket"},
                {"manifest_bucket": "existing-reports"}):
        with pytest.raises(m.ManifestBindingError):
            m.normalize({IDENTITY: bad})
    assert m.normalize({IDENTITY: POINTER}) == {IDENTITY: POINTER}


def test_an_identity_must_name_a_connection_and_a_bucket():
    for bad in ("not-a-uuid/bucket", CONNECTION, f"{CONNECTION}/Not A Bucket", f"{CONNECTION}/"):
        with pytest.raises(m.ManifestBindingError):
            m.normalize({bad: POINTER})
    with pytest.raises(m.ManifestBindingError):
        m.normalize([IDENTITY])


def test_a_stored_binding_that_no_longer_validates_is_dropped_not_used():
    """Reading a report from a name that stopped being a bucket name is not
    something to attempt; the scan reports INVENTORY_NOT_CONFIGURED instead."""
    repo = InMemoryRepository()
    repo.put_setting(m.KEY, {"bindings": {IDENTITY: POINTER,
                                          "broken/x": POINTER,
                                          f"{CONNECTION}/other": {"manifest_bucket": "b"}}}, "admin")
    assert m.stored(repo) == {IDENTITY: POINTER}


def test_a_malformed_configuration_pin_is_refused_rather_than_ignored():
    for bad in ("not json", "[]", '{"x": 1}'):
        with pytest.raises(m.ManifestBindingError):
            m.pinned(_settings(SCAN_INVENTORY_MANIFESTS=bad))
    assert m.pinned(_settings()) is None
    assert m.pinned(_settings(SCAN_INVENTORY_MANIFESTS="{}")) is None
