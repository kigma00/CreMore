"""The isolated configuration never restores legacy credential-opening roots."""

import pytest

from cremore.config import Settings


@pytest.mark.parametrize("name", ["SEALING_KEY", "SEALING_KEY_PREVIOUS", "SEALING_PASSPHRASE",
    "SEALING_KEY_CIPHERTEXT", "SEALING_KEY_VAULT_PATH"])
def test_isolated_settings_reject_configured_legacy_opening_material(name):
    settings = Settings(ISOLATED_DEPLOYMENT=True, SEALING_PUBLIC_KEYS_FILE="public.json", **{name: "ab" * 32})
    with pytest.raises(ValueError, match="cannot retain legacy"):
        settings.validate_sealing()


def test_settings_construction_has_no_key_file_io_and_control_is_not_fingerprint_fallback():
    settings = Settings(ISOLATED_DEPLOYMENT=True, SEALING_PUBLIC_KEYS_FILE="does-not-exist.json",
                        FINGERPRINT_KEY="ab" * 32)
    settings.validate_sealing()
    assert settings.control_sealing_keys.current is None
    assert settings.sealing_keys.legacy is None


def test_execution_role_enum_preserves_legacy_default_and_explicit_control_role():
    assert Settings().worker_execution_role == "mixed"
    assert Settings(WORKER_EXECUTION_ROLE="control").worker_execution_role == "control"
    with pytest.raises(ValueError):
        Settings(WORKER_EXECUTION_ROLE="unknown")


def test_worker_concurrency_is_explicit_or_picked_for_the_database_and_the_cpus_it_may_use(monkeypatch):
    import os

    from cremore import config

    # Synthetic, built at run time so the file holds no connection-string-shaped literal.
    postgres, sqlite = "postgresql://cremore:" + "synthetic@localhost:5432/cremore", "sqlite:///cremore.db"
    monkeypatch.delenv("WORKER_CONCURRENCY", raising=False)
    assert Settings().worker_concurrency == 0
    for url in (postgres, sqlite):
        assert Settings(WORKER_CONCURRENCY=6, DATABASE_URL=url).effective_worker_concurrency == 6
    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    monkeypatch.setattr(config, "_cgroup_cpus", lambda: None)
    for cpus, expected in ((16, 4), (3, 3), (1, 1), (None, 2)):
        monkeypatch.setattr(os, "cpu_count", lambda cpus=cpus: cpus)
        assert Settings(DATABASE_URL=postgres).effective_worker_concurrency == expected
    # A container sees its host's CPUs: the affinity mask and the CPU limit are what it may use.
    monkeypatch.setattr(os, "cpu_count", lambda: 64)
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: {0, 1, 2}, raising=False)
    assert Settings(DATABASE_URL=postgres).effective_worker_concurrency == 3
    for limit, expected in ((1.5, 2), (0.25, 1), (8.0, 3)):
        monkeypatch.setattr(config, "_cgroup_cpus", lambda limit=limit: limit)
        assert Settings(DATABASE_URL=postgres).effective_worker_concurrency == expected
    # SQLite takes one writer at a time: one runner, however many CPUs.
    assert Settings(DATABASE_URL=sqlite).effective_worker_concurrency == 1
    assert Settings(WORKER_CONCURRENCY=32).worker_concurrency == 32
    for invalid in (-1, 33):
        with pytest.raises(ValueError):
            Settings(WORKER_CONCURRENCY=invalid)


@pytest.mark.parametrize("files, limit", [
    ({"/sys/fs/cgroup/cpu.max": "150000 100000\n"}, 1.5),
    ({"/sys/fs/cgroup/cpu.max": "max 100000\n"}, None),
    ({"/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "200000\n", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000\n"}, 2.0),
    ({"/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "-1\n", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000\n"}, None),
    ({}, None),
])
def test_the_container_cpu_limit_is_read_from_cgroup_v2_or_v1(monkeypatch, files, limit):
    from types import SimpleNamespace

    from cremore import config

    def path(name):
        def read_text():
            if name not in files:
                raise FileNotFoundError(name)
            return files[name]
        return SimpleNamespace(read_text=read_text)

    monkeypatch.setattr(config, "Path", path)
    assert config._cgroup_cpus() == limit


def test_isolated_root_report_describes_configured_group_access_without_attesting_deployment():
    from cremore.secretstore.stored_locally import local_credentials, sealing_root

    settings = Settings(ISOLATED_DEPLOYMENT=True, SEALING_PUBLIC_KEYS_FILE="unread-public-file.json",
                        CONTROL_SEALING_KEY="ab" * 32, FINGERPRINT_KEY="cd" * 32)
    report = local_credentials(settings)
    assert sealing_root(settings) == report["sealing"]["root"] == "SCOPED_PUBLIC_KEY"
    assert report["sealing"]["held_here"] is False
    assert "DEPLOYMENT_PERMISSIONS_NOT_ATTESTED" in report["reasons"]
    assert "ab" * 32 not in str(report) and "cd" * 32 not in str(report)
