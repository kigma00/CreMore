"""A sign-in's address, kept per subject in each repository (cremore.governance.principals)."""

from __future__ import annotations

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.governance import principals

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)


def test_a_repository_that_gets_a_freed_ones_address_still_gets_the_mark(monkeypatch):
    # CPython hands a freed object's address to a new one: a repository whose id() equals an earlier one's must not
    # inherit "already written" and go without the subject's mark. Every object shares one id here to make it certain.
    monkeypatch.setattr(principals, "id", lambda obj: 1, raising=False)
    first, second = InMemoryRepository(), InMemoryRepository()
    principals.remember(first, SETTINGS, "sub-rita", "rita@example.com")
    principals.remember(second, SETTINGS, "sub-rita", "rita@example.com")
    assert principals.marks(second, ["sub-rita"]) == {"sub-rita": principals.mark(SETTINGS, "rita@example.com")}


def test_the_same_repository_is_written_once_and_again_when_the_address_changes():
    repo = InMemoryRepository()
    writes = []
    original = repo.put_setting
    repo.put_setting = lambda key, value, actor: (writes.append(key), original(key, value, actor))[1]
    principals.remember(repo, SETTINGS, "sub-kim", "kim@example.com")
    principals.remember(repo, SETTINGS, "sub-kim", "kim@example.com")
    principals.remember(repo, SETTINGS, "sub-kim", "kim.new@example.com")
    assert len(writes) == 2
