"""Locked settings updates using the existing repository transaction boundary."""

from contextlib import contextmanager

from sqlalchemy import select

from cremore.coverage.store import CoverageStore
from cremore.db.task_store import TaskStore


@contextmanager
def locked_settings(repo, *, account_id=None, setting_key=None):
    """Yield a bound repository while holding one existing parent row's lock.

    The account or settings parent must already exist. Its lock also serializes
    the first write of child settings that have no row of their own yet.
    Memory uses its repository lock; SQLite retains BEGIN IMMEDIATE.
    """
    if (account_id is None) == (setting_key is None):
        raise ValueError("Exactly one settings lock parent is required")
    with CoverageStore(repo).transaction() as conn:
        bound = TaskStore(repo)._bound(conn)
        if conn is not None:
            from cremore.db.schema import aws_accounts, installation_settings

            query = (select(aws_accounts.c.id).where(aws_accounts.c.account_id == account_id)
                     if account_id is not None else
                     select(installation_settings.c.key).where(installation_settings.c.key == setting_key))
            conn.execute(query.with_for_update()).all()
        yield bound
