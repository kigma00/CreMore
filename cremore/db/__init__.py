"""Persistence layer (Apache-2.0).

The orchestration and API depend only on the :class:`Repository` protocol, so
the same logic runs against the in-memory store used in tests and the
SQLAlchemy/Postgres store used in production.
"""

from cremore.db.repository import InMemoryRepository, Repository

__all__ = ["InMemoryRepository", "Repository"]
