"""The coverage error type, importable without the database layer.

Moved unchanged from ``cremore.coverage.store`` during the three-way integration
(the boundary rule of refactor/saas-libraries): store.py imports SQLAlchemy, so
every provider library and the collector runtime that raised or caught this
error loaded the whole DB layer on import. ``store.CoverageError`` re-exports
this class, so both import paths name the same object.
"""


class CoverageError(ValueError):
    pass
