"""HTTP API and reusable API libraries (FastAPI, Apache-2.0).

Importing a library does not load the application composition root. The
``from cremore.api import create_app`` returns the application factory from main.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cremore.main import create_app as create_app

__all__ = ["create_app"]


def __getattr__(name: str):
    if name == "create_app":
        from cremore.main import create_app

        globals()[name] = create_app
        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
