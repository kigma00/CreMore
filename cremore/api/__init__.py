"""HTTP API and reusable API libraries (FastAPI, Apache-2.0).

Importing a library does not load the application composition root. The
historical ``from cremore.api import create_app`` entry point remains available
and returns the original factory, including its signature.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cremore.api.app import create_app as create_app

__all__ = ["create_app"]


def __getattr__(name: str):
    if name == "create_app":
        from cremore.api.app import create_app

        globals()[name] = create_app
        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
