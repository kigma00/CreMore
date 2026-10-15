"""Native credential detection engine (Apache-2.0).

Written from public encoding specifications and provider documentation; every
detector records the provider document it was written from in
``CatalogEntry.source_url``.
"""

from typing import TYPE_CHECKING

from cremore.detection.models import (
    CatalogEntry,
    DetectorInput,
    ResourceRef,
    SanitizedDetection,
)

if TYPE_CHECKING:
    from cremore.detection.engine import Engine as Engine
    from cremore.detection.engine import EngineConfig as EngineConfig

__all__ = [
    "CatalogEntry",
    "DetectorInput",
    "Engine",
    "EngineConfig",
    "ResourceRef",
    "SanitizedDetection",
]

NAME = "cremore-native"
VERSION = "0.1.0"


def __getattr__(name: str):
    # Pure helpers must not load the engine that imports their provider callers.
    if name in {"Engine", "EngineConfig"}:
        from cremore.detection.engine import Engine, EngineConfig

        globals().update(Engine=Engine, EngineConfig=EngineConfig)
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
