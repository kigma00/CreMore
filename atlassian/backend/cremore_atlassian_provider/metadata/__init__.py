# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/__init__.py).
"""Read-only Atlassian Cloud credential metadata collection."""

__all__ = ["CloudClient", "Limits", "collect"]


def __getattr__(name):
    # Descriptor imports need no HTTP/collector modules. Keep the existing
    # public objects available lazily, without wrapping their implementation.
    if name == "collect":
        from .collector import collect

        value = collect
    elif name in {"CloudClient", "Limits"}:
        from . import http

        value = getattr(http, name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value
