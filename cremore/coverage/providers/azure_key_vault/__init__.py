"""Compatibility package for :mod:`cremore_azure_provider.metadata`."""

from importlib import import_module as _import_module

_native = _import_module("cremore_azure_provider.metadata")


def __getattr__(name):
    if name == "__all__":
        return [key for key in vars(_native) if not key.startswith("_")]
    return getattr(_native, name)


def __dir__():
    return sorted(set(globals()) | set(dir(_native)))
