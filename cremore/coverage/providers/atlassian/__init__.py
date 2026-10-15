"""Compatibility package for :mod:`cremore_atlassian_provider.metadata`."""

from importlib import import_module as _import_module

_native = _import_module("cremore_atlassian_provider.metadata")


def __getattr__(name):
    return getattr(_native, name)


def __dir__():
    return sorted(set(globals()) | set(dir(_native)))
