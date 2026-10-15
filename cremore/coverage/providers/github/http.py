"""Compatibility alias for :mod:`cremore_github_provider.metadata.http`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_github_provider.metadata.http")
