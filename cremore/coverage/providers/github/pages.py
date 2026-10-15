"""Compatibility alias for :mod:`cremore_github_provider.metadata.pages`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_github_provider.metadata.pages")
