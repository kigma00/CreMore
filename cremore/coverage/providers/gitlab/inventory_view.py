"""Compatibility alias for :mod:`cremore_gitlab_provider.metadata.inventory_view`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_gitlab_provider.metadata.inventory_view")
