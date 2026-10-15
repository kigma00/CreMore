"""Compatibility alias for :mod:`cremore_atlassian_provider.metadata.collector`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_atlassian_provider.metadata.collector")
