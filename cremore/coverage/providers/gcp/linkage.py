"""Compatibility alias for :mod:`cremore_gcp_provider.metadata.linkage`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_gcp_provider.metadata.linkage")
