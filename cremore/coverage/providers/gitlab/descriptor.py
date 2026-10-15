"""Compatibility alias for :mod:`cremore_gitlab_provider.metadata.descriptor`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_gitlab_provider.metadata.descriptor")
