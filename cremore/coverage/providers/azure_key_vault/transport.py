"""Compatibility alias for :mod:`cremore_azure_provider.metadata.transport`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore_azure_provider.metadata.transport")
