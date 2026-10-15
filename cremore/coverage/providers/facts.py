"""Compatibility alias: the fact helpers live in :mod:`cremore.coverage.facts`.

Importing this path still runs the provider registry package; new code imports
``cremore.coverage.facts`` so a provider library stays free of the registry.
"""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("cremore.coverage.facts")
