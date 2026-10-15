"""Compatibility import; implementation lives in cremore_github_provider.collectors.github."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_github_provider.collectors.github")
