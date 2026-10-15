"""Compatibility import; implementation lives in cremore_github_provider.github_hosts."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_github_provider.github_hosts")
