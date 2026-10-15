"""Compatibility import; implementation lives in cremore_gitlab_provider.source."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_gitlab_provider.source")
