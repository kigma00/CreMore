"""Compatibility import; implementation lives in cremore_gcp_provider.source."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_gcp_provider.source")
