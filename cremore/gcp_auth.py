"""Compatibility import; implementation lives in cremore_gcp_provider.gcp_auth."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_gcp_provider.gcp_auth")
