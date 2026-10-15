"""Compatibility import; implementation lives in cremore_vault_provider.secretstore."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_vault_provider.secretstore")
