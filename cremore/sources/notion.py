"""Compatibility import; implementation lives in cremore_notion_provider.source."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_notion_provider.source")
