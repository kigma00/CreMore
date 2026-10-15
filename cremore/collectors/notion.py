"""Compatibility import; implementation lives in cremore_notion_provider.collectors.notion."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_notion_provider.collectors.notion")
