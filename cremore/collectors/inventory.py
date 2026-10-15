"""Compatibility import; implementation lives in cremore_aws_provider.collectors.inventory."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_aws_provider.collectors.inventory")
