"""Compatibility import; implementation lives in cremore_aws_provider.collectors.s3."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_aws_provider.collectors.s3")
