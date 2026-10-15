"""Compatibility import; implementation lives in cremore_atlassian_provider.bitbucket_source."""

import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_atlassian_provider.bitbucket_source")
