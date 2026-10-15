"""Compatibility import for cremore_aws_provider.worker_session."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_aws_provider.worker_session")
