"""Compatibility import for cremore_aws_provider.kms."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("cremore_aws_provider.kms")
