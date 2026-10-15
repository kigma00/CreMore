"""Compatibility alias for cremore_aws_provider.aws_access."""

import sys as _sys
from importlib import import_module as _import_module

_sys.modules[__name__] = _import_module('cremore_aws_provider.aws_access')
