"""Compatibility alias for :mod:`cremore_atlassian_provider.metadata.qa.bitbucket_connection`."""

import sys
from importlib import import_module

if not __package__:
    from pathlib import Path

    _root = Path(__file__).resolve().parents[5]
    sys.path[:0] = [str(_root), str(_root / "atlassian" / "backend")]

sys.modules[__name__] = import_module("cremore_atlassian_provider.metadata.qa.bitbucket_connection")
