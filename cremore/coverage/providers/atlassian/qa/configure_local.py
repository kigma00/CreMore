"""Compatibility alias for :mod:`cremore_atlassian_provider.metadata.qa.configure_local`."""

import sys
from importlib import import_module

if not __package__:
    from pathlib import Path

    _root = Path(__file__).resolve().parents[5]
    sys.path[:0] = [str(_root), str(_root / "atlassian" / "backend")]

if __name__ == "__main__":
    from runpy import run_module

    run_module("cremore_atlassian_provider.metadata.qa.configure_local", run_name="__main__")
else:
    sys.modules[__name__] = import_module("cremore_atlassian_provider.metadata.qa.configure_local")
