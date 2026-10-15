"""Compatibility alias for :mod:`cremore_atlassian_provider.metadata.bitbucket`."""

import sys
from importlib import import_module

if __name__ == "__main__":
    from runpy import run_module

    run_module("cremore_atlassian_provider.metadata.bitbucket", run_name="__main__")
else:
    sys.modules[__name__] = import_module("cremore_atlassian_provider.metadata.bitbucket")
