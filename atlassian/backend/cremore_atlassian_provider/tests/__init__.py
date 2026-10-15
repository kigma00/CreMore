"""Synthetic Atlassian regression and integration contracts."""

import os
import unittest

# The preserved native CLI stores private artifacts with POSIX-only guards:
# O_DIRECTORY, O_NOFOLLOW, mode 0700 and st_uid. Windows has no equivalent, so
# those QA paths are skipped there rather than relaxing the guard. The product
# adapter writes through the shared database and is covered on every platform
# by test_common_adapter.py.
posix_native_io = unittest.skipUnless(
    os.name == "posix", "Native CLI private-file QA requires POSIX O_NOFOLLOW and uid checks"
)
