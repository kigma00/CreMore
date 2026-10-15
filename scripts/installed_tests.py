"""Run provider and platform tests from an installed wheel, outside the checkout.

Second review 2026-09-26, item 2: refactor/saas-libraries ran its tests against the
installed wheel (validation_tools/refactor_installed_suite.py); this does the same for
this repository. Run it with the installed environment's interpreter after
``scripts/installed_check.py``:

    python -I -X utf8 scripts/installed_tests.py

``-X utf8`` keeps file reads UTF-8 even where ``python -I`` ignores PYTHONUTF8. Tests are
collected with ``--pyargs`` from the installed packages; the working directory is a
fresh temporary directory, so no source file can stand in for the wheel. Tests that
read repository files the wheel does not ship are deselected by name (NEEDS_CHECKOUT);
they still run in the ordinary suite.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

MODULES = (
    # Platform contracts that every provider library is held to.
    "cremore.worker.content_contract_test", "cremore.coverage.collector_runtime_test",
    "cremore.coverage.metadata_job_test",
    # Every provider library's own tests.
    "cremore_aws_provider", "cremore_gcp_provider", "cremore_github_provider", "cremore_gitlab_provider",
    "cremore_notion_provider", "cremore_atlassian_provider", "cremore_azure_provider", "cremore_vault_provider",
)
# They read CloudFormation templates under deploy/ or scan the worker source in the checkout.
NEEDS_CHECKOUT = (
    "test_direct_role_trust_accepts_only_an_exact_iam_principal",
    "test_the_permission_set_policy_matches_what_the_member_role_may_do",
    "test_unconditional_scanner_deny_covers_mutations_without_disabling_required_reads",
    "test_single_account_is_the_default_and_still_asserts_the_account_match",
    "test_organization_mode_skips_the_account_match_but_requires_the_org_id",
    "test_aws_clients_are_built_only_in_reviewed_places",
    "test_every_read_is_allowed_for_the_scanner_and_granted_by_the_templates",
    "test_the_worker_actually_wires_that_wrapper",
)


def main() -> int:
    if not sys.flags.isolated or not sys.flags.utf8_mode:
        raise SystemExit("run with python -I -X utf8")
    import cremore

    if not Path(cremore.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
        raise SystemExit(f"cremore loads from {cremore.__file__}, not this environment's wheel")
    env = dict(os.environ, AWS_EC2_METADATA_DISABLED="true")
    with tempfile.TemporaryDirectory() as workdir:
        return subprocess.run([sys.executable, "-I", "-X", "utf8", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                               "--pyargs", *MODULES, "-k", "not (" + " or ".join(NEEDS_CHECKOUT) + ")"],
                              cwd=workdir, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
