"""Check that an installed cremore wheel works without the source checkout.

Three-way integration step PR-6: refactor/saas-libraries verified its wheel with
validation_tools/refactor_installed_check.py; this is that check for this
repository's ten wheel packages. Run it with the installed environment's
interpreter in isolated mode (-I keeps the script directory, the working
directory and PYTHONPATH off sys.path), so no source file can hide a broken wheel:

    python -m pip install dist/cremore-*.whl        (a fresh venv: python -m venv --clear ...)
    python -I scripts/installed_check.py --source .

``--source`` is only read, to compare the packaged files with the checkout;
nothing is imported from it. No provider is contacted. The CI run on a fresh
checkout is authoritative; the file comparison mirrors hatchling (the root
.gitignore only), so machine-local ignore rules do not affect it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from importlib import import_module, metadata
from pathlib import Path

ENTRY_POINTS = {"cremore-api", "cremore-worker", "cremore-coverage", "cremore-siem",
                "cremore-token-refresher"}
ALIAS = re.compile(r"_?sys\.modules\[__name__\]\s*=\s*(?:importlib\.)?_?import_module\(([\"'])([\w.]+)\1\)")
# Importing the adapter registry and every adapter must not pull in the DB layer (PR-2 boundary).
BOUNDARY = """import sys
from importlib import import_module
from cremore.coverage import providers
for registration in providers._ADAPTERS.values():
    import_module(registration.module)
assert not [n for n in sys.modules if n.split('.')[0] in ('sqlalchemy', 'psycopg') or n.startswith('cremore.db')]
"""


def installed(module) -> Path:
    path = Path(module.__file__).resolve()
    assert path.is_relative_to(Path(sys.prefix).resolve()), f"{module.__name__} loads from {path}, not the wheel"
    return path


def wheel_packages(root: Path) -> dict[str, str]:
    """Import name -> source directory, from [tool.hatch.build.targets.wheel] packages in pyproject.toml."""
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return {Path(path).name: path for path in config["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]}


def packaged_files(root: Path, relative: str) -> dict[str, str]:
    """The files hatchling packages: tracked or untracked files not ignored by the root .gitignore.

    Hatchling reads only the root .gitignore, so nested .gitignore files, .git/info/exclude and a global
    excludes file are deliberately not applied. -z keeps non-ASCII file names unquoted.
    """
    names = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "-co", f"--exclude-from={root / '.gitignore'}",
                            "--", relative], capture_output=True, text=True, encoding="utf-8",
                           check=True).stdout.split("\0")
    return {Path(name).relative_to(relative).as_posix(): hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in names if name and (root / name).is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, required=True, help="checkout the wheel was built from (read only)")
    parser.add_argument("--output", type=Path, help="write a JSON summary here")
    args = parser.parse_args()
    source = args.source.resolve()
    # -I keeps the script directory and PYTHONPATH off sys.path; each check below also asserts that the
    # module it uses loads from this environment's prefix, not from the checkout. The checks are assert
    # statements, so -O would silently skip them.
    if not sys.flags.isolated or sys.flags.optimize:
        raise SystemExit("run with python -I and without -O")
    packages = wheel_packages(source)

    # 1. Every package loads from the wheel and ships exactly the checkout's files.
    for name, relative in packages.items():
        package = installed(import_module(name)).parent
        shipped = {path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in package.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
        expected = packaged_files(source, relative)
        missing, extra = sorted(set(expected) - set(shipped)), sorted(set(shipped) - set(expected))
        changed = sorted(key for key in set(expected) & set(shipped) if expected[key] != shipped[key])
        assert not missing and not extra and not changed, (name, missing[:10], extra[:10], changed[:10])

    # 2. Both registries resolve every provider to installed modules.
    from cremore.coverage.providers import _ADAPTERS, collector_for
    from cremore.sources.registry import PROVIDERS

    for provider, registration in _ADAPTERS.items():
        assert collector_for(provider).adapter is import_module(registration.module)
        installed(import_module(registration.module))
    for module in PROVIDERS.values():
        installed(module)

    # 3. Moved contracts keep one identity, and every compatibility path is its provider module.
    from cremore.coverage import collector_runtime, errors, facts, store
    from cremore.coverage.providers import facts as legacy_facts

    assert store.CoverageError is errors.CoverageError is collector_runtime.CoverageError
    assert legacy_facts is facts
    aliases = []
    platform = installed(import_module("cremore")).parent
    for path in sorted(platform.rglob("*.py")):
        match = ALIAS.search(path.read_text(encoding="utf-8"))
        if match:
            legacy = ".".join(("cremore", *path.relative_to(platform).with_suffix("").parts)).removesuffix(".__init__")
            assert import_module(legacy) is import_module(match.group(2)), (legacy, match.group(2))
            installed(import_module(match.group(2)))
            aliases.append(legacy)
    assert len(aliases) > 100, len(aliases)

    # 4. The installed registry and adapters keep the DB layer out (fresh isolated interpreter).
    subprocess.run([sys.executable, "-I", "-c", BOUNDARY], check=True, cwd=sys.prefix)

    # 5. GitLab code provenance hashes the installed files it ships.
    from cremore_gitlab_provider.metadata.provenance import code_provenance

    provenance = code_provenance()
    gitlab = installed(import_module("cremore_gitlab_provider.metadata")).parent
    assert provenance["code_root"] == str(gitlab.parent)
    assert provenance["source_files_sha256"] == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(gitlab.glob("*.py"))}

    # 6. Console entry points load.
    entries = {entry.name: entry for entry in metadata.distribution("cremore").entry_points
               if entry.group == "console_scripts"}
    assert set(entries) == ENTRY_POINTS, sorted(entries)
    assert all(callable(entry.load()) for entry in entries.values())

    # 7. One synthetic PAT proves offline collection from the wheel, without shipped demo data.
    from cremore_gitlab_provider.metadata import adapter
    from cremore_gitlab_provider.metadata.http import Client, Response

    from cremore.coverage.metadata_models import MetadataConnectionSpec

    spec = MetadataConnectionSpec(name="installed-check", provider="gitlab", origin="https://gitlab.com",
                                  scopes=[{"kind": "user", "id": "self"}], capabilities=["inventory"],
                                  secret_refs={"token": "vault://synthetic/gitlab"},
                                  options={"enrich_users": False})
    class OfflineClient(Client):
        requests = retries = 0

        def request(self, url, query=None, variables=None):
            from urllib.parse import urlsplit
            path = urlsplit(self.checked_url(url)).path.removeprefix("/api/v4")
            bodies = {"/user": {"id": 1}, "/personal_access_tokens": [{"id": 101}],
                      "/personal_access_tokens/101": {"id": 101}}
            self.requests += 1
            return Response(bodies[path], {"x-next-page": ""})

    pages = list(adapter.collect_pages(spec, secrets={"token": "SYNTHETIC_OPERATOR_AUTH"}, checkpoint={},
                                       check=lambda: None,
                                       client=OfflineClient(adapter._config(spec), "SYNTHETIC_AUTH")))
    assert pages[-1].status == "COMPLETE" and any(page.records for page in pages)

    summary = {"prefix": sys.prefix, "packages": sorted(packages), "metadata_adapters": sorted(_ADAPTERS),
               "content_sources": sorted(PROVIDERS), "compatibility_paths": len(aliases),
               "entry_points": sorted(entries), "offline_collection_pages": len(pages)}
    if args.output:
        args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("installed wheel check passed:", json.dumps(summary))


if __name__ == "__main__":
    main()
