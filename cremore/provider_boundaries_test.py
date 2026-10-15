"""Provider libraries stay usable without the platform runtime.

Ported during the three-way integration from the boundary checks of
refactor/saas-libraries to this repository's provider-directory layout. Here a
provider may import the platform's pure contracts (models, runtime, facts,
errors, the content framework), but importing or running a provider library
must not load the database layer, the API or worker runtime, the provider
registries, or another SaaS provider's SDK. Checks run in a fresh interpreter
because a module the test process already imported would hide an eager import.
"""

import ast
import importlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# The provider roots pytest puts on sys.path, read from pyproject.toml so a new provider is never missed.
VENDOR_PATHS = tuple(tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
                     ["tool"]["pytest"]["ini_options"]["pythonpath"])
# Loading any of these ties a provider library to the platform runtime.
PLATFORM_RUNTIME = ("sqlalchemy", "psycopg", "fastapi", "starlette", "uvicorn", "cremore.api", "cremore.db",
                    "cremore.worker", "cremore.coverage.store", "cremore.coverage.metadata_store",
                    "cremore.coverage.providers", "cremore.sources.registry")
# A SaaS SDK may only be loaded by the provider that owns it. Generic libraries (PyJWT, protobuf) are
# platform dependencies, so only the vendor SDK namespaces count.
SDK_OWNERS = {"boto3": "aws", "botocore": "aws", "google.auth": "gcp", "google.oauth2": "gcp",
              "google.cloud": "gcp", "googleapiclient": "gcp", "azure": "azure"}

PROVIDER_MODULES = (
    "cremore_aws_provider.source", "cremore_aws_provider.collectors.s3", "cremore_aws_provider.collectors.inventory",
    "cremore_aws_provider.coverage",
    "cremore_github_provider.source", "cremore_github_provider.collectors.github",
    "cremore_github_provider.metadata.adapter",
    "cremore_gitlab_provider.source", "cremore_gitlab_provider.content", "cremore_gitlab_provider.metadata.adapter",
    "cremore_gcp_provider.source", "cremore_gcp_provider.content", "cremore_gcp_provider.coverage",
    "cremore_gcp_provider.metadata.adapter",
    "cremore_notion_provider.source", "cremore_notion_provider.collectors.notion",
    "cremore_notion_provider.metadata.adapter",
    "cremore_atlassian_provider.confluence_source", "cremore_atlassian_provider.bitbucket_source",
    "cremore_atlassian_provider.confluence_content", "cremore_atlassian_provider.bitbucket_content",
    "cremore_atlassian_provider.metadata.adapter",
    "cremore_azure_provider.blob_source", "cremore_azure_provider.devops_source",
    "cremore_azure_provider.blob_content", "cremore_azure_provider.devops_content",
    "cremore_azure_provider.metadata.adapter", "cremore_azure_provider.entra.adapter",
    "cremore_azure_provider.arm.adapter", "cremore_azure_provider.devops_tokens.adapter",
    "cremore_vault_provider.coverage",
    # Identity collections for the departed-owner check (cremore.identity).
    "cremore_okta_provider.adapter", "cremore_keycloak_provider.adapter",
    "cremore_azure_provider.entra_id.adapter", "cremore_github_provider.identity.adapter",
    "cremore_gcp_provider.workspace.adapter",
    "cremore_slack_provider.metadata.adapter",
    # The connection wizard's descriptor, check and records per provider (cremore.onboarding).
    "cremore_github_provider.onboarding", "cremore_gitlab_provider.onboarding", "cremore_atlassian_provider.onboarding",
    "cremore_notion_provider.onboarding", "cremore_aws_provider.onboarding", "cremore_gcp_provider.onboarding",
    "cremore_gcp_provider.workspace.onboarding",
    "cremore_azure_provider.onboarding", "cremore_vault_provider.onboarding", "cremore_okta_provider.onboarding",
    "cremore_keycloak_provider.onboarding", "cremore_slack_provider.onboarding",
    # Approved actions on a provider's own credentials (cremore.remediation.provider_actions).
    "cremore_gcp_provider.remediation", "cremore_gitlab_provider.remediation", "cremore_notion_provider.remediation",
    "cremore_github_provider.remediation", "cremore_azure_provider.devops_tokens.remediation",
    # The external exposure scan of verified domains (docs/DOMAIN_VERIFICATION.md).
    "cremore_website_provider.source", "cremore_website_provider.collector", "cremore_website_provider.onboarding",
)

# The platform modules each provider library uses today. A new entry is a new
# coupling between a SaaS owner and the platform: review it, then add it here.
# collectors.changes (gcp, github, gitlab, notion, atlassian, azure): the pure answer a change feed
# or a queued notification gives (cremore.scanning.changes and triggers).
# onboarding.probe (gcp, gitlab, notion, atlassian, azure, vault): the wizard's bounded read-only
# permission probe (cremore.onboarding.check); it holds no state and loads nothing else.
PLATFORM_IMPORTS = {
    "aws": {"cremore.collectors.base", "cremore.collectors.credential_result", "cremore.coverage.aws_scheduling",
            "cremore.coverage.collection", "cremore.coverage.models", "cremore.coverage.store",
            "cremore.db.settings_store", "cremore.detection", "cremore.detection.fingerprint",
            "cremore.detection.verify", "cremore.domain.models", "cremore.http_client",
            "cremore.installation_settings",  # Shared lock/audit for investigation switches; no provider SQL or API import.
            "cremore.onboarding.targets",  # Shared v1/v2 target expansion; no provider-local copy.
            "cremore.remediation.action_plans", "cremore.risk.model", "cremore.scanning",
            "cremore.scanning.catalog_projection", "cremore.scanning.scope", "cremore.scanning.trigger_settings",
            "cremore.sources._collectors"},
    # identity.idp: the shared identity collector the Google Workspace directory runs on.
    "gcp": {"cremore.collectors.base", "cremore.collectors.changes", "cremore.collectors.content",
            "cremore.collectors.credential_result",
            "cremore.coverage.collection", "cremore.coverage.facts", "cremore.coverage.hasher",
            "cremore.coverage.metadata_models", "cremore.coverage.models", "cremore.http_client",
            "cremore.identity.idp",
            "cremore.onboarding.probe", "cremore.sources._collectors", "cremore.sources.validation"},
    # coverage.errors: the installation-check planner refuses other retries with CoverageError, as Atlassian's does.
    # identity.idp: the shared identity collector the SAML/SCIM directory runs on.
    "github": {"cremore.collectors.base", "cremore.collectors.changes", "cremore.collectors.credential_result",
               # Auth-first identity/root discovery reuses the same stateless bounded probe as other providers.
               "cremore.onboarding.probe",
               "cremore.coverage.errors",
               "cremore.coverage.facts", "cremore.identity.idp",
               "cremore.coverage.metadata_models", "cremore.coverage.models", "cremore.detection", "cremore.detection.safe_text",
               "cremore.http_client", "cremore.network_addresses", "cremore.scanning.catalog_projection", "cremore.scanning.scope",
               "cremore.sources._collectors"},
    "gitlab": {"cremore.collectors.base", "cremore.collectors.changes", "cremore.collectors.content",
               "cremore.collectors.credential_probe",
               "cremore.coverage.facts", "cremore.coverage.hasher", "cremore.coverage.metadata_models",
               # The bounded HTTP helper the token's self-rotation calls (token_rotation.py), as other providers do.
               "cremore.http_client",
               "cremore.onboarding.probe", "cremore.sources._collectors", "cremore.sources.validation"},
    "notion": {"cremore.collectors.base", "cremore.collectors.changes", "cremore.collectors.credential_result",
               "cremore.coverage.facts",
               "cremore.coverage.metadata_models", "cremore.coverage.models", "cremore.detection",
               "cremore.http_client", "cremore.onboarding.probe", "cremore.scanning.catalog_projection",
               "cremore.scanning.scope", "cremore.sources._collectors"},
    # coverage.facts: the departed-owner check reads a token's owner from its stored facts.
    # http_client, oauth_client: a Confluence service account's client credentials grant (cloud_api.py).
    # network_addresses: a Cloud attachment download that leaves the site goes only to a public address.
    "atlassian": {"cremore.collectors.base", "cremore.collectors.changes", "cremore.collectors.content",
                  "cremore.collectors.credential_probe",
                  "cremore.coverage.errors", "cremore.coverage.facts", "cremore.coverage.metadata_models",
                  "cremore.coverage.models", "cremore.http_client", "cremore.network_addresses", "cremore.oauth_client",
                  "cremore.onboarding.probe", "cremore.sources._collectors", "cremore.sources.validation"},
    "azure": {"cremore.collectors.base", "cremore.collectors.changes", "cremore.collectors.content",
              "cremore.collectors.credential_result",
              "cremore.coverage.facts", "cremore.coverage.hasher", "cremore.coverage.metadata_models",
              "cremore.identity.idp",
              "cremore.coverage.models", "cremore.detection.fingerprint", "cremore.detection.safe_text", "cremore.http_client",
              "cremore.onboarding.probe", "cremore.sources._collectors", "cremore.sources.validation"},
    "vault": {"cremore.coverage.collection", "cremore.coverage.models", "cremore.http_client",
              "cremore.onboarding.probe", "cremore.sources.validation"},
    # IdP user status: the shared identity collector and bounded HTTP; Keycloak's client credentials grant.
    # coverage.metadata_models: the wizard's check reads through the collection's own reader and spec.
    "okta": {"cremore.coverage.metadata_models", "cremore.http_client", "cremore.identity.idp"},
    "keycloak": {"cremore.coverage.metadata_models", "cremore.http_client", "cremore.identity.idp",
                 "cremore.oauth_client"},
    # Admin and audit log metadata: the shared fact writer, record models and bounded HTTP.
    "slack": {"cremore.coverage.facts", "cremore.coverage.metadata_models", "cremore.coverage.models",
              "cremore.http_client", "cremore.onboarding.probe"},
    # domains: what the scan may read is the company's verified domains (their names, and covering() at fetch).
    "website": {"cremore.collectors.base", "cremore.collectors.credential_result", "cremore.detection",
                "cremore.domains", "cremore.http_client", "cremore.network_addresses", "cremore.scanning.scope", "cremore.sources._collectors"},
}


def fresh(script, *args):
    """Run ``script`` in a new interpreter on this checkout; return sys.modules after it."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT)] + [str(ROOT / path) for path in VENDOR_PATHS]),
               AWS_EC2_METADATA_DISABLED="true")
    probe = script + "\nimport json, sys\nprint('\\n' + json.dumps(sorted(sys.modules)))\n"
    result = subprocess.run([sys.executable, "-B", "-c", probe, *args], cwd=ROOT, env=env, capture_output=True,
                            text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-4000:]
    return set(json.loads(result.stdout.strip().splitlines()[-1]))


def coupling(modules, owner):
    def hit(prefix):
        return any(name == prefix or name.startswith(prefix + ".") for name in modules)
    return ([prefix for prefix in PLATFORM_RUNTIME if hit(prefix)]
            + [sdk for sdk, sdk_owner in SDK_OWNERS.items() if sdk_owner != owner and hit(sdk)])


def owner_of(module):
    return re.match(r"cremore_(\w+?)_provider", module).group(1)


# --- one identity for moved contracts and compatibility paths ---------------------------------


def test_moved_contracts_keep_one_identity():
    from cremore.coverage import collector_runtime, errors, facts, store
    from cremore.coverage.providers import facts as legacy_facts

    assert store.CoverageError is errors.CoverageError is collector_runtime.CoverageError
    assert legacy_facts is facts
    assert legacy_facts.FactWriter is facts.FactWriter


def compatibility_aliases():
    for path in sorted((ROOT / "cremore").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        match = re.search(r"_?sys\.modules\[__name__\]\s*=\s*(?:importlib\.)?_?import_module\(([\"'])([\w.]+)\1\)",
                          source)
        if match:
            module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
            yield module.removesuffix(".__init__"), match.group(2)


def test_every_compatibility_path_resolves_to_its_provider_module():
    aliases = list(compatibility_aliases())
    assert len(aliases) > 100  # the inventory itself must not silently vanish
    for legacy, target in aliases:
        assert importlib.import_module(legacy) is importlib.import_module(target), (legacy, target)


# --- import boundaries -------------------------------------------------------------------------


@pytest.mark.parametrize("module", PROVIDER_MODULES)
def test_provider_modules_import_without_the_platform_runtime(module):
    loaded = fresh("import importlib, sys\nimportlib.import_module(sys.argv[1])", module)
    assert not coupling(loaded, owner_of(module)), (module, coupling(loaded, owner_of(module)))


@pytest.mark.parametrize("module", ["cremore.coverage.providers", "cremore.sources.registry",
                                    "cremore.coverage.collector_runtime"])
def test_registries_and_the_runtime_contract_do_not_load_the_database(module):
    loaded = fresh("import importlib, sys\nimportlib.import_module(sys.argv[1])", module)
    assert not {"sqlalchemy", "psycopg", "cremore.db", "cremore.coverage.store"} & {
        name.split(".")[0] if name.startswith(("sqlalchemy", "psycopg")) else name for name in loaded}


def test_every_provider_library_is_covered():
    # A new <vendor>/backend must get an allowlist entry and at least one boundary-checked module.
    vendors = {path.parent.name for path in ROOT.glob("*/backend")}
    assert set(PLATFORM_IMPORTS) == vendors
    assert {owner_of(module) for module in PROVIDER_MODULES} == vendors


def _imported_names(tree):
    """Module names a file imports: import statements plus constant import_module/__import__ calls."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            yield node.module
        elif (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", ""))
              in ("import_module", "__import__") and node.args and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)):
            yield node.args[0].value


def _provider_sources(vendor):
    for path in (ROOT / vendor / "backend").rglob("*.py"):
        parts = set(path.relative_to(ROOT).parts)  # relative, so a checkout under .../qa/ still counts
        if not (path.name.endswith("_test.py") or path.name.startswith("test_") or {"tests", "qa"} & parts):
            yield path, ast.parse(path.read_text(encoding="utf-8"))


def test_provider_libraries_use_only_their_reviewed_platform_modules():
    used = {}
    for vendor in PLATFORM_IMPORTS:
        for _path, tree in _provider_sources(vendor):
            used.setdefault(vendor, set()).update(name for name in _imported_names(tree)
                                                  if name == "cremore" or name.startswith("cremore."))
    for vendor, modules in used.items():
        assert modules <= PLATFORM_IMPORTS[vendor], (vendor, sorted(modules - PLATFORM_IMPORTS[vendor]))


def test_provider_libraries_do_not_import_each_other():
    """Review 2026-09-26: a provider must not depend on another provider's package, statically or
    through a constant dynamic import. GCP's own shared library (cremore_gcp) is its package."""
    crossing = []
    for vendor in PLATFORM_IMPORTS:
        own = (f"cremore_{vendor}_provider", "cremore_gcp") if vendor == "gcp" else (f"cremore_{vendor}_provider",)
        for path, tree in _provider_sources(vendor):
            crossing += [(str(path.relative_to(ROOT)), name) for name in _imported_names(tree)
                         if name.startswith("cremore_")
                         and not any(name == package or name.startswith(package + ".") for package in own)]
    assert not crossing, crossing


# Provider-folder modules that import the DB, API or worker layer when they are imported. They are
# platform code living in a provider folder: a change needs platform review (AGENTS.md, AWS section).
REVIEWED_DB_MODULES = {"aws/backend/cremore_aws_provider/inventory_view.py": {"cremore.coverage.store"}}
DB_LAYERS = ("sqlalchemy", "psycopg", "cremore.db", "cremore.coverage.store", "cremore.coverage.metadata_store",
             "cremore.api", "cremore.worker")


def _import_time_names(node):
    """Modules a file imports while it is being imported: everything outside function bodies."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(child, (ast.Import, ast.ImportFrom, ast.Call)):
            yield from _imported_names(child)
        yield from _import_time_names(child)


def test_provider_modules_that_load_the_database_at_import_are_reviewed():
    """Second review 2026-09-26: everything else imports those layers lazily, inside functions."""
    found = {}
    for vendor in PLATFORM_IMPORTS:
        for path, tree in _provider_sources(vendor):
            names = {name for name in _import_time_names(tree)
                     if any(name == layer or name.startswith(layer + ".") for layer in DB_LAYERS)}
            if names:
                found[path.relative_to(ROOT).as_posix()] = names
    assert found == REVIEWED_DB_MODULES


def test_platform_entry_points_import_without_optional_provider_sdks():
    """Review 2026-09-26: the content registry imports every provider's source module, and the
    DB, API and worker import the registry, so one provider's top-level import of an optional SDK
    (the [gcp]/[azure] extras) would stop every platform process where it is not installed."""
    loaded = fresh("""import importlib, importlib.abc, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] == "google" and name != "google" or name.startswith("azure.identity"):
            raise ImportError("optional SDK blocked: " + name)
sys.meta_path.insert(0, Block())
for target in ("cremore.sources.registry", "cremore.coverage.providers", "cremore.db", "cremore.api.app",
               "cremore.worker.worker"):
    importlib.import_module(target)""")
    assert "cremore.api.app" in loaded and "cremore.worker.worker" in loaded


# --- offline collections run without the platform runtime ----------------------------------------

COLLECTIONS = {
    "gitlab": """
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_gitlab_provider.metadata import adapter
from cremore_gitlab_provider.metadata.http import Client, Response
from urllib.parse import urlsplit
class OfflineClient(Client):
    requests = retries = 0
    def request(self, url, query=None, variables=None):
        path = urlsplit(self.checked_url(url)).path.removeprefix('/api/v4')
        bodies = {'/user': {'id': 1}, '/personal_access_tokens': [{'id': 101}],
                  '/personal_access_tokens/101': {'id': 101}}
        self.requests += 1
        return Response(bodies[path], {'x-next-page': ''})
spec = MetadataConnectionSpec(name='offline', provider='gitlab', origin='https://gitlab.com',
    scopes=[{'kind': 'user', 'id': 'self'}], capabilities=['inventory'],
    secret_refs={'token': 'vault://synthetic/gitlab'}, options={'enrich_users': False})
pages = list(adapter.collect_pages(spec, secrets={'token': 'SYNTHETIC_OPERATOR_AUTH'}, checkpoint={},
    check=lambda: None, client=OfflineClient(adapter._config(spec), 'SYNTHETIC_AUTH')))
assert pages[-1].status == 'COMPLETE' and any(p.records for p in pages)
""",
    "github": """
from datetime import UTC, datetime
from unittest.mock import patch
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.tests import fake
for enterprise in (False, True):
    spec = fake.enterprise_spec() if enterprise else fake.spec()
    responses = fake.enterprise_responses() if enterprise else fake.org_responses()
    client = fake.FakeTransport(responses, enterprise=fake.ENTERPRISE if enterprise else '')
    state, committed = {}, []
    with patch('cremore_github_provider.metadata.export_http.download', client.download):
        for attempt in range(3):
            pages = list(adapter.collect_pages(spec, secrets=fake.SECRETS, checkpoint=state, check=lambda: None,
                transport=client, broker=fake.FakeBroker(), now=lambda: datetime(2026, 3, 5, tzinfo=UTC),
                read_records=lambda: iter(committed)))
            committed.extend(item.model_dump() for page in pages for item in page.records)
            state = pages[-1].checkpoint
            if pages[-1].status != 'WAITING':
                break
    # The synthetic enterprise fixture lacks some inventory metadata, so PARTIAL is expected there.
    assert pages[-1].status in ('COMPLETE', 'PARTIAL') and client.calls
""",
    "gcp": """
from datetime import UTC, datetime
from types import SimpleNamespace
from cremore_gcp_provider.metadata import adapter
from cremore_gcp_provider.metadata.tests import fake
class Results(list):
    complete = True
class Engine:
    config = SimpleNamespace(fingerprint_key=b'k' * 32)
    calls = 0
    def scan(self, item):
        self.calls += 1
        return Results()
engine = Engine()
spec = fake.spec(capabilities=['inventory', 'vault_metadata', 'issuer_value'],
                 options={'locations': ['europe-west4'], 'include_values': True})
responses = fake.inventory_responses()
responses[f'https://apikeys.googleapis.com/v2/{fake.API_KEY_NAME}/keyString'] = {'keyString': 'synthetic-value-only'}
pages = list(adapter.collect_pages(spec, secrets={}, checkpoint={}, check=lambda: None,
    transport=fake.FakeTransport(responses), now=datetime(2026, 9, 23, tzinfo=UTC), value_context={
        'engine': engine, 'key_id': 'a' * 64, 'engine_digest': 'b' * 64, 'policy_digest': 'c' * 64}))
assert pages[-1].status in ('COMPLETE', 'PARTIAL') and engine.calls
""",
    "azure": """
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_azure_provider.metadata import adapter
spec = MetadataConnectionSpec(name='offline', provider='azure_key_vault', origin='https://acme-prod.vault.azure.net',
    edition='cloud', scopes=[{'kind': 'vault', 'id': 'acme-prod'}], capabilities=['vault_metadata'],
    auth_type='workload_identity')
class Transport:
    requests = 0
    options = spec.options
    def get(self, path, params=None):
        return ({'value': [{'id': spec.origin + '/secrets/example', 'attributes': {'enabled': True}}]}
                if path == '/secrets' else {'value': []})
pages = list(adapter.collect_pages(spec, secrets={}, checkpoint={}, check=lambda: None, transport=Transport()))
assert any(r.record_type == 'entity_observation' for p in pages for r in p.records)
""",
    "atlassian": """
import io, json
from unittest.mock import Mock
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_atlassian_provider.metadata import adapter
from cremore_atlassian_provider.metadata.bitbucket import BitbucketClient
from cremore_atlassian_provider.metadata.http import CloudClient
class Response(io.BytesIO):
    code = status = 200
    headers = {}
    def __init__(self):
        super().__init__(json.dumps({'data': [], 'values': [], 'items': [], 'links': {}}).encode())
    def getcode(self):
        return self.status
for mode in ('inventory', 'bitbucket'):
    cloud = mode == 'inventory'
    spec = MetadataConnectionSpec(name='offline', provider='atlassian' if cloud else 'bitbucket',
        origin='https://api.atlassian.com' if cloud else 'https://api.bitbucket.org',
        scopes=[{'kind': 'organization' if cloud else 'workspace',
                 'id': '00000000-0000-0000-0000-000000000009' if cloud else 'example-workspace'}],
        capabilities=['inventory'], secret_refs={'token': 'vault://synthetic/token'},
        options={'mode': mode, 'max_retries': 0}, max_requests=200)
    opener = Mock()
    opener.open.side_effect = lambda *a, **k: Response()
    def factory(config, scope, secrets, limits, check, cloud=cloud, opener=opener):
        return (CloudClient if cloud else BitbucketClient)(scope.id, secrets['token'], limits, opener=opener, check=check)
    pages = list(adapter.collect_pages(spec, secrets={'token': 'SYNTHETIC_OPERATOR_AUTH'}, checkpoint={},
        check=lambda: None, read_records=lambda: iter(()), client_factory=factory,
        now=lambda: '2026-09-24T00:00:00+00:00'))
    assert opener.open.called and any(p.records for p in pages)
""",
    "gitlab-content": """
import httpx
from cremore_gitlab_provider import content
def answer(request):
    route = request.url.path
    if route.endswith('/projects/7'):
        return httpx.Response(200, json={'path_with_namespace': 'team/example'})
    if '/commits/' in route:
        return httpx.Response(200, json={'id': 'a' * 40})
    if route.endswith('/repository/tree'):
        return httpx.Response(200, json=[{'type': 'blob', 'path': 'src/example.txt', 'id': 'b' * 40}])
    return httpx.Response(200, content=b'Synthetic example content.')
payload = {'base_url': 'https://gitlab.example.test', 'project': '7', 'token': 'synthetic', 'paths': ['src']}
with httpx.Client(transport=httpx.MockTransport(answer), trust_env=False) as client:
    objects = list(content.build(payload, client).collect())
assert [o.read() for o in objects] == [b'Synthetic example content.']
""",
}


@pytest.mark.parametrize("name", sorted(COLLECTIONS))
def test_offline_collections_run_without_the_platform_runtime(name):
    loaded = fresh(COLLECTIONS[name])
    owner = name.split("-")[0]
    assert not coupling(loaded, owner), (name, coupling(loaded, owner))
