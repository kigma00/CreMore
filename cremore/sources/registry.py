"""Explicit built-in source modules; importing contracts performs no runtime I/O."""

import cremore_aws_provider.source as aws
import cremore_github_provider.source as github
import cremore_notion_provider.source as notion

# Preserve the public source/job ordering separately from capability display order.
PROVIDERS = {module.PROVIDER: module for module in (aws, github, notion)}
PROVIDER_FAMILIES = {name: getattr(module, "FAMILY", name) for name, module in PROVIDERS.items()}
BY_SOURCE = {module.SOURCE_TYPE: module for module in PROVIDERS.values()}
BY_JOB_KIND = {kind: module for module in PROVIDERS.values() for kind in module.JOB_KINDS}
BY_RESOURCE_TYPE = {kind: module for module in PROVIDERS.values() for kind in module.RESOURCE_TYPES}
_EXACT_FIELD = {"object": "exact_keys", "path": "exact_paths", "page": "exact_page_ids"}
EXACT_FIELDS = {kind: _EXACT_FIELD[module.SCOPE_KIND] for kind, module in BY_RESOURCE_TYPE.items()}
SOURCE_CAPABILITIES = [module.CAPABILITY for module in sorted(PROVIDERS.values(), key=lambda module: module.CAPABILITY_ORDER)]
SOURCE_TYPES = list(BY_SOURCE)
CONTENT_SCAN_KINDS = (*BY_JOB_KIND, "scope", "inline")
STRUCTURED_PROVIDERS = tuple(module.PROVIDER for module in PROVIDERS.values() if module.STRUCTURED_CONFIG)
# Sources whose resource names repeat across installations; the instance is part of the location.
# Integration: each source module declares INSTANCE_SCOPED, replacing the literal in cremore.db.scan_state.
INSTANCE_SOURCES = tuple(module.SOURCE_TYPE for module in PROVIDERS.values() if module.INSTANCE_SCOPED)
# Sources whose listed revision identifies an object's content, so a scan result is reused for it.
CACHED_SOURCES = tuple(module.SOURCE_TYPE for module in PROVIDERS.values() if getattr(module, "REVISION_CACHE", False))
# Sources whose object revision is a git blob id: one scan result serves the same content anywhere.
CONTENT_ADDRESSED_SOURCES = tuple(module.SOURCE_TYPE for module in PROVIDERS.values()
                                  if getattr(module, "CONTENT_ADDRESSED", False))
TOKEN_KINDS = tuple(kind for module in PROVIDERS.values() if module.TOKEN_AUTH for kind in module.JOB_KINDS) + ("scope", "catalog-refresh")
# The existing public mapping intentionally contains only each provider's primary type.
RESOURCE_SOURCE = {module.RESOURCE_TYPES[0]: module.SOURCE_TYPE for module in PROVIDERS.values()}
