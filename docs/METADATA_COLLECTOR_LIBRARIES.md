# Metadata collector libraries

The schema 2 metadata worker executes GitHub, GitLab, GCP, Atlassian,
Bitbucket and Azure Key Vault through one declared runtime contract. AWS
schema 1 coverage and content scanners keep their existing execution paths.

## Module ownership

| Module | Responsibility |
| --- | --- |
| `cremore.coverage.collector_runtime` | `CollectionContext`, `CollectorRuntime`, supported services and lazy page invocation |
| `cremore.coverage.providers` | Explicit provider registrations, adapter loading and scope/record validation |
| `cremore.coverage.metadata_auth` | Resolve authentication references for one attempt, clear the returned mapping on exit |
| `cremore.coverage.metadata_stream` | Bound batches by item/UTF-8 byte limits, summarize operation reports, select safe error codes |
| `cremore.coverage.metadata_job` | Task lease, cancellation/revision checks, checkpoint and record publication, completion/defer/abort |
| `cremore_<vendor>_provider.metadata.adapter` | Provider API traversal and conversion to typed records; source lives in `<vendor>/backend/cremore_<vendor>_provider/metadata/` |

The metadata owners are `gcp/`, `github/`, `gitlab/`, `atlassian/` and `azure/`.
Atlassian and Bitbucket share `cremore_atlassian_provider.metadata`; the
`azure_key_vault` registration uses `cremore_azure_provider.metadata`.
Their descriptors and provider-specific tests live beside the implementation.
Existing `cremore.coverage.providers.<provider>` imports remain compatibility
paths. Shared registry and runtime tests stay under `cremore/coverage/`.
All provider libraries are included in the root Python wheel; installing a
separate package or discovering arbitrary external collectors is not required.

Runtime and helper modules do not import the worker or HTTP application.
Native `collect_pages` functions remain available for provider-specific tests
and transports. `adapter_for` and `validate_spec` still return native modules
for record projection/export/comparison consumers. Existing helper imports
from `metadata_job` remain aliases; new code should import the owning module.

## Declared services

| Provider | Value-processing context | Selective recollection |
| --- | --- | --- |
| GitHub | Yes (opt-in provider digests) | Yes (installation check only) |
| GitLab | No | No |
| GCP | Yes | No |
| Atlassian | No | Yes |
| Bitbucket | No | Yes |
| Azure Key Vault | No | No |

These are execution services, not permissions or product entitlement claims.
They are declared in `AdapterRegistration`. A provider accepting an argument
does not prove it supports that service: Azure has a `value_context` argument
specifically to reject value collection. Inferring support from its signature
previously made the shared worker fail before listing Azure metadata.

The worker and recollection API use the same `CollectorRuntime` planner. The
catalog's recollection flag is checked against registration by tests. No
registered provider used the old optional `read_previous_records` callback;
that unused signature-based injection has been removed. Current-run replay
remains available through `read_records`.

## Calling a collector

```python
from cremore.coverage.collector_runtime import CollectionContext
from cremore.coverage.providers import collector_for

collector = collector_for(spec.provider)
collector.validate_spec(spec)
request = CollectionContext(
    secrets=resolved_auth,
    checkpoint=provider_checkpoint,
    check=check_lease_and_connection,
    read_records=read_committed_records,
)
pages = collector.collect(spec, request)
```

This example selects the metadata-only services. GCP receives its existing
value-processing context from the worker; its collection/storage policy is
unchanged. Atlassian/Bitbucket retries receive the result of
`collector.plan_recollection(...)` as `recollection_plan`.

`collect` returns a lazy iterable. It does not acquire a task lease, validate
or save pages, resolve secrets, or perform a collection merely by being called.
For queued execution, use `metadata_job.run` through `JobWorker`, which owns
those responsibilities. Never serialize `CollectionContext`: it contains
authentication and callbacks. `resolved_slots` clears the returned mapping on
success or exception, including planning failures; this is reference cleanup,
not guaranteed erasure of Python strings from memory.

## Adding an option

A scope digest (`metadata_contract`) covers every field of `MetadataConnectionSpec`,
defaults included, so a release that only adds an option moves the digest of every
stored connection and run. The platform's comparisons read stored contracts through
today's model (`same_contract`, `scope_matches`) and accept one stored before the
option: storage receipts, run comparisons, recollection bases and the worker's check
of a resumed run's contract. All of them also require the same revision.

Provider adapters that pin their own checkpoint to `digest(spec.model_dump())`
(GitHub, GCP, Azure Key Vault/Entra/ARM/DevOps, Notion) still refuse a checkpoint
made before such a release, so a collection waiting across the upgrade fails once
and the next one starts fresh. Let collections finish, or stop them, before upgrading.

## Pausing and stopping a queued collection

`POST /api/v2/coverage/connections/{id}/collect/pause`, `.../resume` and `.../stop`
(analyst) act on the connection's active metadata job. A pause is an installation
setting (`metadata_collection_pause:<connection>`) naming that job: the worker's
`check` sees it before the adapter's next request, defers the task by 30 seconds
with its last committed checkpoint, and leaves the run open. Resume clears it and
the same run continues from that checkpoint; a pause naming another job is inert.
A run must finish within the store's lifetime (`RUN_LIFETIME`, 6 hours from its
start), so a pause keeps it open only until 10 minutes before that: the worker then
closes it as `PARTIAL` with `METADATA_COLLECTION_PAUSE_EXPIRED`, keeping what it
committed, and a later collection is a new run. A collection paused before it opened
a run ends as long after the pause was requested (the setting's `updated_at`): the
job fails with `METADATA_COLLECTION_PAUSE_EXPIRED` and no longer holds the
connection's job slot. `check` reads the pause in the same transaction as its lease,
revision and cancellation checks.
Stop cancels the job: a queued job is withdrawn at once, a running one ends at its
next `check`, and finalization closes its open run as `FAILED` with
`METADATA_COLLECTION_STOPPED` in the same transaction as the cancelled job. The
records it committed stay readable in that run and are not projected. An adapter
needs nothing new beyond calling `check` before each request.

GitHub's selective recollection is only the installation check
(`plan_recollection` refuses anything else); see the GitHub provider README.

## Adding or extending a provider

1. Implement `validate_spec`, `validate_record` and lazy `collect_pages` in the
   provider-owned `metadata/adapter.py`. Keep provider I/O outside database transactions.
2. Add an `AdapterRegistration` in `cremore/coverage/providers/__init__.py`
   and the provider-owned presentation descriptor used by the catalog. Declare
   `value_context` or `recollection` only for supported execution services.
   A recollection registration must expose a callable `plan_recollection`.
   A secret role a run can do without goes in the descriptor's
   `optional_secret_roles`: when the worker cannot resolve it, the role is left
   out of `secrets` and the adapter fails only the reads that need it. Every
   other role still fails the run with `METADATA_SECRET_UNAVAILABLE`. The connection
   form marks these roles optional.
3. Return `MetadataPage` with only safe records/checkpoints, and an explicit
   terminal status. `WAITING` preserves a checkpoint for a later attempt.
4. Test provider behavior and the shared worker path with synthetic transport.
   In particular, check connection changes, retry/resume and terminal handling.

For a new vendor directory, include its package and test paths in
`pyproject.toml` and its sources in the Python Docker build. Content collection
and custom provider UI have separate registration contracts; follow the
[team guide](AI_TEAM_CODING_GUIDE.md) for those integration points.

The shared worker must continue to check lease/revision before publication,
reject authentication values in pages, publish records and checkpoint in one
transaction, and stop iteration immediately at a terminal page. Avoid fetching
the next page to check whether a provider has more output: that can perform I/O.

## Validation

Run from the repository root. Refresh the editable installation after pulling
the provider directory move:

```sh
python -m pip install -e '.[dev,gcp]'
export AWS_EC2_METADATA_DISABLED=true
python -m pytest cremore/coverage/collector_runtime_test.py \
  cremore/coverage/metadata_job_test.py cremore/coverage/metadata_stream_test.py -q
python -m pytest cremore/api/metadata_coverage_test.py \
  cremore/api/github_metadata_test.py cremore/coverage/providers \
  gcp/backend/cremore_gcp_provider/metadata \
  github/backend/cremore_github_provider/metadata \
  gitlab/backend/cremore_gitlab_provider/metadata \
  atlassian/backend/cremore_atlassian_provider/metadata \
  azure/backend/cremore_azure_provider/metadata -q
python -m pytest -q
```

In PowerShell use `$env:AWS_EC2_METADATA_DISABLED='true'` instead of `export`
and join the continued commands onto one line. The final command uses the
configured `testpaths` to include both platform and provider backend tests;
independent CLI suites remain separate.

The runner tests cover memory and SQLite stores. They include the actual Azure
adapter with a synthetic data plane, checkpoint resume before/after a run has
started, terminal handling, revision/principal changes, authentication echoes,
planning cleanup and I/O outside publication transactions. No live credentials
or SaaS requests are needed. PostgreSQL coverage is a separate deployment/CI
concern; these tests do not establish its behavior.

There is no database migration or new dependency. Deploy
the API and worker from the same revision after review, as with other runtime
changes.

## Inventory and event filter responses

`GET /api/v2/coverage/inventory` returns `items`, `total`, `total_all`, `offset`,
`limit` and `counts`. Page navigation uses `offset + limit < total`; this endpoint
does not require `next_offset`. `counts` remains the object-kind histogram after
applying the current filters.

The additive `facets` field contains sorted distinct `provider`, `object_kind`
and `purpose` arrays from all stored inventory entities with an observation.
It is independent of paging, search and selected filters, including connection
filters. Registered but uncollected providers and event-only entity references
are excluded. Facets describe choices in the stored inventory, not provider
collection completeness or the number of matches for a filter combination.

`GET /api/v2/coverage/events` likewise adds `facets.provider` and
`facets.event_type` from all stored provider events. Existing `event_types`
continues to describe the filtered result. The UI uses the unfiltered facets
and retains active selections so empty or failed reads cannot hide the option
to clear a filter. Both endpoints retain their existing authentication boundary.
