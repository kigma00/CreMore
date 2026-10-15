"""GitHub organization and Enterprise credential metadata for the shared runtime.

Both teammate programs are kept: the organization collectors' per-source reads
and the Enterprise engine's task graph, audit window and resumable pagination.
What is replaced is everything around them -- the CLIs, the SQLite dashboard and
the JSON state directory -- because the product already owns execution, storage
and authentication. Host handling comes from the existing GitHub App source, so
GitHub.com, GHES and ghe.com stay supported for metadata as they are for content.
"""

SOURCE_COMMIT = "bfb97fb1f6147439904045824fa1a756c2768655"
API_VERSION = "2026-03-10"
# The only version GitHub Enterprise Server 3.20 and earlier accept (docs: rest/about-the-rest-api/api-versions).
SERVER_API_VERSION = "2022-11-28"
NATIVE_SCHEMA = "1"
CONTRACT_VERSION = "github.1"
