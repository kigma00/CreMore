"""Google Cloud issuer, vault and usage metadata for the shared coverage runtime.

The native connector's project inventory, regional and version listing, value
reads and relationship projection are preserved. Its local JSON state, watcher
process and plaintext snapshots are not: history lives in the shared records and
a value only ever leaves this package as a fingerprint.
"""

SOURCE_COMMIT = "3d79ccbef4ad51a7e7b9e0f73eabb1ac478c5ade"
NATIVE_INVENTORY_SCHEMA = "0.3"
NATIVE_RELATIONS_SCHEMA = "0.1"
CONTRACT_VERSION = "gcp.1"
