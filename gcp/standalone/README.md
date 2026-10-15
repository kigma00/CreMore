# cremore_gcp: the GCP functions the product reuses

`cremore_gcp` is a platform-independent library the product imports directly and
ships in the same Python wheel (see the [GCP module guide](../README.md)):

| Module | Owns |
| --- | --- |
| `resources.py` | Resource identifiers, state and error normalization, regional Secret endpoints |
| `transport.py` | The shared `ApiError` and `JsonTransport` contract |
| `values.py` | Size limits, base64 and CRC32C checks; API key, public certificate and immutable Secret version reads |
| `linkage.py` | Identifier matching and `scan_text`; an API key lookup only when explicitly called |

It imports nothing from the platform and performs no authentication or collection
on import; callers inject a transport. The standalone command-line tools (inventory,
relations, API key matching, plaintext Secret export and the watcher) were removed on
2026-09-27: the integrated product collects GCP through the common worker
([integrated GCP guide](../../docs/integration/GCP_TOTAL_GUIDE_KO.md)).

Run the library's own tests from this directory:

```sh
python -m unittest discover -s tests -v
```
