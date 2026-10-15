# Licensing

This project is licensed under the **Apache License, Version 2.0**.
[`LICENSE`](LICENSE) carries the full text, and it applies to the whole
repository.

## What is covered

The platform is implemented in Python under [`cremore/`](cremore/) and in TypeScript
under [`web/`](web/). Both are the project's own work. The detection engine
under [`cremore/detection/`](cremore/detection/) — every detector, decoder,
verification rule and false-positive heuristic — is written from public
encoding specifications and provider API documentation, and each detector
records the document it was written from in its `source_url`.

## What this permits

Apache-2.0 is a permissive licence. You may use, modify, and redistribute this
software, including in proprietary and networked services, subject to the terms
in [`LICENSE`](LICENSE) (retain notices, state changes, and the patent and
trademark provisions). See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for
the third-party dependencies required at runtime and their licences.
