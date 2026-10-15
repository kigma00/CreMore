# Learned false-positive profiles

Status: **implemented** (`cremore/scanning/learned_fp.py`), off by default
(nothing is suppressed until an Admin switches it on in the dashboard;
`GET`/`PUT /api/v1/settings/learned-false-positives`).
`GET /api/v1/rules/learned-fp` lists profiles for
Admins; the dashboard's Rules tab renders them.

## Problem

Analysts mark the same kind of false positive again and again: a test fixture
under `fixtures/`, a documentation snippet, a vendor SDK example, a placeholder
in a template. The custom-rule scope filters help when the pattern is a path,
but they must be written by hand and they act on the *rule*, not on what an
analyst already decided. The installation already records every decision as a
`FINDING_FALSE_POSITIVE` audit event with a reason code; nothing learns from it.

## Goal

Turn confirmed false positives into conservative, explainable, per-scope
profiles that auto-triage *repeats* of the same context — without ever learning
from, storing, or comparing secret material, and without hiding anything.

## Non-goals

- No shared model across installations, providers or accounts. A profile never
  leaves the scope (connected AWS account or source connection) it was learned in.
- No machine-learning dependency. The similarity is a deterministic set
  measure over redacted features; every decision is reproducible from stored data.
- No deletion. An auto-triaged finding is a normal finding in `FALSE_POSITIVE`
  with the profile named in its resolution; it can be reopened like any other.

## What is learned (a *sample*)

When an Analyst marks a finding `FALSE_POSITIVE`, one sample is recorded per open
exposure of that finding:

| Field | Source | Notes |
| --- | --- | --- |
| scope | `exposure.aws_account_id` or `exposure.source_connection_id` | one of the two, never both |
| source_type, detector_name, credential_type | exposure / credential | the profile key |
| path features | `exposure.location` | extension, directory tokens, filename tokens (lower-cased, split on `/ . _ -`) |
| line-shape features | `exposure.redacted_line` | token classes of the already-masked line (`word`, `KEY=`, `<masked>`, quote/bracket shape), never the value |
| decided_by, event_id, finding_id | the audit event | independence is counted by distinct actors |

Nothing else. No secret, identifier, hint, fingerprint or raw line ever enters
a sample. `redacted_line` is the only content-derived input and it is already
the masked form the platform serves today.

## Profile

A profile is keyed by `(scope, source_type, detector_name, credential_type)` and
holds the union of its samples' feature sets with per-feature counts (a
centroid). Fields (the dashboard's `LearnedFPProfile`):

- `sample_count` — distinct confirmations (distinct finding × actor)
- `min_samples` — dashboard policy, default **3**, never below **2** (pin with `LEARNED_FP_MIN_SAMPLES`)
- `active` — `sample_count ≥ min_samples` **and** at least **2 distinct actors**
  **and** `contradictions == 0`
- `threshold` — dashboard policy, default **0.85** (pin with `LEARNED_FP_THRESHOLD`)
- `model_type` — `CONTEXT_SIMILARITY`
- `account_id` / `account_name` — the scope's display identity

A *contradiction* is an Analyst reopening a finding the profile auto-triaged.
One contradiction deactivates the profile until a new confirmation arrives; the
profile is then re-evaluated from scratch (count reset), because the earlier
samples evidently described the context too loosely.

## Similarity

For a new detection, build the same path and line-shape feature set and compute
a weighted Jaccard similarity against the profile centroid (feature weight =
share of samples containing it). The score, the matched features and the
profile id are stored on the exposure (`metadata.learned_fp`) so the decision is
inspectable.

## Application (auto-triage)

Inside the orchestrator, after the detection is persisted and the finding is
created or updated, and only when **all** of the following hold:

1. An Admin switched auto-triage on (default **off**), and `LEARNED_FP_MODE` does not lock it.
2. An **active** profile exists for the detection's scope and key.
3. Similarity ≥ `threshold`.
4. The detection is **not** provider-verified (`verification_state != VERIFIED`).
5. The exposure is **not** public (`metadata.exposure != "public"`).
6. The detector's confidence is at most the configured ceiling (`max_confidence`, default `medium`)
   (default `medium`; high-confidence formats such as AWS access keys are never
   auto-triaged unless an Admin raises this).
7. The finding is currently `OPEN` (never overrides an Analyst's state).

…the finding is transitioned to `FALSE_POSITIVE` with
`resolution = "LEARNED_FP_PROFILE <profile id> similarity=0.91"` and an audit
event `FINDING_AUTO_FALSE_POSITIVE` (actor `system:learned-fp`). The finding stays
listed under the false-positive filter, reopenable; reopening records a
contradiction (see above).

Without auto-triage (flag off) the profiles still learn and are shown as
`LEARNING`/`ACTIVE` so an Admin can see what *would* apply before enabling it.

## Surfaces

- `GET /api/v1/rules/learned-fp` (Admin) — profiles in the dashboard shape.
- `POST /api/v1/rules/learned-fp/{id}/deactivate` and `/reset` (Admin) — manual
  control; not on the dashboard today.
- Findings auto-triaged carry the profile in `resolution`; exposures carry
  `metadata.learned_fp`.

## Storage

Two additive tables: `fp_samples` (as in the table above, `features` JSON) and
`fp_profiles` (key, counts, `distinct_actors`, `contradictions`, `active`,
`threshold`, `min_samples`, `centroid` JSON, timestamps). Both are recomputed
from samples, so a reset is a delete.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| auto-triage switch (dashboard) | off | learn samples, serve profiles, auto-triage |
| `LEARNED_FP_MODE` | `enabled` | `disabled` hard-locks the switch off |
| `LEARNED_FP_MIN_SAMPLES` | `3` | confirmations before a profile can activate |
| `LEARNED_FP_THRESHOLD` | `0.85` | minimum similarity to auto-triage |
| `LEARNED_FP_MAX_CONFIDENCE` | `medium` | highest detector confidence tier eligible |

Helm: `config.learnedFalsePositivesMode` (worker + API) allows or hard-locks it; the
switch and its policy stay with the Admin, in the dashboard.

## Decisions taken

1. **Auto-triage** to `FALSE_POSITIVE` with reopen-as-contradiction (chosen
   over a confidence-only downgrade).
2. **Defaults**: 3 samples / 2 actors / 0.85 threshold / `medium` ceiling.
3. **Scope**: per connected account or source connection, never per provider.
4. **Line-shape features** are included; the masked value and anything glued
   to it (a format prefix) collapse to one marker before words are extracted.
