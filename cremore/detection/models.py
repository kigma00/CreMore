"""Domain models for the detection engine.

These mirror the fields the platform's detection boundary produces. No raw
secret ever crosses ``SanitizedDetection``: the matched value is fingerprinted
and reduced to a masked hint before it leaves the engine.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class PatternRole(enum.IntEnum):
    """How one expression of a detector participates in a match."""

    #: Any matching SECRET expression produces a candidate.
    SECRET = 0
    #: The non-secret half of a multipart credential; must also match in-window
    #: and supplies the reported identifier.
    IDENTIFIER = 1
    #: Must match in-window but is neither the secret nor the identifier.
    REQUIRED = 2
    #: Locates deployment metadata (e.g. an endpoint host). Never gates a match.
    CONTEXT = 3
    #: Discards a candidate whose secret it matches end to end.
    NEGATIVE = 4


@dataclass(frozen=True)
class CatalogEntry:
    """Safe, non-secret metadata describing one detector.

    ``source_url`` records the provider document the detector was written from,
    and ``provenance`` says what kind of source that is (built-in provider
    documentation, or an operator-authored rule).
    """

    id: str
    name: str
    provider: str
    credential_type: str
    description: str = ""
    keywords: tuple[str, ...] = ()
    match_strategy: str = ""
    source_url: str = ""
    provenance: str = "provider-documentation"
    custom: bool = False
    # How much a passive match alone is trusted. "high" for a distinctive,
    # self-identifying format (prefix/checksum/validator); "medium" for a value
    # anchored only to a nearby label; "low" for a generic shape. Verification,
    # when it runs, overrides this with ground truth.
    confidence: str = "high"


@dataclass(frozen=True)
class PatternDef:
    """One expression belonging to a detector, with its role and capture map."""

    expr: str
    role: PatternRole = PatternRole.SECRET
    name: str = ""
    # Named-group form: when secret_group is set, the expression carries the
    # whole credential and these groups locate its parts. When empty, the value
    # is capture group 1 (or the whole match when there are no groups).
    secret_group: str = ""
    identifier_group: str = ""
    fingerprint_groups: tuple[str, ...] = ()
    # The credential is the entire match rather than group 1 (for expressions
    # that capture a fixed label — a scheme or prefix — in group 1).
    whole_match: bool = False


@dataclass(frozen=True)
class Definition:
    """A detector: its catalog metadata plus the expressions that find it."""

    catalog: CatalogEntry
    patterns: tuple[PatternDef, ...]
    span: int = 0
    detector_name: str = ""
    # Optional predicate applied to the raw matched bytes for format validation
    # the regex cannot express (e.g. base32 checksum, Luhn).
    validate: object | None = None  # Callable[[bytes], bool] | None
    # Optional predicate over (text before the secret on its line, secret) for
    # judgements that depend on how the value is introduced, not on its bytes.
    context_validate: object | None = None  # Callable[[bytes, bytes], bool] | None


@dataclass
class ResourceRef:
    """Where the scanned content came from."""

    source_type: str = ""
    resource: str = ""
    location: str = ""
    account_id: str = ""
    region: str = ""
    resource_arn: str = ""
    version_id: str = ""
    revision: str = ""
    size: int = 0
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class DetectorInput:
    """One unit of content to scan."""

    data: bytes
    resource: ResourceRef = field(default_factory=ResourceRef)
    #: None keeps the engine default; explicit False forces a passive scan.
    verify: bool | None = None
    #: Per-scan verification config (probe/cross-host toggles read from the
    #: dashboard switches at scan start). None keeps the engine's default.
    verify_config: object | None = None


@dataclass
class SanitizedDetection:
    """A finding with all secret material removed.

    ``identifier`` (the non-secret half, e.g. an AWS access key id) stays in
    memory for verification but is never serialized; ``identifier_hint`` is the
    masked form that may be persisted.
    """

    detector_name: str
    credential_type: str
    fingerprint: str
    provider: str = ""
    identifier: str = ""  # not serialized
    identifier_hint: str = ""
    line_number: int | None = None
    redacted_line: str = ""
    confidence: str = "high"
    engine_verified: bool | None = None
    decoder_type: str = ""
    material_kind: str = ""
    extra_safe_data: dict[str, str] = field(default_factory=dict)
