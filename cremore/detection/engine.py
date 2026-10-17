"""The native detection engine.

For each unit of content it:

1. produces decoded views (base64, UTF-16, escapes, HTML entities);
2. keyword-routes the original and every view to candidate detectors, so cost
   scales with keyword density rather than input size;
3. matches each candidate's secret expression, then checks its required and
   negative expressions within a bounded window;
4. redacts the matched line, fingerprints the material and applies
   false-positive suppression;
5. de-duplicates findings by (detector, fingerprint).

Raw content never leaves this boundary — only :class:`SanitizedDetection`.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from dataclasses import asdict, dataclass, field

from cremore_aws_provider.detection.session_material import MAX_TOKEN_BYTES, bind_sessions
from cremore_github_provider.credential_digest import token_fingerprint as github_token_fingerprint

from cremore.detection import decoders as _decoders
from cremore.detection import falsepositives as _falsepositives
from cremore.detection import fingerprint as _fp
from cremore.detection import verify as _verify
from cremore.detection.catalog import builtin_definitions
from cremore.detection.falsepositives import FPPolicy
from cremore.detection.models import (
    Definition,
    DetectorInput,
    PatternRole,
    SanitizedDetection,
)
from cremore.detection.regex import USING_RE2, Pattern, compile_bytes
from cremore.detection.safe_text import safe_evidence_text, safe_fact_text
from cremore.detection.verify import VerificationState, VerifierConfig

# Leading bytes of formats whose content is compressed or encoded, so a text
# pattern run over the raw bytes cannot find a credential cleanly and mostly
# matches noise. Archives and PDFs are skipped as unsupported and reported as
# excluded from the scan; the content behind that encoding is not checked.
# Both lists are part of detection_digest: the scan cache must not replay an
# object's old detections once its format stops being scanned.
UNSUPPORTED_MAGIC = (
    b"PK\x03\x04", b"PK\x05\x06",     # zip, including office documents
    b"\x1f\x8b",                      # gzip
    b"BZh",                           # bzip2
    b"\xfd7zXZ\x00",                  # xz
    b"7z\xbc\xaf\x27\x1c",            # 7-zip
    b"Rar!",                          # rar
    b"%PDF-",                         # pdf
)
# Raster images are likewise outside the current text scan (compressed pixel
# data). They are counted separately from archives and PDFs.
IMAGE_MAGIC = (
    b"\x89PNG\r\n\x1a\n",             # png
    b"\xff\xd8\xff",                  # jpeg
    b"GIF87a", b"GIF89a",             # gif
)

_DEFAULT_SPAN = 512
_MULTIPART_SPAN = 1024
# Same-line text before a secret handed to a context validator.
_CONTEXT_BYTES = 256
# Validator bodies are recorded in detection_digest by name only, so bump this
# whenever a validator's meaning changes (3: generic assignment context rules).
ENGINE_EPOCH = 9  # Also omit evidence containing retired credential families.

_AWS_PAIR = "aws-access-key-pair-v1"
_AWS_PARTS = {"aws-access-key-id-v1": "IDENTIFIER_ONLY", "aws-secret-access-key-v1": "SECRET_ONLY",
              "aws-session-token-v1": "SESSION_TOKEN_ONLY"}
_AWS_TOKEN_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=_-")
# An AWS secret access key is 40 base64 characters and carries no label of its
# own, so the same bytes appear under whatever name a file assigns them.
_AWS_SECRET_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=")

# One step down the confidence ladder, applied when the FP policy flags a match.
_LOWER_CONFIDENCE = {"high": "medium", "medium": "low", "low": "low"}


class _KeywordRouter:
    """Which catalog keywords occur in a lowered view, from one alternation search.

    Testing every keyword with ``in`` scans the view once per keyword (about a
    thousand passes). Here one alternation, longest keyword first, is searched
    again one byte after each match start, so every position where any keyword
    starts is reported with the longest keyword starting there. Any other keyword
    starting there is a prefix of it, and any keyword inside it is a substring:
    both are found through ``contained``. The set therefore equals the
    per-keyword ``in`` test for every input; detector order and the detection
    digest do not depend on it.
    """

    # Each match costs a Python call. In a stretch denser than one match per
    # DENSE_BYTES that outruns testing every keyword with ``in`` (measured break-even),
    # so such a view finishes with that plain test instead -- the same exact answer.
    DENSE_MATCHES = 4096
    DENSE_BYTES = 8

    def __init__(self, keywords):
        ordered = sorted(set(keywords), key=lambda value: (-len(value), value))
        # An empty keyword is in every view; the alternation must never match empty.
        self.always = frozenset(keyword for keyword in ordered if not keyword)
        self._ordered = tuple(keyword for keyword in ordered if keyword)
        self._members = frozenset(self._ordered)
        # Filled when a keyword is first found: operator rules may add many long
        # keywords, and most are never found at all.
        self._contained: dict[bytes, frozenset[bytes]] = {}
        # Latin-1 makes every pattern byte one literal character, NUL and bytes over 0x7f included.
        self._pattern = None
        if self._ordered and USING_RE2:
            import re as _re

            import re2

            options = re2.Options()
            options.encoding = re2.Options.Encoding.LATIN1
            options.max_mem = 64 << 20
            self._pattern = re2.compile(b"|".join(_re.escape(keyword) for keyword in self._ordered), options)

    def contained(self, keyword: bytes) -> frozenset[bytes]:
        """The keywords wholly inside ``keyword``, its own prefixes included."""
        parts = self._contained.get(keyword)
        if parts is None:
            parts = self._contained[keyword] = frozenset(
                part for size in range(1, len(keyword)) for start in range(len(keyword) - size + 1)
                if (part := keyword[start:start + size]) in self._members)
        return parts

    def present(self, lowered: bytes) -> set[bytes]:
        if self._pattern is None:  # the stdlib backtracks per alternative: the plain test is faster there
            return {keyword for keyword in self._ordered if keyword in lowered} | set(self.always)
        found: set[bytes] = set(self.always)
        search = self._pattern.search
        position = stretch = matches = 0
        while (match := search(lowered, position)) is not None:
            found.add(match.group())
            position = match.start() + 1
            matches += 1
            if matches % self.DENSE_MATCHES == 0:
                if position - stretch < self.DENSE_MATCHES * self.DENSE_BYTES:
                    found.update(keyword for keyword in self._ordered if keyword not in found and keyword in lowered)
                    break
                stretch = position
        for keyword in list(found):
            if keyword:
                found |= self.contained(keyword)
        return found


class DetectionResults(list):
    """List-compatible result carrying whether the detector cap was reached."""

    def __init__(self, values=(), *, complete=True):
        super().__init__(values)
        self.complete = complete


class _CandidateLimit(Exception):
    """An object remains incomplete when candidate processing is exhausted."""


@dataclass
class _CandidateBudget:
    count: int
    size: int
    max_match: int

    def consume(self, match) -> None:
        size = match.end() - match.start()
        if self.count <= 0 or size > self.size or size > self.max_match:
            raise _CandidateLimit
        self.count -= 1
        self.size -= size


@dataclass(frozen=True)
class _CompiledPattern:
    pattern: Pattern
    role: PatternRole
    secret_group: int  # 0 = whole match, >=1 named/positional group
    identifier_group: int  # -1 when absent
    fingerprint_groups: tuple[int, ...]


@dataclass
class _CompiledSpec:
    catalog: object  # CatalogEntry
    keywords: tuple[bytes, ...]
    span: int
    detector_name: str
    confidence: str = "high"
    validate: object | None = None  # Callable[[bytes], bool] | None
    context_validate: object | None = None  # Callable[[bytes, bytes], bool] | None
    primary: list[_CompiledPattern] = field(default_factory=list)
    required: list[_CompiledPattern] = field(default_factory=list)
    negative: list[_CompiledPattern] = field(default_factory=list)


@dataclass(frozen=True)
class EngineConfig:
    fp_policy: FPPolicy = field(default_factory=FPPolicy)
    fingerprint_key: bytes | None = None
    max_detections: int = 1000
    max_candidates: int = 10000
    max_candidate_bytes: int = 1024 * 1024
    max_match_bytes: int = 64 * 1024
    max_context_bytes: int = 1024
    #: Verification is off by default; enabling it sends candidates to providers.
    verify: VerifierConfig = field(default_factory=VerifierConfig)
    #: Optional injected HTTP client (httpx.Client) for verifiers, for testing.
    http_client: object | None = None

    def __post_init__(self):
        if any(value <= 0 for value in (self.max_detections, self.max_candidates,
                                       self.max_candidate_bytes, self.max_match_bytes, self.max_context_bytes)):
            raise ValueError("DETECTION_LIMITS_MUST_BE_POSITIVE")


def _compile_pattern(det_id: str, p) -> _CompiledPattern:
    compiled = compile_bytes(p.expr)
    secret_group = 0
    identifier_group = -1
    fingerprint_groups: list[int] = []
    if p.secret_group:
        idx = compiled.group_index(p.secret_group)
        if idx < 1:
            raise ValueError(f"detector {det_id}: no secret group '{p.secret_group}'")
        secret_group = idx
        if p.identifier_group:
            iidx = compiled.group_index(p.identifier_group)
            if iidx < 1:
                raise ValueError(f"detector {det_id}: no identifier group '{p.identifier_group}'")
            identifier_group = iidx
        for name in p.fingerprint_groups:
            gidx = compiled.group_index(name)
            if gidx < 1:
                raise ValueError(f"detector {det_id}: no fingerprint group '{name}'")
            fingerprint_groups.append(gidx)
    elif compiled.num_groups() >= 1 and not p.whole_match:
        secret_group = 1
    return _CompiledPattern(
        pattern=compiled,
        role=p.role,
        secret_group=secret_group,
        identifier_group=identifier_group,
        fingerprint_groups=tuple(fingerprint_groups),
    )


def _compile(definition: Definition) -> _CompiledSpec:
    span = definition.span or _DEFAULT_SPAN
    spec = _CompiledSpec(
        catalog=definition.catalog,
        keywords=tuple(k.lower().encode("utf-8") for k in definition.catalog.keywords),
        span=span,
        detector_name=definition.detector_name or definition.catalog.id,
        confidence=getattr(definition.catalog, "confidence", "high"),
        validate=definition.validate,
        context_validate=definition.context_validate,
    )
    for p in definition.patterns:
        cp = _compile_pattern(definition.catalog.id, p)
        if p.role == PatternRole.SECRET:
            spec.primary.append(cp)
        elif p.role in (PatternRole.IDENTIFIER, PatternRole.REQUIRED):
            spec.required.append(cp)
        elif p.role == PatternRole.NEGATIVE:
            spec.negative.append(cp)
    if not spec.primary:
        raise ValueError(f"detector {definition.catalog.id} has no secret expression")
    if spec.required and spec.span < _MULTIPART_SPAN:
        spec.span = _MULTIPART_SPAN
    return spec


class Engine:
    """A scanning engine over a fixed, provenance-labelled detector catalog."""

    def __init__(
        self,
        config: EngineConfig | None = None,
        definitions: list[Definition] | None = None,
    ) -> None:
        self.config = config or EngineConfig()
        defs = definitions if definitions is not None else builtin_definitions()
        self._specs = [_compile(d) for d in defs]
        self._router = _KeywordRouter(keyword for spec in self._specs for keyword in spec.keywords)
        detection_definitions = []
        for definition in defs:
            value = asdict(definition)
            value["catalog"] = {k: v for k, v in value["catalog"].items() if k in (
                "id", "provider", "credential_type", "keywords", "confidence")}
            detection_definitions.append(value)
        # This digest describes passive detection, not scoring or live verification.
        # Bump ENGINE_EPOCH when decoder/matching/sanitization semantics change.
        identity = {
            "engine_epoch": ENGINE_EPOCH,
            "definitions": detection_definitions,
            "fp_policy": asdict(self.config.fp_policy),
            "placeholder_substrings": list(_falsepositives.PLACEHOLDER_SUBSTRINGS),
            "limit": self.config.max_detections,
            "candidate_limits": (self.config.max_candidates, self.config.max_candidate_bytes,
                                 self.config.max_match_bytes, self.config.max_context_bytes),
            "unsupported_magic": [magic.hex() for magic in UNSUPPORTED_MAGIC],
            "image_magic": [magic.hex() for magic in IMAGE_MAGIC],
            "fingerprint_key_epoch": hashlib.sha256(self.config.fingerprint_key or b"").hexdigest(),
        }
        self.detection_digest = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"),
            default=lambda value: f"{value.__module__}.{value.__qualname__}",
        ).encode()).hexdigest()
        if self.config.verify.enabled:
            _verify.load_default_verifiers()

    def catalog(self) -> list[object]:
        return [s.catalog for s in self._specs]

    def scan(self, item: DetectorInput) -> list[SanitizedDetection]:
        data = item.data
        findings: dict[tuple[str, str], SanitizedDetection] = {}
        vconfig = item.verify_config or self.config.verify
        verify = vconfig.enabled and item.verify is not False
        if verify and not self.config.verify.enabled:
            _verify.load_default_verifiers()
        verify_cache: dict[tuple[str, str], object] = {}
        complete = True
        budget = _CandidateBudget(self.config.max_candidates, self.config.max_candidate_bytes,
                                  self.config.max_match_bytes)
        # Host-scoped verifiers (GitHub) are told which host the content came from.
        verify_context = {"github_host": (item.resource.metadata or {}).get("github_host", ""),
                          "source_type": item.resource.source_type,
                          "source_instance": (item.resource.metadata or {}).get("source_instance", "")}

        # Original content first, then decoded views. A finding seen in the
        # original wins over the same finding surfaced through a decoder.
        sources: list[tuple[bytes, str]] = [(data, "")]
        for view in _decoders.decoded_views(data):
            sources.append((view.data, view.decoder))

        for view_bytes, decoder in sources:
            lowered = view_bytes.lower()
            present = self._router.present(lowered)
            active_specs = [spec for spec in self._specs
                            if not spec.keywords or any(k in present for k in spec.keywords)]
            # Reuse the same candidate set for redaction, pair ambiguity and output.
            matches = {spec.catalog.id: [] for spec in active_specs}
            try:
                for spec in active_specs:
                    for candidate in self._candidate_matches(spec, view_bytes, budget):
                        matches[spec.catalog.id].append(candidate)
            except _CandidateLimit:
                complete = False
            redaction_matches = dict(matches)
            pairs = matches.get(_AWS_PAIR, [])
            session_evidence, complete_tokens = {}, {}
            pair_spec = next((spec for spec in active_specs if spec.catalog.id == _AWS_PAIR), None)
            if complete and pair_spec and b"asia" in lowered:
                structural, session_evidence, complete_tokens = bind_sessions(view_bytes, [
                    (match.start(primary.identifier_group), match.start(primary.secret_group),
                     _group_bytes(match, primary.identifier_group), secret) for primary, match, secret in pairs],
                    key=self.config.fingerprint_key, validate_secret=pair_spec.validate)
                pair_spans = {(m.start(p.identifier_group), m.start(p.secret_group)) for p, m, _ in pairs}
                pairs = pairs + [(pair_spec.primary[0], match, match.secret.value) for match in structural
                                 if (match.identifier.start, match.secret.start) not in pair_spans]
                redaction_matches[_AWS_PAIR] = pairs
            id_links, secret_links = {}, {}
            for primary, match, _secret in pairs:
                id_span = (match.start(primary.identifier_group), match.end(primary.identifier_group))
                secret_span = (match.start(primary.secret_group), match.end(primary.secret_group))
                id_links.setdefault(id_span, set()).add(secret_span)
                secret_links.setdefault(secret_span, set()).add(id_span)
            pairs = [row for row in pairs
                     if len(id_links[(row[1].start(row[0].identifier_group), row[1].end(row[0].identifier_group))]) == 1
                     and len(secret_links[(row[1].start(row[0].secret_group), row[1].end(row[0].secret_group))]) == 1]
            matches[_AWS_PAIR] = pairs
            paired_spans = {
                "aws-access-key-id-v1": {(m.start(p.identifier_group), m.end(p.identifier_group)) for p, m, _ in pairs},
                "aws-secret-access-key-v1": {(m.start(p.secret_group), m.end(p.secret_group)) for p, m, _ in pairs},
                "aws-session-token-v1": set(complete_tokens.values()),
            }
            # A returned line must mask every credential candidate on that
            # physical line, including matches beyond the output count cap.
            redacted_lines = self._redacted_lines(view_bytes, active_specs, redaction_matches, complete=complete) if decoder == "" else {}
            for spec in active_specs:
                for det in self._scan_spec(
                    spec, view_bytes, decoder, verify, verify_cache, redacted_lines, verify_context, vconfig,
                    matches=matches[spec.catalog.id], skip_spans=paired_spans.get(spec.catalog.id, set()),
                    session_evidence=session_evidence, session_tokens=complete_tokens,
                ):
                    key = (spec.catalog.id, det.fingerprint)
                    if key not in findings:
                        findings[key] = det
                        if len(findings) >= self.config.max_detections:
                            return DetectionResults(findings.values(), complete=False)
            if not complete:
                break
        return DetectionResults(findings.values(), complete=complete)

    def _verify(self, spec: _CompiledSpec, secret: str, identifier: str, fp: str, cache: dict, context: dict | None = None, vconfig: VerifierConfig | None = None):
        """Verify a credential once per (detector, fingerprint), returning facts."""

        key = (spec.catalog.id, fp)
        if key in cache:
            return cache[key]
        verifier = _verify.verifier_for(spec.catalog.id)
        if verifier is None:
            result = _verify.VerificationResult(VerificationState.UNSUPPORTED)
        else:
            result = verifier.verify(
                secret=secret,
                identifier=identifier,
                config=vconfig or self.config.verify,
                client=self.config.http_client,
                context=context,
            )
        cache[key] = result
        return result

    def _match_verify_context(self, view, base_context, position, session_tokens):
        """Attach the bound STS session token for one COMPLETE match, transiently.

        ``session_tokens`` maps a COMPLETE binding's (id-start, secret-start) to
        its token span. The raw token is sliced from the view only to hand to the
        verifier, exactly as the secret access key is; it is never written to
        extra_safe_data, a finding, a log, or the fingerprint.
        """
        span = (session_tokens or {}).get(position)
        if span is None:
            return base_context
        return {**(base_context or {}), "aws_session_token": view[span[0]:span[1]].decode("ascii", "ignore")}

    def _candidate_matches(self, spec: _CompiledSpec, view: bytes, budget: _CandidateBudget | None = None):
        """Yield structurally valid secret matches for one detector spec."""

        for primary in spec.primary:
            for match in primary.pattern.finditer(view, resume_group=primary.secret_group):
                if budget is not None:
                    budget.consume(match)
                secret = _group_bytes(match, primary.secret_group)
                if not secret or (spec.validate is not None and not spec.validate(secret)):
                    continue
                start, end = match.start(primary.secret_group), match.end(primary.secret_group)
                if spec.catalog.id == _AWS_PAIR or spec.catalog.id in _AWS_PARTS:
                    spans = [(start, end)]
                    if primary.identifier_group > 0:
                        spans.append((match.start(primary.identifier_group), match.end(primary.identifier_group)))
                    if any((s and view[s - 1] != ord("=") and view[s - 1] in _AWS_TOKEN_CHARS) or
                           (e < len(view) and view[e] in _AWS_TOKEN_CHARS) for s, e in spans):
                        continue
                    if spec.catalog.id == _AWS_PAIR:
                        id_start, id_end = spans[1]
                        if max(start - id_end, id_start - end) > 512:
                            continue
                        # A hash is not enough context for a secret-key pair.
                        if all(c in b"0123456789abcdefABCDEF" for c in secret):
                            continue
                        if view.count(b"\n", min(start, id_start), max(start, id_start)):
                            prefixes = [view[view.rfind(b"\n", 0, s) + 1:s] for s in (start, id_start)]
                            indents = [len(p) - len(p.lstrip(b" \t")) for p in prefixes]
                            if indents[0] != indents[1]:
                                continue
                # Detection and line redaction both come through here, on the
                # decoded view, so they always agree on the same judgement.
                if spec.context_validate is not None:
                    line_start = view.rfind(b"\n", 0, start) + 1
                    if not spec.context_validate(view[max(line_start, start - _CONTEXT_BYTES):start], secret):
                        continue
                if self._negated(spec, secret):
                    continue
                window = view[max(0, start - spec.span) : end + spec.span]
                if all(req.pattern.search(window) for req in spec.required):
                    yield primary, match, secret

    def _redacted_lines(self, view: bytes, specs: list[_CompiledSpec], matches, *, complete=True):
        # Index only candidate positions, not every physical line of an object.
        # Multiline spans mask any intersecting evidence window in one pass.
        spans, whole_lines, positions = [], [], set()
        for spec in specs:
            for primary, match, _secret in matches[spec.catalog.id]:
                start, end = match.start(primary.secret_group), match.end(primary.secret_group)
                positions.add(start)
                spans.append((start, end))
                if spec.catalog.id == _AWS_PAIR or spec.catalog.id in _AWS_PARTS or spec.catalog.id == "azure-sas-token-v1":
                    whole_lines.append((start, end))
        spans = _merged_spans(spans)
        whole_lines = _merged_spans(whole_lines)
        starts, ends = [s for s, _ in spans], [e for _, e in spans]
        whole_starts, whole_ends = [s for s, _ in whole_lines], [e for _, e in whole_lines]
        evidence = {}
        previous, line_no, line_start, line_end = 0, 1, 0, -1
        for start in sorted(positions):
            line_no += view.count(b"\n", previous, start)
            if start > line_end:
                line_start = view.rfind(b"\n", previous, start) + 1
                line_end = view.find(b"\n", start)
                if line_end < 0:
                    line_end = len(view)
            previous = start
            if not complete:
                text = "[Evidence omitted: detection limit reached]"
            elif bisect_left(whole_starts, line_end) > bisect_right(whole_ends, line_start):
                text = "[Credential material redacted]"
            else:
                left = max(line_start, start - self.config.max_context_bytes // 4)
                right = min(line_end, left + self.config.max_context_bytes)
                first, last = bisect_right(ends, left), bisect_left(starts, right)
                local_spans = [(max(s, left) - left, min(e, right) - left) for s, e in spans[first:last]]
                text = ("…" if left > line_start else "") + _fp.redact_line(view[left:right], local_spans)
                if right < line_end:
                    text += "…"
                if safe_evidence_text(text) is None:
                    text = "[Credential material redacted]"
            evidence[start] = (line_no, text)
        return evidence

    def _scan_spec(
        self,
        spec: _CompiledSpec,
        view: bytes,
        decoder: str,
        verify: bool = False,
        verify_cache: dict | None = None,
        redacted_lines: dict[int, str] | None = None,
        verify_context: dict | None = None,
        vconfig: VerifierConfig | None = None,
        *,
        matches=None,
        skip_spans=frozenset(),
        session_evidence=None,
        session_tokens=None,
    ):
        for primary, m, secret_bytes in matches if matches is not None else self._candidate_matches(spec, view):
            if spec.catalog.id == "aws-session-token-v1" and len(secret_bytes) > MAX_TOKEN_BYTES:
                continue  # Redaction still sees the whole labelled candidate, never a truncated token.
            start, end = m.start(primary.secret_group), m.end(primary.secret_group)
            if (start, end) in skip_spans:
                continue

            identifier = ""
            if primary.identifier_group > 0:
                identifier = _group_str(m, primary.identifier_group)

            material = self._fingerprint_material(m, primary, secret_bytes)
            if spec.catalog.id in _AWS_PARTS:
                # Partial observations never share a complete credential's identity.
                material = spec.catalog.credential_type.encode() + b"\x00" + material
            secret_str = secret_bytes.decode("utf-8", "replace")

            signal = self.config.fp_policy.signal(secret_str)
            if signal and not self.config.fp_policy.retain:
                continue

            fp = _fp.fingerprint(material, key=self.config.fingerprint_key)
            extra = {"catalog_id": spec.catalog.id}
            session_position = None
            if spec.catalog.id == _AWS_PAIR and identifier.startswith("ASIA"):
                session_position = (m.start(primary.identifier_group), start)
                extra.update((session_evidence or {}).get(session_position, {"aws_session_material": "UNBOUND"}))
            keyed = bool(self.config.fingerprint_key) and len(self.config.fingerprint_key) >= 32
            if keyed:
                extra["issuer_comparison"] = {"key_id": hashlib.sha256(self.config.fingerprint_key).hexdigest()}
            if keyed and spec.catalog.credential_type == "GITHUB_TOKEN":
                extra["issuer_comparison"]["github_token_digest"] = github_token_fingerprint(secret_bytes, self.config.fingerprint_key)
            if spec.catalog.id == _AWS_PAIR and keyed:
                # Component equality can link saved observations without retaining
                # plaintext or trying candidate combinations against a provider.
                extra["aws_id_component_fingerprint"] = _fp.fingerprint(
                    b"AWS_ACCESS_KEY_ID\x00" + identifier.encode(), key=self.config.fingerprint_key)
                extra["aws_secret_component_fingerprint"] = _fp.fingerprint(
                    b"AWS_SECRET_ACCESS_KEY\x00" + secret_bytes, key=self.config.fingerprint_key)
            elif keyed and len(secret_bytes) == 40 and not set(secret_bytes) - _AWS_SECRET_CHARS:
                # A value of that exact shape may be an AWS secret stored under a
                # name this catalog does not read as AWS. Recording the component
                # hash lets byte equality link it to a complete pair later. It
                # never retypes the finding or raises its confidence: a value
                # only ever links when every byte matches.
                extra["aws_secret_component_fingerprint"] = _fp.fingerprint(
                    b"AWS_SECRET_ACCESS_KEY\x00" + secret_bytes, key=self.config.fingerprint_key)
            if spec.catalog.id in _AWS_PARTS:
                extra["aws_material_kind"] = _AWS_PARTS[spec.catalog.id]
            if signal:
                extra["fp_signal"] = signal

            engine_verified: bool | None = None
            if verify:
                match_context = self._match_verify_context(view, verify_context, session_position, session_tokens)
                result = self._verify(spec, secret_str, identifier, fp, verify_cache if verify_cache is not None else {}, match_context, vconfig)
                extra["verification_state"] = result.state.value
                extra["verification_checked_at"] = result.checked_at.isoformat()
                for name, value in result.facts.items():
                    if value and safe_fact_text(value, secrets=(secret_str,)) is not None:
                        extra[f"verification_{name}"] = value
                if result.error_code:
                    extra["verification_error"] = result.error_code
                if result.state == VerificationState.VERIFIED:
                    engine_verified = True
                elif result.state == VerificationState.REJECTED:
                    engine_verified = False

            # Confidence: the detector's passive tier by default. A match the
            # FP policy flagged (placeholder/low-entropy) drops a tier; one the
            # provider verified is authoritative.
            confidence = spec.confidence
            if signal:
                confidence = _LOWER_CONFIDENCE.get(confidence, "low")
            if engine_verified is True:
                confidence = "high"

            line_no, redacted_line = (redacted_lines or {}).get(start, (None, ""))
            det = SanitizedDetection(
                detector_name=spec.detector_name,
                credential_type=spec.catalog.credential_type,
                provider=spec.catalog.provider,
                fingerprint=fp,
                identifier=identifier,
                identifier_hint=_fp.mask_hint(identifier or secret_str),
                line_number=line_no if decoder == "" else None,
                redacted_line=redacted_line if decoder == "" else "",
                confidence=confidence,
                engine_verified=engine_verified,
                decoder_type=decoder,
                extra_safe_data=extra,
            )
            yield det

    def _negated(self, spec: _CompiledSpec, secret: bytes) -> bool:
        for neg in spec.negative:
            m = neg.pattern.search(secret)
            if m and m.start() == 0 and m.end() == len(secret):
                return True
        return False

    @staticmethod
    def _fingerprint_material(m, primary: _CompiledPattern, secret: bytes) -> bytes:
        if primary.fingerprint_groups:
            parts = [_group_bytes(m, g) for g in primary.fingerprint_groups]
            return b"\x00".join(p for p in parts if p)
        return secret


def _group_bytes(m, group: int) -> bytes:
    value = m.group(group)
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _group_str(m, group: int) -> str:
    b = _group_bytes(m, group)
    return b.decode("utf-8", "replace")


def _merged_spans(spans):
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
