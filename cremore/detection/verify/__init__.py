"""Credential verification.

Verification asks the issuing provider whether a discovered credential currently
authenticates. It is the only step that sends candidate material off the host,
so it is **off by default** and each verifier is written from the provider's own
API documentation.

Verification runs inside the detection boundary, on the raw match, before the
finding is sanitized; its outcome is recorded in
``SanitizedDetection.extra_safe_data['verification_state']`` and never the secret.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol


class VerificationState(str, enum.Enum):
    #: Provider confirmed the credential authenticates right now.
    VERIFIED = "verified"
    #: Provider rejected the credential.
    REJECTED = "rejected"
    #: Provider accepted authentication but policy/SSO restricts its use.
    RESTRICTED = "restricted"
    #: A transient or ambiguous response left current usability undetermined.
    INDETERMINATE = "indeterminate"
    #: No verifier exists for this credential type, or it was skipped.
    UNSUPPORTED = "unsupported"
    #: Verification is disabled or was not requested for this scan.
    NOT_ATTEMPTED = "not_attempted"


@dataclass
class VerificationResult:
    state: VerificationState
    #: Non-secret facts learned during verification (scopes, owner, account…).
    facts: dict[str, str] = field(default_factory=dict)
    #: A safe error code when the check could not complete (never raw provider text).
    error_code: str = ""
    #: Time of the result, retained when the engine reuses it from its cache.
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class VerifierConfig:
    #: Master switch. When False the engine never contacts a provider.
    enabled: bool = False
    #: Per-request timeout in seconds. Every verifier calls a fixed, documented
    #: provider URL; no endpoint is ever taken from scanned content.
    timeout: float = 10.0
    #: After a credential verifies, make a few read-only calls with it to record
    #: what it can reach (only for types whose provider hides permissions, e.g. a
    #: GitHub fine-grained PAT or a Notion integration). Off by default.
    probe_capabilities: bool = False
    #: When a host-scoped credential (a GitHub token) is rejected by the host it
    #: was found on, also try these other operator-registered hosts. Sends the
    #: token to an additional server, so off by default.
    #: Also required before trying a host-ambiguous token found outside GitHub
    #: when an Enterprise host is registered; absence of source is not github.com.
    cross_host: bool = False
    #: Bare hostnames of every GitHub host this installation knows (from the
    #: registered connections). "" means github.com. Used to decide whether a
    #: single-host rejection is conclusive and, with cross_host, where to retry.
    known_github_hosts: tuple[str, ...] = ()
    #: Bare hostnames of self-managed GitLab instances registered in this
    #: installation. A token found in one of their sources is verified on that
    #: registered instance only. With any present, a GitLab token found outside a
    #: GitLab source may be theirs, so it is not sent to GitLab.com without cross_host.
    known_gitlab_hosts: tuple[str, ...] = ()


class Verifier(Protocol):
    """Verifies one credential type against its provider."""

    def verify(
        self,
        *,
        secret: str,
        identifier: str,
        config: VerifierConfig,
        client: object | None = None,
        context: dict | None = None,
    ) -> VerificationResult: ...


# Registry: detector id -> verifier instance. Populated by register().
_REGISTRY: dict[str, Verifier] = {}


def register(detector_id: str, verifier: Verifier) -> None:
    _REGISTRY[detector_id] = verifier


def verifier_for(detector_id: str) -> Verifier | None:
    return _REGISTRY.get(detector_id)


def load_default_verifiers() -> None:
    """Register the built-in verifiers. Idempotent."""

    import cremore_aws_provider.detection.verify.aws as _aws

    from cremore.detection.verify import http as _http

    _aws.register_all()
    _http.register_all()


__all__ = [
    "VerificationResult",
    "VerificationState",
    "Verifier",
    "VerifierConfig",
    "load_default_verifiers",
    "register",
    "verifier_for",
]
