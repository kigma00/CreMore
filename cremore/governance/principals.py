"""The mail address each company sign-in carried, kept as a keyed digest per subject.

A separation-of-duties check that meets a person only by address (the owner a ticket system asked,
cremore.remediation.owner_approval) compares that address with the people on the security side of a plan, who
are known to CreMore by their sign-in subject. The verified ``email`` claim of each OIDC sign-in is kept for its
subject as an HMAC under the installation's fingerprint key; this comparison store retains neither the address
nor the claim. Team activity receipts separately retain the verified display identity (api/activity_audit.py).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import weakref

PREFIX = "principal_email:"
ACTOR = "system:principals"
_CONTEXT = b"cremore-principal-email-v1"
# repository -> {subject: the mark this process last saw stored}. Kept with the repository object itself: a new one
# that happens to get a freed one's address (id) never inherits what was written to the other.
_written: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

logger = logging.getLogger(__name__)


def mark(settings, email: str) -> str:
    """The keyed digest of an address, compared as ASCII lower case (addresses CreMore sends to are ASCII)."""
    key = hmac.new(settings.fingerprint_key_bytes, _CONTEXT, hashlib.sha256).digest()
    return hmac.new(key, email.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()


def _key(subject: str) -> str:
    return PREFIX + hashlib.sha256(subject.encode("utf-8")).hexdigest()


def remember(repo, settings, subject: str, email: str) -> None:
    """Keep the subject's address when this process has not seen it stored yet; never fails a sign-in."""
    if not subject or not isinstance(email, str) or "@" not in email or not email.isascii():
        return
    value = mark(settings, email)
    try:
        seen = _written.setdefault(repo, {})
    except TypeError:  # a repository that cannot be referenced weakly is asked every time
        seen = {}
    if seen.get(subject) == value:
        return
    try:
        key = _key(subject)
        if ((repo.get_setting(key) or {}).get("value") or {}).get("mark") != value:
            repo.put_setting(key, {"mark": value}, ACTOR)
        if len(seen) >= 10000:
            seen.clear()
        seen[subject] = value
    except Exception as exc:  # noqa: BLE001 -- the next request tries again
        logger.warning("could not keep a sign-in address: %s", type(exc).__name__)


def marks(repo, subjects) -> dict[str, str | None]:
    """Each subject's kept mark, or None when its sign-in never carried a verified address."""
    return {subject: ((repo.get_setting(_key(subject)) or {}).get("value") or {}).get("mark") for subject in subjects}
