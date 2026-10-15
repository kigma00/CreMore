"""Auto-triage of learned false positives, configured from the dashboard.

This is detection policy, not deployment plumbing: the threshold and the sample
floor decide which findings get suppressed without anyone looking at them. An
operator who cannot edit the deployment could neither see nor tune that, and a
change left no trace. Everything now lives in ``installation_settings``, so the
dashboard shows the live policy and the setting record carries who changed it
and when.

``LEARNED_FP_MODE=disabled`` hard-locks auto-triage off for the whole
installation, the way the scan toggles do. ``LEARNED_FP_THRESHOLD``,
``LEARNED_FP_MIN_SAMPLES`` and ``LEARNED_FP_MAX_CONFIDENCE`` stay as optional
pins for an installation that wants the policy fixed in configuration.

Auto-triage is off until someone turns it on. Nothing is suppressed by default.
"""

from __future__ import annotations

KEY = "learned_false_positives"
CONFIDENCE_LEVELS = ("low", "medium", "high")
# A profile needs at least this many samples before it can suppress anything,
# whatever an Admin asks for; two distinct actors are required separately.
MIN_SAMPLE_FLOOR = 2
DEFAULTS = {"threshold": 0.85, "min_samples": 3, "max_confidence": "medium"}


def _stored(repo) -> tuple[dict, dict]:
    record = repo.get_setting(KEY) or {}
    return (record.get("value") or {}), record


def stored(repo) -> dict:
    """The saved policy, so a caller can change one field and write it back."""
    return _stored(repo)[0]


def _pinned_float(settings, name: str) -> float | None:
    """A configured pin, or None. Zero means "unset", never a real threshold."""
    value = getattr(settings, name, None)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 1:
        return None
    return float(value)


def config(settings, repo) -> dict:
    """The effective auto-triage policy, and which parts configuration pins."""
    stored, record = _stored(repo)
    allowed = bool(getattr(settings, "learned_fp_allowed", True))

    threshold = stored.get("threshold")
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0 < threshold <= 1:
        threshold = DEFAULTS["threshold"]
    samples = stored.get("min_samples")
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < MIN_SAMPLE_FLOOR:
        samples = DEFAULTS["min_samples"]
    confidence = str(stored.get("max_confidence") or "").lower()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = DEFAULTS["max_confidence"]

    # A configured value wins over the dashboard for that one field.
    pins = {
        "threshold": _pinned_float(settings, "learned_fp_threshold_pin"),
        "min_samples": getattr(settings, "learned_fp_min_samples_pin", None) or None,
        "max_confidence": (getattr(settings, "learned_fp_max_confidence_pin", "") or "").lower() or None,
    }
    return {
        "enabled": allowed and stored.get("enabled", False) is True,
        "switch": stored.get("enabled", False) is True,
        "installation_allows": allowed,
        "threshold": pins["threshold"] if pins["threshold"] is not None else threshold,
        "threshold_locked": pins["threshold"] is not None,
        "min_samples": max(MIN_SAMPLE_FLOOR, int(pins["min_samples"] or samples)),
        "min_samples_locked": pins["min_samples"] is not None,
        "max_confidence": pins["max_confidence"] if pins["max_confidence"] in CONFIDENCE_LEVELS else confidence,
        "max_confidence_locked": pins["max_confidence"] in CONFIDENCE_LEVELS,
        "updated_by": record.get("updated_by") or None,
        "updated_at": record.get("updated_at"),
    }
