"""One durable export reservation per GitHub origin and Enterprise.

GitHub documents a small daily export allowance without an exact number. The
product conservatively creates at most one export per rolling 24 hours; normal
organization and audit reads do not consume this allowance. Confirmed exports
can be re-read by another connection without creating another one.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime, timedelta

from cremore.coverage.errors import CoverageError
from cremore.coverage.store import utc
from cremore.db.settings_store import locked_settings

INTERVAL = timedelta(hours=24)
ACTOR = "github-export"
_STAGES = {"reserved", "submitting", "queued", "reading", "complete", "quota_wait", "submission_unknown", "rejected", "failed"}


def _reusable(state):
    return bool(state.get("export_id") and state.get("error") not in {
        "github_export_expired", "github_export_identity_changed", "github_export_snapshot_changed",
        "github_export_content_changed", "github_export_failed", "github_export_unavailable_or_not_authorized"})


def applicable(spec):
    raw = spec.model_dump() if hasattr(spec, "model_dump") else spec
    return (raw.get("provider") == "github" and raw.get("schema_version") == 2
            and raw.get("options", {}).get("mode") == "enterprise"
            and raw.get("options", {}).get("github_inventory", True))


def key_for(spec):
    raw = spec.model_dump() if hasattr(spec, "model_dump") else spec
    enterprise = next(scope["id"] for scope in raw["scopes"] if scope["kind"] == "enterprise")
    identity = raw["origin"].lower().rstrip("/") + "|" + enterprise.casefold()
    return "github-export:" + hashlib.sha256(identity.encode()).hexdigest()


def state_for(repo, spec):
    if not applicable(spec):
        return {}
    return dict((repo.get_setting(key_for(spec)) or {}).get("value") or {})


def next_create_at(repo, spec):
    value = state_for(repo, spec).get("next_create_at")
    return utc(datetime.fromisoformat(value)) if value else None


def public_state(repo, spec, *, now=None):
    state = state_for(repo, spec)
    if not state:
        return {}
    now = utc(now or datetime.now(UTC))
    waiting = bool(state.get("next_create_at") and now < utc(datetime.fromisoformat(state["next_create_at"])))
    # A confirmed export's as_of may still be null internally; the public field stays a string or absent.
    return {**{key: state[key] for key in ("stage", "as_of", "submitted_at", "next_create_at", "last_success_at", "error")
               if state.get(key) is not None}, "creation_allowed": not waiting,
            "reuse_available": bool(waiting and _reusable(state)),
            "request_blocked_reason": request_refusal(repo, spec, now=now, state=state)}


def request_refusal(repo, spec, *, now=None, state=None):
    """Read-only early feedback. The fenced worker reservation remains authoritative."""
    state = state_for(repo, spec) if state is None else state
    now = utc(now or datetime.now(UTC))
    if (not state.get("next_create_at") or now >= utc(datetime.fromisoformat(state["next_create_at"]))
            or _reusable(state)):
        return None
    return ("GITHUB_EXPORT_SUBMISSION_UNKNOWN" if state.get("stage") in {"submitting", "submission_unknown"}
            else "GITHUB_EXPORT_QUOTA_WAIT")


def job_state(repo, job):
    """Current Enterprise state, never an export handle or a signed URL."""
    from cremore.coverage import METADATA_JOB_KIND
    from cremore.coverage.metadata_store import MetadataStore

    if job.kind != METADATA_JOB_KIND or not job.payload.get("coverage_connection_id"):
        return None
    row = MetadataStore(repo).get(uuid.UUID(job.payload["coverage_connection_id"]))
    if row is None or row["revision"] != job.payload.get("coverage_revision") or not applicable(row["spec"]):
        return None
    return public_state(repo, row["spec"])


class ExportControl:
    """Fenced worker service; the provider never imports repositories or SQL."""

    def __init__(self, repo, spec, job_id, *, context, now=None):
        self.repo, self.key, self.job_id = repo, key_for(spec), str(job_id)
        self.context, self.now = context, now or (lambda: datetime.now(UTC))
        self.lock = self.key + ":lock"
        if repo.get_setting(self.lock) is None:
            repo.claim_slot(self.lock, 0, ACTOR)

    def reserve(self):
        now = utc(self.now())
        with self.context() as repo, locked_settings(repo, setting_key=self.lock) as bound:
            current = dict((bound.get_setting(self.key) or {}).get("value") or {})
            eligible = utc(datetime.fromisoformat(current["next_create_at"])) if current.get("next_create_at") else now
            if now < eligible:
                if _reusable(current):
                    # The same immutable export, checked again by GitHub with
                    # this connection's own Enterprise installation token.
                    return {"stage": "queued", **{key: current[key] for key in
                        ("export_id", "as_of", "submitted_at", "warnings") if key in current}}
                if current.get("job_id") == self.job_id and current.get("stage") == "reserved":
                    return {"stage": "reserved"}
                stage = "submission_unknown" if current.get("stage") in {"submitting", "submission_unknown"} else "quota_wait"
                return {"stage": stage, "next_create_at": eligible.isoformat()}
            current = {"stage": "reserved", "job_id": self.job_id,
                       "next_create_at": (now + INTERVAL).isoformat(),
                       **({"last_success_at": current["last_success_at"]} if current.get("last_success_at") else {})}
            bound.put_setting(self.key, current, ACTOR)
            return {"stage": "reserved"}

    def save(self, state):
        stage = state.get("stage")
        if stage not in _STAGES:
            raise CoverageError("GITHUB_EXPORT_STATE_INVALID")
        safe = {"stage": stage}
        if "export_id" in state:
            if not isinstance(state["export_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", state["export_id"]):
                raise CoverageError("GITHUB_EXPORT_STATE_INVALID")
            safe["export_id"] = state["export_id"]
        for field in ("as_of", "submitted_at"):
            if field == "as_of" and field in state and state[field] is None:
                safe[field] = None  # GitHub documents a confirmed export's as_of as nullable.
            elif field in state:
                try:
                    parsed = datetime.fromisoformat(state[field])
                    if parsed.tzinfo is None:
                        raise ValueError
                    safe[field] = utc(parsed).isoformat()
                except (ValueError, TypeError):
                    raise CoverageError("GITHUB_EXPORT_STATE_INVALID") from None
        if "export_id" in safe and "as_of" not in safe:
            raise CoverageError("GITHUB_EXPORT_STATE_INVALID")
        if "error" in state:
            if not isinstance(state["error"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", state["error"]):
                raise CoverageError("GITHUB_EXPORT_STATE_INVALID")
            safe["error"] = state["error"]
        if "warnings" in state:
            safe["warnings"] = ["github_inventory_metadata_incomplete"] if state["warnings"] else []
        with self.context() as repo, locked_settings(repo, setting_key=self.lock) as bound:
            current = dict((bound.get_setting(self.key) or {}).get("value") or {})
            if current.get("job_id") != self.job_id:
                # Readers sharing an already confirmed export cannot replace
                # its reservation or consume another Enterprise allowance.
                if safe.get("export_id") and safe["export_id"] == current.get("export_id"):
                    return
                raise CoverageError("GITHUB_EXPORT_RESERVATION_LOST")
            if current.get("export_id") and safe.get("export_id") != current["export_id"]:
                raise CoverageError("GITHUB_EXPORT_ID_CHANGED")
            changed = {**current, **safe}
            if stage == "rejected":
                changed["next_create_at"] = utc(self.now()).isoformat()
            if stage == "quota_wait":
                seconds = state.get("retry_after_seconds", 86400)
                if isinstance(seconds, bool) or not isinstance(seconds, int) or not 0 < seconds <= 604800:
                    raise CoverageError("GITHUB_EXPORT_STATE_INVALID")
                changed["next_create_at"] = max(datetime.fromisoformat(changed["next_create_at"]),
                    utc(self.now()) + timedelta(seconds=max(86400, seconds))).isoformat()
            if stage == "complete":
                changed["last_success_at"] = utc(self.now()).isoformat()
                changed.pop("error", None)
            bound.put_setting(self.key, changed, ACTOR)
