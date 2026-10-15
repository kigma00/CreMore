"""Safe evidence contract for a configured connection credential."""
import datetime as dt
from dataclasses import dataclass, field

ACTIVE, REJECTED, INDETERMINATE = "ACTIVE", "REJECTED", "INDETERMINATE"

@dataclass(frozen=True)
class CredentialCheck:
    status: str  # ACTIVE | REJECTED | INDETERMINATE
    owner: str = ""
    workspace: str = ""
    scopes: tuple[str, ...] = ()
    error: str = ""  # short safe label (HTTP status / exception class), never a message
    detail: dict = field(default_factory=dict)

    def as_evidence(self, checked_at: str) -> dict:
        evidence = {"status": self.status, "owner": self.owner, "workspace": self.workspace,
                    "scopes": list(self.scopes), "error": self.error, "checked_at": checked_at}
        if self.detail.get("credential_mode") in ("GITHUB_APP", "ADC", "GOOGLE_OAUTH"):
            evidence["credential_mode"] = self.detail["credential_mode"]
            evidence["refresh_supported"] = self.detail.get("refresh_supported") is True
            expires_at = self.detail.get("expires_at")
            if isinstance(expires_at, str) and len(expires_at) <= 64:
                try:
                    parsed = dt.datetime.fromisoformat(expires_at)
                except ValueError:
                    parsed = None
                if parsed and parsed.tzinfo:
                    evidence["expires_at"] = parsed.astimezone(dt.UTC).isoformat()
        return evidence
