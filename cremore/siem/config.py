"""Exporter-only configuration: no scanner settings, keys or source credentials."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Destination(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    options: dict[str, object] = Field(default_factory=dict, max_length=32)
    # native: CreMore's schema v1. ocsf: OCSF 1.3.0 where a class fits the
    # event (findings, departed owners, vault verdicts, admin actions); the
    # rest stays native. See cremore/siem/formats.py.
    format: Literal["native", "ocsf"] = "native"

    @model_validator(mode="after")
    def encodings_agree(self):
        if self.format == "ocsf" and self.options.get("message_format") in ("cef", "leef"):
            # CEF and LEEF encode the native event; they are not OCSF carriers.
            raise ValueError("SIEM_FORMAT_CONFLICT")
        return self


class ExportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    schema_version: int = 1
    destinations: list[Destination] = Field(min_length=1, max_length=32)
    allow_plugins: list[str] = Field(default_factory=list, max_length=32)
    poll_seconds: float = Field(default=5.0, ge=0.2, le=3600)
    batch_size: int = Field(default=100, ge=1, le=1000)
    # 0 keeps retrying (with the backoff capped at an hour) so a SIEM outage recovers by
    # itself. A positive value holds an event after that many failed attempts, for an
    # Admin to release (POST /api/v1/siem/destinations/{id}/release-held).
    max_attempts: int = Field(default=0, ge=0, le=1000)

    @model_validator(mode="after")
    def unique_destinations(self):
        if self.schema_version != 1:
            raise ValueError("SIEM_CONFIG_VERSION_UNSUPPORTED")
        if len({item.id for item in self.destinations}) != len(self.destinations):
            raise ValueError("SIEM_DESTINATION_DUPLICATE")
        external = set(self.allow_plugins)
        if len(external) != len(self.allow_plugins) or not external.issubset(
            {item.provider for item in self.destinations}
        ):
            raise ValueError("SIEM_PLUGIN_ENABLEMENT_INVALID")
        return self


def load_config(path: str) -> ExportConfig:
    try:
        with Path(path).open("rb") as source:
            raw = source.read(131073)
        if len(raw) > 131072:
            raise ValueError("SIEM_CONFIG_TOO_LARGE")
        return ExportConfig.model_validate(json.loads(raw))
    except (OSError, ValueError):
        # Pydantic/JSON errors can otherwise repeat configuration credentials.
        raise ValueError("SIEM_CONFIG_INVALID") from None
