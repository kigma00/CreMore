# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/identities.py).
"""Source-local record identities and list quality; never deduplicate metadata."""

from .specs import SOURCES

CLOUD_IDS = {name: (spec["id_field"],) for name, spec in SOURCES.items()}
CLOUD_IDS.update(
    {
        "service-accounts": ("atlassianId", "id"),
        "managed-accounts": ("account_id",),
        "service-account-api-tokens-by-account": ("id",),
        "service-account-oauth-clients-by-account": ("clientId",),
        "user-api-tokens": ("id",),
    }
)
BITBUCKET_IDS = {
    "workspace-members": ("user.uuid",),
    "projects": ("uuid",),
    "repositories": ("uuid",),
    "user-ssh-keys": ("uuid",),
    "user-gpg-keys": ("fingerprint",),
    "workspace-gpg-key": ("fingerprint",),
    "project-deploy-keys": ("id",),
    "repository-deploy-keys": ("id",),
    "pipeline-known-hosts": ("uuid",),
    "workspace-runners": ("uuid",),
    "repository-runners": ("uuid",),
    "repository-branch-restrictions": ("id",),
    "workspace-oidc-keys": ("kid",),
}


def record_identity(row, fields):
    """Use only an explicitly selected provider ID, with its original JSON type."""
    if type(row) is not dict:
        return None
    for field in fields:
        value = row
        for part in field.split("."):
            value = value.get(part) if type(value) is dict else None
        if (
            type(value) is str
            and 0 < len(value) <= 1024
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
        ) or (type(value) is int and value >= 0):
            return {"field": field, "value": value}
    return None


class RecordQuality:
    """Bounded by saved records; one instance per operation/target collection."""

    def __init__(self, fields):
        self.fields = fields
        self._seen = set()
        self.counts = dict.fromkeys(
            (
                "assessed_records",
                "identified_records",
                "unique_identities",
                "duplicate_records",
                "invalid_records",
                "unidentified_records",
                "identity_not_configured_records",
            ),
            0,
        )

    def observe(self, rows):
        for row in rows:
            self.counts["assessed_records"] += 1
            if type(row) is not dict:
                self.counts["invalid_records"] += 1
                continue
            if not self.fields:
                self.counts["identity_not_configured_records"] += 1
                continue
            identity = record_identity(row, self.fields)
            if identity is None:
                self.counts["unidentified_records"] += 1
                continue
            self.counts["identified_records"] += 1
            value = identity["value"]
            key = (identity["field"], type(value), value)
            if key in self._seen:
                self.counts["duplicate_records"] += 1
            else:
                self._seen.add(key)
                self.counts["unique_identities"] += 1

    def reason(self):
        if self.counts["invalid_records"] or self.counts["unidentified_records"]:
            return "unidentifiable_records"
        if self.counts["duplicate_records"]:
            return "duplicate_record_identities"
        if self.counts["identity_not_configured_records"]:
            return "record_identity_not_configured"
        return None
