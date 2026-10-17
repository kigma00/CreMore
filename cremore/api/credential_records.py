"""The dashboard's credential list: every credential found exposed and every one an issuer listed.

One row per credential, joined from what CreMore already keeps; nothing here calls a
provider or reads a secret:

* a finding: the exposed credential with its locations, verification, triage status,
  review and owner (``present_finding``);
* the issued-credential inventories: schema 2 metadata collections and the AWS IAM
  schema 1 collections. An issued credential joins the finding of the same credential
  by the evidence the vault comparison uses (keyed value fingerprint, GitHub token
  digest, AWS key ID); one nobody found exposed is its own row;
* the vault comparison state of each (``cremore.coverage.correlation.report``);
* what analysts added (tags, review stage, remediation steps, owner contact).

Issuer facts come from the provider's owner module when it has one (the same reading
the departed-owner check uses), else from the collected fact tree by field name.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from importlib import import_module

from cremore.api.detection_catalog import category, kind, kind_of
from cremore.api.finding_evidence import merged_locations, removal_pending
from cremore.api.finding_presenters import present_finding
from cremore.api.http_support import isoformat
from cremore.coverage.facts import unpack_facts
from cremore.db.annotation_store import AnnotationStore
from cremore.detection.custom import custom_credential_type
from cremore.governance.usage_sources import recent_sources
from cremore.onboarding.catalog import inventory_type

MAX_LOCATIONS = 10
MAX_SCOPES = 50
_STATUS = {"OPEN": "pending", "RESOLVED": "done", "FALSE_POSITIVE": "fp", "IGNORED": "ignored"}
_RISK = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
_VERIFIED = {"VERIFIED_ACTIVE": "active", "VERIFIED_INACTIVE": "failed", "VERIFIED_EXPIRED": "expired"}
_CREDENTIAL_STATUS = {"Active": "active", "Inactive": "inactive", "Revoked": "revoked"}
_ISSUED_STATE = {"ACTIVE": "active", "INACTIVE": "inactive", "DISABLED": "inactive", "EXPIRED": "expired",
                 "REVOKED": "revoked", "DELETED": "revoked"}
_ENDED = {"revoked", "expired", "inactive"}
_STORED = {"MATCHED"}
# A key ID or a public certificate seen in a vault names the credential there; neither proves the vault
# holds its value (an identifier is not a value, a public certificate is not its private key).
_NAMED = {"IDENTIFIER_ONLY", "PUBLIC_CERTIFICATE_MATCH"}
_ABSENT = {"NO_VAULT_MATCH", "IDENTIFIER_NOT_OBSERVED", "PUBLIC_CERTIFICATE_NOT_OBSERVED"}
# The dashboard names an issuer by its product.
_ISSUER = {}
_VISIBILITY = {"public": "public", "internal": "internal", "private": "private", "org": "org",
               "organization": "org", "workspace": "org"}
_TYPE_BY_PREFIX = (("fgpat:", "GITHUB_FINE_GRAINED_PAT"), ("sso:", "GITHUB_SSO_AUTHORIZED_CREDENTIAL"),
                   ("deployKey:", "GITHUB_DEPLOY_KEY"))
# The credential_type values GitHub's credential-authorizations list gives (REST "List SAML SSO authorizations").
_GITHUB_SSO_TYPES = {"personal access token": "GITHUB_CLASSIC_PAT", "SSH key": "GITHUB_SSH_KEY",
                     "OAuth app token": "GITHUB_OAUTH_TOKEN", "GitHub app token": "GITHUB_APP_USER_TOKEN"}
# Field names providers use for the same fact, most specific first.
_FIELDS = {
    "name": ("token_name", "name", "display_name", "displayName", "label", "title", "authorized_credential_title",
             "authorized_credential_note", "clientName", "user_programmatic_access_name"),
    # GitHub's access_granted_at (a fine-grained PAT's organization grant) and credential_authorized_at
    # (a SAML SSO authorization) are when an organization allowed the credential, not when it was created.
    "created": ("created_at", "createdAt", "token_created_at", "created", "created_on",
                "valid_after_time", "added_on", "issued_at"),
    "expires": ("expires_at", "expiresAt", "token_expires_at", "authorized_credential_expires_at", "valid_before_time",
                "expiry", "expires", "expires_on", "token_expiration"),
    "last_used": ("last_used_at", "token_last_used_at", "lastActiveAt", "last_active_at", "lastAccess", "last_used",
                  "lastUsed", "credential_accessed_at", "last_accessed_at", "last_active"),
    "issuer": ("owner", "login", "username", "service_account_email", "serviceAccount", "authorized_user",
               "user.name", "serviceAccount.name", "user.id", "serviceAccount.id"),
    "creator": ("created_by", "createdBy", "creator", "added_by", "created_by_user_id", "createdByUser",
                "createdBy.name", "createdBy.id"),
    "scopes": ("scopes", "token_scopes", "granular_scopes"),
}
_WRITE_WORDS = ("write", "admin", "delete", "manage", "full", "owner", "sudo", "push", "contributor", "officer",
                "data access")
_WRITE_SCOPES = {"repo", "workflow", "api", "incoming-webhook", "chat:write"}
# An IAM permission named service.resource.verb (GCP) is judged by its verb, not by words in the service's name
# (secretmanager.versions.access reads). A verb outside both lists falls back to the words above.
_IAM_PERMISSION = re.compile(r"[a-z][a-z0-9]*\.[A-Za-z]+\.([A-Za-z]+)")
_IAM_WRITES = ("create", "update", "delete", "undelete", "patch", "set")
_IAM_TOKENS = {"actAs", "getAccessToken", "getOpenIdToken", "signBlob", "signJwt", "implicitDelegation"}
_IAM_READS = ("get", "list", "access", "read", "useToDecrypt")


def _lookup(tree, names):
    """``(found, value)`` for the first of ``names`` nearest the top of an unpacked fact tree.

    A raw field the provider reported as null is found, with value None: the provider said so.
    At one depth, an earlier name wins over a later one wherever each sits.
    """
    level = [tree]
    for _ in range(5):
        following = []
        for name in names:
            for node in level:
                if not isinstance(node, dict):
                    continue
                # Some collectors preserve presence/null/unsupported separately
                # in normalized fields. A field's label is not its value.
                metadata = node.get("metadata")
                if isinstance(metadata, dict) and "state" in metadata and isinstance(node.get("name"), str):
                    if node["name"] == name:
                        # A normalized null says only that the field was null, never what null means
                        # (Atlassian: a null expiresAt is no evidence of no expiry).
                        return metadata["state"] == "present", metadata.get("value") if metadata["state"] == "present" else None
                    continue
                if (name in node and not isinstance(node[name], dict | list)) or node.get(name):
                    return True, node[name]
        for node in level:
            if isinstance(node, dict):
                metadata = node.get("metadata")
                if not (isinstance(metadata, dict) and "state" in metadata and isinstance(node.get("name"), str)):
                    following.extend(v for v in node.values() if isinstance(v, dict | list))
            elif isinstance(node, list):
                following.extend(v for v in node if isinstance(v, dict | list))
        level = following
    return False, None


def _when(value, *, end_of_day=False):
    """An ISO time from a provider's ISO text or epoch number; None for anything else."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        try:
            return _dt.datetime.fromtimestamp(value / 1000 if value > 10**11 else value, _dt.UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if len(text) == 10 and end_of_day:  # a date alone is valid through that day
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)).isoformat()


def _label(value):
    if isinstance(value, dict):
        profile = value.get("profile") if isinstance(value.get("profile"), dict) else {}
        value = (value.get("login") or value.get("username") or value.get("name") or profile.get("username")
                 or value.get("email") or value.get("display_name") or value.get("id"))
    return str(value)[:200] if isinstance(value, str | int) and not isinstance(value, bool) and value != "" else None


def _writes(name: str) -> bool | None:
    # A role named with where it holds ("Reader · /providers/Microsoft.Management/...") is judged by the role alone, and
    # an API's permission ("Office 365 Management APIs: ActivityFeed.Read") by the permission, not the API's name.
    name = name.split(" · ", 1)[0].rsplit(": ", 1)[-1]
    if verb := (match.group(1) if (match := _IAM_PERMISSION.fullmatch(name)) else None):
        if verb in _IAM_TOKENS or verb.startswith(_IAM_WRITES):
            return True
        if verb.startswith(_IAM_READS):
            return False
    lowered = name.lower()
    if lowered in _WRITE_SCOPES or any(word in lowered for word in _WRITE_WORDS):
        return True
    if "read" in lowered or lowered.endswith(":view"):
        return False
    return None


def _scopes(names) -> list[dict] | None:
    names = [str(n)[:256] for n in dict.fromkeys(names) if isinstance(n, str) and n][:MAX_SCOPES]
    return [{"name": name, "write": _writes(name)} for name in names] or None


def _permission_names(summary) -> list[str]:
    out = []
    for permission in summary.get("permissions") or []:
        if permission.get("effect") != "ALLOW":
            continue  # Denied/unknown grants are not token scopes or usable permissions.
        if permission.get("kind") in ("scope", "role"):
            out.append(permission["name"])
        elif permission.get("kind") == "permission":
            actions = [a for a in permission.get("actions") or [] if isinstance(a, str)]
            out.extend([f"{permission['name']}:{a}" for a in actions] or [permission["name"]])
    return out


def _vault(rows) -> dict:
    """The comparison's verdict for one credential's rows, counted the way the report counts it."""
    rows = [row for row in rows if row]
    if not rows:
        return {"state": "unknown", "where": [], "basis": "NOT_COMPARED", "reasons": [], "absence_basis": None}
    states = {row["state"] for row in rows}
    state, wanted = (("stored", _STORED) if states & _STORED else ("unknown", _NAMED) if states & _NAMED
                     else ("none", _ABSENT) if states & _ABSENT else ("unknown", set()))
    chosen = next((row for row in rows if row["state"] in wanted), rows[0])
    where = []
    for item in chosen.get("locations") or []:
        place = {"provider": item.get("provider") or "", "connection": item.get("connection_name") or "",
                 "reference": item.get("reference") or ""}
        if place not in where:
            where.append(place)
    return {"state": state, "where": where[:10], "basis": chosen["state"],
            "reasons": list(chosen.get("reasons") or [])[:20], "absence_basis": chosen.get("absence_basis")}


def _expiry(expires_at, known: bool) -> str:
    return "date" if expires_at else "none" if known else "unknown"


def _compatible(match, contract, key_id) -> bool:
    return (bool(key_id) and match.get("key_id") == key_id and match.get("material_kind") == "credential"
            and all(match.get(name) == contract[name] for name in ("engine_digest", "policy_digest")))


class _Index:
    """Findings' rows by the evidence an issued credential can name the same credential with."""

    def __init__(self, contract, key_id):
        self.contract, self.key_id = contract, key_id
        self.value, self.digest, self.aws = {}, {}, {}

    def add(self, cred, exposures, record):
        if cred.fingerprint:
            self.value.setdefault((cred.credential_type, cred.fingerprint), record)
            if not cred.credential_type.startswith("AWS_"):
                self.value.setdefault(("OPAQUE_VALUE", cred.fingerprint), record)
        if cred.provider == "aws" and cred.identifier and cred.credential_type in ("AWS_ACCESS_KEY", "AWS_ACCESS_KEY_ID"):
            self.aws.setdefault(cred.identifier, record)
        for exposure in exposures:
            private = (exposure.metadata or {}).get("issuer_comparison") or {}
            if not self.key_id or private.get("key_id") != self.key_id:
                continue
            if private.get("github_token_digest"):
                self.digest.setdefault(private["github_token_digest"], record)

    def entity(self, entity):
        match = (entity.get("summary") or {}).get("value_match") or {}
        if match.get("fingerprint") and _compatible(match, self.contract, self.key_id):
            if match.get("evidence") == "PROVIDER_DIGEST" and entity["provider"] == "github":
                return self.digest.get(match["fingerprint"])
            if match.get("evidence") == "VALUE":
                return (self.value.get((match.get("credential_type"), match["fingerprint"]))
                        or self.value.get(("OPAQUE_VALUE", match["fingerprint"])))
        return None


def _exposure(representative, rows, authors=()) -> dict:
    meta = representative.metadata or {}
    return {"source_type": representative.source_type, "resource_name": representative.resource_name,
            # Who last changed the file, as its code host said (cremore.governance.ownership).
            "author": next((name for source, connection_id, repository, path, name in authors
                            if (source, connection_id, repository, path) == (representative.source_type,
                                str(representative.source_connection_id), representative.resource_name, representative.location)), None),
            "location": representative.location,
            "line": representative.line_number if isinstance(representative.line_number, int) else None,
            "snippet": representative.redacted_line or None,
            "visibility": _VISIBILITY.get(str(meta.get("exposure") or "").lower(), "unknown"),
            "current": representative.status not in ("REMOVED", "FALSE_POSITIVE"),
            "removal_pending": removal_pending(representative, rows),
            "first_seen_at": isoformat(min((r.first_seen_at for r in rows if r.first_seen_at), default=None)),
            "last_seen_at": isoformat(representative.last_seen_at)}


def _exposed(finding, cred, exposures, review, notes, settings, context=None) -> dict:
    from cremore_aws_provider.investigation.permission_evidence import permission_snapshot

    from cremore.risk.verification import latest_verification

    observed = latest_verification(exposures, cred)
    view = present_finding(finding, cred, exposures, owner_review=review, settings=settings, verification=observed)
    # The finding's context summary (cremore.governance.ownership.summary), if one was read.
    known = context or {}
    facts = {fact["key"]: fact for fact in (view.get("governance") or {}).get("metadata") or []}
    verification = facts.get("verification") or {}
    state = _VERIFIED.get(verification.get("value"), "unknown")
    if state == "unknown" and cred is not None and cred.credential_status in _CREDENTIAL_STATUS:
        state = _CREDENTIAL_STATUS[cred.credential_status]
    expires = (facts.get("expires_at") or {}).get("value")
    # All locations describe one credential; an old location must not resurrect
    # scopes superseded by its most recent check elsewhere.
    scopes = ([s.strip() for s in str(observed.metadata.get("verification_scopes") or "").split(",") if s.strip()]
              if observed.state in ("verified", "restricted") else [])
    locations = merged_locations(exposures)
    # Keep current evidence visible when the bounded detail also retains history.
    locations.sort(key=lambda item: (item[0].status == "REMOVED", not removal_pending(*item)))
    active_locations = view["exposure_count"]
    pending_locations = view["removal_pending_location_count"]
    workflow = finding.workflow_status
    owner = finding.assigned_to or (cred.business_owner if cred else None)
    team = (review.assigned_team if review is not None else None) or (cred.team if cred else None)
    principal = (cred.principal_name or cred.principal_arn) if cred else None
    credential_type = view["credential_type"]
    provider = view.get("provider") or ""
    sources, sources_total, sources_more = recent_sources(cred) if cred and provider == "aws" else ([], 0, False)
    return {
        "id": "credential:" + str(finding.credential_id), "credential_id": str(finding.credential_id),
        "finding_id": str(finding.id), "entity_id": None,
        "provider": provider, "credential_type": credential_type, "category": category(credential_type),
        "kind": kind(credential_type, provider), "name": (cred.principal_name if cred else None) or None,
        "hint": view.get("identifier_hint"),
        "exposed": True, "status": _STATUS.get(workflow) or notes.get("stage") or "review",
        "exposure_state": "REMOVED" if finding.all_locations_removed else "ACTIVE",
        "all_locations_removed": finding.all_locations_removed,
        "active_location_count": active_locations,
        "removed_location_count": len(locations) - active_locations - pending_locations,
        "removal_pending_location_count": pending_locations,
        "workflow_status": workflow, "acknowledged_at": isoformat(finding.acknowledged_at),
        "resolved_at": isoformat(finding.resolved_at),
        "risk": _RISK.get(str(view.get("severity") or "").upper(), "info"),
        "verification": {"state": state, "at": verification.get("observed_at"),
                         "basis": verification.get("source") or None, "reason": verification.get("reason") or None},
        "owner": ({"name": owner, "team": team, "basis": "ASSIGNED" if finding.assigned_to else "BUSINESS_OWNER"}
                  if owner else {"name": known["owner"]["name"], "team": team or known["owner"]["team"],
                                 "basis": "CODEOWNERS", "where": known["owner"]["where"]} if known.get("owner")
                  else {"name": None, "team": team, "basis": "TEAM"} if team else None),
        "access": known.get("access"),
        "issuer": {"name": principal, "role": None, "basis": "VERIFIED_PRINCIPAL"} if principal else None,
        "exposures": [_exposure(e, rows, known.get("author_sources") or ()) for e, rows in locations[:MAX_LOCATIONS]],
        "exposure_count": view["exposure_count"], "location_count": len(locations),
        "first_seen_at": view.get("first_seen_at") or None, "last_seen_at": view.get("last_seen_at") or None,
        "created_at": None, "expires_at": expires, "expiry": _expiry(expires, False),
        "last_used": {"at": view["last_used_at"], "basis": "CREDENTIAL_USAGE"} if view.get("last_used_at") else None,
        "scopes": _scopes(scopes),
        "aws_permissions": permission_snapshot(cred.usage_snapshot, cred.principal_arn)
        if cred and provider == "aws" else None,
        "recent_sources": sources, "recent_sources_total": sources_total, "recent_sources_more": sources_more,
        "vault": _vault([]),
        "tags": list(notes.get("tags") or []), "stage": notes.get("stage"), "steps": dict(notes.get("steps") or {}),
        "contact": notes.get("contact"), "annotations_revision": notes.get("revision", 0),
        "review": view.get("owner_review"), "issued": None,
    }


def _entity_facts(entity, owners) -> dict:
    """What an issuer reported about one listed credential."""
    summary = entity.get("summary") or {}
    tree = unpack_facts(summary.get("facts") or [])
    owner = None
    if module := owners.get(entity["provider"]):
        try:
            owner = import_module(module).credential_owner(entity)
        except (KeyError, TypeError, ValueError, AttributeError):
            owner = None
    owner = owner or {}

    def fact(field, *, end_of_day=False):
        """(reported, time): reported is True when the provider named the field, even as null."""
        found, value = _lookup(tree, _FIELDS[field])
        if not found and owner.get(field + "_at") is not None:
            found, value = True, owner[field + "_at"]
        return found and value is None, _when(value, end_of_day=end_of_day)

    _, created = fact("created")
    reported_null, expires = fact("expires", end_of_day=True)
    never = reported_null or _lookup(tree, ("never_expires",))[1] is True
    _, last_used = fact("last_used")
    name = owner.get("name") or _label(_lookup(tree, _FIELDS["name"])[1])
    if name and name.startswith(("projects/", "organizations/", "subscriptions/")):
        name = name.rsplit("/", 1)[-1]
    issuer = (owner.get("label") if owner.get("relation") != "created_by" else None) or _label(_lookup(tree, _FIELDS["issuer"])[1])
    creator = _label(_lookup(tree, _FIELDS["creator"])[1])
    if owner.get("relation") == "created_by":
        creator = owner.get("label") or creator
    state = _ISSUED_STATE.get(summary.get("normalized_state"), "unknown")
    if state == "unknown" and owner.get("state") == "REVOKED_OR_EXPIRED":
        state = "revoked"
    match = summary.get("value_match") or {}
    credential_type = (owner.get("credential_type")
                       or (match.get("credential_type") if match.get("credential_type") not in (None, "UNKNOWN") else None)
                       or next((t for p, t in _TYPE_BY_PREFIX if str(entity["object_id"]).startswith(p)), None)
                       or "ISSUED_CREDENTIAL")
    if credential_type == "GITHUB_SSO_AUTHORIZED_CREDENTIAL":
        credential_type = _GITHUB_SSO_TYPES.get(tree.get("credential_type"), credential_type)
    # The inventory type the provider declares for it (cremore.onboarding.catalog), which names it
    # when nothing above did.
    declared = inventory_type(_ISSUER.get(entity["provider"], entity["provider"]), {
        "provider": entity["provider"], "object_id": entity["object_id"], "object_kind": entity.get("object_kind"),
        "facts": tree, "credential_type": credential_type})
    if declared and credential_type == "ISSUED_CREDENTIAL" and declared.get("credential_type"):
        credential_type = declared["credential_type"]
    found_scopes = _lookup(tree, _FIELDS["scopes"])[1]
    last_eight = tree.get("token_last_eight")
    observed = entity["observed_at"]
    return {"name": name, "credential_type": credential_type, "created": created, "expires": expires,
            "expiry_known": never, "last_used": last_used,
            "issuer": {"name": issuer, "role": None, "basis": entity["provider"]} if issuer else None,
            "scopes": _scopes(_permission_names(summary) or (found_scopes if isinstance(found_scopes, list) else [])),
            "state": state, "hint": "••••" + last_eight[-8:] if isinstance(last_eight, str) and last_eight else None,
            "source": {"entity_id": str(entity["id"]), "provider": entity["provider"], "origin": entity["origin"],
                       "tenant": entity["tenant"], "object_id": entity["object_id"],
                       "type": declared["id"] if declared else None,
                       "creator_name": creator,
                       "observed_at": isoformat(observed) if hasattr(observed, "isoformat") else observed}}


def _issuer_verification(found) -> dict:
    """The issuer's reported state while its latest collection still lists the credential; an older
    observation is history, never the current state."""
    at = found["source"]["observed_at"]
    if found["state"] == "unknown":
        return {"state": "unknown", "at": at, "basis": None, "reason": None}
    if found["source"].get("current") is False:
        return {"state": "unknown", "at": at, "basis": None, "reason": "ISSUER_OBSERVATION_NOT_CURRENT"}
    return {"state": found["state"], "at": at, "basis": "ISSUER_REPORTED", "reason": None}


def _later(value, than) -> bool:
    """Whether one provider time is after another; an unreadable ``than`` is no later time."""
    value, than = _when(value), _when(than)
    return bool(value) and (not than or _dt.datetime.fromisoformat(value) > _dt.datetime.fromisoformat(than))


def _merge(record, found):
    """Fill what the issuer reported into a finding's row without overriding the finding's own facts."""
    record["created_at"] = record["created_at"] or found["created"]
    record["expires_at"] = record["expires_at"] or found["expires"]
    record["expiry"] = _expiry(record["expires_at"], found["expiry_known"])
    # The newer of the finding's usage refresh and the issuer's inventory, each with its own basis.
    if found["last_used"] and (not record["last_used"] or _later(found["last_used"], record["last_used"]["at"])):
        record["last_used"] = {"at": found["last_used"], "basis": found.get("last_used_basis", "ISSUER_REPORTED")}
    record["name"] = record["name"] or found["name"]
    record["issuer"] = record["issuer"] or found["issuer"]
    record["scopes"] = record["scopes"] or found["scopes"]
    issuer = _issuer_verification(found)
    if record["verification"]["state"] == "unknown" and issuer["state"] != "unknown":
        record["verification"] = issuer
    record["issued"] = found["source"]


def _issued(rid, provider, found, vault) -> dict:
    credential_type = found["credential_type"]
    return {
        "id": rid, "credential_id": None, "finding_id": None, "entity_id": found["source"]["entity_id"],
        "provider": provider, "credential_type": credential_type, "category": category(credential_type),
        "kind": kind(credential_type, provider), "name": found["name"], "hint": found["hint"],
        "exposed": False, "status": None, "workflow_status": None, "acknowledged_at": None, "resolved_at": None,
        "exposure_state": None, "all_locations_removed": False,
        "active_location_count": 0, "removed_location_count": 0, "removal_pending_location_count": 0,
        "risk": "info" if found["state"] in _ENDED else "low",
        "verification": _issuer_verification(found),
        "owner": None, "access": None, "issuer": found["issuer"], "exposures": [], "exposure_count": 0, "location_count": 0,
        "first_seen_at": None, "last_seen_at": None, "created_at": found["created"], "expires_at": found["expires"],
        "expiry": _expiry(found["expires"], found["expiry_known"]),
        "last_used": {"at": found["last_used"], "basis": found.get("last_used_basis", "ISSUER_REPORTED")} if found["last_used"] else None,
        "scopes": found["scopes"], "vault": vault, "tags": [], "stage": None, "steps": {}, "contact": None,
        "recent_sources": [], "recent_sources_total": 0, "recent_sources_more": False,
        "annotations_revision": 0, "review": None, "issued": found["source"],
    }


def _aws_found(issued) -> dict:
    """An AWS IAM key from the schema 1 inventory, in the shape ``_entity_facts`` returns."""
    arn = issued.get("principal_arn") or issued.get("reference") or ""
    user = arn.rsplit("/", 1)[-1] if ":user/" in arn else None
    key_id = issued.get("identifier") or ""
    observed = issued.get("observed_at")
    credential_type = issued.get("credential_type") or "AWS_ACCESS_KEY"
    declared = inventory_type("aws", {"provider": "aws_iam", "object_id": key_id, "credential_type": credential_type})
    return {"name": user, "credential_type": credential_type,
            "created": _when(issued.get("created_at")),
            # An access key never expires; a service-specific credential's ExpirationDate is not collected.
            "expires": None, "expiry_known": credential_type == "AWS_ACCESS_KEY",
            "last_used": _when(issued.get("last_used_at")),
            "issuer": {"name": user, "role": "IAM_USER", "basis": "aws_iam"} if user else None, "scopes": None,
            "state": {"Active": "active", "Inactive": "inactive", "Expired": "expired"}.get(issued.get("state"), "unknown"),
            "hint": key_id[:4] + "••••••••" + key_id[-4:] if len(key_id) == 20 else None,
            "source": {"entity_id": None, "provider": "aws_iam", "origin": issued.get("connection_name") or "",
                       "tenant": issued.get("account_id") or "", "object_id": key_id,
                       "type": declared["id"] if declared else None,
                       "current": bool(issued.get("current_evidence")),
                       "last_used_status": (issued.get("iam_last_used") or {}).get("status", "NOT_COLLECTED"),
                       "iam_policies": issued.get("iam_policies"),
                       "creator": issued.get("creator"), "creator_status": issued.get("creator_status", "NOT_CONNECTED"),
                       "observed_at": isoformat(observed) if hasattr(observed, "isoformat") else observed}}


def build(repo, settings, orchestrator, *, now=None) -> dict:
    """Every credential row, the comparison's summary and whether the vault scope is confirmed."""
    from cremore.coverage.correlation import REPORT_LIMIT, report
    from cremore.coverage.metadata_correlation import current_issuer_observation
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.coverage.models import Contract
    from cremore.coverage.providers import _ADAPTERS

    now = now or _dt.datetime.now(_dt.UTC)
    orchestrator.refresh_rules()
    contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                        policy_digest=orchestrator.coverage_policy_digest).model_dump()
    key = orchestrator.config.fingerprint_key
    key_id = hashlib.sha256(key).hexdigest() if key else None
    compared = report(repo, contract, limit=REPORT_LIMIT, now=now, settings=settings, fingerprint_key_id=key_id)
    by_finding, by_entity, by_key = {}, {}, {}
    for row in compared["items"]:
        if row["origin"] == "EXPOSURE":
            by_finding[row["finding_id"]] = row
        elif row["origin"] == "ISSUANCE" and row.get("entity_id"):
            by_entity.setdefault(row["entity_id"], []).append(row)
        elif row["origin"] == "ISSUANCE" and row["issued"].get("evidence") == "ISSUED" and row["identifier"]:
            by_key.setdefault(row["identifier"], []).append(row)

    findings = repo.list_findings()
    notes = AnnotationStore(repo).many([f.id for f in findings])
    from cremore.governance.ownership import ContextStore
    from cremore.governance.response import summaries
    from cremore.governance.response_routing import owners as response_owners

    contexts = ContextStore(repo).summaries([f.id for f in findings])
    responses = summaries(repo, findings)
    assigned = response_owners(repo, settings, [f.id for f in findings], responses, now=now)
    index, out = _Index(contract, key_id), []
    # An organization rule says what its value is; its matches take that type.
    declared = {custom_credential_type(rule.name): rule.category for rule in repo.list_rules() if rule.category}
    for finding, cred, exposures in repo.findings_with_exposures([f.id for f in findings]):
        record = _exposed(finding, cred, exposures, repo.get_ownership_review(finding.id),
                          notes.get(finding.id) or {}, settings, contexts.get(finding.id))
        record["response"] = responses[str(finding.id)]
        if str(finding.id) in assigned:
            record["owner"] = assigned[str(finding.id)]
        if record["credential_type"] in declared:
            record["category"] = declared[record["credential_type"]]
            record["kind"] = kind_of(record["category"], record["provider"])
        record["vault"] = _vault([by_finding.get(str(finding.id))])
        # A false positive is not a credential; an issued key with its value stays its own row.
        if cred is not None and finding.workflow_status != "FALSE_POSITIVE":
            index.add(cred, exposures, record)
        out.append(record)

    owners = {provider: registration.owners for provider, registration in _ADAPTERS.items() if registration.owners}
    store = MetadataStore(repo)
    page = store.inventory(object_kind="credential", purpose="issuer_inventory", limit=REPORT_LIMIT, details=False)
    listed, complete = list(page["items"]), page["total"] <= len(page["items"])
    # Public keys (SSH and deploy keys, certificates) and app installations are listed as a kind a
    # provider declares for its inventory; the rest of those kinds are context, not credentials.
    for other in ("public_key", "installation"):
        extra = store.inventory(object_kind=other, purpose="issuer_inventory", limit=REPORT_LIMIT, details=False)
        complete = complete and extra["total"] <= len(extra["items"])
        listed.extend(extra["items"])
    usage = store.latest_usage([entity["id"] for entity in listed])
    creators = store.explicit_creators([entity["id"] for entity in listed])
    # Whether each issuer's latest collection still lists the credential (the report's own test).
    store.inventory_details(listed)
    collections = {row["id"]: row for row in store.list_connections()}
    for entity in listed:
        found = _entity_facts(entity, owners)
        found["source"]["current"] = current_issuer_observation(
            entity, collections.get((entity["observation_run"] or {}).get("connection_id")), now=now)
        if entity["id"] in creators:
            found["source"]["creator_name"] = creators[entity["id"]]
        observed_use = usage.get(entity["id"])
        if observed_use and (not found["last_used"] or observed_use["at"] > found["last_used"]):
            found.update(last_used=observed_use["at"], last_used_basis=observed_use["basis"])
        if entity.get("object_kind") != "credential" and not found["source"]["type"]:
            continue
        if (linked := index.entity(entity)) is not None:
            _merge(linked, found)
            continue
        out.append(_issued("issued:" + str(entity["id"]), _ISSUER.get(entity["provider"], entity["provider"]), found,
                           _vault(by_entity.get(str(entity["id"]), []))))
    snapshots = store.snapshot_matches(index.digest, limit=REPORT_LIMIT)
    complete = complete and not snapshots["truncated"]
    for entity in snapshots["items"]:
        if (linked := index.entity(entity)) is not None and linked["issued"] is None:
            found = _entity_facts(entity, owners)
            found["source"]["snapshot_observation"] = True
            _merge(linked, found)
    # Unmatched snapshot rows never manufacture additional unique credentials.
    for key_id_, rows in by_key.items():
        rows.sort(key=lambda row: not row["issued"].get("current_evidence"))
        found = _aws_found(rows[0]["issued"])
        if (linked := index.aws.get(key_id_)) is not None:
            _merge(linked, found)
            continue
        out.append(_issued("issued:aws:" + key_id_, "aws", found, _vault(rows)))
    return {"items": out, "total": len(out),
            "complete": bool(compared["summary"].get("complete", True)) and complete,
            "scope_confirmed": compared["scope_confirmed"], "scope_reasons": compared["scope_reasons"],
            "coverage": compared["summary"], "generated_at": now.isoformat()}
