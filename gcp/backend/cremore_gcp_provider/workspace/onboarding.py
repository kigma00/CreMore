"""Google Workspace in the connection wizard (cremore.onboarding): the departed-owner check's people.

A Google Cloud service account holds a key; the Workspace admin console allows its client ID one scope,
``admin.directory.user.readonly``, by domain-wide delegation, and CreMore acts as the super administrator named
here. The check signs in, confirms that administrator is a super administrator and reads one page of each listing
with the collection's own reader.
"""

from __future__ import annotations

from cremore_gcp_provider.workspace.identity import (
    ADMIN,
    DOMAIN,
    MAX_RECORDS,
    ORIGIN,
    PAGE_MAX,
    SOURCES,
    client_id,
    reader,
    service_account,
)

_PEOPLE = {"name": "people_details", "kind": "bool", "default": True,
           "label": "Keep people's names, emails and departments (owners and contacts)",
           "label_ko": "사람 이름·이메일·부서 보관(담당자·연락 대상 표시)"}

DESCRIPTORS = [{
    "provider": "google_workspace",
    "label": "Google Workspace", "label_ko": "Google Workspace",
    "category": "identity",
    "editions": [{"id": "cloud", "label": "Google Workspace", "label_ko": "Google Workspace"}],
    "target": [{"name": "domain", "label": "Primary domain", "label_ko": "기본 도메인", "kind": "text", "required": True,
                "hint": "acme.com"}],
    "purposes": {"identity": {"permissions": [
        {"id": "users_read", "label": "https://www.googleapis.com/auth/admin.directory.user.readonly (domain-wide delegation)",
         "label_ko": "https://www.googleapis.com/auth/admin.directory.user.readonly(도메인 전체 위임)"}],
        "plan": [{"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes)",
                  "label_ko": "수집 주기(분)", "default": 60, "min": 0, "max": 10080}, _PEOPLE]}},
    "auth_methods": [{"id": "service_account_delegation", "reference_keys": ["private_key", "username"],
                      "auth_first": {"context": ["domain"]},
                      "label": "Service account with domain-wide delegation",
                      # A user-managed key expires only when an organization policy (iam.serviceAccountKeyExpiryHours) says
                      # so, as recommended; its date can then be entered for reminders.
                      "label_ko": "서비스 계정(도메인 전체 위임)", "renewal": "EXPIRES", "purposes": ["identity"],
                      "fields": [{"name": "username", "label": "Super administrator to act as",
                                  "label_ko": "위임받을 최고 관리자 이메일", "kind": "text"},
                                 {"name": "private_key", "label": "Service account key (JSON)",
                                  "label_ko": "서비스 계정 키(JSON)", "kind": "multiline", "secret": True}]}],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    domain = str(values.get("domain", "")).strip().lower().removeprefix("https://").rstrip("/")
    if not DOMAIN.fullmatch(domain):
        raise OnboardingValueError("GOOGLE_WORKSPACE_DOMAIN_INVALID")
    return {"domain": domain}


def sign_in_target(provider, issuer):
    """Google sign-in names no Workspace domain in its issuer: any domain until the installation names its own
    (cremore.onboarding.sign_in)."""
    return {} if issuer.rstrip("/") in ("https://accounts.google.com", "accounts.google.com") else None


def credential(provider, method, fields):
    admin, key = str(fields.get("username", "")).strip(), str(fields.get("private_key", "")).strip()
    local, at, domain = admin.rpartition("@")
    admin = f"{local}@{domain.lower()}" if at else admin  # a domain is case-insensitive; the tenant is lower case
    if not ADMIN.fullmatch(admin):
        raise OnboardingValueError("GOOGLE_WORKSPACE_ADMIN_INVALID")
    try:
        service_account(key)
    except ValueError:
        raise OnboardingValueError("GOOGLE_WORKSPACE_KEY_INVALID") from None
    return {"credential": {"private_key": key, "username": admin}}


def spec(connection, schedule=60, people=False):
    domain = connection["target"]["domain"]
    return {"schema_version": 2, "provider": "google_workspace", "name": f"Google Workspace · {domain}", "origin": ORIGIN,
            "edition": "cloud", "tenant": domain, "tenant_confirmed": True,
            "scopes": [{"kind": "organization", "id": domain}], "capabilities": ["identity_status"],
            "auth_type": "private_key_jwt",
            "options": {"mode": "inventory", "page_size": PAGE_MAX, **({"keep_profiles": True} if people else {})},
            "max_records": MAX_RECORDS, "schedule_minutes": schedule}


auth_context = target


def authenticate(connection, secrets, context):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer, ReadError

    model = MetadataConnectionSpec.model_validate({**spec(connection), "secret_refs": {
        "private_key": "vault://onboarding/check", "username": "vault://onboarding/check"}})
    with context.http_client() as client:
        read = reader(model, dict(secrets["credential"]), client, Pacer(model, lambda: None))
        try:
            read._require_super_admin()
            return {"status": "GRANTED", "subject": connection["target"]["domain"]}
        except ReadError as exc:
            return {"status": "MISSING" if not exc.retryable else "ERROR", "detail": exc.code}
        finally:
            read.close()


def discover(connection, secrets, context):
    return [{"label": connection["target"]["domain"], "target": {"domain": connection["target"]["domain"]}}], "COMPLETE"


def check(connection, purpose, secrets, context):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer, ReadError

    model = MetadataConnectionSpec.model_validate({**spec(connection), "secret_refs": {
        "private_key": "vault://onboarding/check", "username": "vault://onboarding/check"}})
    envelope = dict(secrets.get("credential") or {})
    client = context.http_client()
    try:
        read = reader(model, envelope, client, Pacer(model, lambda: None))
        try:
            for source in SOURCES:  # a collection reads both: the check says GRANTED only when both answer
                read.read(model.scopes[0], source.name, None)
        except ReadError as exc:
            if exc.code == "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED":
                # The client ID the admin console's domain-wide delegation must allow the scope for.
                named = client_id(envelope.get("private_key", ""))
                return [{"permission": "users_read", "status": "MISSING", "detail": exc.code,
                         **({"subject": named} if named else {})}]
            refused = exc.code.endswith(("_ACCESS_DENIED", "_TOKEN_REFUSED", "_ADMIN_INVALID", "_ADMIN_OUTSIDE_DOMAIN",
                                         "_ADMIN_NOT_SUPER_ADMIN", "_API_NOT_ENABLED", "_KEY_INVALID"))
            return [{"permission": "users_read", "status": "MISSING" if refused else "ERROR", "detail": exc.code}]
        finally:
            read.close()
        return [{"permission": "users_read", "status": "GRANTED"}]
    finally:
        client.close()


def role_group_members(connection, secrets, client, groups):
    """``{group: [address]}``: who is in each group that gives console roles to people who sign in with Google
    (cremore.identity.sign_in_groups), people in groups inside it included. Read in the worker with a token holding
    admin.directory.group.member.readonly alone, which the admin console's domain-wide delegation must allow too."""
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.identity.idp import Pacer
    from cremore_gcp_provider.workspace.identity import GROUP_SCOPE, Reader

    model = MetadataConnectionSpec.model_validate({**spec(connection), "secret_refs": {
        "private_key": "vault://sign-in/groups", "username": "vault://sign-in/groups"}})
    read = Reader(model, dict(secrets.get("credential") or {}), client, Pacer(model, lambda: None), scope=GROUP_SCOPE)
    try:
        return {group: read.group_members(group) for group in groups}
    finally:
        read.close()


def children(connection, purpose, plan):
    return [{"kind": "metadata", "purpose": purpose,
             "spec": spec(connection, plan.get("schedule_minutes", 60), bool(plan.get("people_details"))),
             "secret_slots": {"private_key": "credential", "username": "credential"}}]
