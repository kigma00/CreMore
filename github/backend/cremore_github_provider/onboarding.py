"""GitHub in the connection wizard (cremore.onboarding): descriptor, credential, check and records.

A GitHub App serves repository scans, the organization's credential inventory and its
Actions secret metadata; its installation token names the permissions it holds, so the
check compares them with what each purpose reads. Whose login is which person comes from
the organization's SAML and SCIM identities (the App with "Members: read", or an organization
owner's classic token with ``read:org``) or, for managed users and SAML set on the enterprise,
the enterprise's (an enterprise owner's classic token, ``read:enterprise``, never an App);
GitHub reports a classic token's scopes in ``X-OAuth-Scopes``. A GitHub App of its own, with
"Personal access tokens: write", revokes a fine-grained token's organization access an
approved plan names (cremore_github_provider.remediation).
"""

from __future__ import annotations

import base64
import re

from cremore.http_client import bounded_request
from cremore_github_provider.github_hosts import api_base, normalize_host, web_base

_ORG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_TOKEN = re.compile(r"[\x21-\x7e]{20,255}")
_LEVELS = {"read": 1, "write": 2, "admin": 3}
_PEOPLE = {"name": "people_details", "kind": "bool", "default": True,
           "label": "Keep people's names, emails and departments (owners and contacts)",
           "label_ko": "사람 이름·이메일·부서 보관(담당자·연락 대상 표시)"}
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}

# The App permission (read) each purpose's reads need, as GitHub names them.
APP_PERMISSIONS = {
    "exposure": ("metadata", "contents"),
    "inventory": ("organization_administration", "organization_personal_access_tokens",
                  "organization_personal_access_token_requests", "administration"),
    # Listing a repository's environments (before their secrets) is under Actions: read in GitHub's App permissions.
    "vault": ("organization_secrets", "secrets", "environments", "actions"),
    # GraphQL ExternalIdentity: with SAML set on the organization, shown to an App installation with Members (read).
    "identity": ("members",),
}
# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state). The organization
# APIs give the grant or SSO authorization time; the Enterprise credential inventory gives creation.
_GRANTED = ["조직 접근이 승인된 시각만 줍니다. 엔터프라이즈 인벤토리를 연결하면 생성일을 줍니다",
            "Only the time access to the organization was granted; the Enterprise inventory gives creation"]
_AUTHORIZED = ["SSO 승인 시각만 줍니다. 엔터프라이즈 인벤토리를 연결하면 생성일을 줍니다",
               "Only the SSO authorization time; the Enterprise inventory gives creation"]
_LISTED = ["승인된 동안 목록에 있고, 폐기되면 목록에서 빠집니다", "Listed while authorized; a revoked one leaves the list"]
_CREATOR = ["목록의 소유자·승인자를 생성자로 추정하지 않습니다. 별도 생성 근거는 현재 미지원입니다",
            "The owner or authorizer is not assumed to be the creator; separate creation evidence is not implemented"]
_SSO = {"prefix": "sso:", "fact": "credential_type"}
# The four SSO-authorized types come from an organization's SAML SSO credential authorizations or the Enterprise
# credential export (their inventory: rows). Enterprise Server has neither (no /orgs/{org}/credential-authorizations,
# and onboarding_export does not offer the export there), so a Server lists none of them.
_SSO_EDITIONS = ["cloud", "enterprise_cloud", "dedicated"]
_INVENTORY = {"prefix": "inventory:", "fact": "credential_type"}
_EXPORT_FIELDS = {name: ["Export가 제공한 값만 표시하며 빈 값은 미확인입니다",
                        "Shown only when reported by the export; blank values are unknown"]
                  for name in ("name", "created", "expires", "scopes", "owner", "last_used", "state")}
INVENTORY_TYPES = [
    {"id": "fine_grained_pat", "label": "Fine-grained PAT", "label_ko": "세분화 PAT(fine-grained)",
     "description": "Expiry, repositories and permissions of fine-grained tokens approved for the organization.",
     "description_ko": "조직 저장소 접근이 승인된 세분화 토큰의 만료일·저장소·권한을 가져옵니다.",
     "permission": "organization_personal_access_tokens", "credential_type": "GITHUB_FINE_GRAINED_PAT",
     "match": [{"prefix": "fgpat:"}, {**_INVENTORY, "in": ["fine_grained_pat"]}],
     "support": "YYPYYNYYY", "reasons": {"created": _GRANTED, "creator": _CREATOR}},
    {"id": "classic_pat", "label": "Classic PAT (SSO-authorized)", "label_ko": "Classic PAT(SSO 승인)",
     "description": "Classic tokens authorized for the SAML SSO organization; a token never authorized for it is not listed.",
     "description_ko": "SAML SSO 조직에 승인된 Classic 토큰입니다. 조직에 승인하지 않은 토큰은 목록에 없습니다.",
     "permission": "organization_administration", "credential_type": "GITHUB_CLASSIC_PAT", "editions": _SSO_EDITIONS,
     "match": [{**_SSO, "in": ["personal access token"]}, {**_INVENTORY, "in": ["classic_pat"]}],
     "support": "YYPYYNYYP", "reasons": {"created": _AUTHORIZED, "state": _LISTED, "creator": _CREATOR}},
    {"id": "oauth_app_token", "label": "OAuth app token (SSO-authorized)", "label_ko": "OAuth 앱 토큰(SSO 승인)",
     "description": "Tokens members granted to OAuth apps and authorized for the organization.",
     "description_ko": "구성원이 OAuth 앱에 허용하고 조직에 승인한 토큰입니다.",
     "permission": "organization_administration", "credential_type": "GITHUB_OAUTH_TOKEN", "editions": _SSO_EDITIONS,
     "match": [{**_SSO, "in": ["OAuth app token"]}, {**_INVENTORY, "in": ["oauth_app_user_token"]}],
     "support": "YYPNYNYYP", "reasons": {"created": _AUTHORIZED, "state": _LISTED, "creator": _CREATOR,
                                         "expires": ["OAuth 앱 토큰에는 만료일이 없습니다", "OAuth app tokens do not expire"]}},
    {"id": "github_app_user_token", "label": "GitHub App user token (SSO-authorized)",
     "label_ko": "GitHub App 사용자 토큰(SSO 승인)",
     "description": "Tokens GitHub Apps act with on behalf of members, authorized for the organization.",
     "description_ko": "GitHub App이 구성원 대신 쓰는 토큰으로, 조직에 승인된 것입니다.",
     "permission": "organization_administration", "credential_type": "GITHUB_APP_USER_TOKEN", "editions": _SSO_EDITIONS,
     "match": [{**_SSO, "in": ["GitHub app token"]}, {**_INVENTORY, "in": ["github_app_user_token"]}],
     "support": "YYPPYNYYP", "reasons": {"created": _AUTHORIZED, "state": _LISTED, "creator": _CREATOR,
                                         "expires": ["토큰 만료를 켠 앱의 토큰만 만료일이 있습니다",
                                                     "Only apps with token expiration give an expiry"]}},
    {"id": "ssh_key", "label": "SSH key (SSO-authorized)", "label_ko": "SSH 키(SSO 승인)",
     "description": "Fingerprints and dates of members' SSH keys authorized for the organization.",
     "description_ko": "조직에 승인된 구성원 SSH 키의 지문과 날짜입니다.",
     "permission": "organization_administration", "credential_type": "GITHUB_SSH_KEY", "editions": _SSO_EDITIONS,
     "match": [{**_SSO, "in": ["SSH key"]}, {**_INVENTORY, "in": ["ssh_key", "SSH key"]}],
     "support": "YYPNNNYYP", "reasons": {"created": _AUTHORIZED, "state": _LISTED, "creator": _CREATOR,
                                         "expires": ["SSH 키에는 만료일이 없습니다", "SSH keys do not expire"],
                                         "scopes": ["SSH 키는 사용자의 권한을 그대로 씁니다", "An SSH key acts with its user's access"]}},
    {"id": "deploy_key", "label": "Deploy key", "label_ko": "배포 키",
     "description": "Deploy keys on each repository and whether they allow writes.",
     "description_ko": "저장소마다 등록된 배포 키와 쓰기 허용 여부입니다.",
     "permission": "administration", "credential_type": "GITHUB_DEPLOY_KEY",
     "match": [{"prefix": "deployKey:"}, {**_INVENTORY, "in": ["deploy_key", "Deploy key"]}],
     "support": "YYYNYPNYY", "reasons": {
         "expires": ["배포 키에는 만료일이 없습니다", "Deploy keys do not expire"],
         "creator": ["추가한 사람을 기록한 키만 줍니다", "Given only for keys whose adder GitHub recorded"],
         "owner": ["사람이 아니라 저장소에 묶입니다", "Bound to a repository, not a person"]}},
    {"id": "app_installation", "label": "GitHub App installation", "label_ko": "GitHub App 설치",
     "description": "Apps installed in the organization and the permissions they hold.",
     "description_ko": "조직에 설치된 앱과 앱이 가진 권한입니다.",
     "permission": "organization_administration", "credential_type": "GITHUB_APP_INSTALLATION",
     "match": [{"prefix": "installation:"}],
     "support": "YYYNYNNNY", "reasons": {
         "expires": ["앱 설치에는 만료일이 없습니다", "App installations do not expire"],
         "creator": ["설치한 사람을 API가 주지 않습니다", "The API does not say who installed it"],
         "owner": ["사람이 아니라 조직에 설치됩니다", "Installed on the organization, not a person"],
         "last_used": ["앱을 마지막으로 쓴 시각을 주지 않습니다", "The API does not give the app's last use"]}},
    {"id": "app_issuer", "label": "App issuing principal (Export observation)", "label_ko": "App 발급 주체(Export 관측)",
     "description": "Issuing principals reported by the Enterprise export, not individual installation tokens. Rows have no stable credential ID.",
     "description_ko": "Enterprise Export에 보고된 발급 주체입니다. 개별 설치 토큰이 아니며 고정 자격증명 ID가 없어 스냅샷 관측으로 표시합니다.",
     "editions": ["enterprise_cloud", "dedicated"], "permission": "enterprise_credentials_read",
     "snapshot_only": True, "export_type": "github_app_installation",
     "match": [{**_INVENTORY, "in": ["github_app_installation"]}], "support": "NPPPPNPPP",
     "reasons": {**_EXPORT_FIELDS, "id": ["안정적인 개별 식별자가 없어 고유 자격증명 수에 포함하지 않습니다", "No stable individual identifier; excluded from unique credential counts"],
                 "creator": _CREATOR}},
    {"id": "federated_jti", "label": "Federated JTI (Export observation)", "label_ko": "Federated JTI(Export 관측)",
     "description": "Federated credentials reported in the selected Enterprise snapshot. Rows cannot be identified across exports.",
     "description_ko": "선택한 Enterprise 스냅샷이 보고한 연합 자격증명입니다. 다른 Export의 행과 동일성을 확정하지 않습니다.",
     "editions": ["enterprise_cloud", "dedicated"], "permission": "enterprise_credentials_read",
     "snapshot_only": True, "export_type": "federated_jti",
     "match": [{**_INVENTORY, "in": ["federated_jti"]}], "support": "NPPPPNPPP",
     "reasons": {**_EXPORT_FIELDS, "id": ["고정 ID가 없어 스냅샷별 관측 행으로만 집계합니다", "No stable ID; counted only as rows in a snapshot"],
                 "creator": _CREATOR}},
]
_LABELS = {
    "metadata": ("Metadata: read", "메타데이터: 읽기"),
    "contents": ("Contents: read", "콘텐츠: 읽기"),
    "organization_administration": ("Organization administration: read", "조직 관리: 읽기"),
    "organization_personal_access_tokens": ("Personal access tokens: read", "개인 액세스 토큰: 읽기"),
    "organization_personal_access_token_requests": ("Personal access token requests: read", "개인 액세스 토큰 요청: 읽기"),
    "organization_personal_access_tokens_write": ("Personal access tokens: write (revokes a token's organization access)",
                                                  "개인 액세스 토큰: 쓰기(토큰의 조직 접근 회수)"),
    "administration": ("Repository administration: read (deploy keys)", "저장소 관리: 읽기(배포 키)"),
    "organization_secrets": ("Organization secrets: read", "조직 시크릿: 읽기"),
    "secrets": ("Repository secrets: read", "저장소 시크릿: 읽기"),
    "environments": ("Environments: read", "환경: 읽기"),
    "actions": ("Actions: read (lists environments)", "Actions: 읽기(환경 목록)"),
    "members": ("Members: read (organization members and teams; CreMore reads only their SAML SSO identities)",
                "구성원: 읽기(조직 구성원·팀, CreMore는 SAML SSO 신원만 읽음)"),
    # The id predates GitHub's read:org sufficing (Organization.samlIdentityProvider: read:org or admin:org).
    "admin_org": ("read:org (or admin:org) scope of an organization owner", "조직 소유자의 read:org(또는 admin:org) 범위"),
    "read_enterprise": ("read:enterprise (or admin:enterprise) scope of an enterprise owner",
                        "엔터프라이즈 소유자의 read:enterprise(또는 admin:enterprise) 범위"),
    "installation": ("Installed on the organization", "조직에 설치됨"),
}


def _permissions(*names, methods=None):
    return [{"id": name, "label": _LABELS[name][0], "label_ko": _LABELS[name][1],
             **({"methods": list(methods)} if methods else {})} for name in names]


_INSTALLED = _permissions("installation", methods=["github_app"])
# Whose GitHub login is which person: the organization's SAML SSO identities, or the enterprise's -- Enterprise Managed
# Users, or SAML set on the enterprise, which takes over from its organizations' own. One of them applies to an
# organization, never both. The organization's are read with its owner's classic token or the App (Members: read); the
# enterprise's only with its owner's classic token, which the App's check answers as missing. GHE.com has managed users
# only. Enterprise Server sets SAML on the instance, which GitHub answers as its enterprise's.
_ENTERPRISE_IDENTITIES = {
    "name": "enterprise_identities", "kind": "bool", "default": False, "edition_defaults": {"dedicated": True},
    "editions": ["enterprise_cloud", "dedicated", "enterprise_server"], "when": {"enterprise": ["*"]},
    "label": "Read the enterprise's SSO identities instead of the organization's: Enterprise Managed Users, or SAML set "
             "on the enterprise (an enterprise owner's classic PAT, read:enterprise, plus read:org for the wizard's "
             "organization list)",
    "label_ko": "조직 대신 엔터프라이즈의 SSO 신원 읽기: 엔터프라이즈 관리 사용자(EMU) 또는 엔터프라이즈에 설정한 SAML"
                "(엔터프라이즈 소유자의 클래식 PAT, read:enterprise, 마법사의 조직 목록에는 read:org도)"}
_IDENTITY_PERMISSIONS = [{**_permissions("admin_org", methods=["token"])[0], "unless": "enterprise_identities"},
                         {**_permissions("read_enterprise")[0], "option": "enterprise_identities"},
                         *_INSTALLED, {**_permissions("members", methods=["github_app"])[0], "unless": "enterprise_identities"}]


DESCRIPTORS = [{
    "provider": "github",
    "label": "GitHub", "label_ko": "GitHub",
    "category": "code",
    "editions": [
        {"id": "cloud", "label": "GitHub.com", "label_ko": "GitHub.com"},
        {"id": "enterprise_cloud", "label": "GitHub Enterprise Cloud", "label_ko": "GitHub Enterprise Cloud"},
        {"id": "dedicated", "label": "GitHub Enterprise Cloud with data residency (GHE.com)",
         "label_ko": "GitHub Enterprise Cloud 데이터 상주(GHE.com)", "origin": True},
        {"id": "enterprise_server", "label": "GitHub Enterprise Server", "label_ko": "GitHub Enterprise Server",
         "origin": True},
    ],
    "target": [
        {"name": "host", "label": "Server address", "label_ko": "서버 주소", "kind": "url", "required": True,
         "editions": ["dedicated", "enterprise_server"], "hint": "https://github.example.com"},
        {"name": "organization", "label": "Organization", "label_ko": "조직", "kind": "name", "required": True,
         "hint": "acme"},
        {"name": "enterprise", "label": "Enterprise (credential inventory and SSO identities across it)",
         "label_ko": "엔터프라이즈(전체 발급 목록·SSO 신원)", "kind": "name",
         "editions": ["enterprise_cloud", "dedicated", "enterprise_server"]},
    ],
    "purposes": {
        "exposure": {"permissions": _INSTALLED + _permissions(*APP_PERMISSIONS["exposure"]),
                     "scans": [{"id": "repository_files", "label": "Repository files", "label_ko": "저장소 파일",
                           "description": "Files of the repositories in scope, at the default branch unless the scope names another.",
                           "description_ko": "검사 범위에 넣은 저장소의 파일입니다. 범위에서 따로 정하지 않으면 기본 브랜치를 읽습니다."}]},
        "inventory": {"permissions": _INSTALLED + _permissions(*APP_PERMISSIONS["inventory"]) + [
                         {"id": "enterprise_credentials_read", "label": "Enterprise credentials: read",
                          "label_ko": "Enterprise credentials: 읽기", "option": "enterprise_inventory",
                          "when": {"enterprise": ["*"]}},
                         {"id": "enterprise_audit_read", "label": "Read Enterprise audit log",
                          "label_ko": "엔터프라이즈 감사 로그 읽기", "option": "enterprise_audit",
                          "when": {"enterprise": ["*"]}},
                         {"id": "org_audit_read", "label": "Read organization audit log", "label_ko": "조직 감사 로그 읽기",
                          "option": "audit_events"}],
                      "types": INVENTORY_TYPES,
                      "plan": [_SCHEDULE,
                          {"name": "enterprise_inventory", "kind": "bool", "default": True,
                           "edition_defaults": {"enterprise_server": False}, "when": {"enterprise": ["*"]},
                           "label": "Enterprise credential inventory", "label_ko": "엔터프라이즈 전체 자격증명 인벤토리",
                           "description": "Enterprise Cloud Export API (GitHub has not announced it for GHE.com or Server). Needs an Enterprise installation with Enterprise credentials: read.",
                           "description_ko": "Enterprise Cloud의 Export API입니다(GHE.com·Server 지원은 GitHub이 아직 밝히지 않았습니다). Enterprise credentials: 읽기 권한이 있는 엔터프라이즈 설치가 필요합니다."},
                          {**_SCHEDULE, "name": "enterprise_schedule_minutes", "schedule": True, "when": {"enterprise": ["*"]},
                           "label": "Enterprise inventory interval (minutes, 0 = on demand)",
                           "label_ko": "엔터프라이즈 전체 인벤토리 주기(분, 0이면 수동)",
                           "description": "New exports are limited to one attempt per 24 hours by CreMore. Organization and audit collection have separate intervals.",
                           "description_ko": "CreMore는 새 Export 생성을 24시간마다 한 번 시도합니다. 조직 목록·감사 로그 주기는 별도입니다."},
                          {**_SCHEDULE, "name": "audit_schedule_minutes", "schedule": True, "default": 60,
                           "label": "Audit collection interval (minutes, 0 = on demand)",
                           "label_ko": "감사 로그 수집 주기(분, 0이면 수동)"},
                          {"name": "enterprise_audit", "kind": "bool", "default": False,
                           "when": {"enterprise": ["*"]}, "label": "Enterprise audit events (audit token required)",
                           "label_ko": "엔터프라이즈 감사 이벤트(감사 로그 토큰 필요)"},
                          {"name": "audit_events", "kind": "bool", "default": False,
                           "label": "Organization audit events", "label_ko": "조직 감사 이벤트",
                           "description": "Needs organization audit API access; availability varies by edition and plan.",
                           "description_ko": "조직 감사 API 접근이 필요하며 버전·요금제에 따라 제공 여부가 다릅니다."},
                          {"name": "audit_days", "kind": "number", "default": 30, "min": 1, "max": 180,
                           "label": "Audit lookback (days)", "label_ko": "감사 로그 조회 기간(일)"}, {
                          "name": "token_digests", "kind": "bool", "default": False,
                          "editions": ["enterprise_cloud", "dedicated", "enterprise_server"],
                          "label": "Token digests from the Enterprise audit log (needs the audit log token)",
                          "label_ko": "엔터프라이즈 감사 로그의 토큰 digest(감사 로그 토큰 필요)"}]},
        "vault": {"permissions": _INSTALLED + _permissions(*APP_PERMISSIONS["vault"]), "plan": [_SCHEDULE]},
        "identity": {"permissions": _IDENTITY_PERMISSIONS, "plan": [_SCHEDULE, _PEOPLE, _ENTERPRISE_IDENTITIES]},
        # Revoking a fine-grained token's organization access an approved plan names (cremore_github_provider.remediation).
        "remediation": {"permissions": _INSTALLED + _permissions("organization_personal_access_tokens_write")},
    },
    "auth_methods": [
        {"id": "github_app", "label": "GitHub App", "label_ko": "GitHub App", "renewal": "AUTOMATIC",
         "auth_first": {"context": ["host", "enterprise"]},
         "purposes": ["exposure", "inventory", "vault", "identity", "remediation"],
         # GitHub shows an App the SAML identities of an organization only: GHE.com has managed users, read from the
         # enterprise with its owner's classic token, and a Server's SAML belongs to the instance, not an organization.
         "purpose_editions": {"identity": ["cloud", "enterprise_cloud"]},
         "reference_keys": ["GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_BASE64"],
         "fields": [
             {"name": "app_id", "label": "App ID or Client ID", "label_ko": "App ID 또는 Client ID", "kind": "text"},
             {"name": "installation_id", "label": "Installation ID", "label_ko": "설치 ID", "kind": "id"},
             {"name": "private_key", "label": "Private key (PEM)", "label_ko": "개인 키(PEM)", "kind": "multiline",
              "secret": True},
             {"name": "audit_token", "label": "Enterprise audit log token (classic, read:audit_log)",
              "label_ko": "엔터프라이즈 감사 로그 토큰(클래식, read:audit_log)", "kind": "secret", "secret": True,
              "optional": True},
         ]},
        {"id": "token", "label": "Personal access token", "label_ko": "개인 액세스 토큰", "renewal": "EXPIRES",
         "auth_first": {"context": ["host", "enterprise"]},
         "advanced": True, "purposes": ["exposure", "identity"],
         "fields": [{"name": "token", "label": "Token", "label_ko": "토큰", "kind": "secret", "secret": True}]},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    organization = values.get("organization", "")
    if not _ORG.fullmatch(organization):
        raise OnboardingValueError("GITHUB_ORGANIZATION_INVALID")
    out = {"organization": organization}
    if values.get("enterprise"):
        if not _ORG.fullmatch(values["enterprise"]):
            raise OnboardingValueError("GITHUB_ENTERPRISE_INVALID")
        out["enterprise"] = values["enterprise"].lower()
    if edition in ("dedicated", "enterprise_server"):
        try:
            host = normalize_host(values.get("host"))
        except ValueError:
            raise OnboardingValueError("GITHUB_HOST_INVALID") from None
        if not host or host.endswith(".ghe.com") != (edition == "dedicated"):
            raise OnboardingValueError("GITHUB_HOST_INVALID")
        out["host"] = host
    return out


def ready(repo, settings, connection):
    """The audit log's classic token is read only for an Enterprise's audit log; GHE.com, which has managed users
    only, keeps whose login is which person in its enterprise."""
    if "audit_token" in connection["secret_refs"] and not connection["target"].get("enterprise"):
        raise OnboardingValueError("GITHUB_AUDIT_TOKEN_NEEDS_AN_ENTERPRISE")
    if (connection["edition"] == "dedicated" and "identity" in connection["purposes"]
            and not connection["target"].get("enterprise")):
        raise OnboardingValueError("GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE")


def credential(provider, method, fields):
    from cremore_github_provider.github_auth import GitHubAuthError, github_app_fields

    if method == "github_app":
        key = fields.get("private_key", "").strip()
        if key.startswith("-----BEGIN"):
            key = base64.b64encode(key.encode()).decode()
        try:
            envelope = github_app_fields({"GITHUB_APP_ID": fields.get("app_id"),
                                          "GITHUB_APP_INSTALLATION_ID": fields.get("installation_id"),
                                          "GITHUB_APP_PRIVATE_KEY_BASE64": key})
        except GitHubAuthError as exc:
            raise OnboardingValueError(getattr(exc, "code", None) or "GITHUB_APP_FIELDS_INVALID") from None
        out = {"credential": envelope}
        audit = fields.get("audit_token", "").strip()
        if audit:
            from cremore_github_provider.metadata.adapter import AUDIT_TOKEN

            if not AUDIT_TOKEN.fullmatch(audit):
                raise OnboardingValueError("GITHUB_AUDIT_TOKEN_MUST_BE_A_CLASSIC_PAT")
            out["audit_token"] = {"token": audit}  # read only for the Enterprise audit log
        return out
    token = fields.get("token", "").strip()
    if not _TOKEN.fullmatch(token):
        raise OnboardingValueError("GITHUB_TOKEN_INVALID")
    return {"credential": {"token": token}}


def _api(connection):
    return api_base(connection["target"].get("host"))


def auth_context(provider, edition, values):
    checked = target(provider, edition, {**values, "organization": "authentication-context"})
    return {key: value for key, value in checked.items() if key in {"host", "enterprise"}}


def _authentication_headers(connection, secrets):
    if connection["auth_method"] == "github_app":
        from cremore_github_provider.github_auth import app_assertion

        envelope = secrets["credential"]
        token = app_assertion(envelope["GITHUB_APP_ID"], envelope["GITHUB_APP_PRIVATE_KEY_BASE64"])
    else:
        token = secrets["credential"].get("token") or secrets["credential"].get("access_token")
    return _headers(token)


def authenticate(connection, secrets, context):
    from cremore.onboarding.probe import json_body, probe

    client = context.http_client()
    try:
        is_app = connection["auth_method"] == "github_app"
        result = probe(client, "GET", _api(connection) + ("/app" if is_app else "/user"),
                       headers=_authentication_headers(connection, secrets))
        if result[0] != "GRANTED":
            return {"status": result[0], "detail": result[1]}
        body = json_body(result[2])
        if is_app:
            from cremore_github_provider.github_auth import app_identity

            app = app_identity(body, secrets["credential"]["GITHUB_APP_ID"])
            connection["target"].setdefault("auth", {})["github_organization_binding"] = True
            if connection["edition"] != "cloud" and not connection["target"].get("enterprise"):
                connection["target"].setdefault("auth", {}).pop("github_enterprise", None)
                enterprise = app["owner"] if app["owner_type"] == "Enterprise" else None
                if not enterprise:
                    from cremore_github_provider.enterprise_install import installations
                    from cremore_github_provider.github_auth import GitHubAuthError

                    envelope = secrets["credential"]
                    try:
                        listed = installations(client, connection["target"].get("host"),
                                               envelope["GITHUB_APP_ID"], envelope["GITHUB_APP_PRIVATE_KEY_BASE64"])
                    except GitHubAuthError:
                        # This optional hint only opens installation management. A partial/unavailable list
                        # proves no enterprise; it must not reject the App identity already verified above.
                        listed = {"enterprises": {}}
                    enterprise = next(iter(listed["enterprises"])) if len(listed["enterprises"]) == 1 else None
                if enterprise and _ORG.fullmatch(enterprise):
                    connection["target"].setdefault("auth", {})["github_enterprise"] = enterprise.lower()
        if not isinstance(body, dict) or type(body.get("id")) is not int:
            return {"status": "ERROR", "detail": "GITHUB_IDENTITY_INVALID"}
        granted = {"status": "GRANTED", "subject": str(body["id"])}
        if not is_app:
            # Organization listing (GET /user/orgs) comes next: what will refuse it is told now, as a warning, since
            # the sign-in itself works. Discovery still refuses; the console offers the existing single-target setup.
            if str(secrets["credential"].get("token", "")).startswith("github_pat_"):
                return {**granted, "detail": "AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED"}
            scopes = result[2].headers.get("X-OAuth-Scopes")  # classic tokens only; GitHub: read:org or user
            if scopes is not None and not {s.strip() for s in scopes.split(",")} & {"read:org", "write:org",
                                                                                  "admin:org", "user"}:
                return {**granted, "detail": "GITHUB_TOKEN_READ_ORG_REQUIRED"}
        return granted
    finally:
        client.close()


def discover(connection, secrets, context):
    from cremore.onboarding.probe import json_body, probe

    if connection["edition"] == "dedicated" and "identity" in connection["purposes"]:
        raise OnboardingValueError("AUTH_FIRST_ENTERPRISE_DISCOVERY_UNSUPPORTED")
    is_app = connection["auth_method"] == "github_app"
    if not is_app and str(secrets["credential"].get("token", "")).startswith("github_pat_"):
        raise OnboardingValueError("AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED")
    page = connection.get("discovery_cursor") or 1
    if type(page) is not int or not 1 <= page <= 100:
        raise OnboardingValueError("GITHUB_ORGANIZATIONS_INVALID")
    path = "/app/installations" if is_app else "/user/orgs"
    client = context.http_client()
    try:
        result = probe(client, "GET", _api(connection) + path, headers=_authentication_headers(connection, secrets),
                       params={"per_page": 100, "page": page})
        if result[0] != "GRANTED":
            raise OnboardingValueError("GITHUB_ORGANIZATIONS_" + (result[1] or "UNAVAILABLE"))
        body = json_body(result[2])
        rows = body
        if not isinstance(rows, list) or len(rows) > 100:
            raise OnboardingValueError("GITHUB_ORGANIZATIONS_INVALID")
        roots = []
        for row in rows:
            if is_app:
                if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] < 1:
                    raise OnboardingValueError("GITHUB_ORGANIZATIONS_INVALID")
                if row.get("suspended_at") is not None:
                    continue
                account = row.get("account")
                if not isinstance(account, dict):
                    raise OnboardingValueError("GITHUB_ORGANIZATIONS_INVALID")
                # Enterprise installations authorize installation management, not an organization scope.
                # Personal installations remain available through the existing single-target setup.
                if row.get("target_type", account.get("type")) != "Organization":
                    continue
                row = account
            if not isinstance(row, dict) or not _ORG.fullmatch(str(row.get("login", ""))):
                raise OnboardingValueError("GITHUB_ORGANIZATIONS_INVALID")
            # The draft keeps the normalized host; a root is read again through the URL field it came from.
            roots.append({"label": row["login"], "target": {"organization": row["login"],
                **{k: "https://" + v if k == "host" else v for k, v in connection["target"].items()
                   if k in {"host", "enterprise"}}}})
        # Only our numeric page is followed; response Link URLs never choose a host.
        more = len(rows) == 100
        if page >= 100 and more:
            raise OnboardingValueError("GITHUB_ORGANIZATIONS_LIMIT")
        return roots, "PARTIAL" if more else "COMPLETE", page + 1 if more else None
    finally:
        client.close()


def _headers(token):
    return {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": "Bearer " + token}


def _get(client, url, token):
    return bounded_request(client, "GET", url, headers=_headers(token), max_response_bytes=1 << 20,
                           follow_redirects=False)


def _app_check(connection, purpose, envelope, context):
    from cremore_github_provider.github_auth import GitHubAppTokenSource, GitHubAuthError

    organization = connection["target"]["organization"]
    # A check never mints a token that may write: a read-only one proves the key and the installation work, and the
    # installation it read first names the account, the App and what it holds. One per check, for every purpose.
    key = ("github_app", _api(connection), organization.lower())
    memo = context.memo.setdefault(key, {})
    source = memo.get("source")
    if source is None:
        source = memo["source"] = GitHubAppTokenSource(
            context.http_client, envelope.get("GITHUB_APP_ID"), envelope.get("GITHUB_APP_INSTALLATION_ID"),
            envelope.get("GITHUB_APP_PRIVATE_KEY_BASE64"), base_url=_api(connection), read_only=True,
            organization=organization if (connection.get("target_id")
                or connection["target"].get("auth", {}).get("github_organization_binding")) else None)
    refused = memo.get("refused")
    if refused is None and not memo.get("bare"):
        try:
            source()
        except GitHubAuthError as exc:
            if exc.code == "GITHUB_APP_REJECTED" and source.holds_no_read:
                # Installed, holding no read permission yet (the account card's App): what each feature lacks is
                # listed below, and no token is asked for, since an empty request would get every permission.
                memo["bare"] = True
            else:
                refused = memo["refused"] = exc.code  # the other purposes do not ask again
    if refused:
        return [{"permission": "installation", "status": "MISSING" if refused == "GITHUB_APP_REJECTED" else "ERROR",
                 "detail": refused}]
    granted = dict(scope.split(":", 1) for scope in source.scopes() if ":" in scope)
    body = source.installation if isinstance(source.installation, dict) else {}
    installed_on = (body.get("account") or {}).get("login") if isinstance(body.get("account"), dict) else None
    held = body.get("permissions") if isinstance(body.get("permissions"), dict) else None
    items = []
    if not isinstance(installed_on, str):
        items.append({"permission": "installation", "status": "NOT_REPORTED", "detail": "INSTALLATION_UNREADABLE"})
    elif installed_on.lower() != organization.lower():
        # Another account is named to the reader, never as the one a remediation plan would bind.
        items.append({"permission": "installation", "status": "MISSING", "detail": "INSTALLED_ON_ANOTHER_ACCOUNT",
                      **({} if purpose == "remediation" else {"subject": installed_on[:256]})})
    else:
        items.append({"permission": "installation", "status": "GRANTED", "subject": organization})
    if purpose == "remediation":
        # Revoking needs write; the installation names what it holds, so nothing is revoked to find out.
        if held is None:
            return items + [{"permission": "organization_personal_access_tokens_write", "status": "NOT_REPORTED",
                             "detail": "INSTALLATION_UNREADABLE"}]
        write = _LEVELS.get(held.get("organization_personal_access_tokens", ""), 0) >= _LEVELS["write"]
        return items + [{"permission": "organization_personal_access_tokens_write",
                         "status": "GRANTED" if write else "MISSING", **({} if write else {"detail": "WRITE_REQUIRED"})}]
    for name in APP_PERMISSIONS[purpose]:
        level = _LEVELS.get(granted.get(name, ""), 0)
        items.append({"permission": name, "status": "GRANTED" if level >= 1 else "MISSING"})
    if purpose == "identity":
        # Installed on the organization with Members: read; GitHub says whether it shows the identities to the token the
        # people directory reads with (Members: read alone).
        members = next(index for index, item in enumerate(items) if item["permission"] == "members")
        if items[0]["status"] == items[members]["status"] == "GRANTED":
            narrow = memo.get("members")
            if narrow is None:
                narrow = memo["members"] = GitHubAppTokenSource(
                    context.http_client, envelope.get("GITHUB_APP_ID"), envelope.get("GITHUB_APP_INSTALLATION_ID"),
                    envelope.get("GITHUB_APP_PRIVATE_KEY_BASE64"), base_url=_api(connection),
                    permissions={"members": "read"}, organization=organization)
            try:
                items[members] = _saml_identities(connection, narrow(), context)
            except GitHubAuthError as exc:
                items[members] = {"permission": "members", "detail": exc.code,
                                  "status": "MISSING" if exc.code == "GITHUB_APP_REJECTED" else "ERROR"}
        # An enterprise's identities are shown to its owners' classic tokens alone (GraphQL Enterprise.ownerInfo).
        return items + [{"permission": "read_enterprise", "status": "MISSING", "detail": "CLASSIC_TOKEN_REQUIRED"}]
    plan = connection.get("checks", {}).get("requested_plans", {}).get(purpose, connection.get("plans", {}).get(purpose, {}))
    if purpose == "inventory" and plan.get("audit_events"):
        if memo.get("bare"):
            return items + [{"permission": "org_audit_read", "status": "MISSING"}]
        from cremore.onboarding.probe import item, probe

        client = context.http_client()
        try:
            items.append(item("org_audit_read", probe(client, "GET",
                f"{_api(connection)}/orgs/{organization}/audit-log?per_page=1", headers=_headers(source()))))
        finally:
            client.close()
    return items


# Their count alone: the check reads no identity.
_SAML_COUNT = ("query($org: String!) { organization(login: $org) { samlIdentityProvider { "
               "externalIdentities(first: 1) { totalCount } } } }")


def _saml_identities(connection, token, context):
    """``members`` as GitHub answers the App: whether it shows it the organization's SAML identities."""
    from cremore.onboarding.probe import probe
    from cremore_github_provider.identity.directory import graphql_url

    client = context.http_client()
    try:
        status, detail, response = probe(client, "POST", graphql_url(_origin(connection)), headers=_headers(token),
                                         json={"query": _SAML_COUNT,
                                               "variables": {"org": connection["target"]["organization"]}})
        try:
            body = response.json() if status == "GRANTED" else {}
        except Exception:  # noqa: BLE001 -- nothing of the reply is kept
            body = {}
    finally:
        client.close()
    if status != "GRANTED":
        return {"permission": "members", "status": status, "detail": detail}
    body = body if isinstance(body, dict) else {}
    if body.get("errors"):
        errors = body["errors"] if isinstance(body["errors"], list) else []
        denied = any(isinstance(error, dict) and error.get("type") == "FORBIDDEN" for error in errors)
        return {"permission": "members", "status": "MISSING" if denied else "NOT_REPORTED",
                "detail": "ACCESS_DENIED" if denied else "REQUEST_FAILED"}
    organization = body["data"].get("organization") if isinstance(body.get("data"), dict) else None
    provider = organization.get("samlIdentityProvider") if isinstance(organization, dict) else None
    if isinstance(organization, dict) and provider is None:
        # No SAML SSO of its own: managed users and SAML set on the enterprise need an enterprise owner's token.
        return {"permission": "members", "status": "MISSING", "detail": "GITHUB_IDENTITY_SAML_NOT_ENABLED"}
    identities = provider.get("externalIdentities") if isinstance(provider, dict) else None
    if isinstance(identities, dict) and type(identities.get("totalCount")) is int:
        return {"permission": "members", "status": "GRANTED"}
    return {"permission": "members", "status": "NOT_REPORTED", "detail": "REQUEST_FAILED"}


def _owns(client, connection, token, *, organization, enterprise):
    """Whether the token's user owns the organization (asked when ``organization``) and the enterprise named
    ``enterprise``: True or False, None when GitHub hides it from the token (not a member, or not authorized for the
    organization's SAML SSO); a name is left out when not asked or GitHub did not answer. Identities are shown to
    owners only. Each is asked only of a token holding the scope that reads it, so a scope it lacks fails no answer."""
    from cremore_github_provider.identity.directory import graphql_url

    asked, selections, variables = [], [], {}
    if organization:
        asked.append("organization")
        selections.append("organization(login: $org) { viewerCanAdminister }")
        variables["org"] = connection["target"]["organization"]
    if enterprise:
        # ownerInfo is shown to enterprise owners only; viewerIsAdmin is also true for billing managers.
        asked.append("enterprise")
        selections.append("enterprise(slug: $enterprise) { ownerInfo { __typename } }")
        variables["enterprise"] = enterprise
    if not asked:
        return {}
    query = "query(" + ", ".join(f"${name}: String!" for name in variables) + ") { " + " ".join(selections) + " }"
    try:
        response = bounded_request(client, "POST", graphql_url(_origin(connection)), headers=_headers(token),
                                   json={"query": query, "variables": variables}, max_response_bytes=1 << 20,
                                   follow_redirects=False)
        data = response.json().get("data") if response.status_code == 200 else None
    except Exception:  # noqa: BLE001 -- the scopes still answer; nothing of the reply is kept
        return {}
    if not isinstance(data, dict):
        return {}

    def owner(name):
        node = data.get(name)
        if not isinstance(node, dict):
            return None
        return node.get("viewerCanAdminister") is True if name == "organization" else isinstance(node.get("ownerInfo"), dict)

    return {name: owner(name) for name in asked}


def _token_check(connection, purpose, envelope, context):
    token = envelope.get("token") or envelope.get("access_token") or ""
    organization = connection["target"]["organization"]
    client = context.http_client()
    try:
        user = _get(client, f"{_api(connection)}/user", token)
        if user.status_code in (401, 403):
            return [{"permission": name, "status": "MISSING", "detail": "GITHUB_TOKEN_REJECTED"}
                    for name in (("metadata", "contents") if purpose == "exposure" else ("admin_org", "read_enterprise"))]
        scopes = {scope.strip() for scope in (user.headers.get("X-OAuth-Scopes") or "").split(",") if scope.strip()}
        classic = "X-OAuth-Scopes" in user.headers
        if purpose == "identity":
            if not classic:
                return [{"permission": name, "status": "MISSING", "detail": "CLASSIC_TOKEN_REQUIRED"}
                        for name in ("admin_org", "read_enterprise")]
            org_scope = bool(scopes & {"read:org", "admin:org"})
            enterprise_scope = bool(scopes & {"read:enterprise", "admin:enterprise"})
            owns = _owns(client, connection, token, organization=org_scope,
                         enterprise=connection["target"].get("enterprise") if enterprise_scope else None)

            def answer(permission, granted, subject):
                if not granted:
                    return {"permission": permission, "status": "MISSING"}
                if subject not in owns:
                    return {"permission": permission, "status": "NOT_REPORTED", "detail": "TARGET_OWNER_NOT_CHECKED"}
                owner = owns[subject]
                if owner is not True:
                    return {"permission": permission, "status": "MISSING",
                            "detail": "NOT_AN_OWNER" if owner is False else "TARGET_NOT_VISIBLE"}
                return {"permission": permission, "status": "GRANTED"}

            # Both answered: the console counts the one the plan's choice needs (the organization or the enterprise).
            return [answer("admin_org", org_scope, "organization"),
                    answer("read_enterprise", enterprise_scope, "enterprise")]
        repos = _get(client, f"{_api(connection)}/orgs/{organization}/repos?per_page=1", token)
        listed = repos.status_code == 200
        items = [{"permission": "metadata", "status": "GRANTED" if listed else "MISSING",
                  "detail": None if listed else f"HTTP_{repos.status_code}"}]
        listing = repos.json() if listed and repos.content else []
        first = listing[0] if isinstance(listing, list) and listing and isinstance(listing[0], dict) else None
        if first is None:
            items.append({"permission": "contents", "status": "NOT_REPORTED", "detail": "NO_REPOSITORY_TO_READ"})
        else:
            code = _get(client, f"{_api(connection)}/repos/{organization}/{first.get('name')}/contents/",
                        token).status_code
            # An empty repository answers 404 whatever the token may read.
            status = "GRANTED" if code == 200 else "MISSING" if code in (401, 403) else "NOT_REPORTED"
            items.append({"permission": "contents", "status": status, "detail": None if code == 200 else f"HTTP_{code}"})
        return items
    finally:
        client.close()


def check(connection, purpose, secrets, context):
    envelope = secrets.get("credential") or {}
    if connection["auth_method"] == "github_app":
        items = _app_check(connection, purpose, envelope, context)
        if purpose == "inventory" and connection["target"].get("enterprise"):
            from cremore_github_provider.onboarding_export import audit_access, inventory_access

            plan = connection.get("checks", {}).get("requested_plans", {}).get(purpose, connection.get("plans", {}).get(purpose, {}))
            effective = permission_plan(connection, purpose, plan)
            if effective["enterprise_inventory"]:
                items.append(inventory_access(connection, envelope, context))
            if effective["enterprise_audit"]:
                items.append(audit_access(connection, secrets, context))
        return items
    return _token_check(connection, purpose, envelope, context)


def permission_plan(connection, purpose, plan):
    if purpose != "inventory":
        return plan
    enterprise = bool(connection["target"].get("enterprise"))
    return {**plan, "enterprise_inventory": enterprise and plan.get("enterprise_inventory", True),
            "enterprise_audit": enterprise and (plan.get("enterprise_audit",
                "audit_token" in connection.get("secret_refs", {})) or bool(plan.get("token_digests")))}


def collection_identity_purpose(spec, purpose):
    # Separate audit jobs keep the same credential owner and approval purpose.
    # The existing inventory child retains its identity and collection history.
    return purpose + ":audit" if spec.get("options", {}).get("github_inventory") is False else purpose


def credential_identity(connection, secrets, context):
    """What acts, to tell one credential that collects and acts (cremore.onboarding.check.credential_marks): a
    GitHub App is its App, since its key mints a token for any of its installations; a token is itself (None)."""
    if connection["auth_method"] != "github_app":
        return None
    from cremore_github_provider.github_auth import GitHubAppTokenSource

    # The App GitHub itself named when the check read the installation with this key; else the configured one.
    key = ("github_app", _api(connection), connection["target"].get("organization", "").lower())
    checked = getattr((getattr(context, "memo", None) or {}).get(key, {}).get("source"), "installation", None) or {}
    app = checked.get("app_id") if isinstance(checked, dict) else None
    if type(app) is not int or app < 1:
        envelope = secrets.get("credential") or {}
        app = str(envelope.get("GITHUB_APP_ID") or "")
        if not app.isdecimal():  # a Client ID: the App's number, as its installations name it
            app = GitHubAppTokenSource(context.http_client, app, envelope.get("GITHUB_APP_INSTALLATION_ID"),
                                       envelope.get("GITHUB_APP_PRIVATE_KEY_BASE64"),
                                       base_url=_api(connection)).identity()["id"]
    return [f"github_app:{_api(connection)}:{app}"]


def _origin(connection):
    host = connection["target"].get("host")
    return web_base(host) if host else "https://github.com"


def children(connection, purpose, plan):
    if purpose == "remediation":
        return []  # used only by an approved action plan (cremore_github_provider.remediation)
    organization = connection["target"]["organization"]
    host = connection["target"].get("host")
    name = f"GitHub · {organization}"
    if purpose == "exposure":
        config = {"org": organization, **({"github_host": host} if host else {})}
        if connection["auth_method"] == "github_app":
            # The source list shows a credential that expires in an hour, not a stored token.
            config["auth_kind"] = "GITHUB_APP"
            if connection.get("target_id") or connection["target"].get("auth", {}).get("github_organization_binding"):
                config["app_organization"] = organization
        return [{"kind": "content", "purpose": purpose, "source_type": "github", "name": name, "config": config,
                 "secret_slots": {"secret_ref": "credential"}}]
    base = {"schema_version": 2, "provider": "github", "origin": _origin(connection),
            "edition": connection["edition"], "tenant": organization,
            "scopes": [{"kind": "organization", "id": organization}],
            "schedule_minutes": plan.get("schedule_minutes", 1440)}
    app_slots = {"app_id": "credential", "installation_id": "credential", "private_key": "credential"}
    if purpose == "inventory":
        # Stored plans predating the separate intervals keep their mixed jobs
        # until edited. _plan_for fills descriptor defaults even when describing
        # the old side of an edit, so consult the unexpanded activating plan.
        original = connection.get("activating", {}).get(purpose, plan)
        split = "audit_schedule_minutes" in original
        effective = permission_plan(connection, purpose, original)
        organization_audit = bool(plan.get("audit_events"))
        spec = {**base, "name": name + " · inventory", "auth_type": "github_app",
                "capabilities": ["inventory", "relations", "public_keys", "policy"] + (["audit"] if organization_audit and not split else []),
                "options": {"mode": "organization", **({"include_audit_events": True,
                    "audit_lookback_days": plan.get("audit_days", 30)} if organization_audit and not split else {})}}
        out = [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": app_slots}]
        enterprise = connection["target"].get("enterprise")
        audit = effective["enterprise_audit"]
        digests = bool(plan.get("token_digests"))
        if (audit or digests) and not (enterprise and "audit_token" in connection["secret_refs"]):
            # The digests are read from the Enterprise audit log with its own classic token.
            raise OnboardingValueError("GITHUB_TOKEN_DIGESTS_NEED_THE_AUDIT_TOKEN")
        if effective["enterprise_inventory"]:
            out.append({"kind": "metadata", "purpose": purpose, "spec": {
                **base, "name": f"GitHub Enterprise · {enterprise}", "auth_type": "github_app",
                **({"schedule_minutes": plan.get("enterprise_schedule_minutes", 1440)} if split else {}),
                "edition": connection["edition"], "tenant": enterprise,
                "scopes": [{"kind": "enterprise", "id": enterprise}],
                "capabilities": ["inventory", "relations", "policy", "public_keys"] + (["audit"] if audit and not split else [])
                + (["issuer_digest"] if digests else []),
                "options": {"mode": "enterprise", **({"enterprise_only": True} if split else {}),
                            **({"include_audit_events": True,
                    "audit_lookback_days": plan.get("audit_days", 30),
                    **({"audit_scope": "enterprise"} if organization_audit else {})} if audit and not split else {}),
                            **({"include_provider_hashes": True} if digests else {})}},
                "secret_slots": {"app_id": "credential", "private_key": "credential",
                                 **({"audit_token": "audit_token"} if audit and not split else {})}})
        if split:
            for enterprise_audit, enabled in ((False, organization_audit), (True, audit)):
                if not enabled:
                    continue
                scope = {"kind": "enterprise", "id": enterprise} if enterprise_audit else base["scopes"][0]
                out.append({"kind": "metadata", "purpose": purpose, "spec": {
                    **base, "name": f"GitHub · {scope['id']} · audit", "auth_type": "github_app",
                    "tenant": scope["id"], "scopes": [scope],
                    "schedule_minutes": plan.get("audit_schedule_minutes", 60),
                    "capabilities": ["inventory", "audit"] + (["issuer_digest"] if digests and enterprise_audit else []),
                    "options": {"mode": "enterprise" if enterprise_audit else "organization",
                        "github_inventory": False, "include_audit_events": True,
                        "audit_scope": "enterprise" if enterprise_audit else "organization",
                        "audit_lookback_days": plan.get("audit_days", 30),
                        **({"enterprise_only": True} if enterprise_audit else {}),
                        **({"include_provider_hashes": True} if digests and enterprise_audit else {})}},
                    "secret_slots": {"app_id": "credential", "private_key": "credential",
                        **({"audit_token": "audit_token"} if enterprise_audit else {"installation_id": "credential"})}})
        return out
    if purpose == "vault":
        spec = {**base, "name": name + " · Actions secrets", "auth_type": "github_app",
                "capabilities": ["inventory", "vault_metadata"],
                "options": {"mode": "organization",
                            "sources": ["org_actions_secrets", "repo_actions_secrets", "environment_actions_secrets"]}}
        return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": app_slots}]
    enterprise = connection["target"].get("enterprise")
    chosen = plan.get("enterprise_identities")  # absent from a plan saved before the choice: the organization's
    if connection["edition"] == "dedicated" and chosen is False:
        # GHE.com has managed users only: no organization there has SAML SSO of its own.
        raise OnboardingValueError("GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE")
    if chosen and not enterprise:
        raise OnboardingValueError("GITHUB_IDENTITY_ENTERPRISE_REQUIRED")
    app = connection["auth_method"] == "github_app"
    if chosen and app:
        # GitHub shows an enterprise's identities to its owners' classic tokens alone (GraphQL Enterprise.ownerInfo).
        raise OnboardingValueError("GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN")
    source = {"tenant": enterprise, "scopes": [{"kind": "enterprise", "id": enterprise}]} if chosen else {}
    spec = {**base, **source, "name": name + " · identities", "provider": "github_identity",
            "auth_type": "github_app" if app else "bearer", "capabilities": ["identity_status"],
            "options": {"mode": "inventory", **({"keep_profiles": True} if plan.get("people_details") else {})}}
    return [{"kind": "metadata", "purpose": purpose, "spec": spec,
             "secret_slots": app_slots if app else {"token": "credential"}}]
