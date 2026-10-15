"""Microsoft (Entra ID, Azure and Azure DevOps), Azure DevOps and Microsoft Entra ID people in the connection
wizard (cremore.onboarding).

* Microsoft (``azure``): one app registration reaches the tenant's application credentials and people
  (Microsoft Graph), a subscription's resources and storage keys, Key Vault, a storage account's blobs and an
  Azure DevOps organization connected to the tenant (its repositories and its users' personal access
  tokens). It signs in with a certificate CreMore makes (``certificate``: only the public certificate is
  uploaded, and the worker renews it before it expires with Microsoft Graph ``addKey``), or with the worker's
  own Azure identity (``workload_identity``: workload or managed identity, or the company IdP's federated
  credential; ``DefaultAzureCredential``). Each permission is checked by the read that needs it.
* Azure DevOps: a personal access token scans repositories and lists the organization's personal access
  tokens -- for Azure DevOps Server, and for an organization that is not connected to the tenant. A Project
  Collection Administrator's token, on a connection of its own, revokes a token an approved plan names
  (cremore_azure_provider.devops_tokens.remediation).
* Entra ID people: the connection the Microsoft one replaced; existing ones keep running.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import quote

from cremore.onboarding.probe import item, json_body, probe

_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STORAGE = re.compile(r"[a-z0-9]{3,24}")
_VAULT = re.compile(r"[A-Za-z](?:[A-Za-z0-9-]{1,22}[A-Za-z0-9])")
_ORGANIZATION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?")
_TOKEN = re.compile(r"[\x21-\x7e]{20,255}")
GRAPH, ARM = "https://graph.microsoft.com", "https://management.azure.com"
DEVOPS, DEVOPS_GRAPH = "https://dev.azure.com", "https://vssps.dev.azure.com"
_PEOPLE = {"name": "people_details", "kind": "bool", "default": True,
           "label": "Keep people's names, emails and departments (owners and contacts)",
           "label_ko": "사람 이름·이메일·부서 보관(담당자·연락 대상 표시)"}
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
_DEVOPS_TOKEN = {"name": "token", "label": "Token", "label_ko": "토큰", "kind": "secret", "secret": True}
_AMBIENT = {"id": "workload_identity", "label": "Workload identity or managed identity",
            "label_ko": "워크로드 신원 또는 관리 ID", "renewal": "AUTOMATIC", "fields": []}
# The Microsoft connection's sign-in for a worker without a managed identity or federated token (which Microsoft
# prefers): CreMore makes the key and a self-signed certificate; the admin uploads only the certificate to the app
# registration, and the worker renews it (app_certificate).
_CERTIFICATE = {"id": "certificate", "label": "App registration certificate (made and renewed by CreMore)",
                "label_ko": "앱 등록 인증서(CreMore가 만들고 교체)", "renewal": "AUTOMATIC", "generated": True,
                "reference": False,
                "fields": [{"name": "client_id", "label": "Application (client) ID", "label_ko": "애플리케이션(클라이언트) ID",
                            "kind": "id", "public": True}]}
_ANY = ["*"]
_SERVICES = ("exposure", "inventory", "vault", "identity")


def _p(name, label, label_ko, **more):
    return {"id": name, "label": label, "label_ko": label_ko, **more}


# The certificate is renewed by the app itself, which needs Application.Read.All to find its own
# application object; the inventory reads with the same permission.
_SELF_READ = _p("applications_read", "Application.Read.All", "Application.Read.All", methods=["certificate"])
# Needed only when the token's tid cannot be read (the runtime then fails closed, ENTRA_ID_TENANT_UNVERIFIED), so the
# check shows it without holding back activation.
_PEOPLE_ORGANIZATION = _p(
    "organization_read", "Organization.Read.All (application; tenant check for opaque tokens)",
    "Organization.Read.All(애플리케이션; 불투명 토큰의 테넌트 확인)", required=False,
    description="People collection needs this permission only when the token's tid cannot be read. "
                "Existing connections with a matching readable tid do not need an extra grant.",
    description_ko="사람 수집은 토큰의 tid를 읽을 수 없을 때만 이 권한이 필요합니다. "
                   "tid가 읽히고 테넌트가 일치하는 기존 연결에는 추가 동의가 필요하지 않습니다.")

# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state).
_APP_SECRET = {
    "scopes": ["비밀에는 권한 범위가 없고 앱의 권한을 따릅니다. 앱 권한 옵션을 켜면 수집마다 서비스 주체 50개까지 앱의 애플리케이션 권한·Entra 역할·Azure 역할을 보여 줍니다",
               ("A secret has no scopes; it acts with the app's permissions. With the app permission options on, it shows "
                "the application permissions, Entra roles and Azure roles of up to 50 service principals a collection")],
    "created": ["Graph는 추가한 시각이 아니라 유효 시작 시각(startDateTime)만 줍니다",
                "Graph gives only when it becomes valid (startDateTime), not when it was added"],
    "creator": ["선택한 디렉터리 감사 로그에서 키 ID의 추가와 실행자가 정확히 확인될 때만 연결합니다",
                "Opt-in directory audit additions with an exact key ID and explicit actor only"],
    "owner": ["사람이 아니라 앱 등록에 묶입니다", "Bound to the app registration, not a person"],
    "last_used": ["선택한 Graph 베타 로그인 로그에 앱·키 ID가 명시된 성공한 사용만 연결합니다. AuditLog.Read.All과 Microsoft Entra ID P1 또는 P2가 필요합니다",
                  "Opt-in Graph beta successful sign-ins with explicit app and key IDs only; requires AuditLog.Read.All and Microsoft Entra ID P1 or P2"],
    "state": ["상태를 주지 않아 만료일로만 판단합니다", "No state is given; only the expiry tells"]}
AZURE_TYPES = [
    {"id": "client_secret", "label": "App registration secret", "label_ko": "앱 등록 비밀",
     "description": "Client secrets of Entra ID app registrations and service principals, with their expiry.",
     "description_ko": "Entra ID 앱 등록·서비스 주체의 클라이언트 비밀과 만료일입니다.",
     "permission": "applications_read", "credential_type": "AZURE_CLIENT_SECRET",
     "match": [{"provider": "azure_entra", "fact": "credential_type", "in": ["AZURE_CLIENT_SECRET", "AZURE_APPLICATION_KEY"]}],
     "support": "YYNYPPNPP", "reasons": _APP_SECRET},
    {"id": "certificate", "label": "App registration certificate", "label_ko": "앱 등록 인증서",
     "description": "Certificates of Entra ID app registrations and service principals, with their expiry.",
     "description_ko": "Entra ID 앱 등록·서비스 주체의 인증서와 만료일입니다.",
     "permission": "applications_read", "credential_type": "AZURE_CERTIFICATE",
     "match": [{"provider": "azure_entra", "fact": "credential_type", "in": ["AZURE_CERTIFICATE"]}],
     "support": "YYNYPPNPP", "reasons": _APP_SECRET},
    {"id": "storage_account_key", "label": "Storage account key", "label_ko": "스토리지 계정 키",
     "description": "Key names, creation and permissions of the storage accounts chosen for key fingerprints.",
     "description_ko": "키 지문을 읽도록 정한 스토리지 계정의 키 이름·생성일·권한입니다.",
     "permission": "subscription_read", "credential_type": "AZURE_STORAGE_KEY", "plan": [{"field": "storage_key_accounts"}],
     "match": [{"provider": "azure_resource_manager", "fact": "credential_type", "in": ["AZURE_STORAGE_KEY"]}],
     "support": "YYYNYNNNN", "reasons": {
         "expires": ["스토리지 키에는 만료일이 없습니다", "Storage keys do not expire"],
         "creator": ["만든 사람을 주지 않습니다", "Who made it is not given"],
         "owner": ["사람이 아니라 스토리지 계정에 묶입니다", "Bound to the storage account, not a person"],
         "last_used": ["마지막 사용을 주지 않습니다", "No last use is given"],
         "state": ["상태를 주지 않습니다", "No state is given"]}},
]
DEVOPS_TYPES = [
    {"id": "personal_access_token", "label": "Personal access token", "label_ko": "개인 액세스 토큰(PAT)",
     "description": "The organization's users' PATs with scopes and expiry.", "description_ko": "조직 사용자의 PAT 목록·범위·만료일입니다.",
     "permission": "token_administration", "credential_type": "AZURE_DEVOPS_PAT",
     "match": [{"provider": "azure_devops", "prefix": "pat:"}], "support": "YYYYYNYNY", "reasons": {
         "creator": ["목록의 사용자는 소유자입니다. 별도 생성자는 제공되지 않습니다",
                     "The listed user is the owner; no separate creator is returned"],
         "last_used": ["마지막 사용을 주지 않습니다", "No last use is given"]}},
]
_DEVOPS_READS = [_p("graph_read", "Graph (read)", "Graph(읽기)"),
                 # vso.tokenadministration has no read-only form: it views and revokes every user's tokens.
                 _p("token_administration", "Token Administration (views and revokes every user's PATs; Project "
                    "Collection Administrator)", "토큰 관리(모든 사용자 PAT 조회·폐기, 프로젝트 컬렉션 관리자)")]
_DEVOPS_SCANS = [{"id": "git", "label": "Git repositories", "label_ko": "Git 저장소",
                  "description": "Files of the Git repositories in scope, at the default branch.",
                  "description_ko": "검사 범위에 넣은 Git 저장소의 기본 브랜치 파일입니다."},
                 {"id": "tfvc", "label": "TFVC", "label_ko": "TFVC",
                  "description": "Files of the TFVC paths in scope.",
                  "description_ko": "검사 범위에 넣은 TFVC 경로의 파일입니다."}]

DESCRIPTORS = [
    {
        "provider": "azure",
        "label": "Microsoft", "label_ko": "Microsoft",
        "category": "cloud",
        "editions": [{"id": "cloud", "label": "Microsoft Entra ID · Azure · Azure DevOps",
                      "label_ko": "Microsoft Entra ID · Azure · Azure DevOps"}],
        "target": [
            {"name": "tenant", "label": "Tenant ID", "label_ko": "테넌트 ID", "kind": "id", "required": True},
            {"name": "subscription", "label": "Subscription ID (inventory)", "label_ko": "구독 ID(발급 목록)",
             "kind": "id"},
            {"name": "storage_account", "label": "Storage account (exposure scan)", "label_ko": "스토리지 계정(노출 스캔)",
             "kind": "name"},
            {"name": "key_vaults", "label": "Key vaults (vault)", "label_ko": "Key Vault(금고)", "kind": "list"},
            {"name": "devops_organization", "label": "Azure DevOps organization (optional)",
             "label_ko": "Azure DevOps 조직(선택)", "kind": "text",
             "hint": "An organization connected to this tenant"},
            {"name": "devops_project", "label": "Azure DevOps project (exposure scan)",
             "label_ko": "Azure DevOps 프로젝트(노출 스캔)", "kind": "text"},
        ],
        "purposes": {
            "exposure": {"permissions": [_p("blob_read", "Storage Blob Data Reader", "Storage Blob 데이터 읽기 권한자",
                                            when={"storage_account": _ANY}),
                                         _p("code_read", "Azure DevOps code (read)", "Azure DevOps 코드(읽기)",
                                            when={"devops_project": _ANY}), _SELF_READ],
                         "scans": [{"id": "blobs", "label": "Container blobs", "label_ko": "컨테이너 Blob",
                                    "description": "Blobs in the storage account's containers in scope.",
                                    "description_ko": "검사 범위에 넣은 스토리지 계정 컨테이너의 Blob입니다.",
                                    "when": {"storage_account": _ANY}},
                                   *[{**scan, "label": f"Azure DevOps {scan['label']}",
                                      "label_ko": f"Azure DevOps {scan['label_ko']}", "when": {"devops_project": _ANY}}
                                     for scan in _DEVOPS_SCANS]]},
            "inventory": {"permissions": [_p("applications_read", "Application.Read.All", "Application.Read.All"),
                                          _p("organization_read", "Organization.Read.All", "Organization.Read.All"),
                                          _p("credential_sign_ins", "AuditLog.Read.All (Graph beta service-principal sign-ins)",
                                             "AuditLog.Read.All(Graph 베타 서비스 주체 로그인)", option="credential_sign_ins"),
                                          _p("directory_audits", "AuditLog.Read.All (directory credential additions)",
                                             "AuditLog.Read.All(디렉터리 자격증명 추가 기록)", option="directory_audits"),
                                          _p("role_management_read", "RoleManagement.Read.Directory (Entra roles of apps)",
                                             "RoleManagement.Read.Directory(앱의 Entra 역할)", option="app_permissions"),
                                          _p("root_role_assignments", "Role assignment and definition read on the tenant "
                                             "root management group (Azure roles of apps)",
                                             "테넌트 루트 관리 그룹의 역할 할당·정의 읽기(앱의 Azure 역할)",
                                             option="app_azure_roles"),
                                          _p("subscription_read", "Reader on the subscription", "구독 읽기 권한자",
                                             when={"subscription": _ANY}),
                                          _p("subscriptions_list", "List subscriptions", "구독 목록 조회",
                                             option="find_subscriptions"),
                                          _p("storage_keys_read", "Storage account listKeys (Reader and Data Access; "
                                             "a key opens all of the account's data)",
                                             "스토리지 계정 listKeys(Reader and Data Access, 키로 계정의 모든 데이터에 접근 가능)",
                                             nonempty="storage_key_accounts"),
                                          *[{**permission, "when": {"devops_organization": _ANY}}
                                            for permission in _DEVOPS_READS]],
                          "types": AZURE_TYPES + [{**kind, "label": f"Azure DevOps {kind['label']}",
                                                   "label_ko": f"Azure DevOps {kind['label_ko']}",
                                                   "when": {"devops_organization": _ANY}} for kind in DEVOPS_TYPES],
                          "plan": [_SCHEDULE,
                                   {"name": "credential_sign_ins", "kind": "bool", "default": False,
                                    "label": "Credential sign-ins (Microsoft Graph beta)",
                                    "label_ko": "자격증명 로그인 기록(Microsoft Graph 베타)",
                                    "description": "Optional beta API. Requires Microsoft Entra ID P1 or P2; unmatched or empty logs do not prove non-use.",
                                    "description_ko": "선택적 베타 API입니다. Microsoft Entra ID P1 또는 P2가 필요하며 빈 로그·키 ID 없는 로그는 미사용 증거가 아닙니다."},
                                   {"name": "directory_audits", "kind": "bool", "default": False,
                                    "label": "Directory audit: credential creation actors", "label_ko": "디렉터리 감사: 자격증명 생성자",
                                    "description": "Exact listed credential additions with an explicit actor and before/after key IDs only.",
                                    "description_ko": "감사 기록의 변경 전·후 키 ID가 현재 발급 목록과 정확히 연결될 때만 생성자를 표시합니다."},
                                   {"name": "audit_days", "kind": "number", "default": 1, "min": 1, "max": 30,
                                    "label": "Audit lookback (days)", "label_ko": "감사 기록 조회 기간(일)"},
                                   {"name": "app_permissions", "kind": "bool", "default": False,
                                    "label": "What app credentials can do: application permissions and Entra roles",
                                    "label_ko": "앱 자격증명이 할 수 있는 일: 애플리케이션 권한·Entra 역할",
                                    "description": ("For each app with a secret or certificate (up to 50): the application "
                                                    "permissions granted to it and its active Entra roles. Needs "
                                                    "RoleManagement.Read.Directory."),
                                    "description_ko": ("비밀이나 인증서가 있는 앱마다(최대 50개) 받은 애플리케이션 권한과 활성 "
                                                       "Entra 역할을 읽습니다. RoleManagement.Read.Directory가 필요합니다.")},
                                   {"name": "app_azure_roles", "kind": "bool", "default": False,
                                    "label": "What app credentials can do: Azure roles",
                                    "label_ko": "앱 자격증명이 할 수 있는 일: Azure 역할",
                                    "description": ("For each app with a secret or certificate (up to 50): its Azure role "
                                                    "assignments in the tenant, including those through groups, read from the "
                                                    "tenant root management group with a role that only reads role assignments "
                                                    "and definitions."),
                                    "description_ko": ("비밀이나 인증서가 있는 앱마다(최대 50개) 그룹으로 받은 것을 포함한 테넌트의 "
                                                       "Azure 역할 할당을, 역할 할당·정의만 읽는 역할로 테넌트 루트 관리 그룹에서 "
                                                       "읽습니다.")},
                                   {"name": "federated_credentials", "kind": "bool", "default": False,
                                    "label": "Application workload federation configuration",
                                    "label_ko": "앱 워크로드 신원 연합 설정"},
                                   {"name": "public_certificates", "kind": "bool", "default": False,
                                    "label": "Public certificates for exact Key Vault comparison",
                                    "label_ko": "Key Vault 대조용 공개 인증서",
                                    "description": "Compares public DER only; never proves private-key storage.",
                                    "description_ko": "공개 DER만 대조하며 개인키 보관을 입증하지 않습니다."},
                                   {"name": "find_subscriptions", "kind": "bool", "default": False,
                                    "label": "Also list the subscriptions the identity can see",
                                    "label_ko": "신원이 볼 수 있는 구독 목록도 수집"},
                                   {"name": "storage_key_accounts", "kind": "list",
                                    "label": "Storage accounts whose key fingerprints are read (resource IDs)",
                                    "label_ko": "키 지문을 읽을 스토리지 계정(리소스 ID)",
                                    "hint": "/subscriptions/…/resourceGroups/…/providers/Microsoft.Storage/"
                                            "storageAccounts/acmedata"}]},
            "vault": {"permissions": [_p("key_vault_list", "List Key Vault secrets", "Key Vault 시크릿 목록"),
                                      _p("key_vault_keys", "List Key Vault keys", "Key Vault 키 목록", option="keys"),
                                      _p("key_vault_certificates", "List Key Vault certificates", "Key Vault 인증서 목록",
                                         option="certificates"),
                                      _p("key_vault_deleted", "List deleted Key Vault resources", "Key Vault 삭제 리소스 목록",
                                         option="deleted"),
                                      _p("key_vault_public_certificates", "Read public certificate bundles",
                                         "공개 인증서 번들 읽기", option="public_certificates"),
                                      _p("key_vault_values", "Read Key Vault secret values", "Key Vault 시크릿 값 읽기",
                                         option="read_values"), _SELF_READ],
                      "plan": [_SCHEDULE, {"name": "read_values", "kind": "bool", "default": False,
                                           "label": "Read secret values to compare with what was found exposed",
                                           "label_ko": "노출 발견값과 대조하도록 시크릿 값 읽기"},
                               {"name": "versions", "kind": "bool", "default": False,
                                "label": "Include resource versions", "label_ko": "리소스 버전 목록 포함"},
                               {"name": "deleted", "kind": "bool", "default": False,
                                "label": "Include soft-deleted resources", "label_ko": "복구 가능한 삭제 리소스 포함"},
                               {"name": "keys", "kind": "bool", "default": False,
                                "label": "Key metadata (no key material)", "label_ko": "키 메타데이터(키 원문 제외)"},
                               {"name": "certificates", "kind": "bool", "default": False,
                                "label": "Certificate metadata", "label_ko": "인증서 메타데이터"},
                               {"name": "public_certificates", "kind": "bool", "default": False,
                                "label": "Public certificates for exact Entra comparison",
                                "label_ko": "Entra 대조용 공개 인증서(인증서 목록 포함)"}]},
            "identity": {"permissions": [_p("users_read", "User.Read.All", "User.Read.All"),
                                         _PEOPLE_ORGANIZATION, _SELF_READ],
                         "plan": [{**_SCHEDULE, "default": 60}, _PEOPLE]},
        },
        "auth_methods": [{**_CERTIFICATE, "purposes": list(_SERVICES), "auth_first": {"context": ["tenant"]}},
                         {**_AMBIENT, "purposes": list(_SERVICES), "auth_first": {"context": ["tenant"]}}],
    },
    {
        "provider": "azure_devops",
        "label": "Azure DevOps", "label_ko": "Azure DevOps",
        "category": "code",
        "editions": [{"id": "cloud", "label": "Azure DevOps Services", "label_ko": "Azure DevOps Services"},
                     {"id": "server", "label": "Azure DevOps Server", "label_ko": "Azure DevOps Server",
                      "origin": True}],
        "target": [
            {"name": "base_url", "label": "Server address", "label_ko": "서버 주소", "kind": "url", "required": True,
             "editions": ["server"], "hint": "https://devops.example.com/tfs"},
            {"name": "organization", "label": "Organization (or collection)", "label_ko": "조직(또는 컬렉션)",
             "kind": "text", "required": True},
            {"name": "project", "label": "Project", "label_ko": "프로젝트", "kind": "text"},
        ],
        "purposes": {
            "exposure": {"permissions": [_p("code_read", "Code (read)", "코드(읽기)")], "scans": _DEVOPS_SCANS},
            "inventory": {"permissions": list(_DEVOPS_READS), "types": DEVOPS_TYPES, "plan": [_SCHEDULE]},
            # Revoking a token an approved plan names: vso.tokenadministration lists and revokes, for a Project
            # Collection Administrator; the check lists one user's tokens and revokes nothing.
            "remediation": {"permissions": [
                _DEVOPS_READS[0],
                _p("token_administration", "Token administration (lists and revokes; Project Collection Administrator)",
                   "토큰 관리(목록·폐기, 프로젝트 컬렉션 관리자)")]},
        },
        # Azure DevOps Server publishes the token list too, but CreMore lists tokens only on Services; a Server scans
        # only.
        "auth_methods": [{"id": "token", "label": "Personal access token", "label_ko": "개인 액세스 토큰",
                          "auth_first": {"context": ["organization"]},
                          "renewal": "EXPIRES", "editions": ["cloud"], "purposes": ["exposure", "inventory", "remediation"],
                          "fields": [_DEVOPS_TOKEN]},
                         {"id": "server_token", "label": "Personal access token", "label_ko": "개인 액세스 토큰",
                          "auth_first": {"context": ["base_url", "organization"]},
                          "renewal": "EXPIRES", "editions": ["server"], "purposes": ["exposure"],
                          "fields": [_DEVOPS_TOKEN]}],
    },
    {
        "provider": "entra_id",
        "label": "Microsoft Entra ID (people)", "label_ko": "Microsoft Entra ID(사람)",
        "category": "identity",
        # New connections take people from the Microsoft connection (its "people directory" feature).
        "replaced_by": "azure",
        "editions": [{"id": "cloud", "label": "Microsoft Entra ID", "label_ko": "Microsoft Entra ID"}],
        "target": [{"name": "tenant", "label": "Tenant ID", "label_ko": "테넌트 ID", "kind": "id", "required": True}],
        "purposes": {"identity": {"permissions": [_p("users_read", "User.Read.All", "User.Read.All"),
                                                  _PEOPLE_ORGANIZATION],
                                  "plan": [{**_SCHEDULE, "default": 60}, _PEOPLE]}},
        "auth_methods": [{**_AMBIENT, "purposes": ["identity"]}],
    },
]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _guid(value, code):
    value = str(value or "").lower()
    if not _GUID.fullmatch(value):
        raise OnboardingValueError(code)
    return value


def sign_in_target(provider, issuer):
    """The tenant people sign in with, when the console's sign-in issuer is Microsoft Entra ID's: v2.0
    (``https://login.microsoftonline.com/<tenant>/v2.0``) or v1 (``https://sts.windows.net/<tenant>/``) tokens of the
    global cloud (cremore.onboarding.sign_in)."""
    from urllib.parse import urlsplit

    if provider not in ("azure", "entra_id"):
        return None
    parts = urlsplit(issuer)
    host, segments = (parts.hostname or "").lower(), [part for part in parts.path.split("/") if part]
    if parts.scheme != "https" or parts.port not in (None, 443) or parts.query or parts.fragment or not segments:
        return None
    tenant = segments[0].lower()
    shapes = {"login.microsoftonline.com": (["v2.0"],), "sts.windows.net": ([],)}
    if not _GUID.fullmatch(tenant) or segments[1:] not in shapes.get(host, ()):
        return None
    return {"tenant": tenant}


def target(provider, edition, values):
    if provider == "azure_devops":
        from cremore_azure_provider.devops_content import valid_name

        organization, project = values.get("organization", ""), values.get("project", "")
        if edition == "cloud" and not _ORGANIZATION.fullmatch(organization) or not valid_name(organization):
            raise OnboardingValueError("AZURE_DEVOPS_ORGANIZATION_INVALID")
        if project and not valid_name(project):
            raise OnboardingValueError("AZURE_DEVOPS_PROJECT_INVALID")
        out = {"organization": organization, **({"project": project} if project else {})}
        if edition == "server":
            from cremore.sources.validation import https_base

            try:
                out["base_url"] = https_base(values.get("base_url") or "").rstrip("/")
            except ValueError:
                raise OnboardingValueError("AZURE_DEVOPS_ADDRESS_INVALID") from None
        return out
    out = {"tenant": _guid(values.get("tenant"), "AZURE_TENANT_ID_INVALID")}
    if provider == "entra_id":
        return out
    if values.get("subscription"):
        out["subscription"] = _guid(values["subscription"], "AZURE_SUBSCRIPTION_ID_INVALID")
    if values.get("storage_account"):
        if not _STORAGE.fullmatch(values["storage_account"]):
            raise OnboardingValueError("AZURE_STORAGE_ACCOUNT_INVALID")
        out["storage_account"] = values["storage_account"]
    vaults = values.get("key_vaults") or []
    if any(not _VAULT.fullmatch(vault) for vault in vaults):
        raise OnboardingValueError("AZURE_KEY_VAULT_NAME_INVALID")
    if vaults:
        out["key_vaults"] = [vault.lower() for vault in vaults]
    organization, project = values.get("devops_organization") or "", values.get("devops_project") or ""
    if project and not organization:
        raise OnboardingValueError("AZURE_DEVOPS_ORGANIZATION_REQUIRED")
    if organization:
        if not _ORGANIZATION.fullmatch(organization):
            raise OnboardingValueError("AZURE_DEVOPS_ORGANIZATION_INVALID")
        out["devops_organization"] = organization
    if project:
        from cremore_azure_provider.devops_content import valid_name

        # The same rule as the Azure DevOps connection and the content source this project becomes.
        if not valid_name(project):
            raise OnboardingValueError("AZURE_DEVOPS_PROJECT_INVALID")
        out["devops_project"] = project
    return out


def credential(provider, method, fields):
    if provider != "azure_devops":
        return {}  # the worker's own Azure identity; a certificate is made by generate()
    token = fields.get("token", "").strip()
    if not _TOKEN.fullmatch(token):
        raise OnboardingValueError("AZURE_DEVOPS_TOKEN_INVALID")
    return {"credential": {"token": token}}


def ready(repo, settings, connection):
    if (connection["provider"] == "azure_devops" and "exposure" in connection["purposes"]
            and not connection["target"].get("project")):
        raise OnboardingValueError("AZURE_DEVOPS_PROJECT_REQUIRED")


def generate(provider, method, fields, target_):
    """The key and certificate CreMore makes for the app registration a Microsoft connection signs in with:
    ``({"credential": envelope}, public part)``. Only the public part is ever shown."""
    if provider != "azure" or method != "certificate":
        raise OnboardingValueError("CREDENTIAL_NOT_GENERATED")
    from cremore_azure_provider.app_certificate import make

    client_id = _guid(fields.get("client_id"), "AZURE_CLIENT_ID_INVALID")
    envelope, shown = make(client_id, target_["tenant"])
    return {"credential": envelope}, shown


def _ambient(scope, tenant):
    from cremore_azure_provider.metadata.transport import default_token

    return default_token(scope, tenant_id=tenant)()


def _bearer(connection, secrets, scope, context):
    """The Authorization header for one Microsoft resource: a token from the app certificate, or from the
    worker's own identity. Asked once per check (the purposes share it)."""
    key = ("azure-token", scope)
    if key not in context.memo:
        if connection["auth_method"] == "certificate":
            from cremore_azure_provider.app_certificate import CertificateError, request_token

            client = context.http_client()
            try:
                context.memo[key] = request_token(client, secrets.get("credential") or {}, scope)[0]
            except CertificateError as exc:
                raise OnboardingValueError(exc.code) from None
            finally:
                client.close()
        else:
            context.memo[key] = _ambient(scope, connection["target"]["tenant"])
    return {"Authorization": "Bearer " + context.memo[key]}


def _devops_items(client, headers, base, organization, project, purpose):
    """Azure DevOps: code for an exposure scan; the organization's users, then one user's tokens, for the
    inventory. A refused token answers 203 (the sign-in page), 401 or 403."""
    organization = quote(organization, safe="")
    if purpose == "exposure":
        from cremore_azure_provider.devops_content import API_VERSION

        # The scan's own version: a Server answers only the versions it ships (5.0 from Server 2019).
        version = API_VERSION["cloud" if base == DEVOPS else "server"]
        return [item("code_read", probe(client, "GET", f"{base}/{organization}/{quote(project, safe='')}"
                                                       f"/_apis/git/repositories?api-version={version}", headers=headers,
                                        missing=(203, 401, 403)))]
    users = probe(client, "GET", f"{DEVOPS_GRAPH}/{organization}/_apis/graph/users?api-version=7.1-preview.1",
                  headers=headers, missing=(203, 401, 403))
    items = [item("graph_read", users)]
    rows = (json_body(users[2]) or {}).get("value") if users[0] == "GRANTED" else None
    descriptor = (rows or [{}])[0].get("descriptor") if rows else None
    if not descriptor:
        items.append({"permission": "token_administration", "status": "NOT_REPORTED", "detail": "NO_USER_TO_ASK_ABOUT"})
    else:
        items.append(item("token_administration", probe(
            client, "GET", f"{DEVOPS_GRAPH}/{organization}/_apis/tokenadmin/personalaccesstokens/"
                           f"{quote(descriptor, safe='')}?api-version=7.1&pageSize=1", headers=headers,
            missing=(203, 401, 403))))
    return items


def _devops_check(connection, purpose, envelope, context):
    target_ = connection["target"]
    if purpose == "exposure" and not target_.get("project"):
        return [{"permission": "code_read", "status": "MISSING", "detail": "AZURE_DEVOPS_PROJECT_REQUIRED"}]
    headers = {"Authorization": "Basic " + base64.b64encode((":" + envelope.get("token", "")).encode()).decode()}
    client = context.http_client()
    try:
        return _devops_items(client, headers, target_.get("base_url") or DEVOPS, target_["organization"],
                             target_.get("project", ""), purpose)
    finally:
        client.close()


from cremore_azure_provider.onboarding_discovery import (  # noqa: F401
    auth_context,
    authenticate,
    discover,
)


def _own_application(connection, secrets, client, context):
    """The certificate's renewal reads the app's own application object (Application.Read.All)."""
    key = ("azure-own-application",)
    if key not in context.memo:
        client_id = (secrets.get("credential") or {}).get("client_id", "")
        graph = _bearer(connection, secrets, GRAPH + "/.default", context)
        context.memo[key] = item("applications_read", probe(
            client, "GET", f"{GRAPH}/v1.0/applications(appId='{quote(client_id, safe='')}')?$select=id", headers=graph))
    return dict(context.memo[key])


def _logs(permission, result):
    """A log read's answer; a tenant without Microsoft Entra ID P1 or P2 is refused for its license, not a permission."""
    row = item(permission, result)
    body = json_body(result[2]) if row["status"] == "MISSING" else None
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict) and error.get("code") == "Authentication_RequestFromNonPremiumTenantOrB2CTenant":
        row["detail"] = "AZURE_ENTRA_PREMIUM_REQUIRED"
    return row


def permission_plan(connection, purpose, plan):
    if purpose == "vault" and plan.get("public_certificates"):
        return {**plan, "certificates": True}
    if purpose == "inventory" and connection.get("target_id"):
        prefix = f"/subscriptions/{connection['target'].get('subscription', '')}/".lower()
        return {**plan, "storage_key_accounts": [key for key in plan.get("storage_key_accounts", [])
                                                if key.lower().startswith(prefix)]}
    return plan


def permission_subjects(connection, purpose, permission, plan):
    if permission in {"key_vault_list", "key_vault_values", "key_vault_keys", "key_vault_certificates",
                      "key_vault_deleted", "key_vault_public_certificates"}:
        return connection["target"].get("key_vaults", [])
    if permission == "storage_keys_read":
        return permission_plan(connection, purpose, plan).get("storage_key_accounts", [])
    return []


def check(connection, purpose, secrets, context):
    if connection["provider"] == "azure_devops":
        return _devops_check(connection, purpose, secrets.get("credential") or {}, context)
    target_ = connection["target"]
    plan = permission_plan(connection, purpose, connection.get("checks", {}).get("requested_plans", {}).get(
        purpose, connection.get("plans", {}).get(purpose, {})))
    client = context.http_client()
    try:
        own = ([_own_application(connection, secrets, client, context)]
               if connection["auth_method"] == "certificate" and purpose != "inventory" else [])
        if connection["provider"] == "entra_id" or purpose == "identity":
            graph = _bearer(connection, secrets, GRAPH + "/.default", context)
            return [item("users_read", probe(client, "GET", GRAPH + "/v1.0/users?$top=1&$select=id", headers=graph)),
                    item("organization_read", probe(client, "GET", GRAPH + "/v1.0/organization?$select=id", headers=graph)),
                    *own]
        if purpose == "inventory":
            graph = _bearer(connection, secrets, GRAPH + "/.default", context)
            items = [item("applications_read", probe(client, "GET", GRAPH + "/v1.0/applications?$top=1&$select=id",
                                                     headers=graph)),
                     # The inventory confirms the tenant by its organization before it lists anything.
                     item("organization_read", probe(client, "GET", GRAPH + "/v1.0/organization?$select=id", headers=graph))]
            if plan.get("directory_audits"):
                items.append(_logs("directory_audits", probe(client, "GET", GRAPH + "/v1.0/auditLogs/directoryAudits",
                    headers=graph, params={"$top": 1, "$select": "id"})))
            if plan.get("credential_sign_ins"):
                items.append(_logs("credential_sign_ins", probe(client, "GET", GRAPH + "/beta/auditLogs/signIns",
                    params={"$top": 1, "$select": "id", "$filter": "signInEventTypes/any(t: t eq 'servicePrincipal')"},
                    headers=graph)))
            if plan.get("app_permissions"):
                # The Global Administrator role's definition.
                items.append(item("role_management_read", probe(client, "GET", GRAPH + "/v1.0/roleManagement/directory/"
                                  "roleDefinitions/62e90394-69f5-4237-9190-012177145e10", params={"$select": "id"},
                                  headers=graph)))
            if plan.get("app_azure_roles"):
                # The role assignments made at the tenant root, which exists once management groups are first used.
                arm = _bearer(connection, secrets, ARM + "/.default", context)
                row = item("root_role_assignments", probe(
                    client, "GET", f"{ARM}/providers/Microsoft.Management/managementGroups/{target_['tenant']}"
                    "/providers/Microsoft.Authorization/roleAssignments",
                    params={"api-version": "2022-04-01", "$filter": "atScope()"}, headers=arm))
                if row.get("detail") == "HTTP_404":
                    row["detail"] = "AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND"
                items.append(row)
            if target_.get("subscription"):
                arm = _bearer(connection, secrets, ARM + "/.default", context)
                items.append(item("subscription_read", probe(
                    client, "GET", f"{ARM}/subscriptions/{target_['subscription']}?api-version=2022-12-01",
                    headers=arm), subject=target_["subscription"]))
            else:
                items.append({"permission": "subscription_read", "status": "NOT_REPORTED",
                              "detail": "NO_SUBSCRIPTION_CHOSEN"})
            if connection.get("checks", {}).get("requested_plans", {}).get(purpose, {}).get("find_subscriptions"):
                arm = _bearer(connection, secrets, ARM + "/.default", context)
                items.append(item("subscriptions_list", probe(client, "GET",
                    ARM + "/subscriptions?api-version=2022-12-01", headers=arm)))
            # ARM Reader is not listKeys. Probing listKeys would retrieve live
            # credentials; no non-value permission evidence is available here.
            items.extend({"permission": "storage_keys_read", "status": "NOT_REPORTED", "subject": account,
                          "detail": "VALUE_READ_PERMISSION_NOT_CHECKED"}
                         for account in plan.get("storage_key_accounts", []))
            if target_.get("devops_organization"):
                from cremore_azure_provider.app_certificate import SCOPES

                devops = _bearer(connection, secrets, SCOPES["devops"], context)
                items.extend(_devops_items(client, devops, DEVOPS, target_["devops_organization"], None, "inventory"))
            return items
        if purpose == "exposure":
            items = list(own)
            account = target_.get("storage_account")
            if account:
                storage = {**_bearer(connection, secrets, "https://storage.azure.com/.default", context),
                           "x-ms-version": "2021-12-02"}
                items.append(item("blob_read", probe(client, "GET", f"https://{account}.blob.core.windows.net/?comp=list"
                                                                    "&maxresults=1", headers=storage), subject=account))
            elif target_.get("devops_project"):
                items.append({"permission": "blob_read", "status": "NOT_REPORTED", "detail": "NO_STORAGE_ACCOUNT_CHOSEN"})
            else:
                items.append({"permission": "blob_read", "status": "MISSING", "detail": "STORAGE_ACCOUNT_REQUIRED"})
            if target_.get("devops_project"):
                from cremore_azure_provider.app_certificate import SCOPES

                devops = _bearer(connection, secrets, SCOPES["devops"], context)
                items.extend(_devops_items(client, devops, DEVOPS, target_["devops_organization"],
                                           target_["devops_project"], "exposure"))
            return items
        vaults = target_.get("key_vaults") or []
        if not vaults:
            return [{"permission": "key_vault_list", "status": "MISSING", "detail": "KEY_VAULT_REQUIRED"}, *own]
        vault_headers = _bearer(connection, secrets, "https://vault.azure.net/.default", context)
        extra = []
        for vault in vaults:
            for family in ("secrets", "keys", "certificates"):
                if family != "secrets" and not plan.get(family):
                    continue
                paths = [("key_vault_" + family, family)] if family != "secrets" else []
                if plan.get("deleted"):
                    paths.append(("key_vault_deleted", "deleted" + family))
                for permission, path in paths:
                    result = probe(client, "GET",
                        f"https://{vault}.vault.azure.net/{path}?maxresults=1&api-version=7.4",
                        headers=vault_headers)
                    extra.append(item(permission, result, subject=vault))
                    if path == "certificates" and plan.get("public_certificates"):
                        body = json_body(result[2])
                        rows = body.get("value", []) if isinstance(body, dict) else []
                        name = rows[0].get("id") if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
                        if isinstance(name, str) and re.fullmatch(
                                re.escape(f"https://{vault}.vault.azure.net/certificates/") + r"[A-Za-z0-9-]{1,127}", name):
                            extra.append(item("key_vault_public_certificates", probe(client, "GET", name,
                                params={"api-version": "7.4"}, headers=vault_headers), subject=vault))
                        else:
                            extra.append({"permission": "key_vault_public_certificates", "subject": vault,
                                          "status": "NOT_REPORTED", "detail": "PUBLIC_CERTIFICATE_GET_NOT_CHECKED"})
        return [*[item("key_vault_list", probe(client, "GET", f"https://{vault}.vault.azure.net/secrets?maxresults=1"
                                                              "&api-version=7.4", headers=vault_headers), subject=vault)
                  for vault in vaults],
                *({"permission": "key_vault_values", "status": "NOT_REPORTED", "subject": vault,
                   "detail": "VALUE_READ_PERMISSION_NOT_CHECKED"}
                  for vault in vaults if plan.get("read_values")), *extra, *own]
    finally:
        client.close()


def children(connection, purpose, plan):
    plan = permission_plan(connection, purpose, plan)
    target_ = connection["target"]
    schedule = plan.get("schedule_minutes", 1440)
    if connection["provider"] == "azure_devops":
        organization, project = target_["organization"], target_.get("project", "")
        if purpose == "remediation":
            return []  # used only by an approved action plan (cremore_azure_provider.devops_tokens.remediation)
        if purpose == "exposure":
            if not project:
                raise OnboardingValueError("AZURE_DEVOPS_PROJECT_REQUIRED")
            config = {"organization": organization, "project": project,
                      **({"base_url": target_["base_url"]} if target_.get("base_url") else {})}
            return [{"kind": "content", "purpose": purpose, "source_type": "azure_devops",
                     "name": f"Azure DevOps · {organization}/{project}", "config": config,
                     "secret_slots": {"secret_ref": "credential"}}]
        spec = {"schema_version": 2, "provider": "azure_devops", "name": f"Azure DevOps · {organization} · tokens",
                "origin": DEVOPS_GRAPH, "edition": "cloud", "scopes": [{"kind": "organization", "id": organization}],
                "capabilities": ["inventory"], "auth_type": "token", "options": {"mode": "inventory"},
                "schedule_minutes": schedule}
        return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": {"token": "credential"}}]
    tenant = target_["tenant"]
    # The app certificate's one envelope serves every record: a collection names its three parts, a content
    # source the envelope itself. The worker's own identity needs no reference.
    signed = connection["auth_method"] == "certificate"
    slots = {"secret_slots": dict.fromkeys(("client_id", "private_key", "tenant_id"), "credential")} if signed else {}
    content = {"secret_slots": {"secret_ref": "credential"}} if signed else {}
    auth = "private_key_jwt" if signed else "workload_identity"
    base = {"schema_version": 2, "edition": "cloud", "auth_type": auth, "schedule_minutes": schedule}
    if connection["provider"] == "entra_id" or purpose == "identity":
        return [{"kind": "metadata", "purpose": purpose, **slots, "spec": {
            **base, "provider": "entra_id", "name": "Entra ID · people", "origin": GRAPH, "tenant": tenant,
            "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": tenant}],
            "capabilities": ["identity_status"],
            "options": {"mode": "inventory", **({"keep_profiles": True} if plan.get("people_details") else {})}}}]
    organization, project = target_.get("devops_organization"), target_.get("devops_project")
    if purpose == "exposure":
        out = []
        account = target_.get("storage_account")
        if account:
            out.append({"kind": "content", "purpose": purpose, "source_type": "azure_blob",
                        "name": f"Azure Blob · {account}", "config": {"account": account}, **content})
        if organization and project:
            out.append({"kind": "content", "purpose": purpose, "source_type": "azure_devops",
                        "name": f"Azure DevOps · {organization}/{project}",
                        "config": {"organization": organization, "project": project}, **content})
        if not out:
            raise OnboardingValueError("AZURE_EXPOSURE_TARGET_REQUIRED")
        return out
    if purpose == "inventory":
        sources = ["applications", "service_principals"]
        if plan.get("federated_credentials"):
            sources.append("federated_identity_credentials")
        if plan.get("public_certificates"):
            sources.append("public_certificates")
        if plan.get("credential_sign_ins"):
            sources.append("credential_sign_ins")
        if plan.get("directory_audits"):
            sources.append("directory_audits")
        sources += [name for name in ("app_permissions", "app_azure_roles") if plan.get(name)]
        out = [{"kind": "metadata", "purpose": purpose, **slots, "spec": {
            **base, "provider": "azure_entra", "name": "Entra ID · application credentials", "origin": GRAPH,
            "tenant": tenant, "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": tenant}],
            "capabilities": ["inventory", "public_keys"]
                            + (["policy"] if plan.get("federated_credentials") or plan.get("app_permissions")
                               or plan.get("app_azure_roles") else [])
                            + (["audit"] if plan.get("credential_sign_ins") or plan.get("directory_audits") else []),
            "options": {"mode": "inventory", "sources": sources,
                        **({"audit_lookback_days": plan.get("audit_days", 1)} if plan.get("credential_sign_ins") or plan.get("directory_audits") else {})}}}]
        arm = {**base, "provider": "azure_resource_manager", "origin": ARM, "tenant": tenant, "tenant_confirmed": True}
        keys = plan.get("storage_key_accounts") or []
        if keys and not target_.get("subscription"):
            raise OnboardingValueError("AZURE_STORAGE_KEYS_NEED_THE_SUBSCRIPTION")
        if target_.get("subscription"):
            # Key fingerprints are read only for the accounts named here, in the approved subscription.
            out.append({"kind": "metadata", "purpose": purpose, **slots, "spec": {
                **arm, "name": f"Azure · subscription {target_['subscription']}",
                "scopes": [{"kind": "subscription", "id": target_["subscription"]}],
                "capabilities": ["inventory"] + (["issuer_value"] if keys else []),
                "options": {"mode": "inventory",
                            **({"sources": ["vaults", "storage_accounts", "storage_keys"], "include_values": True,
                                "azure_storage_accounts": keys} if keys else {})}}})
        if plan.get("find_subscriptions"):
            out.append({"kind": "metadata", "purpose": purpose, **slots, "spec": {
                **arm, "name": "Azure · subscriptions", "scopes": [{"kind": "organization", "id": tenant}],
                "capabilities": ["inventory"], "options": {"mode": "discovery", "sources": ["subscriptions"]}}})
        if organization:
            out.append({"kind": "metadata", "purpose": purpose, **slots, "spec": {
                **base, "provider": "azure_devops", "name": f"Azure DevOps · {organization} · tokens",
                "origin": DEVOPS_GRAPH, "scopes": [{"kind": "organization", "id": organization}],
                "capabilities": ["inventory"], "options": {"mode": "inventory"}}})
        return out
    vaults = target_.get("key_vaults") or []
    if not vaults:
        raise OnboardingValueError("AZURE_KEY_VAULT_REQUIRED")
    values = bool(plan.get("read_values"))
    sources = ["secrets"]
    for family, singular in (("secrets", ""), ("keys", "key_"), ("certificates", "certificate_")):
        if family != "secrets":
            if not plan.get(family):
                continue
            sources.append(family)
        if plan.get("versions"):
            sources.append(singular + "versions")
        if plan.get("deleted"):
            sources.append("deleted_" + family)
    if plan.get("public_certificates"):
        sources.append("public_certificates")
    return [{"kind": "metadata", "purpose": purpose, **slots, "spec": {
        **base, "provider": "azure_key_vault", "name": f"Key Vault · {vault}", "origin": f"https://{vault}.vault.azure.net",
        "scopes": [{"kind": "vault", "id": vault}],
        "capabilities": ["vault_metadata"] + (["vault_value"] if values else [])
                        + (["public_keys"] if plan.get("public_certificates") else []),
        "options": {"mode": "inventory", "sources": sources,
                    **({"include_values": True} if values else {})}}} for vault in vaults]


def renew_due(record, kept, now):
    """What the worker does next for the certificate a Microsoft connection signs in with: ``renew`` it in
    its last months, ``retire`` the old one a day after, or nothing (app_certificate.due)."""
    if record.get("provider") != "azure" or record.get("auth_method") != "certificate":
        return None
    from cremore_azure_provider.app_certificate import due

    return due((record.get("target") or {}).get("generated"), (kept or {}).get("retire"), now)


def renew(record, envelope, action, kept, context):
    """``renew``: the next certificate added to the application with the current one --
    ``{"credential": envelope, "generated": public part, "keep": {"retire": ...}}``; ``retire``: the old
    certificate removed -- ``{"keep": None}``."""
    from cremore_azure_provider import app_certificate

    client = context.http_client()
    try:
        if action == "retire":
            old = (kept or {}).get("retire") or {}
            app_certificate.retire(envelope, old.get("object_id"), old.get("key_id"), client=client)
            return {"keep": None}
        made = app_certificate.renew(envelope, client=client, now=context.now)
        return {"credential": made["envelope"], "generated": made["public"], "keep": {"retire": made["retire"]}}
    except app_certificate.CertificateError as exc:
        raise OnboardingValueError(exc.code) from None
    finally:
        client.close()
