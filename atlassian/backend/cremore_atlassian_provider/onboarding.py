"""Confluence, Bitbucket and the Atlassian organization in the connection wizard (cremore.onboarding).

* Confluence: a token that reads the space scans its pages (the space ID on Cloud, the
  space key on Data Center).
* Bitbucket: a workspace access token (Cloud) or HTTP access token (Data Center) scans
  the repositories; the inventory lists a Data Center project's HTTP access tokens, or a
  Cloud workspace's SSH and deploy keys (Cloud access tokens cannot be listed). Cloud also
  takes an Atlassian API token with the account's e-mail. Admin reads are checked with the
  listing they need.
* Atlassian organization: an organization admin API key lists the API tokens of the
  organization's managed accounts.
"""

from __future__ import annotations

import base64
import re
import uuid as _uuid
from urllib.parse import quote

from cremore.onboarding.probe import all_items, item, json_body, probe
from cremore.sources.validation import https_base
from cremore_atlassian_provider import cloud_api

_TOKEN = re.compile(r"[\x21-\x7e]{16,1024}")
_SPACE = re.compile(r"[A-Za-z0-9_-]{1,255}")
_KEY = re.compile(r"[A-Za-z0-9_~-]{1,128}")
_EMAIL = re.compile(r"[^\s:@]+@[^\s:@]+")
BITBUCKET_CLOUD = "https://api.bitbucket.org"
ADMIN = "https://api.atlassian.com"
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
_TOKEN_FIELD = {"name": "token", "label": "Token", "label_ko": "토큰", "kind": "secret", "secret": True}


def _p(name, label, label_ko, **extra):
    return {"id": name, "label": label, "label_ko": label_ko, **extra}


# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state).
_NO_STATE = ["상태를 주지 않고, 삭제되면 목록에서 빠집니다", "No state is given; a deleted one leaves the list"]
BITBUCKET_TYPES = [
    {"id": "http_access_token", "label": "HTTP access token", "label_ko": "HTTP 액세스 토큰", "editions": ["data_center"],
     "description": "Project HTTP access tokens of the project.",
     "description_ko": "프로젝트의 HTTP 액세스 토큰입니다.",
     "permission": "list_access_tokens", "credential_type": "BITBUCKET_HTTP_ACCESS_TOKEN",
     "match": [{"provider": "bitbucket", "prefix": "dc:"}], "support": "YYYNNNNNN", "reasons": {
         "expires": ["목록 API가 만료일을 주지 않습니다", "The list API gives no expiry"],
         "scopes": ["목록 API가 권한을 주지 않습니다", "The list API gives no permissions"],
         "creator": ["목록 API가 만든 사람을 주지 않습니다", "The list API does not say who made it"],
         "owner": ["목록 API가 소유 계정을 주지 않습니다", "The list API gives no owning account"],
         "last_used": ["목록 API가 마지막 사용을 주지 않습니다", "The list API gives no last use"],
         "state": ["목록 API가 상태를 주지 않습니다", "The list API gives no state"]}},
    {"id": "ssh_key", "label": "SSH key", "label_ko": "SSH 키", "editions": ["cloud"],
     "description": "SSH keys of the workspace's members, as far as Bitbucket shows them to the token.",
     "description_ko": "워크스페이스 구성원의 SSH 키입니다(Bitbucket이 이 토큰에 보여 주는 만큼).",
     "permission": "list_access_tokens", "credential_type": "BITBUCKET_SSH_KEY",
     "match": [{"provider": "bitbucket", "contains": "/user-ssh-key/"}], "support": "YYYYNYYYN", "reasons": {
         "scopes": ["SSH 키는 사용자의 권한을 그대로 씁니다", "An SSH key acts with its user's access"], "state": _NO_STATE}},
    {"id": "deploy_key", "label": "Deploy key", "label_ko": "배포 키", "editions": ["cloud"],
     "description": "Read-only access keys of projects and repositories.", "description_ko": "프로젝트·저장소의 읽기 전용 접근 키입니다.",
     "permission": "list_access_tokens", "credential_type": "BITBUCKET_DEPLOY_KEY",
     "match": [{"provider": "bitbucket", "contains": "/project-deploy-key/"},
               {"provider": "bitbucket", "contains": "/repository-deploy-key/"}], "support": "YYYNNPNYN", "reasons": {
         "expires": ["배포 키에는 만료일이 없습니다", "Deploy keys do not expire"],
         "scopes": ["Bitbucket 배포 키는 읽기 전용뿐입니다", "Bitbucket deploy keys are read-only"],
         "creator": ["프로젝트 배포 키만 만든 사람을 줍니다", "Only project deploy keys say who made them"],
         "owner": ["사람이 아니라 저장소·프로젝트에 묶입니다", "Bound to repositories or projects, not a person"],
         "state": _NO_STATE}},
]


def _source(*names):
    return [{"provider": "atlassian", "fact": "metadata.source", "in": list(names)},
            {"provider": "atlassian", "fact": "context.operation", "in": list(names)}]


_SCOPED = ["범위를 지정해 만든 토큰만 권한을 줍니다", "Only tokens made with scopes list them"]
_SERVICE_ACCOUNT_ROWS = ["서비스 계정 형태의 행만 줍니다. 조직 OAuth 클라이언트 목록 행에는 없습니다",
                         "Only service-account-shaped rows give it; organization OAuth client rows do not"]
ATLASSIAN_TYPES = [
    {"id": "api_token", "label": "User API token", "label_ko": "사용자 API 토큰",
     "description": "API tokens of the organization's managed accounts.", "description_ko": "조직 관리 계정의 API 토큰입니다.",
     "permission": "organization_admin", "credential_type": "ATLASSIAN_API_TOKEN",
     "match": _source("org-api-tokens", "user-api-tokens"), "support": "YYYYPNYYY", "reasons": {"scopes": _SCOPED,
         "creator": ["목록의 계정은 소유자입니다. 별도 생성자는 제공되지 않습니다", "The listed account is the owner; no separate creator is returned"]}},
    {"id": "admin_api_key", "label": "Organization API key", "label_ko": "조직 API 키",
     "description": "Keys used for the organization admin API.", "description_ko": "조직 관리 API에 쓰는 키입니다.",
     "permission": "organization_admin", "credential_type": "ATLASSIAN_ADMIN_API_KEY",
     "match": _source("admin-api-keys"), "support": "YYYYYYNYP", "reasons": {
         "owner": ["사람이 아니라 조직에 묶입니다", "Bound to the organization, not a person"],
         "state": ["상태를 주지 않아 만료일로만 판단합니다", "No state is given; only the expiry tells"]}},
    {"id": "service_account_token", "label": "Service account API token", "label_ko": "서비스 계정 API 토큰",
     "description": "API tokens of the organization's service accounts.", "description_ko": "조직 서비스 계정의 API 토큰입니다.",
     "permission": "organization_admin", "credential_type": "ATLASSIAN_SERVICE_ACCOUNT_TOKEN",
     "match": _source("service-account-api-tokens", "service-account-api-tokens-by-account"),
     "support": "YYYYPNYYY", "reasons": {"scopes": _SCOPED,
                                         "creator": ["만든 관리자를 주지 않습니다", "The admin who made it is not given"]}},
    {"id": "oauth_client", "label": "Service account OAuth client", "label_ko": "서비스 계정 OAuth 클라이언트",
     "description": "OAuth clients of service accounts, with their scopes and expiry, and of the organization.",
     "description_ko": "서비스 계정의 OAuth 클라이언트와 권한·만료일, 조직의 OAuth 클라이언트입니다.",
     "permission": "organization_admin", "credential_type": "ATLASSIAN_OAUTH_CLIENT",
     "plan": [{"field": "oauth_clients"}],
     "match": _source("service-account-oauth-clients", "service-account-oauth-clients-by-account", "org-oauth-clients"),
     # The organization listing's data/links rows carry only clientId, name, createdAt, updatedAt and status.
     "support": "YYYPPPPNY", "reasons": {
         "expires": _SERVICE_ACCOUNT_ROWS, "scopes": _SERVICE_ACCOUNT_ROWS, "creator": _SERVICE_ACCOUNT_ROWS,
         "owner": _SERVICE_ACCOUNT_ROWS, "last_used": ["마지막 사용을 주지 않습니다", "No last use is given"]}},
]

DESCRIPTORS = [
    {
        "provider": "confluence",
        "label": "Confluence", "label_ko": "Confluence",
        "category": "saas",
        "editions": [{"id": "cloud", "label": "Confluence Cloud", "label_ko": "Confluence Cloud"},
                     {"id": "data_center", "label": "Confluence Data Center", "label_ko": "Confluence Data Center",
                      "origin": True}],
        "target": [
            {"name": "base_url", "label": "Confluence address", "label_ko": "Confluence 주소", "kind": "url",
             "required": True, "hint": "https://acme.atlassian.net/wiki"},
            {"name": "space", "label": "Space (ID on Cloud, key on Data Center)",
             "label_ko": "공간(Cloud는 ID, Data Center는 키)", "kind": "id", "required": True},
        ],
        "purposes": {"exposure": {"scans": [
            {"id": "pages", "label": "Page content", "label_ko": "페이지 본문",
             "description": "The body of the pages in scope.", "description_ko": "검사 범위에 넣은 페이지의 본문입니다."},
            {"id": "attachments", "label": "Attachments", "label_ko": "첨부 파일",
             "description": "Attachments of those pages the connection can read.",
             "description_ko": "그 페이지에 붙은 첨부 파일 중 연동 계정이 읽을 수 있는 것입니다."}], "permissions": [
            _p("read_space", "Read the space (Cloud: read:space:confluence)", "공간 읽기(Cloud: read:space:confluence)",
               methods=["token"]),
            _p("read_content", "Read pages (Cloud: read:page:confluence)", "페이지 읽기(Cloud: read:page:confluence)",
               methods=["token"]),
            *(_p(scope, f"{scope} ({what})", f"{scope}({what_ko})", methods=["service_account"])
              for scope, what, what_ko in zip(cloud_api.SCOPES, ("space", "page bodies", "attachments",
                                                                 "changes and authors"),
                                              ("공간", "페이지 본문", "첨부 파일", "변경 감지·작성자"), strict=True))]}},
        "auth_methods": [
            {"id": "service_account", "label": "Service account (OAuth 2.0)", "label_ko": "서비스 계정(OAuth 2.0)",
             "renewal": "AUTOMATIC", "editions": ["cloud"], "purposes": ["exposure"], "reference": False,
             "fields": [{"name": "client_id", "label": "Client ID", "label_ko": "클라이언트 ID", "kind": "text"},
                        {"name": "client_secret", "label": "Client secret", "label_ko": "클라이언트 시크릿",
                         "kind": "secret", "secret": True}]},
            {"id": "token", "label": "API token", "label_ko": "API 토큰", "renewal": "EXPIRES",
             "purposes": ["exposure"], "fields": [_TOKEN_FIELD]}],
    },
    {
        "provider": "bitbucket",
        "label": "Bitbucket", "label_ko": "Bitbucket",
        "category": "code",
        "editions": [{"id": "cloud", "label": "Bitbucket Cloud", "label_ko": "Bitbucket Cloud"},
                     {"id": "data_center", "label": "Bitbucket Data Center", "label_ko": "Bitbucket Data Center",
                      "origin": True}],
        "target": [
            {"name": "base_url", "label": "Server address", "label_ko": "서버 주소", "kind": "url", "required": True,
             "editions": ["data_center"], "hint": "https://bitbucket.example.com"},
            {"name": "workspace", "label": "Workspace", "label_ko": "워크스페이스", "kind": "name", "required": True,
             "editions": ["cloud"]},
            {"name": "project", "label": "Project key", "label_ko": "프로젝트 키", "kind": "name", "required": True,
             "editions": ["data_center"]},
        ],
        "purposes": {
            "exposure": {"permissions": [_p("read_repositories", "Read repositories", "저장소 읽기")],
                         "scans": [{"id": "repository_files", "label": "Repository files", "label_ko": "저장소 파일",
                           "description": "Files of the repositories in scope, at the default branch unless the scope names another.",
                           "description_ko": "검사 범위에 넣은 저장소의 파일입니다. 범위에서 따로 정하지 않으면 기본 브랜치를 읽습니다."}]},
            "inventory": {"permissions": [_p("list_access_tokens",
                                             "Read keys and tokens (Cloud: Account read, Repositories admin for deploy keys; "
                                             "Data Center: Project admin)",
                                             "키·토큰 읽기(Cloud: 계정 읽기, 배포 키는 저장소 관리; Data Center: 프로젝트 관리)")],
                          "types": BITBUCKET_TYPES, "plan": [_SCHEDULE]},
        },
        "auth_methods": [
            {"id": "access_token", "label": "Workspace access token", "label_ko": "워크스페이스 액세스 토큰",
             "renewal": "EXPIRES", "editions": ["cloud"], "purposes": ["exposure", "inventory"],
             "fields": [_TOKEN_FIELD]},
            {"id": "http_token", "label": "HTTP access token", "label_ko": "HTTP 액세스 토큰", "renewal": "EXPIRES",
             "editions": ["data_center"], "purposes": ["exposure", "inventory"], "fields": [_TOKEN_FIELD]},
            {"id": "api_token", "label": "Atlassian API token with e-mail", "label_ko": "Atlassian API 토큰과 이메일",
             "renewal": "EXPIRES", "advanced": True, "editions": ["cloud"], "purposes": ["exposure", "inventory"],
             "reference_keys": ["username", "token"],
             "fields": [{"name": "email", "label": "Account e-mail", "label_ko": "계정 이메일", "kind": "text",
                         "public": True}, _TOKEN_FIELD]},
        ],
    },
    {
        "provider": "atlassian",
        "label": "Atlassian organization", "label_ko": "Atlassian 조직",
        "category": "saas",
        "editions": [{"id": "cloud", "label": "Atlassian Cloud", "label_ko": "Atlassian Cloud"},
                     {"id": "enterprise_cloud", "label": "Atlassian Cloud Enterprise",
                      "label_ko": "Atlassian Cloud Enterprise"}],
        "target": [{"name": "organization", "label": "Organization ID", "label_ko": "조직 ID", "kind": "id",
                    "required": True, "hint": "00000000-0000-0000-0000-000000000000"}],
        "purposes": {"inventory": {"permissions": [_p("organization_admin", "Organization admin API key",
                                                      "조직 관리자 API 키"),
                                      _p("oauth_clients_read", "List organization and service-account OAuth clients",
                                         "조직·서비스 계정 OAuth 클라이언트 목록", option="oauth_clients")], "types": ATLASSIAN_TYPES,
                                   "plan": [_SCHEDULE, {"name": "oauth_clients", "kind": "bool", "default": False,
                                      "label": "Include organization and service-account OAuth clients",
                                      "label_ko": "조직·서비스 계정 OAuth 클라이언트 포함"}]}},
        "auth_methods": [{"id": "api_key", "label": "Organization API key", "label_ko": "조직 API 키", "auth_first": {"context": []},
                          "renewal": "EXPIRES", "purposes": ["inventory"], "fields": [_TOKEN_FIELD]}],
    },
]

# Only the deployment address (or the scope fixed by a workspace token) is
# entered before authentication. Collection targets come from provider lists.
DESCRIPTORS[0]["auth_methods"][0]["auth_first"] = {"context": ["base_url"]}
DESCRIPTORS[0]["auth_methods"][1]["auth_first"] = {"context": ["base_url"]}
DESCRIPTORS[1]["auth_methods"][0]["auth_first"] = {"context": ["workspace"]}
DESCRIPTORS[1]["auth_methods"][1]["auth_first"] = {"context": ["base_url"]}
DESCRIPTORS[1]["auth_methods"][2]["auth_first"] = {"context": []}


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _base(value, code):
    try:
        return https_base(value or "").rstrip("/")
    except ValueError:
        raise OnboardingValueError(code) from None


def target(provider, edition, values):
    if provider == "confluence":
        base = _base(values.get("base_url"), "CONFLUENCE_ADDRESS_INVALID")
        space = str(values.get("space", ""))
        if not _SPACE.fullmatch(space) or edition == "cloud" and (not space.isdigit() or not base.endswith("/wiki")):
            raise OnboardingValueError("CONFLUENCE_CLOUD_SPACE_ID_AND_WIKI_BASE_REQUIRED" if edition == "cloud"
                                       else "CONFLUENCE_SPACE_INVALID")
        return {"base_url": base, "space": space}
    if provider == "bitbucket":
        if edition == "cloud":
            if not _KEY.fullmatch(values.get("workspace", "")):
                raise OnboardingValueError("BITBUCKET_WORKSPACE_INVALID")
            return {"workspace": values["workspace"]}
        if not _KEY.fullmatch(values.get("project", "")):
            raise OnboardingValueError("BITBUCKET_PROJECT_INVALID")
        return {"base_url": _base(values.get("base_url"), "BITBUCKET_ADDRESS_INVALID"), "project": values["project"]}
    try:
        organization = str(_uuid.UUID(str(values.get("organization", ""))))
    except ValueError:
        raise OnboardingValueError("ATLASSIAN_ORGANIZATION_ID_INVALID") from None
    return {"organization": organization}


def credential(provider, method, fields):
    if method == "service_account":
        try:
            return {"credential": cloud_api.envelope(fields.get("client_id", "").strip(),
                                                     fields.get("client_secret", "").strip())}
        except cloud_api.CloudError as exc:
            raise OnboardingValueError(exc.code) from None
    token = fields.get("token", "").strip()
    if not _TOKEN.fullmatch(token):
        raise OnboardingValueError("ATLASSIAN_TOKEN_INVALID")
    if method == "api_token":
        email = fields.get("email", "").strip()
        if not _EMAIL.fullmatch(email):
            raise OnboardingValueError("BITBUCKET_API_TOKEN_EMAIL_REQUIRED")
        # The e-mail is not secret; it rides with the token so both reach every use together.
        return {"credential": {"token": token, "username": email, "password": token}}
    return {"credential": {"token": token}}


def _authorization(connection, envelope):
    if connection["auth_method"] == "api_token":
        pair = f"{envelope.get('username', '')}:{envelope.get('token', '')}"
        return "Basic " + base64.b64encode(pair.encode()).decode()
    return "Bearer " + envelope.get("token", "")


def auth_context(provider, edition, values):
    if provider == "bitbucket":
        if edition == "data_center":
            return {"base_url": _base(values.get("base_url"), "BITBUCKET_ADDRESS_INVALID")}
        if "workspace" in values:
            return target(provider, edition, values)
        return {}
    if provider != "confluence":
        return {}
    base = _base(values.get("base_url"), "CONFLUENCE_ADDRESS_INVALID")
    if edition == "cloud" and not base.endswith("/wiki"):
        raise OnboardingValueError("CONFLUENCE_CLOUD_SPACE_ID_AND_WIKI_BASE_REQUIRED")
    return {"base_url": base}


def _discovery_read(connection, secrets, context, path, params=None):
    with context.http_client() as client:
        if connection["auth_method"] == "service_account":
            try:
                token = cloud_api.ClientToken(secrets["credential"], client=client)()
                base = connection["target"]["base_url"]
                if not path.startswith(base + "/"):
                    raise OnboardingValueError("CONFLUENCE_GATEWAY_ADDRESS_INVALID")
                path = cloud_api.api_site(base, client) + path[len(base):]
            except cloud_api.CloudError as exc:
                raise OnboardingValueError(exc.code) from None
            authorization = "Bearer " + token
        else:
            authorization = _authorization(connection, secrets["credential"])
        result = probe(client, "GET", path, params=params, headers={
            "Authorization": authorization, "Accept": "application/json"})
    if result[0] != "GRANTED":
        raise OnboardingValueError(result[1] or "REQUEST_FAILED")
    body = json_body(result[2])
    if not isinstance(body, dict):
        raise OnboardingValueError("MALFORMED_RESPONSE")
    return body


def authenticate(connection, secrets, context):
    provider = connection["provider"]
    if provider == "confluence":
        if connection["auth_method"] == "service_account":
            # Client credentials grant proves this service identity without a
            # user-profile scope; space access is checked after discovery.
            try:
                with context.http_client() as client:
                    cloud_api.ClientToken(secrets["credential"], client=client)()
            except cloud_api.CloudError as exc:
                return {"status": "ERROR" if exc.code == "ATLASSIAN_OAUTH_UNAVAILABLE" else "MISSING", "detail": exc.code}
            return {"status": "GRANTED"}
        body = _discovery_read(connection, secrets, context, connection["target"]["base_url"] + "/rest/api/user/current")
        ident = body.get("accountId") or body.get("userKey")
        if body.get("type") != "known" or not isinstance(ident, str) or not ident:
            return {"status": "MISSING", "detail": "AUTHENTICATION_REQUIRED"}
    elif provider == "bitbucket":
        if connection["auth_method"] == "access_token":
            # Workspace tokens are not user accounts and cannot call /user.
            # Unlike public repository listings, this endpoint requires auth.
            workspace = quote(connection["target"]["workspace"], safe="")
            body = _discovery_read(connection, secrets, context,
                f"{BITBUCKET_CLOUD}/2.0/workspaces/{workspace}/permissions", {"pagelen": 1})
            if not isinstance(body.get("values"), list):
                return {"status": "ERROR", "detail": "MALFORMED_RESPONSE"}
            return {"status": "GRANTED", "subject": connection["target"]["workspace"]}
        if connection["edition"] == "data_center":
            # The projects endpoint can return anonymous/public projects.
            # A service user's HTTP token must first pass an auth-only API.
            body = _discovery_read(connection, secrets, context,
                connection["target"]["base_url"] + "/rest/api/latest/profile/recent/repos", {"limit": 1})
            return {"status": "GRANTED"} if isinstance(body.get("values"), list) else {
                "status": "ERROR", "detail": "MALFORMED_RESPONSE"}
        body = _discovery_read(connection, secrets, context, BITBUCKET_CLOUD + "/2.0/user")
        ident = body.get("uuid")
        if not isinstance(ident, str) or not ident:
            return {"status": "ERROR", "detail": "MALFORMED_RESPONSE"}
    else:
        # Organization API keys have no separate whoami; a bounded organization
        # listing is their minimum authenticated endpoint, not collection access.
        body = _discovery_read(connection, secrets, context, ADMIN + "/admin/v1/orgs")
        if not isinstance(body.get("data"), list):
            return {"status": "ERROR", "detail": "MALFORMED_RESPONSE"}
        return {"status": "GRANTED"}
    return {"status": "GRANTED", "subject": ident}


def discover(connection, secrets, context):
    from urllib.parse import parse_qs, urlsplit

    provider, edition = connection["provider"], connection["edition"]
    cursor = connection.get("discovery_cursor")
    if provider == "confluence":
        cloud = edition == "cloud"
        base = connection["target"]["base_url"]
        path = base + ("/api/v2/spaces" if cloud else "/rest/api/space")
        body = _discovery_read(connection, secrets, context, path,
            {"limit": 100, **({"cursor" if cloud else "start": cursor} if cursor is not None else {})})
        rows = body.get("results")
        link = (body.get("_links") or {}).get("next")
        following = (parse_qs(urlsplit(link).query).get("cursor" if cloud else "start") or [None])[0] if isinstance(link, str) else None
        roots = [{"label": row.get("name") or str(row.get("id")), "target": {"base_url": base,
                  "space": str(row.get("id") if cloud else row.get("key", ""))}} for row in rows or [] if isinstance(row, dict)]
    elif provider == "bitbucket":
        if connection["auth_method"] == "access_token":
            workspace = connection["target"]["workspace"]
            return [{"label": workspace, "target": {"workspace": workspace}}], "COMPLETE"
        if edition == "data_center":
            base = connection["target"]["base_url"]
            body = _discovery_read(connection, secrets, context, base + "/rest/api/latest/projects",
                                   {"limit": 100, "start": cursor or 0})
            rows = body.get("values")
            last, next_start = body.get("isLastPage"), body.get("nextPageStart")
            if type(last) is not bool or not last and (type(next_start) is not int or next_start <= int(cursor or 0)):
                raise OnboardingValueError("PAGINATION_INVALID")
            following = None if last else str(next_start)
            roots = [{"label": row.get("name") or row.get("key"),
                      "target": {"base_url": base, "project": row.get("key", "")}}
                     for row in rows or [] if isinstance(row, dict)]
        else:
            # GET /2.0/workspaces left with the cross-workspace APIs on 2026-04-14 (CHANGE-2770); CHANGE-3022 lists
            # the caller's workspaces at /2.0/user/workspaces. A row is the workspace, or a membership naming it.
            body = _discovery_read(connection, secrets, context, BITBUCKET_CLOUD + "/2.0/user/workspaces",
                                   {"pagelen": 100, "page": cursor or 1})
            rows = body.get("values")
            following = (parse_qs(urlsplit(body["next"]).query).get("page") or [None])[0] if isinstance(body.get("next"), str) else None
            spaces = [row["workspace"] if isinstance(row.get("workspace"), dict) else row
                      for row in rows or [] if isinstance(row, dict)]
            roots = [{"label": space.get("name") or space.get("slug"), "target": {"workspace": space.get("slug", "")}}
                     for space in spaces]
    else:
        body = _discovery_read(connection, secrets, context, ADMIN + "/admin/v1/orgs", {"cursor": cursor} if cursor else {})
        rows = body.get("data")
        following = (body.get("links") or {}).get("next")
        roots = [{"label": row.get("attributes", {}).get("name") or row.get("id"), "target": {"organization": row.get("id")}}
                 for row in rows or [] if isinstance(row, dict)]
    if not isinstance(rows, list) or len(rows) > 100 or len(rows) != len(roots):
        raise OnboardingValueError("MALFORMED_RESPONSE")
    if following is not None and (not isinstance(following, str) or not 0 < len(following) <= 2048
                                   or any(ord(c) < 33 for c in following) or following == str(cursor)):
        raise OnboardingValueError("PAGINATION_INVALID")
    return roots, "PARTIAL" if following else "COMPLETE", following


def _service_account_items(client, envelope, target_):
    """A service account's scopes, through the gateway: the space, its first page, that page's attachments and a
    CQL search. A space it cannot see answers 404."""
    try:
        token = cloud_api.ClientToken(envelope, client=client)()
        site = cloud_api.api_site(target_["base_url"], client)
    except cloud_api.CloudError as exc:
        raise OnboardingValueError(exc.code) from None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    space_url = f"{site}/api/v2/spaces/{quote(target_['space'], safe='')}"
    space = probe(client, "GET", space_url, headers=headers, missing=(401, 403, 404))
    if space[1] == "HTTP_404":
        space = ("MISSING", "CONFLUENCE_SPACE_NOT_VISIBLE", None)
    pages = probe(client, "GET", space_url + "/pages?limit=1", headers=headers)
    body = json_body(pages[2]) if pages[0] == "GRANTED" else None
    rows = body.get("results") if isinstance(body, dict) else None
    first = rows[0].get("id") if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
    if first is not None:
        attachments = probe(client, "GET", f"{site}/api/v2/pages/{quote(str(first), safe='')}/attachments?limit=1",
                            headers=headers)
    else:  # no page to ask about: none in the space, or the pages could not be read
        attachments = ("NOT_REPORTED", "CONFLUENCE_NO_PAGE_TO_TRY" if pages[0] == "GRANTED" else "NOT_CHECKED", None)
    search = probe(client, "GET", f"{site}/rest/api/content/search", params={"cql": "type = page", "limit": 1},
                   headers=headers)
    return [item(scope, result) for scope, result in zip(cloud_api.SCOPES, (space, pages, attachments, search),
                                                         strict=True)]


def check(connection, purpose, secrets, context):
    envelope = secrets.get("credential") or {}
    target_ = connection["target"]
    client = context.http_client()
    if connection["auth_method"] == "service_account":
        try:
            return _service_account_items(client, envelope, target_)
        except KeyError:
            return all_items(list(cloud_api.SCOPES), "ERROR", "TARGET_INCOMPLETE")
        finally:
            client.close()
    headers = {"Authorization": _authorization(connection, envelope), "Accept": "application/json"}
    try:
        if connection["provider"] == "confluence":
            base, space = target_["base_url"], quote(target_["space"], safe="")
            if connection["edition"] == "cloud":
                space_url, pages_url = f"{base}/api/v2/spaces/{space}", f"{base}/api/v2/spaces/{space}/pages?limit=1"
            else:
                space_url = f"{base}/rest/api/space/{space}"
                pages_url = f"{base}/rest/api/content?spaceKey={space}&limit=1"
            return [item("read_space", probe(client, "GET", space_url, headers=headers)),
                    item("read_content", probe(client, "GET", pages_url, headers=headers))]
        if connection["provider"] == "bitbucket":
            if connection["edition"] == "cloud":
                workspace = quote(target_["workspace"], safe="")
                if purpose == "exposure":
                    return [item("read_repositories", probe(
                        client, "GET", f"{BITBUCKET_CLOUD}/2.0/repositories/{workspace}?pagelen=1", headers=headers))]
                listing = probe(client, "GET", f"{BITBUCKET_CLOUD}/2.0/workspaces/{workspace}/permissions?pagelen=1",
                                headers=headers)
                if listing[0] != "GRANTED":
                    return [item("list_access_tokens", listing)]
                # Deploy keys need Repositories: Admin; ask a repository's deploy-key listing, as the collector does.
                repos = probe(client, "GET", f"{BITBUCKET_CLOUD}/2.0/repositories/{workspace}?pagelen=1", headers=headers)
                if repos[0] != "GRANTED":
                    return [item("list_access_tokens", repos)]
                body = json_body(repos[2])
                rows = body.get("values") if isinstance(body, dict) else None
                if rows == []:  # a validated empty workspace: no repository deploy keys to ask about
                    return [item("list_access_tokens", listing)]
                slug = rows[0].get("slug") if isinstance(rows, list) and isinstance(rows[0], dict) else None
                if not isinstance(slug, str) or not slug:
                    return [item("list_access_tokens", ("ERROR", "MALFORMED_RESPONSE", None))]
                return [item("list_access_tokens", probe(
                    client, "GET", f"{BITBUCKET_CLOUD}/2.0/repositories/{workspace}/{quote(slug, safe='')}"
                    "/deploy-keys?pagelen=1", headers=headers))]
            base, project = target_["base_url"], quote(target_["project"], safe="")
            if purpose == "exposure":
                return [item("read_repositories", probe(
                    client, "GET", f"{base}/rest/api/1.0/projects/{project}/repos?limit=1", headers=headers))]
            return [item("list_access_tokens", probe(
                client, "GET", f"{base}/rest/access-tokens/latest/projects/{project}?limit=1", headers=headers))]
        from .metadata.http import BASE_URL
        from .metadata.specs import DEFAULT_SOURCES, SOURCES

        plans = connection.get("checks", {}).get("requested_plans", {}).get(purpose, connection.get("plans", {}).get(purpose, {}))
        selected = [*DEFAULT_SOURCES, *(["service-account-oauth-clients", "org-oauth-clients"] if plans.get("oauth_clients") else [])]
        # The same API-access listings the collector reads (metadata.http.BASE_URL), not the organization user API.
        return [item("oauth_clients_read" if "oauth-clients" in source else "organization_admin", probe(
            client, "GET", f"{BASE_URL}/orgs/{target_['organization']}/{SOURCES[source]['path']}", headers=headers))
                for source in selected]
    except KeyError:
        return all_items([p["id"] for p in _purpose_permissions(connection, purpose)], "ERROR", "TARGET_INCOMPLETE")
    finally:
        client.close()


def _purpose_permissions(connection, purpose):
    descriptor = next(d for d in DESCRIPTORS if d["provider"] == connection["provider"])
    return descriptor["purposes"][purpose]["permissions"]


def children(connection, purpose, plan):
    target_, edition = connection["target"], connection["edition"]
    schedule = plan.get("schedule_minutes", 1440)
    if connection["provider"] == "confluence":
        return [{"kind": "content", "purpose": purpose, "source_type": "confluence",
                 "name": f"Confluence · {target_['space']}",
                 "config": {"base_url": target_["base_url"], "space": target_["space"], "edition": edition},
                 "secret_slots": {"secret_ref": "credential"}}]
    if connection["provider"] == "bitbucket":
        cloud = edition == "cloud"
        where = target_["workspace"] if cloud else target_["project"]
        if purpose == "exposure":
            config = ({"workspace": where} if cloud else {"project": where, "base_url": target_["base_url"]})
            config["edition"] = edition
            if connection["auth_method"] == "api_token":
                config.update(auth_type="api_token", username=(target_.get("auth") or {}).get("email"))
            return [{"kind": "content", "purpose": purpose, "source_type": "bitbucket", "name": f"Bitbucket · {where}",
                     "config": config, "secret_slots": {"secret_ref": "credential"}}]
        basic = connection["auth_method"] == "api_token"
        spec = {"schema_version": 2, "provider": "bitbucket", "name": f"Bitbucket · {where} · tokens",
                "edition": edition, "schedule_minutes": schedule, "capabilities": ["inventory"],
                "auth_type": "basic" if basic else "bearer"}
        if cloud:
            spec.update(origin=BITBUCKET_CLOUD, scopes=[{"kind": "workspace", "id": where}],
                        options={"mode": "bitbucket"})
        else:
            spec.update(origin=target_["base_url"], scopes=[{"kind": "project", "id": where}],
                        options={"mode": "inventory"})
        slots = {"username": "credential", "password": "credential"} if basic else {"token": "credential"}
        return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": slots}]
    spec = {"schema_version": 2, "provider": "atlassian", "name": "Atlassian · organization tokens",
            "origin": ADMIN, "edition": edition, "schedule_minutes": schedule,
            "scopes": [{"kind": "organization", "id": target_["organization"]}], "capabilities": ["inventory"],
            "auth_type": "bearer", "options": {"mode": "inventory"}}
    if plan.get("oauth_clients"):
        from .metadata.specs import DEFAULT_SOURCES

        spec["options"]["sources"] = [*DEFAULT_SOURCES, "service-account-oauth-clients", "org-oauth-clients"]
    return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": {"token": "credential"}}]
