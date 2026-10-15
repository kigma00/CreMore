"""Notion in the connection wizard (cremore.onboarding).

Pages are scanned with an internal connection's token (Notion's former "internal
integration") and read only where the connection was added. The workspace's personal access tokens and MCP connections are
listed with an Enterprise organization bot's token -- a different credential, so it is
its own provider connection. An organization bot token with the revoke scope, on a connection
of its own, revokes a personal access token an approved plan names (cremore_notion_provider.remediation).
"""

from __future__ import annotations

import re
import uuid as _uuid

from cremore.onboarding.probe import item, json_body, probe
from cremore_notion_provider.metadata import API_VERSION, ORIGIN

CONTENT_VERSION = "2022-06-28"
_TOKEN = re.compile(r"[\x21-\x7e]{20,512}")
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
_TOKEN_FIELD = {"name": "token", "label": "Token", "label_ko": "토큰", "kind": "secret", "secret": True}

# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state).
INVENTORY_TYPES = [
    {"id": "personal_access_token", "label": "Personal access token", "label_ko": "개인 액세스 토큰",
     "description": "Personal access tokens members of the Enterprise workspace made.",
     "description_ko": "Enterprise 워크스페이스 구성원이 만든 개인 액세스 토큰입니다.",
     "permission": "workspace_tokens", "credential_type": "NOTION_PERSONAL_ACCESS_TOKEN",
     "plan": [{"field": "personal_access_tokens"}],
     "match": [{"provider": "notion", "prefix": "pat:"}], "support": "YYYYNYYYY", "reasons": {
         "scopes": ["목록 API가 토큰의 기능(capabilities)을 주지 않습니다. 만든 사람이 접근할 수 있는 곳에 닿습니다",
                    "The list API does not return the token's capabilities; it reaches what its creator can access"]}},
    {"id": "mcp_connection", "label": "MCP connection", "label_ko": "MCP 연결",
     "description": "AI tools Enterprise members connected to the workspace through MCP.",
     "description_ko": "Enterprise 구성원이 MCP로 워크스페이스에 연결한 AI 도구입니다.",
     "permission": "mcp_connections", "credential_type": "NOTION_MCP_CONNECTION",
     "plan": [{"field": "mcp_connections"}],
     "match": [{"provider": "notion", "prefix": "mcp:"}], "support": "YYYNNYYYN", "reasons": {
         "expires": ["만료일을 주지 않습니다", "No expiry is given"],
         "scopes": ["연결된 워크스페이스만 주고 권한 범위는 주지 않습니다", "Only the connected workspaces, no scopes"],
         "state": ["상태를 주지 않고, 끊긴 연결은 목록에서 빠집니다", "No state is given; a removed connection leaves the list"]}},
]

DESCRIPTORS = [{
    "provider": "notion",
    "label": "Notion", "label_ko": "Notion",
    "category": "saas",
    "editions": [
        {"id": "standard", "label": "Free / Plus / Business", "label_ko": "Free / Plus / Business"},
        {"id": "enterprise", "label": "Enterprise", "label_ko": "Enterprise"},
        {"id": "cloud", "label": "Existing connection (plan not recorded)",
         "label_ko": "기존 연결 (요금제 미기록)", "new_setup": False},
    ],
    "target": [{"name": "workspace", "label": "Workspace ID (credential inventory)", "label_ko": "워크스페이스 ID(발급 목록)",
                "kind": "id", "hint": "00000000-0000-0000-0000-000000000000"}],
    "purposes": {
        "exposure": {"scans": [{"id": "pages", "label": "Pages and databases", "label_ko": "페이지·데이터베이스",
                               "description": "Pages and database entries shared with the connection.",
                               "description_ko": "연결에 공유된 페이지와 데이터베이스 항목입니다."}], "permissions": [
            {"id": "read_content", "label": "Read content capability", "label_ko": "콘텐츠 읽기 기능"},
            {"id": "pages_shared", "label": "Pages shared with the connection (••• → Add connections)",
             "label_ko": "연결에 공유된 페이지(••• → 연결 추가)"}]},
        "inventory": {"editions": ["enterprise", "cloud"], "permissions": [
            {"id": "workspace_tokens", "label": "Read personal access tokens (personal-access-token:read)",
             "label_ko": "개인 액세스 토큰 읽기(personal-access-token:read)", "option": "personal_access_tokens"},
            {"id": "mcp_connections", "label": "Read MCP connections (mcp-client-connection:read)",
             "label_ko": "MCP 연결 목록 읽기(mcp-client-connection:read)", "option": "mcp_connections"}],
            "types": INVENTORY_TYPES, "plan": [_SCHEDULE,
                {"name": "personal_access_tokens", "kind": "bool", "default": True,
                 "label": "Personal access tokens", "label_ko": "개인 액세스 토큰"},
                {"name": "mcp_connections", "kind": "bool", "default": False,
                 "label": "MCP connections (Enterprise)", "label_ko": "MCP 연결 목록(Enterprise)"}]},
        # Revoking a personal access token an approved plan names: Notion's read and revoke scopes are separate.
        "remediation": {"editions": ["enterprise", "cloud"], "permissions": [
            {"id": "workspace_tokens", "label": "Read workspace personal access tokens (personal-access-token:read)",
             "label_ko": "워크스페이스 개인 액세스 토큰 읽기(personal-access-token:read)"},
            {"id": "revoke_tokens", "label": "Revoke personal access tokens (personal-access-token:write-high-impact)",
             "label_ko": "개인 액세스 토큰 폐기(personal-access-token:write-high-impact)", "required": False}]},
    },
    "auth_methods": [
        {"id": "integration", "label": "Internal connection token (formerly internal integration)",
         "label_ko": "내부 연결 토큰(이전 이름: 내부 통합)", "renewal": "NONE",
         "purposes": ["exposure"], "fields": [_TOKEN_FIELD], "auth_first": {"context": []}},
        {"id": "organization_bot", "label": "Organization bot token (Enterprise)", "label_ko": "조직 봇 토큰(Enterprise)",
         "renewal": "NONE", "editions": ["enterprise", "cloud"],
         "purposes": ["inventory", "remediation"], "fields": [_TOKEN_FIELD], "auth_first": {"context": ["workspace"]}},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _prober(client, token):
    """``probe`` behind the token's connection limiter, 429/529 retried as Retry-After asks.

    One limiter per check or sign-in, so its probes are paced against each other and
    against a scan of the same token in this process.
    """
    from cremore_notion_provider.collectors.requests import connection_limiter, paced

    limiter = connection_limiter(token or "", ORIGIN)

    def ask(method, url, **kwargs):
        answers = []

        def send():
            answers.append(probe(client, method, url, **kwargs))
            return answers[-1][2]  # the response; None after a transport failure

        paced(limiter, send)
        return answers[-1]

    return ask


def target(provider, edition, values):
    if not values.get("workspace"):
        return {}
    try:
        return {"workspace": str(_uuid.UUID(str(values["workspace"])))}
    except ValueError:
        raise OnboardingValueError("NOTION_WORKSPACE_ID_INVALID") from None


def credential(provider, method, fields):
    token = fields.get("token", "").strip()
    if not _TOKEN.fullmatch(token):
        raise OnboardingValueError("NOTION_TOKEN_INVALID")
    return {"credential": {"token": token}}


def authenticate(connection, secrets, context):
    """Token identity only: no page search or feature selection is needed to sign in."""
    client = context.http_client()
    try:
        if connection["auth_method"] == "organization_bot":
            workspace = target("notion", connection["edition"], connection["target"]).get("workspace")
            if not workspace:
                return {"status": "MISSING", "detail": "NOTION_WORKSPACE_ID_REQUIRED"}
            headers = {"Authorization": "Bearer " + secrets["credential"]["token"], "Notion-Version": API_VERSION}
            ask = _prober(client, secrets["credential"]["token"])
            # Admin API has no identity or workspace-discovery endpoint. Prove
            # authentication through either supported read scope, never require
            # a people-directory scope solely to authenticate an inventory bot.
            for path, params in [(f"/admin/v1/spaces/{workspace}/personal_access_tokens", {"page_size": 1}),
                                 ("/admin/v1/mcp_client_connections", {"workspace_ids": workspace, "page_size": 1})]:
                result = ask("GET", ORIGIN + path, headers=headers, params=params)
                if result[0] == "GRANTED":
                    body = json_body(result[2])
                    if isinstance(body, dict) and isinstance(body.get("results"), list):
                        return item("authentication", result)
                    return {"status": "ERROR", "detail": "MALFORMED_RESPONSE"}
                if result[1] == "HTTP_404":
                    return {"status": "MISSING", "detail": "NOTION_WORKSPACE_NOT_VISIBLE"}
                if result[1] == "HTTP_401":
                    break
            return item("authentication", result)
        result = _prober(client, secrets["credential"]["token"])("GET", ORIGIN + "/v1/users/me", headers={
            "Authorization": "Bearer " + secrets["credential"]["token"], "Notion-Version": CONTENT_VERSION})
        answer = item("authentication", result)
        body = json_body(result[2])
        if result[0] == "GRANTED" and (not isinstance(body, dict) or body.get("object") != "user"
                                       or not isinstance(body.get("id"), str)):
            return {"status": "ERROR", "detail": "MALFORMED_RESPONSE"}
        if result[0] == "GRANTED":
            answer["subject"] = body["id"]
        return answer
    finally:
        client.close()


def discover(connection, secrets, context):
    # Search is scoped to the pages shared with this integration. It does not
    # enumerate workspaces or prove Enterprise administration permissions.
    if connection["auth_method"] == "organization_bot":
        workspace = target("notion", connection["edition"], connection["target"]).get("workspace")
        if not workspace:
            raise OnboardingValueError("NOTION_WORKSPACE_ID_REQUIRED")
        return [{"label": f"Notion · {workspace}", "target": {"workspace": workspace}}], "COMPLETE"
    return [{"label": "Notion", "target": {}}], "COMPLETE"


def check(connection, purpose, secrets, context):
    token = (secrets.get("credential") or {}).get("token", "")
    client = context.http_client()
    try:
        ask = _prober(client, token)
        if purpose == "exposure":
            headers = {"Authorization": "Bearer " + token, "Notion-Version": CONTENT_VERSION}
            result = ask("POST", ORIGIN + "/v1/search", headers=headers, json={"page_size": 1})
            if result[0] != "GRANTED":
                return [item("read_content", result),
                        {"permission": "pages_shared", "status": "NOT_REPORTED", "detail": result[1]}]
            shared = (json_body(result[2]) or {}).get("results")
            return [item("read_content", result),
                    {"permission": "pages_shared", "status": "GRANTED" if shared else "MISSING",
                     **({} if shared else {"detail": "NO_PAGE_SHARED_WITH_INTEGRATION"})}]
        workspace = connection["target"].get("workspace")
        if not workspace:
            permissions = ["workspace_tokens", "mcp_connections"] if purpose == "inventory" else ["workspace_tokens"]
            return [{"permission": permission, "status": "MISSING", "detail": "WORKSPACE_ID_REQUIRED"}
                    for permission in permissions]
        headers = {"Authorization": "Bearer " + token, "Notion-Version": API_VERSION}
        listed = item("workspace_tokens", ask(
            "GET", f"{ORIGIN}/admin/v1/spaces/{workspace}/personal_access_tokens?page_size=1",
            headers=headers))
        if listed.get("detail") == "HTTP_404":
            listed.update(status="MISSING", detail="NOTION_WORKSPACE_NOT_VISIBLE")
        if purpose == "remediation":
            # Notion tells whether the bot may revoke only by revoking: the first approved plan's run finds out.
            return [listed, {"permission": "revoke_tokens", "status": "NOT_REPORTED", "detail": "CONFIRMED_WHEN_RUN"}]
        # Checks run before the plan is saved. Answer both scopes independently; the wizard
        # counts only the permissions of the selected sources.
        # MCP returns an empty success even for an unknown or foreign workspace.
        if listed.get("detail") == "NOTION_WORKSPACE_NOT_VISIBLE":
            return [listed, {**listed, "permission": "mcp_connections"}]
        mcp = item("mcp_connections", ask("GET", ORIGIN + "/admin/v1/mcp_client_connections",
                   headers=headers, params={"workspace_ids": workspace, "page_size": 1}))
        return [listed, mcp]
    finally:
        client.close()


def children(connection, purpose, plan):
    if purpose == "exposure":
        return [{"kind": "content", "purpose": purpose, "source_type": "notion", "name": "Notion", "config": {},
                 "secret_slots": {"secret_ref": "credential"}}]
    workspace = connection["target"].get("workspace")
    if not workspace:
        raise OnboardingValueError("NOTION_WORKSPACE_ID_REQUIRED")
    if purpose == "remediation":
        return []  # used only by an approved action plan (cremore_notion_provider.remediation)
    sources = (["personal_access_tokens"] if plan.get("personal_access_tokens", True) else [])
    if plan.get("mcp_connections", False):
        sources.append("mcp_client_connections")
    if not sources:
        raise OnboardingValueError("NOTION_INVENTORY_SOURCES_REQUIRED")
    spec = {"schema_version": 2, "provider": "notion", "name": "Notion · workspace tokens", "origin": ORIGIN,
            "edition": "cloud", "scopes": [{"kind": "workspace", "id": workspace}], "capabilities": ["inventory"],
            "auth_type": "bearer", "options": {"mode": "inventory", "sources": sources},
            "schedule_minutes": plan.get("schedule_minutes", 1440)}
    return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": {"token": "credential"}}]
