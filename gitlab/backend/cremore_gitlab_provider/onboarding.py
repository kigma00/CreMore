"""GitLab in the connection wizard (cremore.onboarding).

One group or project access token (or, on GitLab.com Free, a group service account's
personal access token) serves repository scans, the credential inventory and CI variable
metadata. GitLab reports a token's own scopes (``/personal_access_tokens/self``, which group
and project access tokens answer too); the inventory and CI variables also need a role, read
from the membership: a group's Owner, a project's Maintainer.
Scopes are GitLab's numeric group or project ID, as the inventory addresses them.

On GitLab Self-Managed and Dedicated an administrator's token can instead read the
whole instance's credential inventory (the instance scope); that is inventory only, or
(with its own connection) the revoking of the instance's tokens an approved plan asks for.

A remediation connection holds a token with the ``api`` scope and the role GitLab asks of
whoever revokes (cremore_gitlab_provider.remediation); its check reads that role and revokes nothing.

A token with the ``self_rotate`` (or ``api``) scope renews itself before it expires
(cremore_gitlab_provider.token_rotation through cremore.onboarding.renewal); GitLab revokes
the old token at once, so a rotation is never retried with it.
"""

from __future__ import annotations

import datetime as _dt
import re
from urllib.parse import quote

from cremore.onboarding.probe import all_items, item, json_body, probe
from cremore.sources.validation import https_base

# GitLab revokes the rotated token at once: an interrupted rotation waits for a person (cremore.onboarding.renewal).
RENEWAL_REVOKES_OLD = True

CLOUD = "https://gitlab.com"
_TOKEN = re.compile(r"[\x21-\x7e]{20,255}")
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
MAINTAINER = 40
OWNER = 50
_GROUP_OR_PROJECT = {"scope": ["group", "project"]}
_INSTANCE = {"scope": ["instance"]}
# Key sources need the public_keys capability; the rest are credentials (design: gitlab extensions).
_KEY_SOURCES = {"instance_ssh_keys", "instance_deploy_keys", "enterprise_ssh_keys", "project_deploy_keys"}


def _option(value, label, label_ko):
    return {"id": value, "label": label, "label_ko": label_ko}


_INVENTORY_PLAN = [
    _SCHEDULE,
    {"name": "audit_events", "kind": "bool", "default": False, "label": "Audit events (who used or changed tokens)",
     "label_ko": "감사 이벤트(토큰 사용·변경 기록)", "when": {"subscription": ["premium", "ultimate", ""]}},
    {"name": "deploy_keys", "kind": "bool", "default": False, "when": {"scope": ["project"]},
     "label": "Also collect the project's deploy keys", "label_ko": "프로젝트 배포 키도 수집"},
    {"name": "enterprise_ssh_keys", "kind": "bool", "default": False,
     "when": {"scope": ["group"], "subscription": ["premium", "ultimate", ""]},
     "editions": ["cloud"], "label": "Also collect the SSH keys of the group's enterprise users",
     "label_ko": "그룹 기업 사용자의 SSH 키도 수집"},
    {"name": "instance_sources", "kind": "choices", "when": _INSTANCE,
     "default": ["instance_pat", "instance_deploy_tokens"], "label": "Instance-wide lists",
     "label_ko": "인스턴스 전체 목록",
     "options": [_option("instance_pat", "Personal access tokens", "개인 액세스 토큰"),
                 _option("instance_deploy_tokens", "Deploy tokens", "배포 토큰"),
                 _option("instance_ssh_keys", "Users' SSH keys", "사용자 SSH 키"),
                 _option("instance_deploy_keys", "Deploy keys", "배포 키")]},
]


# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state). GitLab keeps every
# non-secret field its API returns; a creator the API does not name comes from audit events.
_AUDIT = ["감사 이벤트를 켜면 생성 기록에서 채웁니다", "Filled from creation records when audit events are on"]
_NO_PERSON = ["사람 계정에 묶이지 않습니다", "Not bound to a person's account"]
_GONE = ["상태를 주지 않고, 삭제되면 목록에서 빠집니다", "No state is given; a deleted one leaves the list"]


def _family(*names):
    return [{"provider": "gitlab", "fact": "family", "in": list(names)},
            {"provider": "gitlab", "fact": "credential_types", "in": list(names)}]


INVENTORY_TYPES = [
    {"id": "personal_access_token", "label": "Personal access token", "label_ko": "개인 액세스 토큰(PAT)",
     "description": "PATs of a GitLab.com group's enterprise users, or of the whole instance with an administrator scope.",
     "description_ko": "GitLab.com 그룹의 기업 사용자나, 관리자 범위라면 인스턴스 전체의 PAT입니다.",
     "permission": "read_api", "credential_type": "GITLAB_PERSONAL_ACCESS_TOKEN",
     "plan": [{"always": True, "when": {"scope": ["group"], "subscription": ["premium", "ultimate", ""]}, "editions": ["cloud"]},
              {"field": "instance_sources", "option": "instance_pat"}],
     "match": _family("personal_access_token"), "support": "YYYYYYYYY", "reasons": {}},
    {"id": "service_account_token", "label": "Service account PAT", "label_ko": "서비스 계정 PAT",
     "description": "Tokens issued to group and project service accounts.",
     "description_ko": "그룹·프로젝트 서비스 계정에 발급된 토큰입니다.",
     "permission": "read_api", "credential_type": "GITLAB_SERVICE_ACCOUNT_TOKEN", "when": _GROUP_OR_PROJECT,
     "match": _family("group_service_account_pat", "project_service_account_pat"),
     "support": "YYYYYPYYY", "reasons": {"creator": _AUDIT}},
    {"id": "group_access_token", "label": "Group access token", "label_ko": "그룹 액세스 토큰",
     "description": "Scopes and expiry of group-level bot tokens.", "description_ko": "그룹 단위 봇 토큰의 권한·만료일입니다.",
     "permission": "read_api", "credential_type": "GITLAB_GROUP_ACCESS_TOKEN", "when": {"scope": ["group"]},
     "plan": [{"always": True, "editions": ["self_managed", "dedicated"]},
              {"always": True, "editions": ["cloud"], "when": {"subscription": ["premium", "ultimate", ""]}}],
     "match": _family("group_access_token"), "support": "YYYYYPYYY", "reasons": {"creator": _AUDIT}},
    {"id": "project_access_token", "label": "Project access token", "label_ko": "프로젝트 액세스 토큰",
     "description": "Scopes and expiry of project-level bot tokens.", "description_ko": "프로젝트 단위 봇 토큰의 권한·만료일입니다.",
     "permission": "read_api", "credential_type": "GITLAB_PROJECT_ACCESS_TOKEN", "when": _GROUP_OR_PROJECT,
     "plan": [{"always": True, "editions": ["self_managed", "dedicated"]},
              {"always": True, "editions": ["cloud"], "when": {"subscription": ["premium", "ultimate", ""]}}],
     "match": _family("project_access_token"), "support": "YYYYYPYYY", "reasons": {"creator": _AUDIT}},
    {"id": "deploy_token", "label": "Deploy token", "label_ko": "배포 토큰",
     "description": "Deploy tokens that read group or project repositories and registries.",
     "description_ko": "그룹·프로젝트 저장소와 레지스트리를 읽는 배포 토큰입니다.",
     "permission": "read_api", "credential_type": "GITLAB_DEPLOY_TOKEN",
     "plan": [{"always": True, "when": _GROUP_OR_PROJECT}, {"field": "instance_sources", "option": "instance_deploy_tokens"}],
     "match": _family("group_deploy_token", "project_deploy_token", "deploy_token"),
     "support": "YYNYYPNNY", "reasons": {
         "created": ["배포 토큰 API가 생성일을 주지 않습니다", "The deploy token API gives no creation date"],
         "creator": _AUDIT, "owner": _NO_PERSON,
         "last_used": ["배포 토큰 API가 마지막 사용을 주지 않습니다", "The deploy token API gives no last use"]}},
    {"id": "pipeline_trigger_token", "label": "Pipeline trigger token", "label_ko": "파이프라인 트리거 토큰",
     "description": "Tokens that start pipelines from outside.", "description_ko": "외부에서 파이프라인을 실행하는 토큰입니다.",
     "permission": "read_api", "credential_type": "GITLAB_PIPELINE_TRIGGER_TOKEN", "when": _GROUP_OR_PROJECT,
     "match": _family("pipeline_trigger_token"), "support": "YYYPNYYYN", "reasons": {
         "expires": ["만료일은 이를 지원하는 GitLab 버전에서만 줍니다", "Only GitLab versions that support it give an expiry"],
         "scopes": ["권한 범위가 없고 파이프라인 실행에만 씁니다", "No scopes; it only starts pipelines"], "state": _GONE}},
    {"id": "error_tracking_client_key", "label": "Error tracking client key", "label_ko": "오류 추적 클라이언트 키",
     "description": "Client keys used for project error tracking.", "description_ko": "프로젝트 오류 추적에 쓰는 클라이언트 키입니다.",
     "permission": "read_api", "credential_type": "GITLAB_ERROR_TRACKING_KEY", "when": _GROUP_OR_PROJECT,
     "match": _family("error_tracking_client_key"), "support": "YNNNNPNNY", "reasons": {
         "name": ["이름이 없는 키입니다", "These keys have no name"],
         "created": ["생성일을 주지 않습니다", "No creation date is given"],
         "expires": ["만료일이 없는 키입니다", "These keys do not expire"],
         "scopes": ["권한 범위가 없고 오류 전송에만 씁니다", "No scopes; it only sends errors"],
         "creator": _AUDIT, "owner": _NO_PERSON,
         "last_used": ["마지막 사용을 주지 않습니다", "No last use is given"]}},
    {"id": "kubernetes_agent_token", "label": "Kubernetes agent token", "label_ko": "Kubernetes 에이전트 토큰",
     "description": "Tokens a cluster agent uses to connect to GitLab.", "description_ko": "클러스터 에이전트가 GitLab에 연결할 때 쓰는 토큰입니다.",
     "permission": "read_api", "credential_type": "GITLAB_AGENT_TOKEN", "when": _GROUP_OR_PROJECT,
     "match": _family("kubernetes_agent_token"), "support": "YYYNNYNYP", "reasons": {
         "expires": ["만료일이 없는 토큰입니다", "These tokens do not expire"],
         "scopes": ["권한 범위가 없고 에이전트 연결에만 씁니다", "No scopes; it only connects the agent"],
         "owner": ["사람이 아니라 에이전트에 묶입니다", "Bound to the agent, not a person"],
         "state": ["목록 API가 활성 토큰만 줍니다", "The list API returns active tokens only"]}},
    {"id": "ssh_key", "label": "SSH key", "label_ko": "SSH 키",
     "description": "Users' SSH keys, listed for a GitLab.com group's enterprise users or the whole instance.",
     "description_ko": "GitLab.com 그룹 기업 사용자나 인스턴스 전체 사용자의 SSH 키입니다.",
     "permission": "read_api", "credential_type": "GITLAB_SSH_KEY",
     "plan": [{"field": "enterprise_ssh_keys"}, {"field": "instance_sources", "option": "instance_ssh_keys"}],
     "match": _family("ssh_key"), "support": "YYYYPYYYN", "reasons": {
         "scopes": ["인증·서명 용도만 줍니다", "Only the use (authentication or signing) is given"], "state": _GONE}},
    {"id": "deploy_key", "label": "Deploy key", "label_ko": "배포 키",
     "description": "Deploy keys and whether they can push.", "description_ko": "배포 키와 쓰기 허용 여부입니다.",
     "permission": "read_api", "credential_type": "GITLAB_DEPLOY_KEY",
     "plan": [{"field": "deploy_keys"}, {"field": "instance_sources", "option": "instance_deploy_keys"}],
     "match": _family("deploy_key"), "support": "YYYYYNNNN", "reasons": {
         "creator": ["추가한 사람을 주지 않습니다", "Who added it is not given"],
         "owner": ["사람이 아니라 프로젝트에 묶입니다", "Bound to projects, not a person"],
         "last_used": ["마지막 사용을 주지 않습니다", "No last use is given"], "state": _GONE}},
]


def _permission(name, label, label_ko):
    return {"id": name, "label": label, "label_ko": label_ko}


# Administrator API calls also need the admin_mode scope while Admin Mode is on (Self-Managed).
_ADMIN = ("Administrator of the instance (with Admin Mode on: admin_mode scope)",
          "인스턴스 관리자(Admin Mode가 켜져 있으면 admin_mode 범위)")
# Every purpose shares the token, and the token renews itself with this scope (api also allows it).
_ROTATE = _permission("self_rotate", "self_rotate scope (renews itself)", "self_rotate 범위(자동 교체)")
_ROTATE["required"] = False  # Manual credential renewal remains supported.


DESCRIPTORS = [{
    "provider": "gitlab",
    "label": "GitLab", "label_ko": "GitLab",
    "category": "code",
    "editions": [
        {"id": "cloud", "label": "GitLab.com", "label_ko": "GitLab.com"},
        {"id": "self_managed", "label": "GitLab Self-Managed", "label_ko": "GitLab Self-Managed", "origin": True},
        {"id": "dedicated", "label": "GitLab Dedicated", "label_ko": "GitLab Dedicated", "origin": True},
    ],
    "target": [
        {"name": "subscription", "product": True, "kind": "choice", "label": "Subscription", "label_ko": "요금제",
         "editions": ["cloud", "self_managed"],
         "options": [_option("free", "Free", "Free"), _option("premium", "Premium", "Premium"),
                     _option("ultimate", "Ultimate", "Ultimate")]},
        {"name": "host", "label": "Server address", "label_ko": "서버 주소", "kind": "url", "required": True,
         "editions": ["self_managed", "dedicated"], "hint": "https://gitlab.example.com"},
        {"name": "scope", "label": "Scope", "label_ko": "범위", "kind": "choice", "default": "group",
         "options": [{"id": "group", "label": "Group", "label_ko": "그룹"},
                     {"id": "project", "label": "Project", "label_ko": "프로젝트"},
                     {"id": "instance", "label": "Whole instance (administrator)",
                      "label_ko": "인스턴스 전체(관리자)"}]},
        {"name": "id", "label": "Group or project ID", "label_ko": "그룹 또는 프로젝트 ID", "kind": "id",
         "required": True, "hint": "12345678", "when": _GROUP_OR_PROJECT},
    ],
    "purposes": {
        "exposure": {"scans": [{"id": "repository_files", "label": "Repository files", "label_ko": "저장소 파일",
                           "description": "Files of the repositories in scope, at the default branch unless the scope names another.",
                           "description_ko": "검사 범위에 넣은 저장소의 파일입니다. 범위에서 따로 정하지 않으면 기본 브랜치를 읽습니다."}], "permissions": [
            _permission("read_repository", "read_repository scope", "read_repository 범위"),
            _permission("read_api", "read_api scope", "read_api 범위"), _ROTATE]},
        # Listing a group's access tokens, its audit events for all users and the credentials inventory takes the
        # group's Owner; a project's tokens, audit events and deploy tokens its Maintainer.
        "inventory": {"permissions": [
            _permission("read_api", "read_api scope", "read_api 범위"),
            {**_permission("instance_admin", _ADMIN[0], _ADMIN[1]), "when": _INSTANCE},
            {**_permission("owner", "Owner role of the group", "그룹 Owner 역할"), "when": {"scope": ["group"]}},
            {**_permission("maintainer", "Maintainer role of the project", "프로젝트 Maintainer 역할"),
             "when": {"scope": ["project"]}},
            _ROTATE],
            "types": INVENTORY_TYPES, "plan": _INVENTORY_PLAN},
        # Group CI variables take the group's Owner (GitLab's group-level variables API), project ones its Maintainer.
        "vault": {"permissions": [
            _permission("read_api", "read_api scope", "read_api 범위"),
            {**_permission("owner", "Owner role of the group (group CI variables)", "그룹 Owner 역할(그룹 CI 변수)"),
             "when": {"scope": ["group"]}},
            {**_permission("maintainer", "Maintainer role of the project (CI variables)", "프로젝트 Maintainer 역할(CI 변수)"),
             "when": {"scope": ["project"]}}, _ROTATE],
            "plan": [_SCHEDULE, {"name": "read_values", "kind": "bool", "default": False,
                                 "label": "Read variable values to compare with what was found exposed",
                                 "label_ko": "노출 발견값과 대조하도록 변수 값 읽기"}]},
        # Revoking a token an approved plan names (cremore_gitlab_provider.remediation).
        "remediation": {"permissions": [
            _permission("api", "api scope (revokes tokens)", "api 범위(토큰 폐기)"),
            {**_permission("instance_admin", _ADMIN[0], _ADMIN[1]), "when": _INSTANCE},
            {**_permission("owner", "Owner role of the group", "그룹 Owner 역할"), "when": {"scope": ["group"]}},
            {**_permission("maintainer", "Maintainer role of the project", "프로젝트 Maintainer 역할"),
             "when": {"scope": ["project"]}},
            _ROTATE]},
    },
    "auth_methods": [
        {"id": "token", "label": "Group/project access token or service account PAT",
         "label_ko": "그룹·프로젝트 액세스 토큰 또는 서비스 계정 PAT",
         "renewal": "ROTATES", "purposes": ["exposure", "inventory", "vault", "remediation"],
         "auth_first": {"context": ["host", "subscription"]},
         "fields": [{"name": "token", "label": "Token", "label_ko": "토큰", "kind": "secret", "secret": True}]},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    scope = values.get("scope") or "group"
    if scope == "instance":
        if edition == "cloud":
            raise OnboardingValueError("GITLAB_INSTANCE_SCOPE_NEEDS_SELF_MANAGED")
        out = {"scope": scope}
    else:
        if not str(values.get("id", "")).isdecimal() or int(values["id"]) < 1:
            raise OnboardingValueError("GITLAB_ID_INVALID")
        out = {"scope": scope, "id": str(int(values["id"]))}
    if edition != "cloud":
        try:
            host = https_base(values.get("host") or "")
        except ValueError:
            raise OnboardingValueError("GITLAB_HOST_INVALID") from None
        if host.rstrip("/") == CLOUD:
            raise OnboardingValueError("GITLAB_HOST_INVALID")
        out["host"] = host.rstrip("/")
    if values.get("subscription"):
        if values["subscription"] not in {"free", "premium", "ultimate"}:
            raise OnboardingValueError("GITLAB_SUBSCRIPTION_INVALID")
        if edition == "dedicated" and values["subscription"] != "ultimate":
            raise OnboardingValueError("GITLAB_DEDICATED_REQUIRES_ULTIMATE")
        out["subscription"] = values["subscription"]
    return out


def credential(provider, method, fields):
    token = fields.get("token", "").strip()
    if not _TOKEN.fullmatch(token):
        raise OnboardingValueError("GITLAB_TOKEN_INVALID")
    return {"credential": {"token": token}}


def _origin(connection):
    return connection["target"].get("host") or CLOUD


def auth_context(provider, edition, values):
    # Reuse the host validator without requiring a collection scope yet.
    validated = target(provider, edition, {**values, "scope": "project", "id": "1"})
    return {key: value for key, value in validated.items() if key in {"host", "subscription"}}


def authenticate(connection, secrets, context):
    client = context.http_client()
    try:
        result = probe(client, "GET", _origin(connection) + "/api/v4/personal_access_tokens/self",
                       headers={"PRIVATE-TOKEN": secrets["credential"]["token"]})
        body = json_body(result[2])
        if result[0] == "GRANTED" and (not isinstance(body, dict) or type(body.get("user_id")) is not int
                                       or body.get("revoked") or body.get("active") is False):
            return {"status": "ERROR", "detail": "GITLAB_TOKEN_IDENTITY_INVALID"}
        return {**item("authentication", result),
                **({"subject": f"user:{body['user_id']}"} if result[0] == "GRANTED" else {})}
    finally:
        client.close()


def discover(connection, secrets, context):
    """One page of visible groups/projects, using IDs, never API-supplied URLs."""
    client = context.http_client()
    cursor = connection.get("discovery_cursor") or {"groups": 1, "projects": 1}
    roots, following = [], {}
    try:
        for endpoint, page in cursor.items():
            # membership: the groups and projects the token's user belongs to -- /projects alone lists every public
            # project it can see, which on GitLab.com is all of them.
            result = probe(client, "GET", _origin(connection) + "/api/v4/" + endpoint,
                headers={"PRIVATE-TOKEN": secrets["credential"]["token"]},
                params={"per_page": 100, "page": page, "order_by": "id", "sort": "asc",
                        **({"membership": "true"} if endpoint == "projects" else {})})
            if result[0] != "GRANTED":
                raise OnboardingValueError("GITLAB_" + endpoint.upper() + "_LIST_" + (result[1] or "FAILED"))
            rows = json_body(result[2])
            if not isinstance(rows, list):
                raise OnboardingValueError("GITLAB_DISCOVERY_RESPONSE_INVALID")
            for row in rows:
                if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] <= 0:
                    raise OnboardingValueError("GITLAB_DISCOVERY_RESPONSE_INVALID")
                roots.append({"label": str(row.get("full_path") or row.get("path_with_namespace") or row["id"]),
                              "target": {**{k: v for k, v in connection["target"].items() if k in {"host", "subscription"}},
                                         "scope": endpoint[:-1], "id": str(row["id"])}})
            next_page = result[2].headers.get("x-next-page", "")
            if next_page:
                if not next_page.isdecimal() or int(next_page) <= page or int(next_page) > 10000:
                    raise OnboardingValueError("GITLAB_DISCOVERY_CURSOR_INVALID")
                following[endpoint] = int(next_page)
        return roots, "PARTIAL" if following else "COMPLETE", following
    finally:
        client.close()


def ready(repo, settings, connection):
    """The whole instance is read for its credential inventory, or acted on for approved plans, only."""
    if connection["target"]["scope"] == "instance" and connection["purposes"] not in (["inventory"], ["remediation"]):
        raise OnboardingValueError("GITLAB_INSTANCE_SCOPE_IS_INVENTORY_ONLY")


def check(connection, purpose, secrets, context):
    token = (secrets.get("credential") or {}).get("token", "")
    base = _origin(connection) + "/api/v4"
    headers = {"PRIVATE-TOKEN": token}
    scope, ident = connection["target"]["scope"], connection["target"].get("id", "")
    wanted = [p["id"] for p in DESCRIPTORS[0]["purposes"][purpose]["permissions"]
              if not p.get("when") or scope in p["when"]["scope"]]
    client = context.http_client()
    try:
        status, detail, response = probe(client, "GET", base + "/personal_access_tokens/self", headers=headers)
        if status != "GRANTED":
            return all_items(wanted, status, detail)
        body = json_body(response) or {}
        scopes = set(body.get("scopes") or [])
        api = bool({"api", "read_api"} & scopes)
        # Without it the token is replaced by hand before it expires.
        rotates = {"permission": "self_rotate", **({"status": "GRANTED"} if {"api", "self_rotate"} & scopes
                                                   else {"status": "MISSING", "detail": "TOKEN_RENEWED_BY_HAND"})}
        if purpose == "remediation":
            return _remediation_check(client, base, headers, body, scopes, scope, ident) + [rotates]
        items = []
        if scope == "instance":
            user = probe(client, "GET", base + "/user", headers=headers)
            admin = user[0] == "GRANTED" and (json_body(user[2]) or {}).get("is_admin") is True
            return [{"permission": "read_api", "status": "GRANTED" if api else "MISSING"},
                    {"permission": "instance_admin", "status": "GRANTED" if admin else "MISSING",
                     **({} if admin else {"detail": "NOT_AN_ADMINISTRATOR"})}, rotates]
        if "read_repository" in wanted:
            items.append({"permission": "read_repository",
                          "status": "GRANTED" if {"read_repository", "api"} & scopes else "MISSING"})
        items.append({"permission": "read_api", "status": "GRANTED" if api else "MISSING"})
        items.append(rotates)
        # The role the reads take: a group's Owner, a project's Maintainer (as the descriptor names it for this scope).
        role = next(((name, least) for name, least in (("owner", OWNER), ("maintainer", MAINTAINER)) if name in wanted), None)
        visible = probe(client, "GET", f"{base}/{scope}s/{quote(ident, safe='')}", headers=headers)
        if visible[0] != "GRANTED":
            return [row if row["permission"] == "self_rotate" else {**row, "status": "MISSING", "detail": "TARGET_NOT_VISIBLE"}
                    for row in items] + (
                [{"permission": role[0], "status": "MISSING", "detail": "TARGET_NOT_VISIBLE"}] if role else [])
        if role:
            name, least = role
            user = body.get("user_id")
            member = probe(client, "GET", f"{base}/{scope}s/{quote(ident, safe='')}/members/all/{user}",
                           headers=headers, missing=(401, 403, 404))
            level = (json_body(member[2]) or {}).get("access_level", 0) if member[0] == "GRANTED" else 0
            held = type(level) is int and level >= least
            items.append({"permission": name, "status": "GRANTED" if held else "MISSING",
                          **({} if held else {"detail": "ACCESS_LEVEL_TOO_LOW"})})
        return items
    finally:
        client.close()


def _remediation_check(client, base, headers, body, scopes, scope, ident) -> list[dict]:
    """Revoking needs the api scope and the role GitLab asks of whoever revokes: an administrator for the instance,
    the group's Owner, the project's Maintainer. Nothing is revoked to find out."""
    user = body.get("user_id")
    # The account that will revoke, which an approved plan binds (cremore.remediation.provider_actions).
    subject = {"subject": f"user:{user}"} if type(user) is int else {}
    items = [{"permission": "api", **subject, **({"status": "GRANTED"} if "api" in scopes
                                                 else {"status": "MISSING", "detail": "API_SCOPE_REQUIRED"})}]
    if scope == "instance":
        user = probe(client, "GET", base + "/user", headers=headers)
        admin = user[0] == "GRANTED" and (json_body(user[2]) or {}).get("is_admin") is True
        return items + [{"permission": "instance_admin", "status": "GRANTED" if admin else "MISSING",
                         **({} if admin else {"detail": "NOT_AN_ADMINISTRATOR"})}]
    role, least = ("owner", OWNER) if scope == "group" else ("maintainer", MAINTAINER)
    member = probe(client, "GET", f"{base}/{scope}s/{quote(ident, safe='')}/members/all/{quote(str(user), safe='')}",
                   headers=headers, missing=(401, 403, 404))
    level = (json_body(member[2]) or {}).get("access_level", 0) if member[0] == "GRANTED" else 0
    held = type(level) is int and level >= least
    return items + [{"permission": role, "status": "GRANTED" if held else "MISSING",
                     **({} if held else {"detail": "ACCESS_LEVEL_TOO_LOW"})}]


def children(connection, purpose, plan):
    free = connection["target"].get("subscription") == "free"
    if free and (plan.get("audit_events") or plan.get("enterprise_ssh_keys")):
        raise OnboardingValueError("GITLAB_FEATURE_REQUIRES_PAID_PLAN")
    if purpose == "remediation":
        return []  # used only by an approved action plan (cremore_gitlab_provider.remediation)
    scope, ident = connection["target"]["scope"], connection["target"].get("id", "")
    if scope == "instance":
        origin = _origin(connection)
        sources = plan.get("instance_sources") or []
        if not sources:
            raise OnboardingValueError("GITLAB_INSTANCE_SOURCES_REQUIRED")
        spec = {"schema_version": 2, "provider": "gitlab", "name": f"GitLab · instance {origin[8:]}",
                "origin": origin, "edition": connection["edition"], "scopes": [{"kind": "organization", "id": origin}],
                "auth_type": "token", "schedule_minutes": plan.get("schedule_minutes", 1440),
                "capabilities": ["inventory"] + (["public_keys"] if _KEY_SOURCES & set(sources) else [])
                + (["audit"] if plan.get("audit_events") else []),
                "options": {"mode": "inventory", "sources": sources,
                            "include_resource_access_tokens": False,
                            **({"include_audit_events": True} if plan.get("audit_events") else {})}}
        return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": {"token": "credential"}}]
    name = f"GitLab · {scope} {ident}"
    if purpose == "exposure":
        return [{"kind": "content", "purpose": purpose, "source_type": "gitlab", "name": name,
                 "config": {"base_url": _origin(connection), scope: ident},
                 "secret_slots": {"secret_ref": "credential"}}]
    spec = {"schema_version": 2, "provider": "gitlab", "origin": _origin(connection), "edition": connection["edition"],
            "scopes": [{"kind": scope, "id": ident}], "auth_type": "token",
            "schedule_minutes": plan.get("schedule_minutes", 1440)}
    if purpose == "inventory":
        keys = [source for source, chosen in (("project_deploy_keys", plan.get("deploy_keys")),
                                              ("enterprise_ssh_keys", plan.get("enterprise_ssh_keys"))) if chosen]
        audit = bool(plan.get("audit_events"))
        spec.update(name=name + " · inventory",
                    capabilities=["inventory", "relations"] + (["public_keys"] if keys else [])
                    + (["audit"] if audit else []),
                    options={"mode": "inventory", **({"sources": keys} if keys else {}),
                             **({"include_enterprise_pat": not free}
                                if free or connection["edition"] == "cloud" else {}),
                             "include_resource_access_tokens": connection["edition"] == "cloud" and not free,
                             **({"include_audit_events": True} if audit else {})})
    else:
        values = bool(plan.get("read_values"))
        spec.update(name=name + " · CI variables",
                    capabilities=["inventory", "vault_metadata"] + (["vault_value"] if values else []),
                    options={"mode": "inventory", "sources": ["ci_variables"],
                             "include_resource_access_tokens": connection["edition"] == "cloud" and not free,
                             **({"include_values": True} if values else {})})
    return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": {"token": "credential"}}]


def renew_due(record, kept, now):
    """What the worker does next for the connection's token: ``inspect`` it once a day (what GitLab says of
    its expiry), ``renew`` it in the last third of its life (token_rotation.due). A failed inspect or a
    missing self_rotate scope waits a day from the recorded failure, not the next hourly sweep."""
    if record.get("provider") != "gitlab" or record.get("auth_method") != "token":
        return None
    from cremore_gitlab_provider.token_rotation import due

    note = (record.get("checks") or {}).get("renewal") or {}
    if note.get("state") == "FAILED" and (
        note.get("action") == "inspect" or note.get("code") == "GITLAB_SELF_ROTATE_SCOPE_REQUIRED"
    ):
        try:
            failed_at = _dt.datetime.fromisoformat(str(note.get("at")))
        except ValueError:
            failed_at = None
        if failed_at is not None and failed_at.tzinfo is not None and now - failed_at < _dt.timedelta(days=1):
            return None
    return due(kept, now)


def renew(record, envelope, action, kept, context):
    """``inspect``: the token's expiry, kept for ``renew_due``; ``renew``: its successor from GitLab's
    self-rotate -- ``{"credential": {"token": ...}, "keep": ...}``. The old token is revoked by GitLab."""
    from cremore_gitlab_provider import token_rotation

    target_ = record["target"]
    client = context.http_client()
    seen = context.now.isoformat()
    try:
        if action == "inspect":
            info = token_rotation.inspect(client, _origin(record), envelope.get("token", ""))
            return {"keep": {"expires_at": info["expires_at"], "created_at": info["created_at"], "seen_at": seen,
                             "self_rotate": bool({"api", "self_rotate"} & set(info["scopes"]))}}
        # A multi-target token rotates itself once. Selecting a group is not
        # evidence that the token was issued by that group.
        scope = "instance" if target_.get("version") == 2 else target_["scope"]
        made = token_rotation.rotate(client, _origin(record), envelope.get("token", ""), scope,
                                     target_.get("id", ""), today=context.now.date())
        return {"credential": {"token": made["token"]},
                "keep": {"expires_at": made["expires_at"], "created_at": made["created_at"], "seen_at": seen,
                         "self_rotate": True}}
    except token_rotation.RotationError as exc:
        raise OnboardingValueError(exc.code) from None
    finally:
        client.close()
