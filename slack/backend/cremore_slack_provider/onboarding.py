"""Slack in the connection wizard (cremore.onboarding).

An Enterprise organization admin's user token -- from an app installed on the organization with
``admin.apps:read``, and ``auditlogs:read`` granted by the Owner for the audit log option -- lists the
apps the organization or one of its workspaces approved and the credentials their scopes imply.
Nothing is posted, installed or changed in Slack, and no token value or webhook URL is read.
"""

from __future__ import annotations

import re

from cremore.onboarding.probe import json_body, probe
from cremore_slack_provider.metadata import API_ORIGIN, AUDIT_ORIGIN
from cremore_slack_provider.metadata.transport import cursor_text

_TOKEN = re.compile(r"xoxp-[A-Za-z0-9-]{20,500}")
_ID = re.compile(r"[ET][A-Z0-9]{2,30}")
_ERROR = re.compile(r"[a-z_]{1,60}")
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
_TOKEN_FIELD = {"name": "token", "label": "Admin app token", "label_ko": "관리자 앱 토큰", "kind": "secret",
                "secret": True}
PERMISSIONS = ("admin_apps_read", "auditlogs_read")

# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state).
_AUDIT = ["감사 로그 옵션을 켜면 설치 기록에서 채웁니다", "Filled from install records when the audit log option is on"]
_NO_USE = ["Slack은 토큰 사용 기록을 주지 않습니다", "Slack does not report token use"]
_STATE = ["승인 목록은 설치 여부를 주지 않습니다. 감사 로그 옵션을 켜면 설치·제거 기록으로 채웁니다",
          "The approved list does not say whether it is installed; the audit log option fills it from installs and removals"]
_APP_BOUND = ["사람이 아니라 앱에 묶입니다", "Bound to the app, not a person"]
INVENTORY_TYPES = [
    {"id": "bot_token", "label": "Bot token", "label_ko": "봇 토큰",
     "description": "Bot-token access of the apps the organization approved or installed, with its scopes (no token value).",
     "description_ko": "조직이 승인하거나 설치한 앱의 봇 토큰 권한과 범위입니다(토큰 값은 읽지 않음).",
     "permission": "admin_apps_read", "credential_type": "SLACK_BOT_TOKEN",
     "match": [{"provider": "slack", "prefix": "bot:"}], "support": "YYPNYPNNP", "reasons": {
         "created": _AUDIT, "creator": _AUDIT, "owner": _APP_BOUND, "last_used": _NO_USE, "state": _STATE,
         "expires": ["만료일을 주지 않습니다. 토큰 교체를 켠 앱은 12시간마다 새 토큰을 받습니다",
                     "No expiry is given; apps with token rotation get a new token every 12 hours"]}},
    {"id": "user_token", "label": "User token", "label_ko": "사용자 토큰",
     "description": "Apps that act as the people who authorize them, and the scopes they ask for.",
     "description_ko": "승인한 사용자를 대신해 동작하는 앱과 요청 권한 범위입니다.",
     "permission": "admin_apps_read", "credential_type": "SLACK_USER_TOKEN",
     "match": [{"provider": "slack", "prefix": "user:"}], "support": "YYNNYNNNP", "reasons": {
         "created": ["사용자마다 승인한 때가 달라 하나로 주지 않습니다", "Each user authorizes at a different time"],
         "expires": ["만료일을 주지 않습니다", "No expiry is given"],
         "creator": ["사용자마다 따로 승인합니다", "Each user authorizes it separately"],
         "owner": ["어떤 사용자가 승인했는지 주지 않습니다", "Which users authorized it is not given"],
         "last_used": _NO_USE, "state": _STATE}},
    {"id": "incoming_webhook", "label": "Incoming webhook", "label_ko": "수신 웹훅",
     "description": "Apps that can post to a channel through an incoming webhook URL.",
     "description_ko": "수신 웹훅 URL로 채널에 메시지를 올릴 수 있는 앱입니다.",
     "permission": "admin_apps_read", "credential_type": "SLACK_WEBHOOK",
     "match": [{"provider": "slack", "prefix": "hook:"}], "support": "YYPNNPNNP", "reasons": {
         "created": _AUDIT, "creator": _AUDIT, "owner": _APP_BOUND, "last_used": _NO_USE, "state": _STATE,
         "expires": ["만료되지 않고, 앱을 제거하면 폐기됩니다", "It does not expire; removing the app revokes it"],
         "scopes": ["메시지를 올릴 채널은 주지 않습니다", "The channel it posts to is not given"]}},
]

DESCRIPTORS = [{
    "provider": "slack",
    "label": "Slack", "label_ko": "Slack",
    "category": "saas",
    "editions": [{"id": "cloud", "label": "Slack Enterprise Grid", "label_ko": "Slack Enterprise Grid"}],
    "target": [{"name": "organization", "label": "Organization or workspace ID", "label_ko": "조직 또는 워크스페이스 ID",
                "kind": "id", "required": True, "hint": "E0123ABCD"}],
    "purposes": {
        "inventory": {"permissions": [
            {"id": "admin_apps_read", "label": "admin.apps:read scope (organization admin)",
             "label_ko": "admin.apps:read 범위(조직 관리자)"},
            {"id": "auditlogs_read", "label": "auditlogs:read scope (audit log option)",
             "label_ko": "auditlogs:read 범위(감사 로그 옵션)", "option": "audit_events"}],
            "types": INVENTORY_TYPES,
            "plan": [_SCHEDULE, {"name": "audit_events", "kind": "bool", "default": False,
                                 "label": "Installer, install date and state from the audit log (last 90 days)",
                                 "label_ko": "감사 로그로 설치자·설치일·설치 상태 확인(최근 90일)"}]},
    },
    "auth_methods": [
        {"id": "token", "label": "Admin app token", "label_ko": "관리자 앱 토큰", "renewal": "NONE",
         "purposes": ["inventory"], "fields": [_TOKEN_FIELD], "auth_first": {"context": []}},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    ident = str(values.get("organization") or "").strip().upper()
    if not _ID.fullmatch(ident):
        raise OnboardingValueError("SLACK_ORGANIZATION_ID_INVALID")
    return {"organization": ident}


def credential(provider, method, fields):
    token = str(fields.get("token") or "").strip()
    if token.startswith("xoxe."):
        # A rotating token lasts 12 hours and needs its refresh token; a stored one would stop working.
        raise OnboardingValueError("SLACK_ROTATING_TOKEN_NOT_SUPPORTED")
    if token.startswith(("xoxb-", "xoxa-", "xapp-")):
        raise OnboardingValueError("SLACK_ADMIN_USER_TOKEN_REQUIRED")
    if not _TOKEN.fullmatch(token):
        raise OnboardingValueError("SLACK_TOKEN_INVALID")
    return {"credential": {"token": token}}


# A refusal Slack gives, as the check detail the wizard explains.
_REFUSED = {
    "missing_scope": "SLACK_SCOPE_MISSING", "no_permission": "SLACK_SCOPE_MISSING", "access_denied": "SLACK_SCOPE_MISSING",
    "not_an_admin": "NOT_AN_ADMINISTRATOR", "restricted_action": "NOT_AN_ADMINISTRATOR", "not_allowed": "NOT_AN_ADMINISTRATOR",
    "not_allowed_token_type": "SLACK_ADMIN_USER_TOKEN_REQUIRED", "feature_not_enabled": "SLACK_ENTERPRISE_REQUIRED",
    "enterprise_is_restricted": "SLACK_ENTERPRISE_REQUIRED",
    "team_not_found": "TARGET_NOT_VISIBLE", "team_access_not_granted": "TARGET_NOT_VISIBLE",
    "app_management_app_not_installed_on_org": "SLACK_APP_NOT_INSTALLED_ON_ORGANIZATION",
    "invalid_auth": "SLACK_TOKEN_REJECTED", "not_authed": "SLACK_TOKEN_REJECTED", "token_revoked": "SLACK_TOKEN_REJECTED",
    "token_expired": "SLACK_TOKEN_REJECTED", "account_inactive": "SLACK_TOKEN_REJECTED",
}


def answer(result):
    """``(status, detail, body)`` of a Slack probe: the Web API refuses with ``ok: false``, often under HTTP 200."""
    status, detail, response = result
    body = json_body(response) if response is not None else None
    body = body if isinstance(body, dict) else {}
    error = body.get("error") if body.get("ok") is False else None
    if error == "ratelimited" or getattr(response, "status_code", 0) == 429:
        return "ERROR", "RATE_LIMITED", body
    if error is not None:
        known = _REFUSED.get(error)
        if known:
            return "MISSING", known, body
        return "ERROR", "SLACK_" + error.upper() if isinstance(error, str) and _ERROR.fullmatch(error) else "REQUEST_FAILED", body
    return status, detail, body


def _row(permission, status, detail=None):
    return {"permission": permission, "status": status, **({"detail": detail} if detail else {})}


def _identity(secrets, context):
    with context.http_client() as client:
        result = answer(probe(client, "GET", API_ORIGIN + "/api/auth.test", headers={
            "Authorization": "Bearer " + secrets["credential"]["token"]}))
    status, detail, body = result
    if status == "GRANTED" and (body.get("ok") is not True or not isinstance(body.get("user_id"), str)
                                or not _ID.fullmatch(str(body.get("enterprise_id") or body.get("team_id") or ""))):
        return "ERROR", "MALFORMED_RESPONSE", {}
    return status, detail, body


def authenticate(connection, secrets, context):
    status, detail, body = _identity(secrets, context)
    return {"status": status, **({"detail": detail} if detail else {}),
            **({"subject": body["user_id"]} if status == "GRANTED" else {})}


def discover(connection, secrets, context):
    status, detail, body = _identity(secrets, context)
    if status != "GRANTED":
        raise OnboardingValueError(detail or "AUTHENTICATION_REQUIRED")
    ident = body.get("enterprise_id") or body["team_id"]
    roots = [{"label": ident, "target": {"organization": ident}}]
    if not ident.startswith("E"):
        return roots, "COMPLETE"
    previous = connection.get("discovery_cursor") or {}
    cursor, seen = previous.get("next"), previous.get("seen", [])
    with context.http_client() as client:
        try:
            teams, following = _teams(client, secrets["credential"]["token"], cursor)
        except OnboardingValueError as exc:
            if exc.code != "SLACK_TEAMS_READ_REQUIRED" or cursor:
                raise
            # Without admin.teams:read the organization itself is the target: its org-wide approved list needs no
            # workspace list. Picking single workspaces needs that scope (the manifest asks only for admin.apps:read).
            return roots, "COMPLETE"
    roots = ([] if cursor else roots) + [{"label": team, "target": {"organization": team}} for team in teams]
    if following in seen:
        raise OnboardingValueError("SLACK_CURSOR_CYCLE")
    if following and len(seen) >= 100:
        raise OnboardingValueError("SLACK_WORKSPACES_NOT_CONFIRMED")
    return roots, "PARTIAL" if following else "COMPLETE", (
        {"next": following, "seen": [*seen, following]} if following else None)


def _teams(client, token, cursor=None):
    """One authenticated enterprise workspace page; never follow response URLs."""
    params = {"limit": 100}
    if cursor:
        params["cursor"] = cursor_text(cursor, token)
    status, detail, body = answer(probe(client, "GET", API_ORIGIN + "/api/admin.teams.list",
        headers={"Authorization": "Bearer " + token}, params=params))
    if status != "GRANTED":
        if body.get("error") == "missing_scope":
            detail = "SLACK_TEAMS_READ_REQUIRED"
        raise OnboardingValueError(detail or "SLACK_WORKSPACES_NOT_CONFIRMED")
    teams = body.get("teams")
    if body.get("ok") is not True or not isinstance(teams, list) or len(teams) > 100:
        raise OnboardingValueError("SLACK_INVALID_RESPONSE")
    ids = []
    for team in teams:
        ident = team.get("id") if isinstance(team, dict) else None
        if not isinstance(ident, str) or not _ID.fullmatch(ident) or not ident.startswith("T"):
            raise OnboardingValueError("SLACK_INVALID_RESPONSE")
        ids.append(ident)
    meta = body.get("response_metadata", {})
    if not isinstance(meta, dict):
        raise OnboardingValueError("SLACK_INVALID_RESPONSE")
    following = meta.get("next_cursor")
    following = None if following in (None, "") else cursor_text(following, token)
    if following and following == cursor:
        raise OnboardingValueError("SLACK_CURSOR_CYCLE")
    return ids, following


def _belongs(client, token, whoami, ident):
    if whoami.get("enterprise_id" if ident.startswith("E") else "team_id") == ident:
        return True
    if ident.startswith("E") or not str(whoami.get("enterprise_id") or "").startswith("E"):
        return False
    cursor, seen = None, set()
    for _ in range(100):
        teams, cursor = _teams(client, token, cursor)
        if ident in teams:
            return True
        if not cursor:
            return False
        if cursor in seen:
            raise OnboardingValueError("SLACK_CURSOR_CYCLE")
        seen.add(cursor)
    raise OnboardingValueError("SLACK_WORKSPACES_NOT_CONFIRMED")


def check(connection, purpose, secrets, context):
    token = (secrets.get("credential") or {}).get("token", "")
    ident = connection["target"]["organization"]
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    client = context.http_client()
    try:
        status, detail, whoami = answer(probe(client, "GET", API_ORIGIN + "/api/auth.test", headers=headers))
        if status == "GRANTED" and whoami.get("ok") is not True:
            status, detail = "ERROR", "MALFORMED_RESPONSE"
        if status != "GRANTED":
            return [_row(permission, status, detail) for permission in PERMISSIONS]
        try:
            belongs = _belongs(client, token, whoami, ident)
        except ValueError as exc:
            return [_row(permission, "ERROR", getattr(exc, "code", "SLACK_WORKSPACES_NOT_CONFIRMED"))
                    for permission in PERMISSIONS]
        if not belongs:
            return [_row(permission, "MISSING", "SLACK_ANOTHER_ORGANIZATION") for permission in PERMISSIONS]
        where = {"enterprise_id" if ident.startswith("E") else "team_id": ident, "limit": 1}
        apps = answer(probe(client, "GET", API_ORIGIN + "/api/admin.apps.approved.list", headers=headers, params=where))
        plan = connection.get("checks", {}).get("requested_plans", {}).get(purpose, connection.get("plans", {}).get(purpose, {}))
        audit = (answer(probe(client, "GET", AUDIT_ORIGIN + "/audit/v1/logs", headers=headers,
                             params={"action": "app_installed", "limit": 1})) if plan.get("audit_events") else
                 ("NOT_REPORTED", "NOT_SELECTED", {}))
        return [_row("admin_apps_read", *apps[:2]), _row("auditlogs_read", *audit[:2])]
    finally:
        client.close()


def children(connection, purpose, plan):
    ident = connection["target"]["organization"]
    audit = bool(plan.get("audit_events"))
    spec = {"schema_version": 2, "provider": "slack", "name": f"Slack · {ident} · apps", "origin": API_ORIGIN,
            "edition": "cloud", "scopes": [{"kind": "enterprise" if ident.startswith("E") else "workspace", "id": ident}],
            "capabilities": ["inventory"] + (["audit"] if audit else []), "auth_type": "bearer",
            "options": {"mode": "inventory", "requests_per_second": 0.3,
                        **({"include_audit_events": True, "audit_lookback_days": 90} if audit else {})},
            "schedule_minutes": plan.get("schedule_minutes", 1440)}
    return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": {"token": "credential"}}]
