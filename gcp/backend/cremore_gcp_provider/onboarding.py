"""Google Cloud in the connection wizard (cremore.onboarding).

A project is read with the worker's Application Default Credentials (a workload
identity or an attached service account; recommended) or with an administrator's
Google sign-in (OAuth refresh token, started from the wizard). The check asks the
project which IAM permissions the identity holds (``testIamPermissions``).

Service-account keys and Secret Manager metadata come from one collection per
project; when a connection serves both, the first of the two to be activated creates
it for both (step 4 asking for both at once merges their choices).

An organization or folder is read for the projects under it (discovery): that is
inventory only and grants nothing on the projects it finds. Secret Manager can also be
read by the CreMore CLI in the customer's own environment, which reports value digests
with a collector token so no value reaches CreMore.
"""

from __future__ import annotations

import re

from cremore.onboarding.probe import json_body, probe
from cremore_gcp_provider.metadata.adapter import ORIGIN

_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_NUMBER = re.compile(r"[1-9][0-9]{0,19}")
PERMISSIONS = {
    "exposure": ("storage.buckets.list", "storage.objects.list", "storage.objects.get"),
    "inventory": ("iam.serviceAccounts.list", "iam.serviceAccountKeys.list", "iam.serviceAccountKeys.get", "apikeys.keys.list"),
    "vault": ("secretmanager.secrets.list", "secretmanager.versions.list"),
    # An approved plan disables, then later deletes, a user-managed key (cremore_gcp_provider.remediation); reading the
    # account confirms it is the project's own.
    "remediation": ("iam.serviceAccounts.get", "iam.serviceAccountKeys.get", "iam.serviceAccountKeys.disable",
                    "iam.serviceAccountKeys.delete"),
}
VALUE_PERMISSIONS = {
    "inventory": ("apikeys.keys.getKeyString",),
    "vault": ("apikeys.keys.getKeyString", "secretmanager.versions.access"),
}
DISCOVERY = ("resourcemanager.projects.list", "resourcemanager.folders.list")
OBSERVATION_PERMISSIONS = {
    "audit_logs": ("logging.logEntries.list", "logging.privateLogEntries.list"),
    "api_metrics": ("monitoring.timeSeries.list",),
    "service_account_iam": ("resourcemanager.projects.getIamPolicy",),
    "secret_iam": ("resourcemanager.projects.getIamPolicy", "secretmanager.secrets.getIamPolicy", "iam.roles.get"),
    # Policy Troubleshooter reads the allow and deny policies itself (Security Reviewer and Deny Reviewer); the
    # project's answers are asked here, its ancestors' only show up as unknown when the identity cannot see them.
    "effective_access": ("resourcemanager.projects.getIamPolicy", "iam.roles.get", "iam.denypolicies.get",
                         "iam.denypolicies.list"),
}
_PROJECT_SCOPE = {"scope": ["project"]}
_PARENT_SCOPE = {"scope": ["organization", "folder"]}
_CLI = "customer_cli"
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
OAUTH_SLOTS = {"client_id": "credential", "client_secret": "credential", "refresh_token": "credential"}


# What the inventory lists, and which key metadata each kind carries
# (support: id, name, created, expires, scopes, creator, owner, last_used, state).
INVENTORY_TYPES = [
    {"id": "service_account_key", "label": "Service account key", "label_ko": "서비스 계정 키",
     "description": "IDs, key types, creation and expiry reported for user-managed and Google-managed service account keys.",
     "description_ko": "사용자 관리·Google 관리 서비스 계정 키의 ID·유형·생성일·만료일입니다. 키 조치는 사용자 관리 키에만 적용됩니다.",
     "permission": "iam.serviceAccountKeys.list", "credential_type": "GCP_SERVICE_ACCOUNT",
     "match": [{"provider": "gcp", "prefix": "serviceAccountKey:"}], "support": "YNYYPPYPY", "reasons": {
         "name": ["키에는 이름이 없습니다", "Keys have no name"],
         "scopes": ["키는 서비스 계정의 IAM 권한을 그대로 씁니다. 실효 판정을 켜면 Policy Troubleshooter가 프로젝트에서 허용한 고위험 권한을 보여 줍니다",
                    "A key acts with its service account's IAM access; with effective access on, it shows the high-impact permissions Policy Troubleshooter allows on the project"],
         "creator": ["감사 로그의 성공한 생성 응답이 이 키 ID를 명시한 경우에만 연결합니다", "Only successful creation audit responses explicitly naming this key are linked"],
         "last_used": ["감사 로그에서 이 키 ID가 명시된 성공한 사용만 연결합니다. 빈 기간은 미사용 증거가 아닙니다", "Successful audit events explicitly naming this key only; an empty window does not mean unused"]}},
    {"id": "api_key", "label": "API key", "label_ko": "API 키",
     "description": "Project API keys and whether they are restricted.", "description_ko": "프로젝트 API 키와 사용 제한 여부입니다.",
     "credential_type": "GCP_API_KEY",
     "match": [{"provider": "gcp", "prefix": "apiKey:"}], "support": "YYYNPPPPY", "reasons": {
         "expires": ["API 키에는 만료일이 없습니다", "API keys do not expire"],
         "scopes": ["API·앱 제한을 둔 키만 제한 내용을 줍니다", "Only restricted keys list their restrictions"],
         "creator": ["감사 로그의 생성 응답이 현재 목록의 API 키 리소스를 정확히 명시할 때 연결합니다", "Creation audit responses must explicitly identify an API key in the current inventory"],
         "owner": ["서비스 계정에 묶은 키만 줍니다", "Only keys bound to a service account name one"],
         "last_used": ["Cloud Monitoring에서 이 키 UID의 사용량이 관측된 마지막 구간입니다. 정확한 호출 시각은 아닙니다", "Last positive Cloud Monitoring interval for this key UID, not an exact request timestamp"]}},
]


def _permissions(purpose):
    out = [{"id": name, "label": name, "label_ko": name, "when": _PROJECT_SCOPE,
            "methods": ["adc", "google_oauth"]} for name in PERMISSIONS[purpose]]
    if purpose in {"inventory", "vault"}:
        out.append({"id": "resourcemanager.projects.get", "label": "Resolve the project's numeric resource names",
                    "label_ko": "프로젝트 번호로 반환된 리소스의 소속 확인", "when": _PROJECT_SCOPE,
                    "methods": ["adc", "google_oauth"], "required": False})
    if purpose == "inventory":
        out += [{"id": name, "label": name, "label_ko": name, "when": _PARENT_SCOPE} for name in DISCOVERY]
    out += [{"id": name, "label": name, "label_ko": name, "when": _PROJECT_SCOPE,
             "methods": ["adc", "google_oauth"], "option": "read_values"}
            for name in VALUE_PERMISSIONS.get(purpose, ())]
    if purpose in {"inventory", "vault"}:
        out += [{"id": name, "label": name, "label_ko": name, "when": _PROJECT_SCOPE,
                 "methods": ["adc", "google_oauth"], "option": option}
                for option, names in OBSERVATION_PERMISSIONS.items()
                if option != "secret_iam" or purpose == "vault" for name in names]
        out.append({"id": "serviceusage.services.get", "label": "Read API enablement state",
                    "label_ko": "API 활성 상태 조회", "when": _PROJECT_SCOPE, "required": False})
    if purpose == "vault":
        out.append({"id": "secretmanager.locations.list", "label": "List Secret Manager locations",
                    "label_ko": "Secret Manager 리전 목록", "when": _PROJECT_SCOPE, "nonempty": "locations"})
        out += [{"id": name, "label": name, "label_ko": name, "when": _PROJECT_SCOPE,
                 "methods": ["adc", "google_oauth"]} for name in PERMISSIONS["inventory"]]
    return out


_VALUES = [
    {"name": "read_values", "kind": "bool", "default": False, "when": _PROJECT_SCOPE,
     "label": "Read key and secret values to compare with what was found exposed",
     "label_ko": "노출 발견값과 대조하도록 키·시크릿 값 읽기"},
    {"name": "include_deleted", "kind": "bool", "default": True, "when": _PROJECT_SCOPE,
     "label": "Include deleted API keys", "label_ko": "삭제된 API 키 포함"},
]
_OBSERVATIONS = [
    {"name": "audit_logs", "kind": "bool", "default": False, "when": _PROJECT_SCOPE,
     "label": "Cloud Audit Logs: observed service account key use",
     "label_ko": "Cloud Audit Logs: 서비스 계정 키 사용 근거",
     "description": "Requires log access and applicable Data Access logging. Empty results remain unknown.",
     "description_ko": "로그 읽기 권한과 해당 Data Access 로그 설정이 필요합니다. 빈 결과는 미사용으로 판정하지 않습니다."},
    {"name": "api_metrics", "kind": "bool", "default": False, "when": _PROJECT_SCOPE,
     "label": "Cloud Monitoring: API key usage intervals", "label_ko": "Cloud Monitoring: API 키 사용 구간"},
    {"name": "service_account_iam", "kind": "bool", "default": False, "when": _PROJECT_SCOPE,
     "label": "Service account project IAM role bindings", "label_ko": "서비스 계정의 프로젝트 IAM 역할",
     "description": "Direct allow bindings only; inherited roles, deny policies and conditions are not evaluated.",
     "description_ko": "프로젝트에 직접 부여된 역할입니다. 상속 역할·거부 정책·조건을 평가한 유효 권한은 아닙니다."},
    {"name": "effective_access", "kind": "bool", "default": False, "when": _PROJECT_SCOPE,
     "label": "Service accounts with keys: effective high-impact access (Policy Troubleshooter)",
     "label_ko": "키가 있는 서비스 계정: 고위험 권한의 실효 판정(Policy Troubleshooter)",
     "description": ("Google evaluates 11 high-impact permissions on the project with inherited and deny policies, groups and "
                     "conditions, for up to 20 accounts. Grant the identity Security Reviewer and Deny Reviewer on the "
                     "organization, and Groups read in a Workspace admin role to include group grants. Enable the Policy "
                     "Troubleshooter API in the identity's project (the OAuth app's project for Google sign-in)."),
     "description_ko": ("Google이 상속·거부 정책과 그룹·조건까지 반영해 프로젝트에서 고위험 권한 11개를 판정합니다(계정 최대 "
                        "20개). 연결 신원에 조직의 보안 검토자·거부 검토자 역할을 주고, 그룹으로 받은 권한까지 보려면 "
                        "Workspace 관리자 역할의 그룹 읽기 권한도 주세요. Policy Troubleshooter API는 연결 신원의 "
                        "프로젝트(Google 로그인은 OAuth 앱 프로젝트)에서 켭니다.")},
    {"name": "audit_days", "kind": "number", "default": 1, "min": 1, "max": 30, "when": _PROJECT_SCOPE,
     "label": "Audit and metrics lookback (days)", "label_ko": "감사 로그·사용량 조회 기간(일)"},
]
# The API rechecks availability; selecting a location never grants access there.
_REGIONS = ["africa-south1", "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2", "australia-southeast1", "australia-southeast2", "europe-central2", "europe-north1", "europe-north2", "europe-southwest1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6", "europe-west8", "europe-west9", "europe-west10", "europe-west12", "me-central1", "me-central2", "me-west1", "northamerica-northeast1", "northamerica-northeast2", "northamerica-south1", "southamerica-east1", "southamerica-west1", "us-central1", "us-east1", "us-east4", "us-east5", "us-south1", "us-west1", "us-west2", "us-west3", "us-west4"]
_VAULT_OPTIONS = [
    {"name": "secret_iam", "kind": "bool", "default": False, "when": _PROJECT_SCOPE,
     "label": "Selected secrets: IAM policy access candidates", "label_ko": "선택한 시크릿: IAM 정책 접근 후보",
     "description_ko": "허용 정책의 후보이며 실제 접근 성공·유효 권한을 의미하지 않습니다.",
     "description": "Allow-policy candidates, not proven effective access."},
    {"name": "locations", "kind": "choices", "default": [], "when": _PROJECT_SCOPE,
     "label": "Regional Secret Manager locations (global secrets are included)",
     "label_ko": "리전별 Secret Manager 위치(글로벌 시크릿은 기본 포함)",
     "options": [{"id": name, "label": name, "label_ko": name} for name in _REGIONS]},
]


DESCRIPTORS = [{
    "provider": "gcp",
    "label": "Google Cloud", "label_ko": "Google Cloud",
    "category": "cloud",
    "editions": [{"id": "cloud", "label": "Google Cloud", "label_ko": "Google Cloud"}],
    "target": [
        {"name": "scope", "label": "Scope", "label_ko": "범위", "kind": "choice", "default": "project",
         "options": [{"id": "project", "label": "Project", "label_ko": "프로젝트"},
                     {"id": "organization", "label": "Organization (find its projects)",
                      "label_ko": "조직(하위 프로젝트 찾기)"},
                     {"id": "folder", "label": "Folder (find its projects)", "label_ko": "폴더(하위 프로젝트 찾기)"}]},
        {"name": "project", "label": "Project ID", "label_ko": "프로젝트 ID", "kind": "id", "required": True,
         "hint": "acme-prod", "when": _PROJECT_SCOPE},
        {"name": "parent", "label": "Organization or folder number", "label_ko": "조직 또는 폴더 번호", "kind": "id",
         "required": True, "hint": "123456789012", "when": _PARENT_SCOPE},
    ],
    "purposes": {
        "exposure": {"permissions": _permissions("exposure"),
                     "scans": [{"id": "objects", "label": "Bucket objects", "label_ko": "버킷 객체",
                                "description": "Objects in the Cloud Storage buckets in scope.",
                                "description_ko": "검사 범위에 넣은 Cloud Storage 버킷의 객체입니다."}]},
        "inventory": {"permissions": _permissions("inventory"), "types": INVENTORY_TYPES,
                      "plan": [_SCHEDULE] + _VALUES + _OBSERVATIONS},
        "vault": {"permissions": _permissions("vault"), "plan": [_SCHEDULE] + _VALUES + _OBSERVATIONS + _VAULT_OPTIONS},
        "remediation": {"permissions": _permissions("remediation")},
    },
    "auth_methods": [
        {"id": "adc", "label": "Workload identity or service account (ADC)",
         "label_ko": "워크로드 신원 또는 서비스 계정(ADC)", "renewal": "AUTOMATIC",
         "auth_first": {"context": []},
         "purposes": ["exposure", "inventory", "vault", "remediation"], "fields": []},
        {"id": "google_oauth", "label": "Google sign-in", "label_ko": "Google 로그인", "renewal": "REFRESH",
         "auth_first": {"context": []},
         "advanced": True, "purposes": ["exposure", "inventory", "vault", "remediation"], "fields": [],
         "flow": "gcp_oauth"},
        {"id": _CLI, "new_setup": False, "label": "CreMore CLI in your Google Cloud environment",
         "label_ko": "고객 Google Cloud 환경의 CreMore CLI", "renewal": "NONE", "advanced": True,
         "purposes": ["vault"], "fields": []},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    scope = values.get("scope") or "project"
    if scope != "project":
        parent = str(values.get("parent", ""))
        if not _NUMBER.fullmatch(parent):
            raise OnboardingValueError("GCP_PARENT_INVALID")
        return {"scope": scope, "parent": parent}
    project = values.get("project", "")
    if not _PROJECT.fullmatch(project):
        raise OnboardingValueError("GCP_PROJECT_INVALID")
    return {"scope": "project", "project": project}


def ready(repo, settings, connection):
    """An organization or folder is read for the projects under it only; the CLI reads Secret Manager."""
    if connection["target"].get("scope", "project") != "project" and (
            connection["purposes"] != ["inventory"] or connection["auth_method"] == _CLI):
        raise OnboardingValueError("GCP_DISCOVERY_IS_INVENTORY_ONLY")


def credential(provider, method, fields):
    return {}  # ADC is the worker's own; a Google sign-in arrives through the OAuth flow


def _token(connection, secrets, client_factory=None):
    if connection["auth_method"] == "google_oauth":
        from cremore_gcp_provider.oauth import oauth_token

        envelope = secrets.get("credential")
        if not envelope:
            raise OnboardingValueError("GCP_SIGN_IN_REQUIRED")
        return oauth_token(envelope, **({"client_factory": client_factory} if client_factory else {}))()
    from cremore_gcp_provider.gcp_auth import adc_token

    return adc_token()()


def authenticate(connection, secrets, context):
    token = _token(connection, secrets, context.http_client)
    client = context.http_client()
    try:
        result = probe(client, "POST", "https://oauth2.googleapis.com/tokeninfo", data={"access_token": token},
                       max_bytes=65536, timeout=30)
        body = json_body(result[2])
        if result[0] == "GRANTED" and (not isinstance(body, dict) or not body.get("expires_in")):
            return {"status": "ERROR", "detail": "GCP_AUTH_RESPONSE_INVALID"}
        return {"status": result[0], **({"detail": result[1]} if result[1] else {})}
    finally:
        client.close()


def discover(connection, secrets, context):
    client = context.http_client()
    try:
        result = probe(client, "GET", "https://cloudresourcemanager.googleapis.com/v3/projects:search",
            params={"pageSize": 100, "pageToken": connection.get("discovery_cursor") or ""},
            headers={"Authorization": "Bearer " + _token(connection, secrets, context.http_client)})
        if result[0] != "GRANTED":
            raise OnboardingValueError("GCP_PROJECT_LIST_" + (result[1] or "FAILED"))
        body = json_body(result[2])
        if not isinstance(body, dict) or not isinstance(body.get("projects", []), list):
            raise OnboardingValueError("GCP_PROJECT_LIST_INVALID")
        roots = []
        for row in body.get("projects", []):
            if not isinstance(row, dict) or not _PROJECT.fullmatch(str(row.get("projectId", ""))):
                raise OnboardingValueError("GCP_PROJECT_LIST_INVALID")
            if row.get("state") == "ACTIVE":
                roots.append({"label": str(row.get("displayName") or row["projectId"]),
                              "target": {"scope": "project", "project": row["projectId"]}})
        cursor = body.get("nextPageToken", "")
        if not isinstance(cursor, str) or len(cursor) > 4096:
            raise OnboardingValueError("GCP_PROJECT_LIST_INVALID")
        return roots, "PARTIAL" if cursor else "COMPLETE", cursor
    finally:
        client.close()


def permission_plan(connection, purpose, plan):
    # Inventory and vault share one project collection, including its value-read
    # switch. Permission evidence must cover the same merged choice as children().
    plans = {**connection.get("plans", {}), **connection.get("checks", {}).get("requested_plans", {}), purpose: plan}
    if purpose in VALUE_PERMISSIONS:
        return {**plan, **{name: any(plans.get(p, {}).get(name) is True
                                   for p in {"inventory", "vault"} & set(connection["purposes"]))
                          for name in ("read_values", *OBSERVATION_PERMISSIONS)}}
    return plan


def check(connection, purpose, secrets, context):
    target_ = connection["target"]
    if connection["auth_method"] == _CLI:
        return [{"permission": name, "status": "NOT_REPORTED", "detail": "CUSTOMER_CLI_REPORTS_ON_UPLOAD"}
                for name in PERMISSIONS[purpose]]
    discovery = target_.get("scope", "project") != "project"
    wanted = DISCOVERY if discovery else PERMISSIONS[purpose]
    if not discovery and purpose in {"inventory", "vault"}:
        wanted += ("resourcemanager.projects.get", "serviceusage.services.get")
        if purpose == "vault":
            wanted += PERMISSIONS["inventory"]
    plan = permission_plan(connection, purpose, connection.get("checks", {}).get("requested_plans", {}).get(
        purpose, connection.get("plans", {}).get(purpose, {})))
    if not discovery and plan.get("read_values"):
        wanted += VALUE_PERMISSIONS.get(purpose, ())
    if not discovery:
        wanted += tuple(name for option, names in OBSERVATION_PERMISSIONS.items()
                        if plan.get(option) and (option != "secret_iam" or purpose == "vault") for name in names)
        if purpose == "vault" and plan.get("locations"):
            wanted += ("secretmanager.locations.list",)
    token = _token(connection, secrets, context.http_client)
    client = context.http_client()
    try:
        if discovery:
            kind = "organizations" if target_["scope"] == "organization" else "folders"
            url = f"https://cloudresourcemanager.googleapis.com/v3/{kind}/{target_['parent']}:testIamPermissions"
        else:
            url = (f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_['project']}"
                   ":testIamPermissions")
        status, detail, response = probe(client, "POST", url, headers={"Authorization": "Bearer " + token},
                                         json={"permissions": list(wanted)})
        if status != "GRANTED":
            return [{"permission": name, "status": status, "detail": detail} for name in wanted]
        granted = set((json_body(response) or {}).get("permissions") or [])
        items = [{"permission": name, "status": "GRANTED" if name in granted else "MISSING"} for name in wanted]
        if purpose == "remediation":
            # The Google account that will act, which an approved plan binds, when Google says (a sign-in does).
            from cremore_gcp_provider.remediation import whoami

            try:
                subject = whoami(connection, secrets, client)
            except ValueError:
                subject = ""
            if subject:
                items[0]["subject"] = subject
        return items
    finally:
        client.close()


def credential_identity(connection, secrets, context):
    """What acts, to tell one credential that collects and acts (cremore.onboarding.check.credential_marks): ADC is
    the worker's own identity, the same for every connection using it; a Google sign-in is the account Google names."""
    if connection["auth_method"] == "adc":
        return ["gcp:adc"]
    if connection["auth_method"] != "google_oauth":
        return []  # the customer's CLI: CreMore holds no credential
    from cremore_gcp_provider.remediation import whoami

    client = context.http_client()
    try:
        subject = whoami(connection, secrets, client)
    finally:
        client.close()
    return [subject] if subject else []


_VALUE_CHOICES = ("read_values", "include_deleted")


def collection_identity_purpose(spec, purpose):
    """Project inventory and vault are capabilities of the same durable collection."""
    if spec.get("schema_version") == 2 and spec.get("options", {}).get("mode") == "inventory":
        return "inventory"
    return purpose


def children(connection, purpose, plan):
    if purpose == "remediation":
        return []  # used only by an approved action plan (cremore_gcp_provider.remediation)
    target_ = connection["target"]
    oauth = connection["auth_method"] == "google_oauth"
    slots = OAUTH_SLOTS if oauth else {}
    auth = "google_oauth" if oauth else "adc"
    if target_.get("scope", "project") != "project":
        parent = target_["parent"]
        spec = {"schema_version": 2, "provider": "gcp", "name": f"GCP · {target_['scope']} {parent}",
                "origin": ORIGIN, "edition": "cloud", "scopes": [{"kind": target_["scope"], "id": parent}],
                "capabilities": ["inventory"], "auth_type": auth, "options": {"mode": "discovery"},
                "schedule_minutes": plan.get("schedule_minutes", 1440)}
        return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": slots}]
    project = target_["project"]
    if connection["auth_method"] == _CLI:
        return [{"kind": "coverage", "purpose": purpose, "collector_token": True, "spec": {
            "name": f"Secret Manager · {project}", "provider": "gcp_secret_manager", "project": project}}]
    if purpose == "exposure":
        return [{"kind": "content", "purpose": purpose, "source_type": "gcp", "name": f"GCS · {project}",
                 "config": {"project": project}, "secret_slots": {"secret_ref": "credential"} if oauth else {}}]
    served = {"inventory", "vault"} & set(connection["purposes"])
    asked = {name: plan.get(name) for name in _VALUE_CHOICES}
    if served - {purpose} & set(connection.get("plans") or {}):
        other = next(other for other in served - {purpose} if other in connection["plans"])
        if other in (connection.get("activating") or {}):
            return []  # created a moment ago in this same step, with this purpose's choices merged in
        # The other purpose's collection already reads this project; its value choices stand.
        earlier = connection["plans"][other]
        if any(asked[name] != earlier.get(name) for name in _VALUE_CHOICES if name in earlier):
            raise OnboardingValueError("GCP_VALUE_CHOICES_SET_BY_THE_PROJECT_COLLECTION")
        return []
    # Asked for both at once: one collection, with what either asks for.
    together = [connection.get("activating", {}).get(other) or {} for other in served - {purpose}]
    chosen = {name: bool(asked.get(name)) or any(other.get(name) for other in together) for name in _VALUE_CHOICES}
    capabilities = ["inventory", "public_keys"] + (["vault_metadata"] if "vault" in served else [])
    if chosen["read_values"]:
        capabilities += ["issuer_value"] + (["vault_value"] if "vault" in served else [])
    options = {"mode": "inventory", "include_deleted": chosen["include_deleted"],
               **({"include_values": True} if chosen["read_values"] else {})}
    plans = {**connection.get("plans", {}), **connection.get("activating", {}), purpose: plan}
    selected = [plans.get(p, {}) for p in served]
    sources = [name for name in OBSERVATION_PERMISSIONS if any(p.get(name) for p in selected)]
    if sources:
        capabilities.append("relations")
        options.update(sources=sources, audit_lookback_days=max(p.get("audit_days", 1) for p in selected))
    if "vault" in served:
        options["locations"] = plans.get("vault", {}).get("locations", [])
    spec = {"schema_version": 2, "provider": "gcp", "name": f"GCP · {project}", "origin": ORIGIN, "edition": "cloud",
            "scopes": [{"kind": "project", "id": project}], "capabilities": capabilities, "auth_type": auth,
            "options": options, "schedule_minutes": plan.get("schedule_minutes", 1440)}
    return [{"kind": "metadata", "purpose": purpose, "spec": spec, "secret_slots": slots}]
