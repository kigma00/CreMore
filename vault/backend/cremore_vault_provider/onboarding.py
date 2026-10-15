"""HashiCorp Vault and OpenBao in the connection wizard (cremore.onboarding).

New server connections use a Kubernetes or JWT login from a projected token file
the deployment renews (recommended), or a sealed Vault token. Legacy customer CLI
connections remain readable but cannot be created. The check uses the collection's
own login and asks which capabilities it has on each mount (``sys/capabilities-self``).
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from types import SimpleNamespace

from cremore.onboarding.probe import json_body, probe

_TOKEN = re.compile(r"[\x21-\x7e]{8,1024}")
_ROLE = re.compile(r"[A-Za-z0-9_.@-]{1,128}")
_FILE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")
_SCHEDULE = {"name": "schedule_minutes", "kind": "number", "label": "Collect every (minutes, 0 = on demand)",
             "label_ko": "수집 주기(분, 0이면 요청할 때만)", "default": 1440, "min": 0, "max": 10080}
_LOGIN_FIELDS = [
    {"name": "role", "label": "Role", "label_ko": "역할", "kind": "text", "public": True},
    {"name": "mount", "label": "Auth mount", "label_ko": "인증 마운트", "kind": "text", "public": True, "optional": True},
    {"name": "token_file", "label": "Token file (under VAULT_CONNECTION_TOKEN_DIR)",
     "label_ko": "토큰 파일(VAULT_CONNECTION_TOKEN_DIR 안)", "kind": "text", "public": True},
]


def _descriptor(provider, label):
    return {
        "provider": provider,
        "label": label, "label_ko": label,
        "category": "vault",
        "editions": ([{"id": "community", "label": "Vault Community", "label_ko": "Vault Community"},
                      {"id": "enterprise", "label": "Vault Enterprise", "label_ko": "Vault Enterprise"},
                      {"id": "hcp_dedicated", "label": "HCP Vault Dedicated", "label_ko": "HCP Vault Dedicated"},
                      {"id": "self_managed", "label": "Existing Vault connection", "label_ko": "기존 Vault 연결", "new_setup": False}]
                     if provider == "vault" else [{"id": "self_managed", "label": label, "label_ko": label}]),
        "target": [
            {"name": "address", "label": "Cluster address", "label_ko": "클러스터 주소", "kind": "url", "required": True,
             "hint": "https://vault.example.com:8200"},
            {"name": "namespace", "label": "Namespace", "label_ko": "네임스페이스", "kind": "text",
             # HCP Vault Dedicated provisions the cluster with the namespace admin; teams use it or a child of it.
             **({"editions": ["enterprise", "hcp_dedicated", "self_managed"], "hint": "admin, admin/team-a"}
                if provider == "vault" else {})},
            {"name": "mounts", "label": "KV mounts", "label_ko": "KV 마운트", "kind": "list", "required": True,
             "hint": "secret, team-a"},
            {"name": "kv_version", "label": "KV version", "label_ko": "KV 버전", "kind": "choice", "default": "2",
             "options": [{"id": "2", "label": "KV v2", "label_ko": "KV v2"},
                         {"id": "1", "label": "KV v1", "label_ko": "KV v1"}]},
            {"name": "prefixes", "label": "Path prefixes (empty = whole mount)",
             "label_ko": "경로 접두어(비우면 마운트 전체)", "kind": "list"},
            {"name": "tls_ca_pem", "label": "Cluster CA certificate (PEM, when it is not publicly trusted)",
             "label_ko": "클러스터 CA 인증서(PEM, 공개 신뢰 인증서가 아닐 때)", "kind": "multiline"},
        ],
        "purposes": {"vault": {"permissions": [
            {"id": "login", "label": "The connection's own login", "label_ko": "연결 자체 로그인",
             "methods": ["kubernetes", "jwt", "token"]},
            {"id": "mounts_read", "label": "read on sys/mounts (lists the KV mounts to pick)",
             "label_ko": "sys/mounts 읽기(고를 KV 마운트 목록)", "methods": ["kubernetes", "jwt", "token"], "required": False},
            {"id": "kv_list", "label": "list on <mount>/metadata/<prefix>/* (KV v1: <mount>/<prefix>/*)",
             "label_ko": "<마운트>/metadata/<접두어>/* 목록(list, KV v1은 <마운트>/<접두어>/*)", "methods": ["kubernetes", "jwt", "token"]},
            {"id": "kv_read", "label": "read on <mount>/data/<prefix>/* (KV v1: <mount>/<prefix>/*)",
             "label_ko": "<마운트>/data/<접두어>/* 읽기(read, KV v1은 <마운트>/<접두어>/*)", "methods": ["kubernetes", "jwt", "token"]},
            {"id": "kv_history", "label": "read on <mount>/metadata/<prefix>/* (earlier versions)",
             "label_ko": "<마운트>/metadata/<접두어>/* 읽기(이전 버전)", "methods": ["kubernetes", "jwt", "token"],
             "option": "previous_versions"},
            {"id": "token_accessors", "label": "sudo and list on auth/token/accessors, update on auth/token/lookup-accessor "
             "(Vault advises keeping this tightly controlled)",
             "label_ko": "auth/token/accessors의 sudo·list, auth/token/lookup-accessor의 update(Vault는 엄격히 통제하라고 권고)",
             "methods": ["kubernetes", "jwt", "token"], "option": "token_accessors"},
            {"id": "leases", "label": "sudo and list on sys/leases/lookup/<prefix>/, update on sys/leases/lookup",
             "label_ko": "sys/leases/lookup/<접두어>/의 sudo·list, sys/leases/lookup의 update",
             "methods": ["kubernetes", "jwt", "token"], "nonempty": "lease_prefixes"},
            {"id": "kv_list", "label": "Reported by the CLI", "label_ko": "CLI 수집 시 보고", "methods": ["customer_cli"], "required": False},
            {"id": "kv_read", "label": "Reported by the CLI", "label_ko": "CLI 수집 시 보고", "methods": ["customer_cli"], "required": False},
        ], "plan": [
            {"name": "previous_versions", "kind": "bool", "default": False, "when": {"kv_version": ["2"]},
             "label": "Also compare earlier KV versions", "label_ko": "이전 KV 버전도 대조"},
            {"name": "max_versions", "kind": "number", "default": 20, "min": 1, "max": 1000,
             "when": {"kv_version": ["2"]}, "label": "Versions per secret", "label_ko": "비밀당 버전 수"},
            {"name": "token_accessors", "kind": "bool", "default": False,
             "label": "Service token accessors (metadata, never a token)",
             "label_ko": "서비스 토큰 accessor(메타데이터, 토큰 값 아님)"},
            {"name": "lease_prefixes", "kind": "list", "label": "Dynamic secret lease prefixes",
             "label_ko": "동적 시크릿 lease 접두어", "hint": "database/creds/app"},
            _SCHEDULE]}},
        "auth_methods": [
            {"id": "customer_cli", "new_setup": False, "label": "CreMore CLI in your environment", "label_ko": "고객 환경의 CreMore CLI",
             "renewal": "NONE", "purposes": ["vault"], "fields": []},
            {"id": "kubernetes", "label": "Kubernetes login (server read)", "label_ko": "쿠버네티스 로그인(서버 읽기)",
             "auth_first": {"context": ["address", "namespace", "tls_ca_pem"]},
             "renewal": "AUTOMATIC", "purposes": ["vault"], "fields": _LOGIN_FIELDS},
            {"id": "jwt", "label": "JWT login (server read)", "label_ko": "JWT 로그인(서버 읽기)", "renewal": "AUTOMATIC",
             "auth_first": {"context": ["address", "namespace", "tls_ca_pem"]},
             "purposes": ["vault"], "fields": _LOGIN_FIELDS},
            {"id": "token", "label": "Vault token (server read)", "label_ko": "Vault 토큰(서버 읽기)", "renewal": "EXPIRES",
             "auth_first": {"context": ["address", "namespace", "tls_ca_pem"]},
             "advanced": True, "purposes": ["vault"], "reference": False,
             "fields": [{"name": "token", "label": "Token", "label_ko": "토큰", "kind": "secret", "secret": True}]},
        ],
    }


DESCRIPTORS = [_descriptor("vault", "HashiCorp Vault"), _descriptor("openbao", "OpenBao")]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    from cremore.coverage.models import scope_path

    address = values.get("address", "").rstrip("/")
    try:
        mounts = [scope_path(mount) for mount in values.get("mounts") or []]
        prefixes = [scope_path(prefix) for prefix in values.get("prefixes") or []] or [""]
        namespace = scope_path(values.get("namespace", "")) if values.get("namespace") else ""
    except ValueError:
        raise OnboardingValueError("VAULT_PATH_INVALID") from None
    if not mounts or any(not mount for mount in mounts):
        raise OnboardingValueError("VAULT_MOUNT_REQUIRED")
    out = {"address": address, "namespace": namespace, "mounts": mounts,
           "kv_version": values.get("kv_version") or "2", "prefixes": prefixes}
    if values.get("tls_ca_pem"):
        out["tls_ca_pem"] = auth_context(provider, edition, values)["tls_ca_pem"]
    if provider == "vault" and edition == "community":
        if namespace:
            raise OnboardingValueError("VAULT_NAMESPACE_REQUIRES_ENTERPRISE")
        out.pop("namespace", None)
    return out


def credential(provider, method, fields):
    if method == "token":
        token = fields.get("token", "").strip()
        if not _TOKEN.fullmatch(token):
            raise OnboardingValueError("VAULT_TOKEN_INVALID")
        return {"credential": {"token": token}}
    if method in ("kubernetes", "jwt") and (not _ROLE.fullmatch(fields.get("role", ""))
                                           or not _FILE.fullmatch(fields.get("token_file", ""))):
        raise OnboardingValueError("VAULT_LOGIN_ROLE_AND_TOKEN_FILE_REQUIRED")
    return {}  # a login reads the deployment's token file; the CLI keeps its own token


def auth_context(provider, edition, values):
    from cremore.coverage.models import ConnectionSpec, scope_path
    from cremore.sources.validation import https_base
    from cremore_vault_provider.connection_login import tls_verify

    if provider == "vault" and edition == "community" and values.get("namespace"):
        raise OnboardingValueError("VAULT_NAMESPACE_REQUIRES_ENTERPRISE")

    try:
        result = {"address": https_base(values["address"]).rstrip("/"),
                  "namespace": scope_path(values["namespace"]) if values.get("namespace") else ""}
    except ValueError:
        raise OnboardingValueError("VAULT_PATH_INVALID") from None
    if values.get("tls_ca_pem"):
        try:
            result["tls_ca_pem"] = ConnectionSpec.valid_ca(values["tls_ca_pem"])
            tls_verify(SimpleNamespace(tls_ca_pem=result["tls_ca_pem"]))
        except (ValueError, OSError):
            raise OnboardingValueError("VAULT_TLS_CA_MUST_BE_A_PEM_CERTIFICATE") from None
    if provider == "vault" and edition == "community":
        result.pop("namespace", None)
    return result


@contextmanager
def _authenticated_client(connection, secrets, context):
    """The same connection-owned workload login before and after mount selection."""
    from cremore.coverage.models import VaultServerAuth
    from cremore_vault_provider.connection_login import connection_token, tls_verify

    target_, settings = connection["target"], context.settings
    options = ({"verify": tls_verify(SimpleNamespace(tls_ca_pem=target_["tls_ca_pem"]))}
               if target_.get("tls_ca_pem") else {})
    with context.http_client(**options) as client:
        if connection["auth_method"] == "token":
            token = secrets["credential"]["token"]
        else:
            # Authentication is not a collection scope: no fictitious KV mount.
            prospective = SimpleNamespace(endpoint=target_["address"],
                                          server_auth=VaultServerAuth.model_validate(_server_auth(connection)))
            install = (settings.secret_store_kubernetes_token_file
                       if getattr(settings, "secret_store_auth_mode", "") == "kubernetes" else "")
            source = connection_token(prospective, client,
                token_dir=getattr(settings, "vault_connection_token_dir", ""), install_token_file=install)
            token = source()
        yield client, {"X-Vault-Token": token,
                       **({"X-Vault-Namespace": target_["namespace"]} if target_.get("namespace") else {})}


def authenticate(connection, secrets, context):
    from cremore_vault_provider.secretstore import SecretStoreError

    try:
        with _authenticated_client(connection, secrets, context) as (client, headers):
            result = probe(client, "GET", connection["target"]["address"] + "/v1/auth/token/lookup-self",
                           headers=headers)
    except SecretStoreError as exc:
        return {"status": "MISSING", "detail": exc.code}
    if result[0] == "GRANTED" and not isinstance((json_body(result[2]) or {}).get("data"), dict):
        return {"status": "ERROR", "detail": "MALFORMED_RESPONSE"}
    return {"status": result[0], **({"detail": result[1]} if result[1] else {})}


def discover(connection, secrets, context):
    with _authenticated_client(connection, secrets, context) as (client, headers):
        result = probe(client, "GET", connection["target"]["address"] + "/v1/sys/mounts",
                       headers=headers)
    if result[0] != "GRANTED":
        raise OnboardingValueError("VAULT_MOUNTS_ACCESS_DENIED" if result[0] == "MISSING" else result[1] or "REQUEST_FAILED")
    mounts = (json_body(result[2]) or {}).get("data")
    if not isinstance(mounts, dict):
        raise OnboardingValueError("MALFORMED_RESPONSE")
    return [{"label": path.rstrip("/") + " · KV v" + str((row.get("options") or {}).get("version") or "1"),
             "target": {**{k: v for k, v in connection["target"].items() if k in {"address", "namespace", "tls_ca_pem"}},
                        "mounts": [path.rstrip("/")], "kv_version": str((row.get("options") or {}).get("version") or "1")}}
            for path, row in mounts.items() if isinstance(row, dict) and row.get("type") == "kv"], "COMPLETE"


def _server_auth(connection):
    method = connection["auth_method"]
    if method == "token":
        return {"method": "token"}
    auth = connection["target"].get("auth") or {}
    return {"method": method, "role": auth.get("role", ""), "token_file": auth.get("token_file", ""),
            "mount": auth.get("mount") or method, "namespace": connection["target"].get("namespace", "")}


def spec(connection, schedule=1440, plan=None):
    """The collection a vault connection runs, as a schema 1 specification."""
    target_, plan = connection["target"], plan or {}
    server = connection["auth_method"] != "customer_cli"
    body = {"name": connection.get("name") or connection["provider"], "provider": connection["provider"], "endpoint": target_["address"],
            "namespaces": [target_.get("namespace", "")],
            "mounts": [{"name": mount, "kv_version": int(target_.get("kv_version") or 2),
                        "prefixes": target_.get("prefixes") or [""]} for mount in target_["mounts"]],
            "include_previous_versions": bool(plan.get("previous_versions")),
            "max_versions_per_secret": plan.get("max_versions", 20),
            "include_token_accessors": bool(plan.get("token_accessors")),
            "lease_prefixes": list(plan.get("lease_prefixes") or [])}
    if target_.get("tls_ca_pem"):
        body["tls_ca_pem"] = target_["tls_ca_pem"]
    if server:
        body.update(server_collection=True, server_auth=_server_auth(connection), schedule_minutes=schedule)
    return body


def _paths(connection, *, values=False, history=False):
    """Where each read is decided. A LIST is decided on the prefix with a trailing slash -- Vault lists ``<path>/`` and
    "policies must operate on a prefix" -- a value or version read on what is under it."""
    target_ = connection["target"]
    version = str(target_.get("kv_version") or "2")
    out = []
    for mount in target_["mounts"]:
        for prefix in target_.get("prefixes") or [""]:
            middle = ("metadata/" if history or not values else "data/") if version == "2" else ""
            out.append(f"{mount}/{middle}{prefix}".rstrip("/") + ("/*" if values or history else "/"))
            if len(out) > 500:
                raise OnboardingValueError("VAULT_PERMISSION_PATH_LIMIT")
    return out


def _option_paths(permission, plan):
    """What an option reads: ``{subject: capabilities it needs}``."""
    if permission == "token_accessors" and plan.get("token_accessors"):
        return {"auth/token/accessors": {"sudo", "list"}, "auth/token/lookup-accessor": {"update"}}
    if permission == "leases" and plan.get("lease_prefixes"):
        return {**{f"sys/leases/lookup/{prefix.strip('/')}/": {"sudo", "list"} for prefix in plan["lease_prefixes"]},
                "sys/leases/lookup": {"update"}}
    return {}


def permission_subjects(connection, purpose, permission, plan):
    if permission in {"kv_list", "kv_read"}:
        return _paths(connection, values=permission == "kv_read")
    if permission == "kv_history" and plan.get("previous_versions") and str(connection["target"].get("kv_version") or "2") == "2":
        return _paths(connection, history=True)
    return list(_option_paths(permission, plan))


def check(connection, purpose, secrets, context):
    if connection["auth_method"] == "customer_cli":
        return [{"permission": name, "status": "NOT_REPORTED", "detail": "CUSTOMER_CLI_REPORTS_ON_UPLOAD"}
                for name in ("kv_list", "kv_read")]
    from cremore_vault_provider.secretstore import SecretStoreError

    try:
        return _check(connection, secrets, context)
    except SecretStoreError as exc:
        return [{"permission": "login", "status": "MISSING", "detail": exc.code},
                {"permission": "kv_list", "status": "NOT_REPORTED", "detail": "LOGIN_REQUIRED"},
                {"permission": "kv_read", "status": "NOT_REPORTED", "detail": "LOGIN_REQUIRED"}]


def _check(connection, secrets, context):
    address = connection["target"]["address"]
    plans = connection.get("checks", {}).get("requested_plans", {})
    plan = plans.get("vault", (connection.get("plans") or {}).get("vault", {})) or {}
    with _authenticated_client(connection, secrets, context) as (client, headers):
        login = probe(client, "GET", address + "/v1/auth/token/lookup-self", headers=headers)
        items = [{"permission": "login", "status": login[0], **({"detail": login[1]} if login[1] else {})}]
        if login[0] != "GRANTED":
            return items + [{"permission": name, "status": "NOT_REPORTED", "detail": "LOGIN_REQUIRED"}
                            for name in ("kv_list", "kv_read")]
        # {permission: {path: capabilities needed}}: the KV reads, the mount list, and what each chosen option reads.
        wanted = {"kv_list": {path: {"list"} for path in _paths(connection)},
                  "kv_read": {path: {"read"} for path in _paths(connection, values=True)},
                  "mounts_read": {"sys/mounts": {"read"}}}
        for name in ("kv_history", "token_accessors", "leases"):
            subjects = permission_subjects(connection, "vault", name, plan)
            if subjects:
                wanted[name] = _option_paths(name, plan) or {path: {"read"} for path in subjects}
        paths = list(dict.fromkeys(path for subjects in wanted.values() for path in subjects))
        answer = probe(client, "POST", address + "/v1/sys/capabilities-self", headers=headers, json={"paths": paths})
        if answer[0] != "GRANTED":
            return items + [{"permission": name, "status": answer[0], "detail": answer[1] or "REQUEST_FAILED"}
                            for name in wanted]
        body = json_body(answer[2]) or {}
        rooted = False
        for name, subjects in wanted.items():
            for path, needed in subjects.items():
                capabilities = set(body.get(path) or (body.get("capabilities") if len(paths) == 1 else []) or [])
                rooted = rooted or "root" in capabilities
                items.append({"permission": name, "subject": path,
                              "status": "GRANTED" if "root" in capabilities or needed <= capabilities else "MISSING"})
        if rooted:  # it reads, but a scanner should hold a read-only policy, never a root token
            items[0]["detail"] = "ROOT_TOKEN_NOT_RECOMMENDED"
        return items


def children(connection, purpose, plan):
    body = spec(connection, plan.get("schedule_minutes", 1440), plan)
    cli = connection["auth_method"] == "customer_cli"
    return [{"kind": "coverage", "purpose": purpose, "spec": body, "collector_token": cli,
             "secret_slots": {"vault_token": "credential"} if connection["auth_method"] == "token" else {}}]
