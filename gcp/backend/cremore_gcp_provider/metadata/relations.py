"""Read-only evidence collection and conservative GCP relationship projection.

Every edge keeps the native distinction between evidence classes: an audit entry
is observed access, an allow policy is only possible access, and a metric series
is the provider's own attribution of requests to a key. Absent evidence stays
unknown -- it is never reported as unused. Each edge's collection_status is the
status of its own coverage path, restored from that path's operation report.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

from .collector import response_pages
from .normalization import _edge_identity
from .transport import DEFERRED, ApiError, Budget

SECRET_RE = re.compile(r"^projects/([a-z0-9-]+)/(?:locations/([a-z][a-z0-9-]{1,62})/)?secrets/([A-Za-z0-9_-]+)$")
VERSION_RE = re.compile(r"^projects/([a-z0-9-]+)/(?:locations/([a-z][a-z0-9-]{1,62})/)?secrets/([A-Za-z0-9_-]+)/versions/[A-Za-z0-9_-]+$")
API_KEY_RE = re.compile(r"^projects/([a-z0-9-]+)/locations/global/keys/([A-Za-z0-9_-]+)$")
KEY_LOG_RE = re.compile(
    r"^//iam\.googleapis\.com/projects/([a-z0-9-]+)/serviceAccounts/([^/]+)/keys/([A-Za-z0-9_-]+)$"
)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]{1,253}$")
RESOURCE_RE = re.compile(r"^[A-Za-z0-9_./:@%~-]{1,512}$")
LOG_ID_RE = re.compile(r"^[A-Za-z0-9_./:@%~-]{1,512}$")
API_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,199}$")
ROLE_RE = re.compile(
    r"^(?:roles/[A-Za-z0-9_.-]+|(?:projects|organizations)/[A-Za-z0-9-]+/roles/[A-Za-z0-9_.-]+)$"
)
ACCESS_METHOD = "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
CREATE_KEY_METHOD = "google.iam.admin.v1.CreateServiceAccountKey"
CREATE_API_KEY_METHOD = "google.api.apikeys.v2.ApiKeys.CreateKey"
REQUEST_METRIC = "serviceruntime.googleapis.com/api/request_count"
LOG_FIELDS = "nextPageToken,entries(logName,insertId,timestamp,protoPayload)"
KNOWN_ACCESS_ROLES = {"roles/owner", "roles/secretmanager.admin", "roles/secretmanager.secretAccessor"}
KNOWN_NON_ACCESS_ROLES = {"roles/editor", "roles/viewer", "roles/secretmanager.viewer"}
LOG_PHASES = ("secret_access_logs", "service_account_activity_logs", "key_creation_logs")
AUDIT_STREAMS = ("activity", "data_access", "system_event", "policy")


def policy_assessment(conditional: bool, direct: bool) -> dict:
    """Record exactly what local allow-policy reads leave unresolved."""
    return {
        "effective_access": "not_evaluated",
        "inherited_policies": "not_evaluated",
        "deny_policies": "not_evaluated",
        "principal_access_boundaries": "not_evaluated",
        "membership_resolution": "direct_member" if direct else "not_evaluated",
        "condition_evaluation": "not_evaluated" if conditional else "not_present",
    }


def utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else None


def safe(value, pattern):
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def status_ok(payload) -> bool:
    status = payload.get("status")
    return status is None or isinstance(status, dict) and status.get("code", 0) in (0, "0")


def edge_id(edge) -> str:
    identity = {
        key: edge[key]
        for key in ("source_id", "target_id", "relation", "evidence_source", "evidence_id")
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]


class RelationshipCollector:
    """Native relationship reads, one provider page per generator step."""

    def __init__(self, project, inventory, transport, *, end, lookback_hours=24, max_pages=100,
                 max_edges=50_000):
        if not 1 <= lookback_hours <= 24 * 30:
            raise ValueError("lookback_hours must be between 1 and 720")
        if end.tzinfo is None:
            raise ValueError("end must include a timezone")
        self.project = project
        self.transport = transport
        self.end = end.astimezone(UTC)
        self.start = self.end - timedelta(hours=lookback_hours)
        self.max_pages = max_pages
        self.max_edges = max_edges
        self.issues: dict[str, int] = {}
        self.role_cache: dict[str, bool | None] = {}
        self.principals = dict(inventory["principals"])
        ids = {}
        for email, uid in inventory.get("account_ids", {}).items():
            if email in self.principals and isinstance(uid, str) and uid.isascii() and uid.isdigit():
                ids.setdefault(uid, set()).add(email)
        self.account_emails = {uid: next(iter(emails)) for uid, emails in ids.items() if len(emails) == 1}
        self.keys = dict(inventory["keys"])
        self.api_keys = dict(inventory["api_keys"])
        self.missing_api_uid = int(inventory.get("missing_api_uid", 0))
        self.secrets = dict(inventory["secrets"])
        self.secret_resources = {name.split("/", 2)[2]: name for name in self.secrets.values() if SECRET_RE.fullmatch(name)}
        self.project_aliases = {value for value in (project, *inventory.get("project_aliases", ()))
                                if isinstance(value, str) and re.fullmatch(r"[a-z0-9-]{1,128}", value)}

    # -- shared helpers ----------------------------------------------------

    def _issue(self, code):
        self.issues[code] = self.issues.get(code, 0) + 1

    def _pages(self, field_name, request, *, cursor=None):
        yield from response_pages(request, field_name, max_pages=self.max_pages, cursor=cursor)

    def _logs(self, filter_text, *, cursor=None):
        def request(token):
            body = {
                "resourceNames": [f"projects/{self.project}"],
                "filter": filter_text,
                "orderBy": "timestamp desc",
                "pageSize": 100,
            }
            if token:
                body["pageToken"] = token
            response = self.transport.post_readonly(
                "https://logging.googleapis.com/v2/entries:list", body, {"fields": LOG_FIELDS}
            )
            # AuditLog is a protobuf Any: Google rejects nested protoPayload
            # response masks. Drop request/response/metadata immediately after
            # deserialization; never retain them in a Page or in a record.
            entries = response.get("entries", [])
            if not isinstance(entries, list):
                return {"entries": entries, "nextPageToken": response.get("nextPageToken", "")}
            projected = []
            for entry in entries:
                if not isinstance(entry, dict):
                    projected.append(entry)
                    continue
                payload = entry.get("protoPayload")
                auth = payload.get("authenticationInfo") if isinstance(payload, dict) else None
                created_key = None
                if isinstance(payload, dict) and payload.get("methodName") in {CREATE_KEY_METHOD, CREATE_API_KEY_METHOD}:
                    response_ = payload.get("response")
                    name = response_.get("name") if isinstance(response_, dict) else None
                    if isinstance(name, str) and (KEY_LOG_RE.fullmatch("//iam.googleapis.com/" + name) or API_KEY_RE.fullmatch(name)):
                        created_key = name
                projected.append({
                    "logName": entry.get("logName"),
                    "insertId": entry.get("insertId"),
                    "timestamp": entry.get("timestamp"),
                    "protoPayload": {
                        "serviceName": payload.get("serviceName"),
                        "methodName": payload.get("methodName"),
                        "resourceName": payload.get("resourceName"),
                        "status": payload.get("status"),
                        "createdKeyName": created_key,
                        "authenticationInfo": {
                            "principalEmail": auth.get("principalEmail"),
                            "serviceAccountKeyName": auth.get("serviceAccountKeyName"),
                        } if isinstance(auth, dict) else None,
                    } if isinstance(payload, dict) else None,
                })
            return {"entries": projected, "nextPageToken": response.get("nextPageToken", "")}

        return self._pages("entries", request, cursor=cursor)

    def base_filter(self):
        names = [f"projects/{project}/logs/cloudaudit.googleapis.com%2F{stream}"
                 for project in sorted(self.project_aliases) for stream in AUDIT_STREAMS]
        return (
            f'timestamp>="{utc(self.start)}" AND timestamp<"{utc(self.end)}" '
            + "AND (" + " OR ".join(f"logName={json.dumps(name)}" for name in names) + ")"
        )

    def audit_log_name(self, value):
        """Canonical audit stream from the approved project ID or verified number."""
        value = safe(value, LOG_ID_RE)
        if value is None:
            return None
        parent, separator, log_id = value.partition("/logs/")
        if not separator or parent not in {f"projects/{name}" for name in self.project_aliases}:
            return None
        try:
            log_id = unquote(log_id, errors="strict")
        except UnicodeError:
            return None
        if log_id not in {f"cloudaudit.googleapis.com/{name}" for name in AUDIT_STREAMS}:
            return None
        return parent + "/logs/" + log_id.replace("/", "%2F")

    def principal_id(self, email):
        value = safe(email, EMAIL_RE)
        if value is None:
            return None
        if value in self.principals:
            return self.principals[value]
        kind = "serviceAccount" if re.fullmatch(r"[^@]+@(?:[A-Za-z0-9-]+\.)*gserviceaccount\.com", value) is not None else "user"
        return f"gcp_principal:{kind}:{value}"

    def key_id(self, key_name, principal_email):
        match = KEY_LOG_RE.fullmatch(key_name) if isinstance(key_name, str) else None
        if match is None or match.group(1) not in self.project_aliases:
            return None
        account = self.account_emails.get(match.group(2), match.group(2))
        principal_email = self.account_emails.get(principal_email, principal_email)
        if account != principal_email:
            return None
        return self.keys.get((account, match.group(3)))

    def log_evidence(self, row):
        log_name = self.audit_log_name(row.get("logName"))
        insert_id = safe(row.get("insertId"), LOG_ID_RE)
        timestamp = parse_time(row.get("timestamp"))
        if log_name is None or insert_id is None or timestamp is None:
            self._issue("invalid_log_evidence")
            return None
        if not self.start <= timestamp < self.end:
            self._issue("log_outside_window")
            return None
        return f"{log_name}#{insert_id}", utc(timestamp), log_name, insert_id

    def _edge(self, source_id, target_id, relation, evidence_class, evidence_source, evidence_id,
              first, last, coverage_key, **extra):
        windowed = evidence_source != "iam_allow_policy"
        edge = {
            "source_id": source_id, "target_id": target_id, "relation": relation,
            "evidence_class": evidence_class, "evidence_source": evidence_source,
            "evidence_id": evidence_id, "first_observed_at": first, "last_observed_at": last,
            "collection_scope": {
                "project_id": self.project,
                "window_start": utc(self.start) if windowed else None,
                "window_end": utc(self.end) if windowed else None,
            },
            "coverage_path": coverage_key,
            **extra,
        }
        edge["id"] = edge_id(edge)
        return edge

    # -- phases ------------------------------------------------------------

    def key_creation(self, *, cursor=None):
        filter_text = (self.base_filter() + f' AND (protoPayload.methodName="{CREATE_KEY_METHOD}"'
                       + f' OR protoPayload.methodName="{CREATE_API_KEY_METHOD}")')
        for page in self._logs(filter_text, cursor=cursor):
            edges = []
            for row in page.rows:
                payload = row.get("protoPayload") if isinstance(row, dict) else None
                if not isinstance(payload, dict) or not status_ok(payload):
                    continue
                api_key = payload.get("methodName") == CREATE_API_KEY_METHOD and payload.get("serviceName") == "apikeys.googleapis.com"
                if not api_key and (payload.get("serviceName") != "iam.googleapis.com" or payload.get("methodName") != CREATE_KEY_METHOD):
                    continue
                name = payload.get("createdKeyName") or payload.get("resourceName")
                match = KEY_LOG_RE.fullmatch("//iam.googleapis.com/" + name) if isinstance(name, str) else None
                auth = payload.get("authenticationInfo") or {}
                actor = self.principal_id(auth.get("principalEmail"))
                evidence = self.log_evidence(row)
                key = self.key_id("//iam.googleapis.com/" + name, match.group(2)) if match else None
                if api_key:
                    match = API_KEY_RE.fullmatch(name) if isinstance(name, str) else None
                    key = next((value for value in self.api_keys.values() if match and match.group(1) in self.project_aliases
                                and value.split("/", 2)[2] == name.split("/", 2)[2]), None)
                if not key or not actor or not evidence:
                    self._issue("unattributed_key_creation")
                    continue
                evidence_id, at, log_name, insert_id = evidence
                edges.append(self._edge(key, actor, "api_key_created_by" if api_key else "service_account_key_created_by", "credential_creation",
                    "cloud_logging.key_creation", evidence_id, at, at, "key_creation_logs",
                    log_name=log_name, insert_id=insert_id, method_name=payload["methodName"]))
            page.rows = edges
            yield page

    def secret_access(self, *, cursor=None):
        filter_text = (
            self.base_filter()
            + ' AND protoPayload.serviceName="secretmanager.googleapis.com"'
            + f' AND protoPayload.methodName="{ACCESS_METHOD}"'
        )
        for page in self._logs(filter_text, cursor=cursor):
            yield self._secret_access_page(page)

    def _secret_access_page(self, page):
        edges = []
        for row in page.rows:
            payload = row.get("protoPayload")
            if (not isinstance(payload, dict)
                    or payload.get("serviceName") != "secretmanager.googleapis.com"
                    or payload.get("methodName") != ACCESS_METHOD):
                self._issue("unexpected_secret_log")
                continue
            if not status_ok(payload):
                self._issue("failed_secret_access_attempt")
                continue
            resource = payload.get("resourceName")
            match = VERSION_RE.fullmatch(resource) if isinstance(resource, str) else None
            if match is None or match.group(1) not in self.project_aliases:
                self._issue("unmatched_secret_version")
                continue
            secret_id = self.secret_resources.get(resource.rsplit("/versions/", 1)[0].split("/", 2)[2])
            evidence = self.log_evidence(row)
            auth = payload.get("authenticationInfo")
            email = auth.get("principalEmail") if isinstance(auth, dict) else None
            principal = self.principal_id(email)
            if secret_id is None or evidence is None or principal is None:
                self._issue("unattributed_secret_access")
                continue
            evidence_id, timestamp, log_name, insert_id = evidence
            version_id = resource
            common = {"log_name": log_name, "insert_id": insert_id,
                      "method_name": payload["methodName"]}
            edges.append(self._edge(principal, secret_id, "secret_access_observed",
                                    "observed_access", "cloud_logging.secret_access", evidence_id,
                                    timestamp, timestamp, "secret_access_logs",
                                    version_id=version_id, **common))
            edges.append(self._edge(principal, version_id, "secret_version_access_observed",
                                    "observed_access", "cloud_logging.secret_access", evidence_id,
                                    timestamp, timestamp, "secret_access_logs",
                                    secret_id=secret_id, **common))
            key_name = auth.get("serviceAccountKeyName") if isinstance(auth, dict) else None
            if not key_name:
                continue
            key_id = self.key_id(key_name, email)
            if key_id is None:
                self._issue("unmatched_service_account_key_name")
                continue
            edges.append(self._edge(key_id, secret_id, "service_account_key_secret_access_observed",
                                    "observed_access", "cloud_logging.secret_access", evidence_id,
                                    timestamp, timestamp, "secret_access_logs",
                                    version_id=version_id, **common))
            edges.append(self._edge(key_id, version_id,
                                    "service_account_key_version_access_observed",
                                    "observed_access", "cloud_logging.secret_access", evidence_id,
                                    timestamp, timestamp, "secret_access_logs",
                                    secret_id=secret_id, **common))
        page.rows = edges
        return page

    def service_account_activity(self, *, cursor=None):
        filter_text = (
            self.base_filter()
            + ' AND protoPayload.authenticationInfo.principalEmail:"gserviceaccount.com"'
        )
        for page in self._logs(filter_text, cursor=cursor):
            yield self._activity_page(page)

    def _activity_page(self, page):
        edges = []
        for row in page.rows:
            payload = row.get("protoPayload")
            if (not isinstance(payload, dict) or (self.secrets and payload.get("methodName") == ACCESS_METHOD)
                    or not status_ok(payload)):
                continue
            auth = payload.get("authenticationInfo")
            email = auth.get("principalEmail") if isinstance(auth, dict) else None
            if email not in self.principals:
                continue
            target = safe(payload.get("resourceName"), RESOURCE_RE)
            if target is not None and _edge_identity(target)[0] == "credential":
                # Acting on a key (update, delete, reading its string) is not that key's use: name the API acted on.
                service = safe(payload.get("serviceName"), API_SERVICE_RE)
                target = f"gcp_api:{service}" if service else None
            evidence = self.log_evidence(row)
            if target is None or evidence is None:
                self._issue("unattributed_service_account_activity")
                continue
            evidence_id, timestamp, log_name, insert_id = evidence
            method = payload.get("methodName")
            common = {"log_name": log_name, "insert_id": insert_id,
                      "method_name": method if isinstance(method, str) and len(method) <= 512 else None}
            edges.append(self._edge(self.principals[email], target,
                                    "service_account_activity_observed", "observed_access",
                                    "cloud_logging.service_account_activity", evidence_id,
                                    timestamp, timestamp, "service_account_activity_logs", **common))
            key_name = auth.get("serviceAccountKeyName")
            if not key_name:
                continue
            key_id = self.key_id(key_name, email)
            if key_id is None:
                self._issue("unmatched_service_account_key_name")
                continue
            edges.append(self._edge(key_id, target, "service_account_key_activity_observed",
                                    "observed_access", "cloud_logging.service_account_activity",
                                    evidence_id, timestamp, timestamp,
                                    "service_account_activity_logs", **common))
        page.rows = edges
        return page

    def api_key_metrics(self, uid, source_id, *, cursor=None):
        filter_text = (
            f'metric.type="{REQUEST_METRIC}" AND resource.type="consumed_api" '
            f'AND resource.labels.credential_id="apikey:{uid}"'
        )

        def request(token):
            params = {
                "filter": filter_text, "interval.startTime": utc(self.start),
                "interval.endTime": utc(self.end), "view": "FULL", "pageSize": 1000,
            }
            if token:
                params["pageToken"] = token
            return self.transport.get(
                f"https://monitoring.googleapis.com/v3/projects/{self.project}/timeSeries", params
            )

        for page in self._pages("timeSeries", request, cursor=cursor):
            page.rows = self._metric_edges(uid, source_id, page)
            yield page

    def _metric_edges(self, uid, source_id, page):
        grouped: dict[str, dict] = {}
        points = 0
        for row in page.rows:
            resource = row.get("resource")
            metric = row.get("metric")
            if not isinstance(resource, dict) or not isinstance(metric, dict):
                self._issue("invalid_metric_series")
                continue
            labels = resource.get("labels")
            if (resource.get("type") != "consumed_api" or metric.get("type") != REQUEST_METRIC
                    or not isinstance(labels, dict)
                    or labels.get("credential_id") != f"apikey:{uid}"
                    or labels.get("project_id", self.project) != self.project):
                self._issue("unmatched_metric_series")
                continue
            service = safe(labels.get("service"), API_SERVICE_RE)
            series = row.get("points")
            if service is None or not isinstance(series, list):
                self._issue("invalid_metric_series")
                continue
            for point in series:
                if not isinstance(point, dict):
                    self._issue("invalid_metric_point")
                    continue
                interval = point.get("interval")
                value = point.get("value")
                start = parse_time(interval.get("startTime")) if isinstance(interval, dict) else None
                end = parse_time(interval.get("endTime")) if isinstance(interval, dict) else None
                raw = value.get("int64Value") if isinstance(value, dict) else None
                try:
                    count = int(raw) if isinstance(raw, (str, int)) and not isinstance(raw, bool) else -1
                except ValueError:
                    count = -1
                # Google selects points by end time in (start, end]; a DELTA point may begin before the window.
                if start is None or end is None or not start < end or not self.start < end <= self.end or count < 0:
                    self._issue("invalid_metric_point")
                    continue
                points += 1
                if count == 0:
                    continue
                bucket = grouped.setdefault(service, {"count": 0, "first": start, "last": end})
                bucket["count"] += count
                bucket["first"] = min(bucket["first"], start)
                bucket["last"] = max(bucket["last"], end)
        page.received = points
        edges = []
        for service, bucket in sorted(grouped.items()):
            first, last = utc(bucket["first"]), utc(bucket["last"])
            evidence = f"{REQUEST_METRIC}|apikey:{uid}|{service}|{first}|{last}"
            edges.append(self._edge(source_id, f"gcp_api:{service}", "api_key_requests_observed",
                                    "observed_access", "cloud_monitoring.api_request_count",
                                    evidence, first, last, "api_key_usage_metrics",
                                    request_count=bucket["count"], caller_identity="unknown",
                                    service=service))
        return edges

    # -- IAM allow policies ------------------------------------------------

    def role_allows_access(self, role):
        if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
            return None
        if role in KNOWN_ACCESS_ROLES:
            return True
        if role in KNOWN_NON_ACCESS_ROLES:
            return False
        if role not in self.role_cache:
            try:
                result = self.transport.get(f"https://iam.googleapis.com/v1/{role}")
                permissions = result.get("includedPermissions")
                self.role_cache[role] = (
                    "secretmanager.versions.access" in permissions
                    if isinstance(permissions, list) else None
                )
            except ApiError as exc:
                if exc.code in DEFERRED:
                    raise
                self.role_cache[role] = None
        return self.role_cache[role]

    def member_id(self, member):
        if not isinstance(member, str) or len(member) > 320:
            return None
        if member.startswith("serviceAccount:"):
            email = safe(member.split(":", 1)[1], EMAIL_RE)
            if not email:
                return None
            return (self.principals.get(email) or f"gcp_principal:serviceAccount:{email}"), True
        if member.startswith("user:"):
            email = safe(member.split(":", 1)[1], EMAIL_RE)
            return (f"gcp_principal:user:{email}", True) if email else None
        if member in ("allUsers", "allAuthenticatedUsers"):
            return f"iam_member:{member}", False
        if member.startswith(("group:", "domain:")) and RESOURCE_RE.fullmatch(member):
            return f"iam_member:{member}", False
        return None

    def apply_policy(self, policy, policy_resource, targets, coverage_key):
        edges = []
        bindings = policy.get("bindings", [])
        if not isinstance(bindings, list):
            self._issue("invalid_policy_bindings")
            return edges
        observed_at = utc(self.end)
        for binding in bindings:
            if not isinstance(binding, dict):
                self._issue("invalid_policy_binding")
                continue
            role = binding.get("role")
            allowed = self.role_allows_access(role)
            if allowed is None:
                self._issue("unresolved_role")
                continue
            if not allowed:
                continue
            members = binding.get("members", [])
            if not isinstance(members, list):
                self._issue("invalid_policy_members")
                continue
            conditional = "condition" in binding
            for member in members:
                resolved = self.member_id(member)
                if resolved is None:
                    self._issue("unresolved_policy_member")
                    continue
                source_id, direct = resolved
                digest = hashlib.sha256(
                    f"{policy_resource}|{role}|{member}|"
                    f"{json.dumps(binding.get('condition'), sort_keys=True)}".encode()
                ).hexdigest()[:20]
                for target in targets:
                    if len(edges) >= self.max_edges:
                        raise Budget("RECORD_BUDGET_EXCEEDED")
                    edges.append(self._edge(
                        source_id, target, "policy_allows_secret_version_access",
                        "policy_possible" if direct and not conditional else "unconfirmed",
                        "iam_allow_policy", f"{policy_resource}#{digest}", observed_at,
                        observed_at, coverage_key, policy_resource=policy_resource, role=role,
                        condition_present=conditional, **policy_assessment(conditional, direct),
                    ))
        return edges

    def project_policy(self):
        resource = f"projects/{self.project}"
        policy = self.transport.post_readonly(
            f"https://cloudresourcemanager.googleapis.com/v1/{resource}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}},
        )
        return self.apply_policy(policy, resource, sorted(self.secrets.values()),
                                 "project_iam_policy")

    def service_account_roles(self):
        """Direct project allow bindings; not inherited or effective permissions."""
        resource = f"projects/{self.project}"
        policy = self.transport.post_readonly(
            f"https://cloudresourcemanager.googleapis.com/v1/{resource}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}})
        bindings = policy.get("bindings", [])
        if not isinstance(bindings, list):
            self._issue("invalid_policy_bindings")
            return []
        edges, at = [], utc(self.end)
        for binding in bindings:
            if not isinstance(binding, dict) or not safe(binding.get("role"), ROLE_RE) or not isinstance(binding.get("members"), list):
                self._issue("invalid_policy_binding")
                continue
            for email, principal in self.principals.items():
                if f"serviceAccount:{email}" not in binding["members"]:
                    continue
                digest = hashlib.sha256(json.dumps({"role": binding["role"], "principal": principal,
                    "condition": binding.get("condition")}, sort_keys=True).encode()).hexdigest()[:24]
                for subject in [principal, *(key for (account, _), key in self.keys.items() if account == email)]:
                    if len(edges) >= self.max_edges:
                        raise Budget("RECORD_BUDGET_EXCEEDED")
                    conditional = "condition" in binding
                    edges.append(self._edge(subject, resource, "project_role_binding", "unconfirmed" if conditional else "policy_possible",
                        "iam_allow_policy.service_account", f"{resource}#{digest}", at, at, "service_account_iam",
                        role=binding["role"], policy_resource=resource, condition_present=conditional,
                        **policy_assessment(conditional, True)))
        return edges

    def secret_policy(self, secret):
        match = SECRET_RE.fullmatch(secret)
        if not match or match.group(1) not in self.project_aliases or secret not in self.secrets.values():
            raise ValueError("SECRET_SCOPE_UNVERIFIED")
        host = f"secretmanager.{match.group(2)}.rep.googleapis.com" if match.group(2) else "secretmanager.googleapis.com"
        policy = self.transport.get(
            f"https://{host}/v1/{secret}:getIamPolicy",
            {"options.requestedPolicyVersion": 3},
        )
        return self.apply_policy(policy, secret, [secret], "secret_iam_policies")
