"""What an app credential can do, read for the service principal it signs in as (phase ``app_access``).

A client secret or certificate acts as its app's service principal in this tenant, so each listed sign-in credential
carries what that service principal holds. Two options choose what is read:

``app_permissions``
    application permissions: the app role assignments granted to the service principal, named by the resource's app
    role (``Microsoft Graph: Directory.ReadWrite.All``), which apply across the tenant; and Microsoft Entra roles: the
    active role assignments made to the service principal itself. A role held through a role-assignable group, or only
    eligible through Privileged Identity Management, is not listed.
``app_azure_roles``
    Azure roles: the role assignments for the service principal from the tenant root management group, including those
    it holds through groups (``assignedTo``). Deny assignments are not read; a condition on an assignment is recorded as
    present, never its text.

Every permission read is a grant that exists (ALLOW). A kind whose read failed leaves one UNKNOWN entry with the error
code, never an empty answer, and a failure that would repeat for every service principal (a refused caller, an
unreachable host, no root management group) is not asked again. The phase is enrichment: its report says what was
asked and what failed, and never makes the credential inventory partial. Nothing here signs in with a listed credential.
https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments
https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignments
https://learn.microsoft.com/azure/role-based-access-control/role-assignments-list-rest
"""

from __future__ import annotations

import re
from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.metadata_models import EntityObservation, MetadataPermission, metadata_text
from cremore_azure_provider.metadata.transport import DEFERRED, ApiError, ReadTransport

from .normalization import guid, provenance, report
from .transport import GUID, cursor_from_link

ARM = "https://management.azure.com"
ARM_VERSION = "2022-04-01"
# The plan options (as sources) and the kinds each reads.
SOURCES = {"app_permissions": ("app_role_assignment", "directory_role_assignment"),
           "app_azure_roles": ("azure_role_assignment",)}
# A management group name is never only dots: a dot segment would leave the approved path once normalized.
_GROUP = r"/providers/Microsoft\.Management/managementGroups/(?!\.+/)[A-Za-z0-9_.()-]{1,90}"
DEFINITION = re.compile(r"(?:/subscriptions/" + GUID + "|" + _GROUP + r")?/providers/Microsoft\.Authorization/roleDefinitions/"
                        + GUID, re.IGNORECASE)
_SCOPE = re.compile(r"/[^\x00-\x1f\x7f]{0,511}")
_DIRECTORY_SCOPE = re.compile(r"/(?:(?:administrativeUnits/)?" + GUID + r")?")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")
# The app role ID an assignment carries for default access: no application permission.
_DEFAULT_ACCESS = "00000000-0000-0000-0000-000000000000"
_MAX_PAGES = 10  # per principal and kind
# Failures that answer the same for every service principal; for Azure roles a missing root management group too.
# A failed request (request_failed) can be one network blip, so it is asked again for the next principal.
_REPEATS = frozenset({"permission_denied", "authentication_failed"})
_REPEATS_AZURE = _REPEATS | {"http_404"}


def kinds_of(spec) -> tuple[str, ...]:
    return tuple(kind for source, kinds in SOURCES.items() if source in spec.options.sources for kind in kinds)


def root(tenant: str) -> str:
    return f"/providers/Microsoft.Management/managementGroups/{tenant}/providers/Microsoft.Authorization"


class RoleTransport(ReadTransport):
    """ARM reads of one tenant's role assignments and the role definitions they name, charged to the collection's one
    request budget and paced with it (the Graph transport's ``charge`` and ``pace``)."""

    def __init__(self, client, token, *, tenant, options, charge, pace, check):
        super().__init__(client, token, origin=ARM, options=options, max_requests=0,
                         api_version=ARM_VERSION, check=check)
        self.charge, self.pace = charge, pace
        self.assignments = root(tenant) + "/roleAssignments"

    def _charge(self):
        self.charge()

    def _pace(self):
        self.pace()

    def get(self, path, params=None):
        if path != self.assignments and not DEFINITION.fullmatch(path):
            raise ValueError("UNAPPROVED_AZURE_ROLE_PATH")
        return self._request("GET", path, params)


def _text(value, fallback, limit=120):
    """Provider text bounded for a permission name or resource, or ``fallback``."""
    if not isinstance(value, str):
        return fallback
    text = _UNSAFE.sub("", value).strip()[:limit]
    try:
        return metadata_text(text) or fallback
    except ValueError:
        return fallback


def _permission(kind, name, resource_kind, resource_id, facts, effect="ALLOW"):
    return MetadataPermission(kind=kind, name=name[:256], resource_kind=resource_kind, resource_id=resource_id[:512],
                              effect=effect, conditions=FactWriter().facts(
                                  {key: value for key, value in facts.items() if value is not None}))


def _unknown(kind, code):
    return _permission("permission", kind, "", "", {"evidence_source": kind, "error_code": code}, effect="UNKNOWN")


def _graph_rows(graph, origin, path, params):
    rows, token = [], ""
    for _ in range(_MAX_PAGES):
        payload = graph.get(path, {**params, **({"$skiptoken": token} if token else {})})
        value = payload.get("value")
        if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
            raise ApiError("invalid_response")
        rows += value
        token = cursor_from_link(payload.get("@odata.nextLink"), origin, path)
        if not token:
            return rows
    raise ApiError("permission_page_limit")


def _application_permissions(graph, origin, principal, cache):
    out = []
    for row in _graph_rows(graph, origin, f"/v1.0/servicePrincipals/{principal}/appRoleAssignments",
                           {"$select": "appRoleId,resourceId"}):
        role, resource = guid(row.get("appRoleId")), guid(row.get("resourceId"))
        if not role or not resource:
            raise ApiError("invalid_app_role_assignment")
        if role == _DEFAULT_ACCESS:
            continue
        if resource not in cache:
            api = graph.get(f"/v1.0/servicePrincipals/{resource}", {"$select": "id,displayName,appRoles"})
            roles = api.get("appRoles")
            if guid(api.get("id")) != resource or not isinstance(roles, list):
                raise ApiError("invalid_app_roles")
            cache[resource] = (_text(api.get("displayName"), "API " + resource),
                               {guid(item.get("id")): _text(item.get("value"), "") for item in roles
                                if isinstance(item, dict) and guid(item.get("id"))})
        api, values = cache[resource]
        out.append(_permission("permission", f"{api}: {values.get(role) or 'app role ' + role}", "api", resource,
                               {"evidence_source": "app_role_assignment", "membership_resolution": "direct_member"}))
    return out


def _entra_roles(graph, origin, principal, cache):
    out = []
    for row in _graph_rows(graph, origin, "/v1.0/roleManagement/directory/roleAssignments",
                           {"$filter": f"principalId eq '{principal}'", "$select": "roleDefinitionId,directoryScopeId"}):
        definition, scope = guid(row.get("roleDefinitionId")), row.get("directoryScopeId")
        if not definition or not isinstance(scope, str) or not _DIRECTORY_SCOPE.fullmatch(scope):
            raise ApiError("invalid_directory_role_assignment")
        if "directory:" + definition not in cache:
            found = graph.get(f"/v1.0/roleManagement/directory/roleDefinitions/{definition}",
                              {"$select": "id,displayName"})
            cache["directory:" + definition] = _text(found.get("displayName"), "Entra role " + definition)
        name = cache["directory:" + definition]
        # A role scoped to an administrative unit or one app says where, as the name the console lists.
        out.append(_permission("role", name if scope == "/" else f"{name} · {scope}", "directory", scope,
                               {"evidence_source": "directory_role_assignment", "membership_resolution": "direct_member"}))
    return out


def _skip_token(link, path):
    """The continuation of an ARM role assignment listing, only from the same listing."""
    if link in (None, ""):
        return None
    try:
        parsed = urlsplit(link) if isinstance(link, str) and len(link) <= 8192 else None
        query = parse_qs(parsed.query) if parsed else {}
        token = [value for key, values in query.items() if key.lower() == "$skiptoken" for value in values]
        if (not parsed or parsed.scheme != "https" or parsed.hostname != "management.azure.com"
                or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment
                or parsed.path.casefold() != path.casefold() or len(token) != 1
                or not 1 <= len(token[0]) <= 4096 or _UNSAFE.search(token[0])):
            raise ValueError
    except ValueError:
        raise ApiError("invalid_pagination") from None
    return token[0]


def _role_name(roles, tenant, definition, cache, errors):
    """A role definition's name: read at the root management group, where every role an assignment in the tenant
    names is assignable, then where the assignment names it; its ID when neither answers."""
    identifier = definition.rsplit("/", 1)[-1].lower()
    if "azure:" + identifier not in cache:
        cache["azure:" + identifier], code = "Azure role " + identifier, None
        for path in dict.fromkeys((root(tenant) + "/roleDefinitions/" + identifier, definition)):
            try:
                found = roles.get(path)
            except ApiError as exc:
                if exc.code in DEFERRED:
                    raise
                code = exc.code
                continue
            fields = found.get("properties")
            name = _text(fields.get("roleName"), "") if isinstance(fields, dict) else ""
            if name:
                cache["azure:" + identifier], code = name, None
                break
            code = "invalid_role_definition"
        if code:
            errors["role_definition_" + code] = errors.get("role_definition_" + code, 0) + 1
    return cache["azure:" + identifier]


def _azure_roles(roles, tenant, principal, cache, errors):
    path, out = root(tenant) + "/roleAssignments", []
    params = {"$filter": f"assignedTo('{principal}')"}
    for _ in range(_MAX_PAGES):
        payload = roles.get(path, params)
        value = payload.get("value")
        if not isinstance(value, list):
            raise ApiError("invalid_response")
        for row in value:
            fields = row.get("properties") if isinstance(row, dict) else None
            definition = fields.get("roleDefinitionId") if isinstance(fields, dict) else None
            scope = fields.get("scope") if isinstance(fields, dict) else None
            if (not isinstance(definition, str) or not DEFINITION.fullmatch(definition)
                    or not isinstance(scope, str) or not _SCOPE.fullmatch(scope) or _text(scope, "", 512) != scope):
                raise ApiError("invalid_role_assignment")
            name = _role_name(roles, tenant, definition, cache, errors)
            out.append(_permission("role", f"{name} · {scope}", "azure_scope", scope, {
                "evidence_source": "azure_role_assignment",
                "membership_resolution": "direct_member" if guid(fields.get("principalId")) == principal else "group_member",
                "condition_present": bool(fields.get("condition")), "inherited_policies": "evaluated",
                "deny_policies": "not_evaluated"}))
        token = _skip_token(payload.get("nextLink"), path)
        if not token:
            return out
        params = {"$filter": params["$filter"], "$skipToken": token}
    raise ApiError("permission_page_limit")


def _bounded(out):
    """At most 250 permissions a record: every UNKNOWN entry stays, and a cut list says it was cut."""
    if len(out) <= 250:
        return out
    unknown = [item for item in out if item.effect == "UNKNOWN"]
    granted = [item for item in out if item.effect != "UNKNOWN"][:249 - len(unknown)]
    return granted + unknown + [_unknown("app_access", "permissions_truncated")]


def evaluate(graph, roles, origin, tenant, principal, cache, kinds, halted):
    """``(permissions, errors)`` of one service principal: each kind read in full, or one UNKNOWN entry for it. A kind
    in ``halted`` is not asked again; a failure that would repeat for every principal is added there."""
    out, errors = [], {}
    reads = {"app_role_assignment": lambda: _application_permissions(graph, origin, principal, cache),
             "directory_role_assignment": lambda: _entra_roles(graph, origin, principal, cache),
             "azure_role_assignment": lambda: _azure_roles(roles, tenant, principal, cache, errors)}
    for kind in kinds:
        if kind in halted:
            out.append(_unknown(kind, halted[kind]))
            continue
        try:
            out += reads[kind]()
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            errors[exc.code] = errors.get(exc.code, 0) + 1
            out.append(_unknown(kind, exc.code))
            if exc.code in (_REPEATS_AZURE if kind == "azure_role_assignment" else _REPEATS):
                halted[kind] = exc.code
    return _bounded(out), errors


def _targets(spec, previous):
    """Service principals with listed sign-in credentials, each with the credentials that sign in as it: its own and
    its application's (joined by application ID). A token-signing key (use Sign) is not a sign-in credential; a
    credential whose application has no listed service principal is counted, never guessed."""
    from .adapter import validate_record

    principals, latest = {}, {}
    for body in previous:
        identity, operation = body.get("identity") or {}, (body.get("provenance") or {}).get("operation")
        if body.get("record_type") != "entity_observation":
            continue
        if identity.get("kind") == "principal" and operation == "azure.entra.service_principals":
            values = unpack_facts(body["facts"])
            if guid(values.get("id")) and guid(values.get("application_id")):
                principals[guid(values["application_id"])] = guid(values["id"])
        elif identity.get("kind") in {"credential", "public_key"} and operation in {
                "azure.entra.applications", "azure.entra.service_principals"}:
            latest[identity.get("object_id")] = body
    targets, orphaned = {}, 0
    for object_id, body in latest.items():
        item = EntityObservation.model_validate(body)
        if not validate_record(spec, item):
            raise ValueError("AZURE_ENTRA_RECORD_REPLAY_REJECTED")
        values = unpack_facts(body["facts"])
        if values.get("use") == "Sign":
            continue
        family, parent = object_id.split(":")[:2]
        principal = parent if family == "service_principal" else principals.get(guid(values.get("application_id")))
        if principal:
            targets.setdefault(principal, []).append(item)
        else:
            orphaned += 1
    return sorted(targets.items()), orphaned


def collect_access(spec, state, transport, roles, previous, spent, check):
    """One page per service principal: its credentials again, now carrying what it holds. The phase ends COMPLETE
    whatever it could read: a failure is on each credential (UNKNOWN) and counted in the report's facts, and the
    credential inventory's own status stays what its listings made it."""
    from .adapter import _page

    kinds = kinds_of(spec)
    targets, orphaned = _targets(spec, previous)
    cursor = state["cursor"]
    index, saved = cursor.get("index", 0), cursor.get("saved", 0)
    errors, halted = dict(cursor.get("errors", {})), dict(cursor.get("halted", {}))
    limit = min(spec.options.max_targets, spec.max_pages)
    asked = targets[:limit]
    if index > len(asked):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    cache = {}
    while True:
        check()
        committed = deepcopy(state)
        records = []
        if index < len(asked):
            principal, items = asked[index]
            granted, troubles = evaluate(transport, roles, spec.origin, spec.tenant, principal, cache, kinds, halted)
            for code, count in troubles.items():
                errors[code] = errors.get(code, 0) + count
            for item in items:
                copy = item.model_copy(deep=True)
                copy.provenance = provenance("app_access", item.provenance.resource_id)
                copy.permissions = granted
                records.append(copy)
            index += 1
            saved += len(records)
            state["requests"] = spent + transport.requests
        finished = index >= len(asked)
        if finished:
            listed = "listed" if state["status"] == "COMPLETE" else "listed partially"
            selection = (f"{', '.join(kinds)} for {index} of {len(targets)} service principals with sign-in credentials"
                         f" (limit {limit}); {orphaned} credentials without a {listed} service principal")
            if halted:
                selection += "; not asked again after " + ", ".join(f"{kind} {code}" for kind, code in sorted(halted.items()))
            records.append(report(spec, "app_access", status="COMPLETE", pages=index, received=len(targets), saved=saved,
                                  facts={"selection": selection, "error_counts": [
                                      {"code": code, "count": count} for code, count in sorted(errors.items())] or None}))
            state["phase"] += 1
            state["cursor"] = {}
        else:
            state["cursor"] = {"index": index, "saved": saved, "errors": errors, "halted": halted}
        yield _page(spec, state, records, committed)
        if finished:
            return
