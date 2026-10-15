"""What an app credential can do, from synthetic Graph and ARM answers; no tenant login or credential use."""

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cremore.coverage.coverage_test import repo as repo  # noqa: PLC0414
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.providers.facts import unpack_facts
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414
from cremore_azure_provider.entra import adapter
from cremore_azure_provider.entra.entra_test import (
    APP,
    CLIENT,
    KEY,
    TENANT,
    Graph,
    application,
    collect,
    records,
    spec,
)
from cremore_azure_provider.entra.permissions import DEFINITION, RoleTransport, root
from cremore_azure_provider.entra.transport import GraphTransport
from cremore_azure_provider.metadata.transport import ApiError, Budget
from cremore_azure_provider.public_certificates import certificate_evidence

SP = "50000000-0000-0000-0000-000000000001"
APP2, CLIENT2, SP2 = ("20000000-0000-0000-0000-000000000002", "30000000-0000-0000-0000-000000000002",
                      "50000000-0000-0000-0000-000000000002")
GRAPH_SP = "60000000-0000-0000-0000-000000000001"
ROLE = "70000000-0000-0000-0000-000000000001"
GROUP = "80000000-0000-0000-0000-000000000001"
SUB = "90000000-0000-0000-0000-000000000001"
SIGNING = "40000000-0000-0000-0000-000000000009"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
OWNER_ID, READER_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "acdd72a7-3385-48ef-bd42-f606fba81ae7"
OWNER = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{OWNER_ID}"
READER = f"/providers/Microsoft.Authorization/roleDefinitions/{READER_ID}"
ASSIGNMENTS = root(TENANT) + "/roleAssignments"
SOURCES = ["applications", "service_principals", "app_permissions", "app_azure_roles"]


def configured(sources=SOURCES, **changes):
    return spec(**{"capabilities": ["inventory", "policy", "public_keys"], "options": {"sources": sources}, **changes})


def principal(identifier=SP, client=CLIENT, **fields):
    return {"id": identifier, "appId": client, "displayName": "Billing", "passwordCredentials": [], "keyCredentials": [],
            **fields}


def answers(**changes):
    return {
        "/v1.0/applications": {"value": [application()]},
        "/v1.0/servicePrincipals": {"value": [principal()]},
        f"/v1.0/servicePrincipals/{SP}/appRoleAssignments": {"value": [
            {"appRoleId": ROLE, "resourceId": GRAPH_SP},
            {"appRoleId": "00000000-0000-0000-0000-000000000000", "resourceId": GRAPH_SP}]},
        f"/v1.0/servicePrincipals/{GRAPH_SP}": {"id": GRAPH_SP, "displayName": "Microsoft Graph",
                                                "appRoles": [{"id": ROLE, "value": "Directory.ReadWrite.All"}]},
        "/v1.0/roleManagement/directory/roleAssignments": {"value": [
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/"}]},
        f"/v1.0/roleManagement/directory/roleDefinitions/{GLOBAL_ADMIN}": {"id": GLOBAL_ADMIN,
                                                                          "displayName": "Global Administrator"},
        ASSIGNMENTS: {"value": [
            {"properties": {"roleDefinitionId": OWNER, "principalId": SP, "scope": f"/subscriptions/{SUB}"}},
            {"properties": {"roleDefinitionId": READER, "principalId": GROUP, "scope": f"/subscriptions/{SUB}/resourceGroups/rg",
                            "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] "
                                         "StringEquals 'synthetic'"}}]},
        # Owner is read at the root management group; Reader, not answered there, where its assignment names it.
        root(TENANT) + f"/roleDefinitions/{OWNER_ID}": {"properties": {"roleName": "Owner"}},
        root(TENANT) + f"/roleDefinitions/{READER_ID}": ApiError("http_404"),
        READER: {"properties": {"roleName": "Reader"}},
        **changes}


def credentials(pages):
    """The latest observation of each listed credential, as the store keeps it."""
    latest = {}
    for row in records(pages):
        if row.record_type == "entity_observation" and row.identity.kind in {"credential", "public_key"}:
            latest[row.identity.object_id] = row
    return latest


def granted(row):
    return {item.name: (item.effect, unpack_facts([fact.model_dump() for fact in item.conditions]))
            for item in row.permissions}


def secret(pages, parent=APP):
    return credentials(pages)[f"application:{parent}:passwordCredentials:{KEY}"]


def operation_report(pages, name="app_access"):
    return next(row for row in records(pages) if row.record_type == "operation_report"
                and row.provenance.operation == "azure.entra." + name)


def report_facts(pages):
    return unpack_facts([fact.model_dump() for fact in operation_report(pages).facts])


def counts(fact):
    return {row["code"]: row["count"] for row in fact or []}


def test_each_app_credential_carries_its_service_principals_grants():
    graph = Graph(answers())
    pages = collect(configured(), graph)
    assert pages[-1].status == "COMPLETE"
    found = credentials(pages)
    assert len(found) == 2  # the app's secret and certificate, both signing in as SP
    for row in found.values():
        assert row.provenance.operation == "azure.entra.app_access"
        assert adapter.validate_record(configured(), row)
        result = granted(row)
        assert result["Microsoft Graph: Directory.ReadWrite.All"][0] == "ALLOW"
        assert result["Global Administrator"][1] == {"evidence_source": "directory_role_assignment",
                                                     "membership_resolution": "direct_member"}
        owner = result[f"Owner · /subscriptions/{SUB}"][1]
        assert owner["membership_resolution"] == "direct_member" and owner["condition_present"] is False
        reader = result[f"Reader · /subscriptions/{SUB}/resourceGroups/rg"][1]
        # Held through a group; the condition is recorded as present, its text is not stored.
        assert reader["membership_resolution"] == "group_member" and reader["condition_present"] is True
        assert reader["deny_policies"] == "not_evaluated"
        assert len(result) == 4  # default access carries no application permission
    assert "synthetic'" not in "".join(page.model_dump_json() for page in pages)
    assert operation_report(pages).status == "COMPLETE" and counts(report_facts(pages).get("error_counts")) == {}
    # Asked once per service principal; the API's app roles and each role definition once, at the root first.
    asked = [path for path, _params in graph.calls]
    assert asked.count(f"/v1.0/servicePrincipals/{GRAPH_SP}") == 1
    assert root(TENANT) + f"/roleDefinitions/{OWNER_ID}" in asked and OWNER not in asked and READER in asked
    assert (ASSIGNMENTS, {"$filter": f"assignedTo('{SP}')"}) in graph.calls


def save(store, connection, pages):
    owner, _ = store.create(connection, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(connection).model_dump())
    items = [item for page in pages for item in page.records]
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=items))
    return store.finish(owner["id"], run["id"], MetadataFinish(batch_count=1, item_count=len(items),
                                                               status=pages[-1].status, reasons=pages[-1].reasons))


def test_a_refused_read_is_unknown_on_the_credential_and_never_makes_the_stored_run_partial(repo):
    connection = configured()
    pages = collect(connection, Graph(answers(**{
        "/v1.0/roleManagement/directory/roleAssignments": ApiError("permission_denied"),
        ASSIGNMENTS: ApiError("permission_denied")})))
    result = granted(secret(pages))
    assert result["directory_role_assignment"] == ("UNKNOWN", {"evidence_source": "directory_role_assignment",
                                                               "error_code": "permission_denied"})
    assert result["azure_role_assignment"][1]["error_code"] == "permission_denied"
    assert result["Microsoft Graph: Directory.ReadWrite.All"][0] == "ALLOW"
    assert operation_report(pages).status == "COMPLETE"
    assert counts(report_facts(pages)["error_counts"]) == {"permission_denied": 2}
    run = save(MetadataStore(repo), connection, pages)
    assert (run["status"], run["reasons"]) == ("COMPLETE", [])


def test_azure_roles_alone_read_no_graph_permission():
    graph = Graph(answers())
    pages = collect(configured(["applications", "service_principals", "app_azure_roles"]), graph)
    asked = {path for path, _params in graph.calls}
    assert ASSIGNMENTS in asked
    assert not any(path.startswith("/v1.0/roleManagement") or path.endswith("/appRoleAssignments") for path in asked)
    assert set(granted(secret(pages))) == {f"Owner · /subscriptions/{SUB}", f"Reader · /subscriptions/{SUB}/resourceGroups/rg"}


def test_a_failure_that_would_repeat_for_every_principal_is_asked_once():
    two = answers(**{"/v1.0/applications": {"value": [application(), {**application(APP2), "appId": CLIENT2}]},
                     "/v1.0/servicePrincipals": {"value": [principal(), principal(SP2, CLIENT2)]},
                     ASSIGNMENTS: ApiError("http_404")})
    graph = Graph(two)
    pages = collect(configured(), graph)
    assert [path for path, _params in graph.calls].count(ASSIGNMENTS) == 1
    for parent in (APP, APP2):
        assert granted(secret(pages, parent))["azure_role_assignment"][1]["error_code"] == "http_404"
    assert "not asked again after azure_role_assignment http_404" in report_facts(pages)["selection"]
    assert counts(report_facts(pages)["error_counts"]) == {"http_404": 1}


def test_a_long_list_keeps_its_unknown_entries_and_says_it_was_cut():
    roles = [{"id": str(uuid.UUID(int=number + 1)), "value": f"Role{number}.Read.All"} for number in range(260)]
    pages = collect(configured(), Graph(answers(**{
        f"/v1.0/servicePrincipals/{SP}/appRoleAssignments": {"value": [{"appRoleId": role["id"], "resourceId": GRAPH_SP}
                                                                       for role in roles]},
        f"/v1.0/servicePrincipals/{GRAPH_SP}": {"id": GRAPH_SP, "displayName": "Microsoft Graph", "appRoles": roles},
        ASSIGNMENTS: ApiError("permission_denied")})))
    permissions = secret(pages).permissions
    assert len(permissions) == 250
    unknown = {(item.name, unpack_facts([fact.model_dump() for fact in item.conditions])["error_code"])
               for item in permissions if item.effect == "UNKNOWN"}
    assert unknown == {("azure_role_assignment", "permission_denied"), ("app_access", "permissions_truncated")}


def test_a_token_signing_key_is_not_a_sign_in_credential():
    signing = principal(keyCredentials=[{"keyId": SIGNING, "type": "AsymmetricX509Cert", "usage": "Sign"}])
    pages = collect(configured(), Graph(answers(**{"/v1.0/servicePrincipals": {"value": [signing]}})))
    key = credentials(pages)[f"service_principal:{SP}:keyCredentials:{SIGNING}"]
    assert key.provenance.operation == "azure.entra.service_principals" and key.permissions == []
    assert granted(secret(pages))  # the app's own secret still signs in as SP


def test_a_credential_without_a_listed_service_principal_is_counted_not_guessed():
    pages = collect(configured(), Graph(answers(**{"/v1.0/servicePrincipals": {"value": []}})))
    assert all(row.permissions == [] for row in credentials(pages).values())
    assert "2 credentials without a listed service principal" in report_facts(pages)["selection"]


def test_an_unreadable_or_malformed_role_definition_still_shows_the_grant_by_its_id():
    pages = collect(configured(), Graph(answers(**{root(TENANT) + f"/roleDefinitions/{OWNER_ID}": {"properties": "Owner"},
                                                   OWNER: ApiError("permission_denied")})))
    assert granted(secret(pages))[f"Azure role {OWNER_ID} · /subscriptions/{SUB}"][0] == "ALLOW"
    assert counts(report_facts(pages)["error_counts"]) == {"role_definition_permission_denied": 1}


def test_azure_role_pages_continue_only_within_the_listing():
    first = {"value": [], "nextLink": f"https://management.azure.com{ASSIGNMENTS}?api-version=2022-04-01&$skipToken=next"}
    graph = Graph(answers(**{ASSIGNMENTS: [first, answers()[ASSIGNMENTS]]}))
    collect(configured(), graph)
    assert [params for asked, params in graph.calls if asked == ASSIGNMENTS][1] == {
        "$filter": f"assignedTo('{SP}')", "$skipToken": "next"}
    moved = Graph(answers(**{ASSIGNMENTS: {"value": [], "nextLink": "https://attacker.test" + ASSIGNMENTS + "?$skipToken=next"}}))
    assert granted(secret(collect(configured(), moved)))["azure_role_assignment"][1]["error_code"] == "invalid_pagination"


def test_a_throttled_azure_read_waits_and_resumes_at_the_same_principal():
    first = collect(configured(), Graph(answers(**{ASSIGNMENTS: [ApiError("rate_limited", retry_after=5),
                                                                 answers()[ASSIGNMENTS]]})))
    assert first[-1].status == "WAITING"
    done = collect(configured(), Graph(answers()), checkpoint=first[-1].checkpoint,
                   read_records=lambda: [row.model_dump() for page in first for row in page.records])
    assert done[-1].status == "COMPLETE"
    assert f"Owner · /subscriptions/{SUB}" in granted(secret(done))


def test_a_certificate_keeps_its_permissions_and_its_public_certificate_evidence():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.invalid")])
    now = datetime.now(UTC)
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
           .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
           .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.DER)
    detail = {"id": APP, "appId": CLIENT, "keyCredentials": [
        {"keyId": KEY, "type": "AsymmetricX509Cert", "key": base64.b64encode(der).decode()}]}
    pages = collect(configured([*SOURCES, "public_certificates"]), Graph(answers(**{f"/v1.0/applications/{APP}": detail})))
    certificate = credentials(pages)[f"application:{APP}:keyCredentials:{KEY}"]
    assert certificate_evidence(certificate)["fingerprint"] == hashlib.sha256(der).hexdigest()
    assert "Global Administrator" in granted(certificate)


def test_without_the_options_nothing_is_asked():
    graph = Graph(answers())
    pages = collect(configured(["applications", "service_principals"]), graph)
    assert all(row.permissions == [] for row in credentials(pages).values())
    assert {path for path, _ in graph.calls} == {"/v1.0/organization", "/v1.0/applications", "/v1.0/servicePrincipals"}


@pytest.mark.parametrize("change", [
    {"options": {"sources": ["applications", "app_permissions"]}},
    {"capabilities": ["inventory", "public_keys"]},
    {"origin": "https://graph.microsoft.us"},
    {"options": {"sources": ["applications", "service_principals", "app_access"]}},
])
def test_the_options_need_service_principals_policy_and_for_azure_roles_the_public_cloud(change):
    adapter.validate_spec(configured())
    # Graph's answers exist in the national clouds; Azure Resource Manager is read in the public cloud only.
    adapter.validate_spec(configured(["applications", "service_principals", "app_permissions"],
                                     origin="https://graph.microsoft.us"))
    with pytest.raises(ValueError):
        adapter.validate_spec(configured(**change))


def test_a_run_from_before_the_phase_resumes_where_it_was():
    for old, new in ((1, 1), (2, 3), (3, 4), (6, 7)):
        state = adapter._initial(configured(), None)
        state.update(version=1, phase=old)
        assert adapter._initial(configured(), state)["phase"] == new


@pytest.mark.parametrize("cursor", [{"halted": {"azure_role_assignment": "Not A Code"}},
                                    {"halted": ["azure_role_assignment"]}, {"errors": {"x": -1}}])
def test_a_tampered_checkpoint_is_refused(cursor):
    state = adapter._initial(configured(), None)
    state["cursor"] = cursor
    with pytest.raises(ValueError, match="CHECKPOINT"):
        adapter._initial(configured(), state)


@pytest.mark.parametrize("path", [
    f"/providers/Microsoft.Management/managementGroups/../providers/Microsoft.Authorization/roleDefinitions/{OWNER_ID}",
    f"/providers/Microsoft.Management/managementGroups/./providers/Microsoft.Authorization/roleDefinitions/{OWNER_ID}",
    f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Authorization/roleDefinitions/{OWNER_ID}",
])
def test_a_role_definition_path_outside_the_approved_shapes_is_refused(path):
    assert not DEFINITION.fullmatch(path)
    with pytest.raises(ValueError):
        RoleTransport(None, lambda: "synthetic", tenant=TENANT, options=configured().options, charge=lambda: None,
                      pace=lambda: None, check=lambda: None).get(path)


def test_the_transports_read_only_their_paths_under_one_budget():
    options = configured().options
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"value": []}))) as client:
        graph = GraphTransport(client, lambda: "synthetic", origin="https://graph.microsoft.com", options=options,
                               max_requests=2, check=lambda: None)
        roles = RoleTransport(client, lambda: "synthetic", tenant=TENANT, options=options, charge=graph._charge,
                              pace=graph._pace, check=lambda: None)
        with pytest.raises(ValueError):
            roles.get(f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments")
        with pytest.raises(ValueError):
            graph.get(f"/v1.0/servicePrincipals/{GRAPH_SP}", {"$select": "id,appRoles,passwordCredentials"})
        roles.get(ASSIGNMENTS, {"$filter": f"assignedTo('{SP}')"})
        graph.get(f"/v1.0/servicePrincipals/{SP}/appRoleAssignments")
        with pytest.raises(Budget):
            roles.get(READER)
    assert graph.requests == 2


def test_the_collection_signs_in_to_each_service_with_its_own_token(monkeypatch):
    from cremore_azure_provider.arm import transport as arm

    monkeypatch.setattr(arm, "default_token", lambda scope, **kwargs: lambda: "arm-" + scope.split("//")[1].split(".")[0])
    seen = []

    def respond(request):
        seen.append((request.url.host, request.url.path, request.headers["authorization"]))
        if request.url.path.endswith("/organization"):
            return httpx.Response(200, json={"value": [{"id": TENANT}]})
        rows = {"/v1.0/applications": [application()], "/v1.0/servicePrincipals": [principal()]}
        return httpx.Response(200, json={"value": rows.get(request.url.path, [])})

    fast = configured(options={"sources": SOURCES, "requests_per_second": 100, "burst": 100})
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(adapter.collect_pages(fast, secrets={}, checkpoint=None, check=lambda: None, client=client,
                                           token=lambda: "graph-token"))
    assert pages[-1].status == "COMPLETE"
    tokens = {host: {auth for other, _path, auth in seen if other == host} for host, _path, _auth in seen}
    assert tokens == {"graph.microsoft.com": {"Bearer graph-token"}, "management.azure.com": {"Bearer arm-management"}}
    assert ("management.azure.com", ASSIGNMENTS) in {(host, path) for host, path, _auth in seen}
