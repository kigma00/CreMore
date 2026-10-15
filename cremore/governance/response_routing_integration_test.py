"""Actual passive issuer -> SAML bridge -> current IdP recommendation, without external services."""

import json
import uuid
from datetime import UTC, datetime

import httpx
from cremore_github_provider.identity import adapter as github_identity
from cremore_github_provider.metadata.tests import test_adapter

from cremore.coverage.metadata_linkage_test import TOKEN, issuer
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable localhost database
from cremore.detection import ResourceRef
from cremore.detection.engine import Engine, EngineConfig
from cremore.governance import response_routing as routing
from cremore.identity import people
from cremore.identity.keys import Digester
from cremore.identity.leavers import LeaverStore, account_ref
from cremore.identity.leavers_test import github_identity_spec
from cremore.identity.people_directory_test import (
    TEAM,
    save,
    setup,
)
from cremore.identity.people_directory_test import (
    repo as repo,  # noqa: PLC0414 -- memory, SQLite and isolated PostgreSQL
)
from cremore.scanning.orchestrator import Orchestrator

KEY = b"k" * 32


def test_exact_issuer_and_current_saml_bridge_recommend_the_same_login_idp_person(repo, monkeypatch):
    setup(repo)
    person = people.directory(repo, TEAM)["items"][0]
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orchestrator = Orchestrator(repo, engine=engine, config=engine.config)
    orchestrator.scan_resource(TOKEN, ResourceRef(source_type="gitlab", resource="team/repo", location="config.env"), verify=False)
    finding = repo.list_findings()[0]
    store = MetadataStore(repo)
    monkeypatch.setattr(test_adapter, "NOW", datetime.now(UTC))
    issuer(store, engine, key=KEY)
    def directory_response(request):
        assert request.url.host == "api.github.com"
        return httpx.Response(200, json={"data": {"organization": {"samlIdentityProvider": {"externalIdentities": {
            "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{
                "samlIdentity": {"nameId": person["email"], "username": None, "emails": []},
                "scimIdentity": None, "user": {"login": "octocat"}}]}}}}})
    spec, records = github_identity_spec(), []
    with httpx.Client(transport=httpx.MockTransport(directory_response)) as client:
        for page in github_identity.collect_pages(spec, secrets={"token": "ghp_" + "a" * 36}, checkpoint={},
                check=lambda: None, identity_digest=Digester(KEY), client=client, sleep=lambda _seconds: None):
            records.extend(page.records)
    connection = save(store, spec, records)
    found = routing.public(repo, TEAM, finding.id, orchestrator=orchestrator)
    assert found["status"] == "READY"
    assert [(row["person"]["person_ref"], row["basis"]) for row in found["recommendations"]] == [(person["person_ref"], "SAML_NAME_ID")]
    assert TOKEN.decode() not in json.dumps(found) and "digest" not in json.dumps(found)
    # A GitHub identity source is a SAML bridge, never a selectable person directory.
    directory = people.directory(repo, TEAM)
    assert directory["total"] == 1 and {row["provider"] for row in directory["directory"]["sources"]} == {"okta"}
    ref = account_ref("github", "https://github.com", "octocat")
    link = {"account_ref": ref, "person_ref": uuid.UUID(person["person_ref"]), "decision": "MATCHED",
            "basis": "SAML_NAME_ID", "actor_ref": None, "decided_at": datetime.now(UTC)}
    LeaverStore(repo).save(links=[link])
    save(store, spec, records, owner=connection, status="PARTIAL")
    stale = routing.public(repo, TEAM, finding.id, orchestrator=orchestrator)
    assert stale["status"] == "UNASSIGNED" and stale["recommendations"] == []
    # Only an explicit administrator confirmation can survive a stale automated bridge.
    LeaverStore(repo).save(links=[{**link, "decision": "CONFIRMED", "basis": "OPERATOR_CONFIRMED", "actor_ref": "admin"}])
    confirmed = routing.public(repo, TEAM, finding.id, orchestrator=orchestrator)
    assert confirmed["status"] == "READY" and confirmed["recommendations"][0]["basis"] == "ADMIN_CONFIRMED"


def test_missing_match_key_and_bounded_directory_failure_are_recommendation_states(repo, monkeypatch):
    setup(repo)
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orchestrator = Orchestrator(repo, engine=engine, config=engine.config)
    orchestrator.scan_resource(TOKEN, ResourceRef(source_type="gitlab", resource="team/repo", location="config.env"), verify=False)
    finding = repo.list_findings()[0]
    no_key = TEAM.model_copy(update={"fingerprint_key": ""})
    status = routing.public(repo, no_key, finding.id)
    assert status["status"] == "UNAVAILABLE" and status["reasons"] == ["DIRECTORY_IDENTITY_KEY_UNAVAILABLE"]
    person = people.directory(repo, TEAM)["items"][0]
    routing.assign(repo, no_key, finding.id, "analyst", person_ref=person["person_ref"], expected_version=0)
    assert routing.public(repo, no_key, finding.id)["status"] == "READY"
    routing.assign(repo, no_key, finding.id, "analyst", person_ref=None, expected_version=1)
    monkeypatch.setattr(routing, "_accounts", lambda *args, **kwargs: ({"account": {}}, Digester(KEY)))
    monkeypatch.setattr(routing, "_targets", lambda *args: {})
    def limited(*args):
        raise people.DirectoryError("DIRECTORY_MATCH_LIMIT")
    monkeypatch.setattr(routing, "_recommend", limited)
    found = routing.public(repo, TEAM, finding.id)
    assert found["status"] == "UNAVAILABLE" and found["reasons"] == ["DIRECTORY_MATCH_LIMIT"]
    routing.assign(repo, TEAM, finding.id, "analyst", person_ref=person["person_ref"], expected_version=2)
    assert routing.public(repo, TEAM, finding.id)["status"] == "READY"
