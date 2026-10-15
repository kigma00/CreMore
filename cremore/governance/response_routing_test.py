"""Directory-bound responsibility and ticket dispatch; synthetic records/HTTP only."""
import datetime as dt
import json
import uuid

import pytest

from cremore.domain.models import Connection, Credential, Exposure
from cremore.governance import response
from cremore.governance import response_routing as routing
from cremore.governance.response_test import (
    plugin as plugin,  # noqa: PLC0414 -- the installed fake ticket adapter
)
from cremore.governance.response_test import (
    prepare,
)
from cremore.governance.response_test import (
    repo as repo,  # noqa: PLC0414 -- existing memory/SQLite fixtures
)
from cremore.governance.tickets_test import seed
from cremore.identity import people
from cremore.identity.keys import Digester
from cremore.identity.leavers import LeaverStore
from cremore.identity.people_directory_test import TEAM, mutate, records, save, setup
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.ticketing import setup as tickets


def directory(repo, email=None):
    store, spec, owner, parent = setup(repo, email=email)
    person = people.directory(repo, TEAM)["items"][0]
    return store, spec, owner, parent, person


def test_manual_assignment_is_stable_audited_and_never_overwritten_by_collection(repo):
    store, spec, owner, _, person = directory(repo)
    _, _, finding, _ = seed(repo=repo)
    result = routing.assign(repo, TEAM, finding.id, "analyst", person_ref=person["person_ref"],
                            team="Platform", expected_version=0)
    assert result["version"] == 1
    assert repo.get_finding(finding.id).assigned_to == person["person_ref"]
    with pytest.raises(response.ResponseError, match="RESPONSE_CHANGED"):
        routing.assign(repo, TEAM, finding.id, "other", person_ref=None, expected_version=0)
    save(store, spec, records(spec, email="changed@acme.test"), owner=owner)
    selected = routing.public(repo, TEAM, finding.id)
    assert selected["recommendations"][0]["person"]["email"] == "changed@acme.test"
    assert selected["recommendations"][0]["person"]["selectable"] is True
    assert selected["assignment"]["person_ref"] == person["person_ref"]
    shown = routing.owners(repo, TEAM, [finding.id], {})[str(finding.id)]
    assert shown["email"] == "changed@acme.test" and shown["department"] == "Platform"
    routing.assign(repo, TEAM, finding.id, "analyst", person_ref=None, expected_version=1)
    assert routing.public(repo, TEAM, finding.id)["assignment"] is None
    history = {str(finding.id): {"current": {"recipient": person, "team": "Platform"}}}
    assert routing.owners(repo, TEAM, [finding.id], history)[str(finding.id)] is None
    assert [e.event_type for e in repo.list_finding_events(finding.id)] == ["RESPONSE_ASSIGNED", "RESPONSE_UNASSIGNED"]


def test_responsibility_rule_reuses_location_only_within_its_connection(repo):
    *_, person = directory(repo)
    _, cred, finding, _ = seed(repo=repo)
    source = repo.create_connection(Connection(provider="github", name="Source", config={}))
    other = repo.create_connection(Connection(provider="github", name="Other", config={}))
    repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="org/repo",
                                 source_connection_id=source.id, location="a.txt"))
    target = routing.public(repo, TEAM, finding.id)["targets"][0]
    routing.save_rule(repo, TEAM, finding.id, "admin", **{k: target[k] for k in ("kind", "key")},
                      person_ref=person["person_ref"], team="App team", expected_version=0)
    result = routing.public(repo, TEAM, finding.id)
    assert result["status"] == "READY"
    assert result["recommendations"][0]["basis"] == "RESPONSIBILITY_RULE"
    assert result["recommendations"][0]["team"] == "App team"
    second = repo.upsert_credential(Credential(fingerprint="second", provider="github", credential_type="GITHUB_PAT"))
    exposure = repo.upsert_exposure(Exposure(credential_id=second.id, source_type="github", resource_name="org/repo",
                                             source_connection_id=other.id, location="a.txt"))
    other_finding = repo.upsert_finding(second.id, exposure.id, "HIGH")
    assert routing.public(repo, TEAM, other_finding.id)["recommendations"] == []
    with pytest.raises(response.ResponseError, match="RESPONSE_RULE_TARGET_INVALID"):
        routing.save_rule(repo, TEAM, other_finding.id, "admin", kind="location", key=target["key"],
                          person_ref=person["person_ref"], team=None, expected_version=1)


def test_a_rule_names_only_an_approved_team_channel_and_the_recommendation_carries_it(repo):
    from cremore.governance import response_channels

    *_, person = directory(repo)
    _, cred, finding, _ = seed(repo=repo)
    source = repo.create_connection(Connection(provider="github", name="Source", config={}))
    repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="org/repo",
                                 source_connection_id=source.id, location="a.txt"))
    target = routing.public(repo, TEAM, finding.id)["targets"][0]
    rule = {k: target[k] for k in ("kind", "key")}
    with pytest.raises(response.ResponseError) as refused:
        routing.save_rule(repo, TEAM, finding.id, "admin", **rule, person_ref=person["person_ref"], team="App team",
                          expected_version=0, channel_id="C0TEAM0001")
    assert (refused.value.code, refused.value.http_status) == ("RESPONSE_CHANNEL_NOT_APPROVED", 422)
    approved = {"channel_id": "C0TEAM0001", "name": "team-app", "is_private": True, "allow_public": False,
                "checked_at": "2026-09-30T03:00:00+00:00"}
    repo.put_setting(response_channels.KEY, {"version": 1, "channels": [approved]}, "admin")
    saved = routing.save_rule(repo, TEAM, finding.id, "admin", **rule, person_ref=person["person_ref"], team="App team",
                              expected_version=0, channel_id="C0TEAM0001")
    assert saved["channel_id"] == "C0TEAM0001"
    result = routing.public(repo, TEAM, finding.id)
    shown = {"channel_id": "C0TEAM0001", "name": "team-app", "is_private": True}
    assert result["recommendations"][0]["slack_channel"] == shown and result["slack_channel"] == shown
    assert repo.list_finding_events(finding.id)[-1].note.endswith("team=App team channel=C0TEAM0001")
    repo.put_setting(response_channels.KEY, {"version": 2, "channels": []}, "admin")  # the Admin withdrew it
    result = routing.public(repo, TEAM, finding.id)
    assert result["recommendations"][0]["slack_channel"] is None and result["slack_channel"] is None



def test_exact_owner_evidence_and_admin_confirmation_never_name_guess_or_old_match(repo, monkeypatch):
    *_, person = directory(repo)
    _, _, finding, _ = seed(repo=repo)
    digester = Digester(b"k" * 32)
    account = {"ref": "aws|aws|123456789012:person", "label": "person", "provider": "aws",
               "keys": {("PROVIDER_LOGIN", digester(person["email"]))}}
    monkeypatch.setattr(routing, "_accounts", lambda *args: ({account["ref"]: account}, digester))
    assert routing.public(repo, TEAM, finding.id)["recommendations"] == []
    state = LeaverStore(repo)
    link = {"account_ref": account["ref"], "person_ref": uuid.UUID(person["person_ref"]), "decision": "MATCHED",
            "basis": "VERIFIED_EMAIL", "actor_ref": None, "decided_at": dt.datetime.now(dt.UTC)}
    state.save(links=[link])
    assert routing.public(repo, TEAM, finding.id)["recommendations"] == []
    state.save(links=[{**link, "decision": "CONFIRMED", "actor_ref": "admin"}])
    assert routing.public(repo, TEAM, finding.id)["recommendations"][0]["basis"] == "ADMIN_CONFIRMED"
    state.save(links=[{**link, "decision": "REJECTED", "actor_ref": "admin"}])
    account["keys"] = {("VERIFIED_EMAIL", digester(person["email"]))}
    assert routing.public(repo, TEAM, finding.id)["recommendations"] == []
    state.save(removed_links=[(account["ref"], uuid.UUID(person["person_ref"]))])
    result = routing.public(repo, TEAM, finding.id)
    assert result["recommendations"][0]["basis"] == "VERIFIED_EMAIL"
    assert digester(person["email"]) not in json.dumps(result)


def test_a_github_directory_value_recommends_only_the_idp_values_it_can_be(repo, monkeypatch):
    """A SCIM user name is a login or an email at the IdP, never its internal user id; a SAML NameID may be either."""
    directory(repo)
    _, _, finding, _ = seed(repo=repo)
    digester = Digester(b"k" * 32)
    account = {"ref": "github|https://github.com|octocat", "label": "octocat", "provider": "github", "keys": set()}
    monkeypatch.setattr(routing, "_accounts", lambda *args: ({account["ref"]: account}, digester))
    for basis, recommended in (("SCIM_EXTERNAL_ID", []), ("VERIFIED_EMAIL", []), ("SAML_NAME_ID", ["SAML_NAME_ID"])):
        account["keys"] = {(basis, digester("00uperson00000"))}  # the person's IdP user id
        assert [row["basis"] for row in routing.public(repo, TEAM, finding.id)["recommendations"]] == recommended


def test_dispatch_uses_directory_address_snapshot_and_survives_idempotent_retry_after_departure(repo):
    store, spec, owner, _, person = directory(repo, email="kim@example.com")
    finding, server = prepare(repo)
    settings = SETTINGS.model_copy(update={"auth_mode": "oidc", "oidc_issuer_url": TEAM.oidc_issuer_url})
    request_id = uuid.uuid4()
    with server.client() as client:
        sent = response.request_ticket(repo, settings, finding.id, "analyst", person_ref=person["person_ref"],
            team="Platform", expected_version=0, request_id=request_id, http_client=client)
    cycle = sent["current"]
    assert cycle["recipient"]["person_ref"] == person["person_ref"] and cycle["assigned_to"] == "kim@example.com"
    assert cycle["ticket"]["approver"] == "42" and cycle["mapping_checked_at"]
    assert "keys" not in cycle["recipient"]
    save(store, spec, records(spec, state="DISABLED", email="kim@example.com"), owner=owner)
    server.seen.clear()
    with server.client() as client:
        assert response.request_ticket(repo, settings, finding.id, "analyst", person_ref=person["person_ref"],
            team="Platform", expected_version=0, request_id=request_id, http_client=client) == sent
        assert server.seen == []
        with pytest.raises(response.ResponseError, match="PERSON_INACTIVE"):
            response.request_ticket(repo, settings, finding.id, "analyst", person_ref=person["person_ref"],
                expected_version=sent["version"], request_id=uuid.uuid4(), http_client=client)
        with pytest.raises(response.ResponseError, match="RESPONSE_REQUEST_REUSED"):
            response.request_ticket(repo, settings, finding.id, "analyst", person_ref=uuid.uuid4(),
                team="Platform", expected_version=0, request_id=request_id, http_client=client)


def test_dispatch_refuses_email_forgery_and_directory_changes_during_adapter_lookup(repo, monkeypatch):
    store, _, owner, _, person = directory(repo, email="kim@example.com")
    finding, _server = prepare(repo)
    settings = SETTINGS.model_copy(update={"auth_mode": "oidc", "oidc_issuer_url": TEAM.oidc_issuer_url})
    sent = []
    class System:
        def find_approver(self, address):
            from cremore.ticketing.contract import Approver
            mutate(store, "connections", owner["id"], enabled=False)
            return Approver("42", (address,))

        def open_approval(self, *args):
            sent.append(args)

        def close(self):
            pass
    monkeypatch.setattr(tickets, "open_system", lambda *a: (System(), "fake", tickets.binding(repo)))
    with pytest.raises(response.ResponseError, match="RESPONSE_PERSON_REQUIRED"):
        response.request_ticket(repo, settings, finding.id, "analyst", to="kim@example.com",
            expected_version=0, request_id=uuid.uuid4(), http_client=None)
    with pytest.raises(response.ResponseError, match="RESPONSE_RECIPIENT_MISMATCH"):
        response.request_ticket(repo, settings, finding.id, "analyst", person_ref=person["person_ref"], to="other@example.com",
            expected_version=0, request_id=uuid.uuid4(), http_client=None)
    with pytest.raises(response.ResponseError, match="PERSON_NOT_AVAILABLE"):
        response.request_ticket(repo, settings, finding.id, "analyst", person_ref=person["person_ref"],
            expected_version=0, request_id=uuid.uuid4(), http_client=None)
    assert sent == [] and response.public(repo, finding.id)["state"] == "NEW"


@pytest.mark.parametrize("team", ["Bearer synthetic", "line\nbreak", "x" * 101])
def test_team_cannot_store_secret_like_or_unbounded_text(repo, team):
    _, _, finding, _ = seed(repo=repo)
    with pytest.raises(response.ResponseError, match="RESPONSE_TEAM_INVALID"):
        routing.assign(repo, TEAM, finding.id, "analyst", person_ref=None, team=team, expected_version=0)
