"""CreMore's GitHub App on the other organizations of an enterprise, against a synthetic GitHub: what is left to do
in GitHub, organizations queued by an admin (or cancelled), auto-install for organizations that appear later, each
one installed and connected by one worker at a time and activated with the source's plans once its check grants
everything, the App key's copies kept current, and a failing source that neither stops the others nor retries
every minute."""

import datetime as dt
import json
import time
import uuid

import httpx
import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import github_enterprise, service
from cremore.onboarding.onboarding_test import PEM, SETTINGS
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver

RESOLVER = SecretResolver(sealing_key=SETTINGS.sealing_keys)
NOW = dt.datetime(2026, 9, 29, 3, 0, tzinfo=dt.UTC)
MINUTE = dt.timedelta(minutes=1)
# Built at run time: nothing token-shaped sits in the source.
TOKEN = "ghs_" + "n" * 36


class GitHub:
    def __init__(self, *, owner_type="Enterprise", on_enterprise=True, orgs=("acme", "acme-labs", "acme-data"), refuse=None):
        self.owner_type, self.on_enterprise, self.orgs = owner_type, on_enterprise, list(orgs)
        self.refuse, self.installed, self.posted, self.revoked, self.minted = refuse or {}, {"acme": 678}, [], 0, 0

    def __call__(self, request):
        path = request.url.path
        if path in self.refuse:
            return httpx.Response(self.refuse[path], json={"message": "synthetic"})
        if path == "/app":
            return httpx.Response(200, json={"id": 12345, "client_id": "Iv23liCREMORE", "slug": "cremore-acme", "name": "CreMore acme",
                                             "owner": {"slug": "acme-corp", "type": self.owner_type}, "permissions": {}})
        if path == "/app/installations":
            rows = [{"id": 99, "target_type": "Enterprise", "account": {"slug": "acme-corp"}}] if self.on_enterprise else []
            rows += [{"id": n, "target_type": "Organization", "account": {"login": login}} for login, n in self.installed.items()]
            return httpx.Response(200, json=rows)
        if path == "/app/installations/99/access_tokens":
            self.minted += 1
            return httpx.Response(201, json={"token": TOKEN, "expires_at": "2099-01-01T00:00:00Z", "permissions": {}})
        assert request.headers["authorization"] == "Bearer " + TOKEN
        if path == "/installation/token" and request.method == "DELETE":
            self.revoked += 1
            return httpx.Response(204)
        if path == "/enterprises/acme-corp/apps/installable_organizations":
            return httpx.Response(200, json=[{"id": n, "login": login} for n, login in enumerate(self.orgs, 1)])
        org = path.split("/")[5]
        assert request.method == "POST" and json.loads(request.content)["client_id"] == "Iv23liCREMORE"
        self.posted.append(org)
        self.installed[org] = 700 + len(self.installed)
        return httpx.Response(201, json={"id": self.installed[org]})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def source(repo, **target):
    """The connection the admin made for the first organization, active with plans."""
    view = service.create(repo, SETTINGS, {
        "provider": "github", "edition": "enterprise_cloud", "purposes": ["exposure", "inventory"], "auth_method": "github_app",
        "target": {"organization": "acme", "enterprise": "acme-corp", **target},
        "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    checked(repo, view["id"])
    service.activate(repo, SETTINGS, view["id"], {"purposes": {"exposure": {}, "inventory": {"schedule_minutes": 60}}}, "admin")
    return view["id"]


def checked(repo, connection_id, granted=True):
    """What the worker's permission check leaves behind."""
    from cremore.onboarding.fixtures_test import grant_access

    record = ProviderConnectionStore(repo).get(connection_id)
    plans = record["checks"].get("requested_plans") or {"exposure": {}, "inventory": {"schedule_minutes": 60}}
    plans = {p: plan for p, plan in plans.items() if p in record["purposes"]}
    grant_access(repo, connection_id, plans, status="GRANTED" if granted else "MISSING")


def state(repo, connection_id):
    return repo.get_setting(github_enterprise.PREFIX + str(connection_id))["value"]


def results(repo, connection_id):
    return state(repo, connection_id)["results"]


def audited(repo, prefix="GITHUB_ENTERPRISE"):
    return [(event.event_type, event.actor, event.note) for event in repo.finding_events.values() if event.event_type.startswith(prefix)]


def test_what_is_left_to_do_in_github_is_named_step_by_step():
    repo = InMemoryRepository()
    connection_id = source(repo)
    for github, step in ((GitHub(owner_type="Organization"), "TRANSFER_REQUIRED"),
                         (GitHub(on_enterprise=False), "ENTERPRISE_INSTALL_REQUIRED"),
                         (GitHub(refuse={"/enterprises/acme-corp/apps/installable_organizations": 403}), "GITHUB_ENTERPRISE_PERMISSION_REQUIRED")):
        assert github_enterprise.status(repo, SETTINGS, connection_id, github.client)["state"] == step
    github = GitHub()
    ready = github_enterprise.status(repo, SETTINGS, connection_id, github.client)
    assert ready["state"] == "READY" and ready["app"] == {"slug": "cremore-acme", "owner": "acme-corp", "owner_type": "Enterprise"}
    rows = {row["organization"]: row for row in ready["organizations"]}
    assert rows["acme"]["installed"] and rows["acme"]["connection"]["id"] == str(connection_id)
    assert not rows["acme-labs"]["installed"] and rows["acme-labs"]["connection"] is None
    assert (github.minted, github.revoked) == (1, 1)  # the enterprise token ends with the look


def test_queued_organizations_are_installed_connected_and_activated_with_the_source_plans():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    answer = github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs", "ACME-DATA", "acme"], "admin-1")
    assert answer == {"requested": ["acme-labs", "acme-data", "acme"], "unchanged": []}
    assert github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW) == 3
    assert github.posted == ["acme-labs", "acme-data"]  # acme already had the App and a connection
    assert github.revoked == github.minted == 1
    done = results(repo, connection_id)
    assert done["acme"]["state"] == "CONNECTED" and done["acme"]["connection_id"] == str(connection_id)
    labs = service.get(repo, done["acme-labs"]["connection_id"])
    assert done["acme-labs"]["state"] == "CHECKING" and labs["status"] == "CHECKING"
    # The organization's own installation, the same App and key; the enterprise-wide inventory stays with the source.
    assert labs["target"] == {"organization": "acme-labs"} and labs["purposes"] == ["exposure", "inventory"]
    envelope = RESOLVER.resolve(labs["secret_refs"]["credential"])
    assert envelope["GITHUB_APP_ID"] == "12345" and envelope["GITHUB_APP_INSTALLATION_ID"] == str(github.installed["acme-labs"])
    assert set(state(repo, connection_id)["made"]) == {"acme-labs", "acme-data"}
    # Asking again for organizations under way changes nothing.
    assert github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin-2")["requested"] == []
    # Its check grants everything: the next tick activates it with the source's plans.
    checked(repo, labs["id"])
    checked(repo, done["acme-data"]["connection_id"], granted=False)
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    done = results(repo, connection_id)
    assert done["acme-labs"]["state"] == "ACTIVE"
    assert service.get(repo, labs["id"])["plans"] == {"exposure": {}, "inventory": {
        "schedule_minutes": 60, "audit_schedule_minutes": 60, "token_digests": False, "audit_events": False, "audit_days": 30}}
    assert (done["acme-data"]["state"], done["acme-data"]["code"]) == ("NEEDS_REVIEW", "PERMISSIONS_NOT_GRANTED")
    events = audited(repo)
    assert ("GITHUB_ENTERPRISE_INSTALL_REQUESTED", "admin-1", "acme-labs,acme-data,acme") in events
    # The worker acts as itself and names who asked.
    assert ("GITHUB_ENTERPRISE_ORG_INSTALLED", github_enterprise.ACTOR, "acme-labs requested by admin-1") in events
    assert service.get(repo, labs["id"])["created_by"] == github_enterprise.ACTOR


@pytest.mark.parametrize("permission, expected", [
    ("org_audit_read", "ACTIVE"), ("administration", "NEEDS_REVIEW"),
])
def test_activation_requires_only_permissions_for_the_selected_plan(monkeypatch, permission, expected):
    from cremore.onboarding import catalog, check
    from cremore.onboarding import permissions as access

    class Clock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(dt, "datetime", Clock)
    monkeypatch.setattr(access, "datetime", Clock)
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    child_id = results(repo, connection_id)["acme-labs"]["connection_id"]
    checked(repo, child_id)
    store = ProviderConnectionStore(repo)
    child = store.get(child_id)
    checks = child["checks"]
    declared = catalog.permissions_for("github", "inventory", "github_app", child["target"])
    items = check.clean([item for item in checks["results"]["inventory"]["items"]
                         if item["permission"] != permission], declared)
    assert next(item["status"] for item in items if item["permission"] == permission) == "NOT_REPORTED"
    checks["results"]["inventory"] = {"status": check.summary(items), "items": items}
    store.update(child_id, child["revision"], "fake-worker", checks=checks)
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    assert results(repo, connection_id)["acme-labs"]["state"] == expected
    assert service.get(repo, child_id)["status"] == ("ACTIVE" if expected == "ACTIVE" else "CHECKED")


@pytest.mark.parametrize("failure", [429, 500, 503, "timeout", "accepted_timeout"])
def test_transient_install_failure_pauses_and_retries_without_duplicate_connections(failure):
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    path = "/enterprises/acme-corp/apps/organizations/acme-labs/installations"
    attempts = []

    def handler(request):
        if request.url.path == path:
            attempts.append(request)
            if len(attempts) == 1:
                if failure == "accepted_timeout":
                    github(request)
                if isinstance(failure, str):
                    raise httpx.ReadTimeout("synthetic", request=request)
                return httpx.Response(failure, json={"message": "synthetic"})
        return github(request)

    def client():
        return httpx.Client(transport=httpx.MockTransport(handler))

    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    assert github_enterprise.sweep(repo, SETTINGS, client, now=NOW) == 0
    after = state(repo, connection_id)
    assert after["paused_code"] == "GITHUB_APP_UNAVAILABLE"
    assert after["paused_until"] == (NOW + github_enterprise.PAUSE).isoformat()
    assert after["results"]["acme-labs"]["state"] == "INSTALLING"
    github_enterprise.sweep(repo, SETTINGS, client, now=NOW + github_enterprise.PAUSE - MINUTE)
    assert len(attempts) == 1
    assert results(repo, connection_id)["acme-labs"]["state"] == "REQUESTED"
    assert github_enterprise.sweep(repo, SETTINGS, client, now=NOW + github_enterprise.PAUSE) == 1
    assert results(repo, connection_id)["acme-labs"]["state"] == "CHECKING"
    assert len(attempts) == (1 if failure == "accepted_timeout" else 2)
    assert len([c for c in ProviderConnectionStore(repo).list() if c["target"].get("organization") == "acme-labs"]) == 1
    assert not any(kind == "GITHUB_ENTERPRISE_ORG_INSTALL_FAILED" for kind, _actor, _note in audited(repo))
    assert github.minted == github.revoked


def test_one_worker_a_minute_and_one_claim_per_organization():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    assert github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW) == 1
    assert github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW) == 0  # a second worker in the same minute
    # A claim another worker holds is left alone; one it left behind past its lease goes back on the queue.
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-data"], "admin")
    assert github_enterprise._claim(repo, connection_id, "acme-data", NOW)[0] == "admin"  # (who asked, the claim)
    assert github_enterprise._claim(repo, connection_id, "acme-data", NOW) is None
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    assert github.posted == ["acme-labs"] and results(repo, connection_id)["acme-data"]["state"] == "INSTALLING"
    later = NOW + github_enterprise.LEASE + 2 * MINUTE
    github_enterprise.sweep(repo, SETTINGS, github.client, now=later)
    assert github.posted == ["acme-labs", "acme-data"] and results(repo, connection_id)["acme-data"]["state"] == "CHECKING"
    assert len([c for c in ProviderConnectionStore(repo).list() if c["target"].get("organization") == "acme-data"]) == 1


def test_a_refused_installation_is_its_own_code_audited_and_the_rest_go_on():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub(refuse={"/enterprises/acme-corp/apps/organizations/acme-labs/installations": 422})
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs", "acme-data"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    done = results(repo, connection_id)
    assert (done["acme-labs"]["state"], done["acme-labs"]["code"]) == ("FAILED", "GITHUB_ENTERPRISE_INSTALL_REFUSED")
    assert done["acme-data"]["state"] == "CHECKING"
    assert ("GITHUB_ENTERPRISE_ORG_INSTALL_FAILED", github_enterprise.ACTOR, "acme-labs GITHUB_ENTERPRISE_INSTALL_REFUSED") in audited(repo)


def test_only_organizations_the_enterprise_lists_are_connected():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github.installed["outsider"] = 777  # an installation elsewhere is not the enterprise's say-so
    github_enterprise.request(repo, SETTINGS, connection_id, ["outsider"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    assert (results(repo, connection_id)["outsider"]["state"], results(repo, connection_id)["outsider"]["code"]) == (
        "FAILED", "GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE")
    assert not [c for c in ProviderConnectionStore(repo).list() if c["target"].get("organization") == "outsider"]


def test_a_reused_organization_list_is_read_again_before_it_decides():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)  # the list is kept for ten minutes
    # A new organization joins, and one leaves the enterprise while the App stays installed there.
    github.orgs = ["acme", "acme-labs", "acme-new"]
    github.installed["acme-data"] = 790
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-new", "acme-data"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    done = results(repo, connection_id)
    assert done["acme-new"]["state"] == "CHECKING" and github.posted == ["acme-labs", "acme-new"]
    assert (done["acme-data"]["state"], done["acme-data"]["code"]) == ("FAILED", "GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE")
    assert not [c for c in ProviderConnectionStore(repo).list() if c["target"].get("organization") == "acme-data"]


def test_an_organization_that_left_with_the_app_still_installed_is_not_connected_from_a_reused_list():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)  # the list, with acme-data, is kept
    github.orgs.remove("acme-data")
    github.installed["acme-data"] = 790  # no install call asks GitHub about it
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-data"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    done = results(repo, connection_id)["acme-data"]
    assert (done["state"], done["code"]) == ("FAILED", "GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE")
    assert not [c for c in ProviderConnectionStore(repo).list() if c["target"].get("organization") == "acme-data"]


def test_failed_results_are_kept_a_month_and_a_thousand_and_what_goes_is_not_new_to_auto():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github_enterprise.set_auto(repo, SETTINGS, connection_id, True, "admin")
    recent, old = (NOW - MINUTE).isoformat(), (NOW - github_enterprise.FAILED_KEPT - MINUTE).isoformat()
    failed = {f"f-{n:04d}": {"state": "FAILED", "code": "X", "at": f"{recent[:-6]}.{n:04d}+00:00"} for n in range(1002)}
    kept = {"old-waiting": {"state": "REQUESTED", "by": "admin", "at": old},
            "old-review": {"state": "NEEDS_REVIEW", "code": "PERMISSIONS_NOT_GRANTED", "at": old}}
    github_enterprise._change(repo, connection_id, "admin", lambda s: {
        **s, "baseline": [], "requested": ["old-waiting"],
        "results": {**failed, **kept, "stale": {"state": "FAILED", "code": "X", "at": old}}})
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW, budget=-1)  # upkeep only
    after = state(repo, connection_id)
    gone = {"stale", "f-0000", "f-0001"}  # a month old; the two oldest beyond a thousand
    assert not gone & set(after["results"]) and len(after["results"]) == 1000 + len(kept)
    assert {"old-waiting", "old-review"} <= set(after["results"]) and after["requested"] == ["old-waiting"]
    assert gone <= set(after["baseline"])  # auto-install does not take them for new organizations


def test_an_organization_asked_for_again_while_old_failures_go_is_kept(monkeypatch):
    repo = InMemoryRepository()
    connection_id = source(repo)
    old = (NOW - github_enterprise.FAILED_KEPT - MINUTE).isoformat()
    github_enterprise._change(repo, connection_id, "admin", lambda s: {
        **s, "results": {"acme-labs": {"state": "FAILED", "code": "X", "at": old}}})
    real, looks = github_enterprise._old_failures, []

    def and_asked_again(state_, now):
        if not looks:  # the look before the lock: an admin asks for it again just then
            github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
        looks.append(now)
        return real(state_, now)

    monkeypatch.setattr(github_enterprise, "_old_failures", and_asked_again)
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW, budget=-1)
    after = state(repo, connection_id)
    assert after["results"]["acme-labs"]["state"] == "REQUESTED" and after["requested"] == ["acme-labs"]


def test_a_failed_list_read_leaves_the_organization_waiting():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW)  # the list is kept
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-new"], "admin")  # not in it: read again first
    failing = GitHub(refuse={"/enterprises/acme-corp/apps/installable_organizations": 500})
    github_enterprise.sweep(repo, SETTINGS, failing.client, now=NOW + MINUTE)
    after = state(repo, connection_id)
    assert after["results"]["acme-new"]["state"] == "REQUESTED" and after["requested"] == ["acme-new"]
    assert after["paused_code"] == "GITHUB_APP_UNAVAILABLE"


def test_a_stalled_worker_leaves_what_was_put_back_on_the_queue(monkeypatch):
    repo = InMemoryRepository()
    connection_id = source(repo)
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")

    def stalled(*_args, **_kwargs):
        # Past its lease, another worker's upkeep puts the organization back on the queue.
        github_enterprise._settle(repo, SETTINGS, str(connection_id), NOW + github_enterprise.LEASE + MINUTE)
        return {"state": "FAILED", "code": "GITHUB_ENTERPRISE_INSTALL_REFUSED"}, None

    monkeypatch.setattr(github_enterprise, "_install_one", stalled)
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW)
    after = state(repo, connection_id)
    assert after["results"]["acme-labs"]["state"] == "REQUESTED" and after["requested"] == ["acme-labs"]


def test_auto_installs_only_organizations_that_appear_after_it_is_turned_on():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub(orgs=["acme", "acme-labs", "acme-data", "acme-old"])
    github_enterprise.cancel(repo, SETTINGS, connection_id, ["acme-data"], "admin")  # an admin left this one out
    github_enterprise.set_auto(repo, SETTINGS, connection_id, True, "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    assert github.posted == [] and state(repo, connection_id)["requested"] == []  # the organizations as they were
    github.orgs += ["acme-new", "acme-newer"]
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + 5 * MINUTE)
    assert github.posted == []  # the same hour: not looked at again
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + dt.timedelta(hours=1))
    assert github.posted == ["acme-new", "acme-newer"]
    assert results(repo, connection_id)["acme-new"]["by"] == github_enterprise.ACTOR
    assert ("GITHUB_ENTERPRISE_AUTO_QUEUED", github_enterprise.ACTOR, "acme-new,acme-newer") in audited(repo)
    # Turning it off drops what it queued and has not started; what an admin asked for stays.
    github.orgs += [f"acme-n{n}" for n in range(6)]
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + dt.timedelta(hours=2))
    [left] = state(repo, connection_id)["requested"]  # five a tick: one still waits
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-old"], "admin")
    github_enterprise.set_auto(repo, SETTINGS, connection_id, False, "admin")
    after = state(repo, connection_id)
    assert after["requested"] == ["acme-old"] and left not in after["results"] and after["auto"] is False


def test_cancelling_takes_an_organization_off_the_queue():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs", "acme-data"], "admin")
    assert github_enterprise.cancel(repo, SETTINGS, connection_id, ["acme-labs"], "admin-2") == {"cancelled": ["acme-labs"]}
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    assert github.posted == ["acme-data"] and "acme-labs" not in results(repo, connection_id)
    assert ("GITHUB_ENTERPRISE_INSTALL_CANCELLED", "admin-2", "acme-labs") in audited(repo)


def test_a_replaced_source_key_reaches_the_connections_it_made():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    labs_id = results(repo, connection_id)["acme-labs"]["connection_id"]
    old = service.get(repo, labs_id)["secret_refs"]["credential"]
    source_record = service.get(repo, connection_id)
    service.set_credential(repo, SETTINGS, connection_id, {"credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    assert service.get(repo, connection_id)["status"] == "ACTIVE"  # a new key keeps it collecting while it is checked
    assert service.get(repo, connection_id)["secret_refs"]["credential"] != source_record["secret_refs"]["credential"]
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    labs = service.get(repo, labs_id)
    assert labs["secret_refs"]["credential"] != old
    assert RESOLVER.resolve(labs["secret_refs"]["credential"])["GITHUB_APP_INSTALLATION_ID"] == str(github.installed["acme-labs"])
    assert ("GITHUB_ENTERPRISE_KEY_PROPAGATED", github_enterprise.ACTOR, "moved=1 left=0") in audited(repo)
    made = github_enterprise.status(repo, SETTINGS, connection_id, github.client)["made"]
    assert [(row["organization"], row["same_app"]) for row in made] == [("acme-labs", True)]


def test_a_failing_source_waits_and_never_stops_the_others():
    repo = InMemoryRepository()
    broken, good = source(repo), source(repo, organization="beta")
    github_enterprise.request(repo, SETTINGS, broken, ["acme-labs"], "admin")
    github_enterprise.request(repo, SETTINGS, good, ["acme-data"], "admin")
    # The first source is gone after asking (as if deleted): its state row stays, the second source still gets its tick.
    del repo.provider_connections[uuid.UUID(str(broken))]
    github = GitHub()
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    assert github.posted == ["acme-data"]
    # GitHub failing pauses the source for a while rather than every minute.
    failing = GitHub(refuse={"/app/installations": 500})  # the organization list is reused for ten minutes
    github_enterprise.request(repo, SETTINGS, good, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, failing.client, now=NOW + MINUTE)
    paused = state(repo, good)
    assert paused["paused_code"] == "GITHUB_APP_UNAVAILABLE" and paused["paused_until"] > (NOW + MINUTE).isoformat()
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + 2 * MINUTE)
    assert "acme-labs" not in github.posted
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + github_enterprise.PAUSE + 2 * MINUTE)
    assert "acme-labs" in github.posted and state(repo, good)["paused_until"] is None
    # A tick with no time left does nothing.
    github_enterprise.request(repo, SETTINGS, good, ["acme"], "admin")
    assert github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + github_enterprise.PAUSE + 3 * MINUTE, budget=-1) == 0


def test_only_an_active_sealed_app_connection_with_an_enterprise_can_be_the_source():
    repo = InMemoryRepository()
    plain = service.create(repo, SETTINGS, {
        "provider": "github", "edition": "cloud", "purposes": ["exposure"], "auth_method": "github_app",
        "target": {"organization": "solo"}, "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    with pytest.raises(github_enterprise.GitHubEnterpriseError) as refused:
        github_enterprise.status(repo, SETTINGS, plain["id"], GitHub().client)
    assert refused.value.code == "GITHUB_ENTERPRISE_REQUIRED"
    referenced = service.create(repo, SETTINGS, {
        "provider": "github", "edition": "enterprise_cloud", "purposes": ["exposure"], "auth_method": "github_app",
        "target": {"organization": "acme", "enterprise": "acme-corp"}, "credential": {"vault_ref": "vault://kv/github/app"}}, "admin")
    with pytest.raises(github_enterprise.GitHubEnterpriseError) as refused:
        github_enterprise.request(repo, SETTINGS, referenced["id"], ["acme-labs"], "admin")
    assert refused.value.code == "GITHUB_ENTERPRISE_SEALED_CREDENTIAL_REQUIRED"
    draft = service.create(repo, SETTINGS, {
        "provider": "github", "edition": "enterprise_cloud", "purposes": ["exposure"], "auth_method": "github_app",
        "target": {"organization": "acme", "enterprise": "acme-corp"},
        "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    # Not active: its steps show, but nothing is installed with plans it does not have.
    assert github_enterprise.status(repo, SETTINGS, draft["id"], GitHub().client)["source_status"] != "ACTIVE"
    for call in (lambda: github_enterprise.request(repo, SETTINGS, draft["id"], ["acme-labs"], "admin"),
                 lambda: github_enterprise.set_auto(repo, SETTINGS, draft["id"], True, "admin")):
        with pytest.raises(github_enterprise.GitHubEnterpriseError) as refused:
            call()
        assert refused.value.code == "GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE"
    connection_id = source(repo)
    for wrong in ([], ["acme/../x"], ["a"] * 101, "acme"):
        with pytest.raises(github_enterprise.GitHubEnterpriseError):
            github_enterprise.request(repo, SETTINGS, connection_id, wrong, "admin")


def test_any_spelling_of_the_source_id_is_the_same_source():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github_enterprise.request(repo, SETTINGS, str(connection_id).upper(), ["acme-labs"], "admin")
    github_enterprise.set_auto(repo, SETTINGS, "{" + str(connection_id) + "}", True, "admin")
    status = github_enterprise.status(repo, SETTINGS, connection_id, GitHub().client)
    assert status["auto"] is True and next(row for row in status["organizations"] if row["organization"] == "acme-labs")["requested"]
    assert [entry["key"] for entry in repo.list_settings(github_enterprise.PREFIX)] == [github_enterprise.PREFIX + str(connection_id)]


def test_the_worker_installs_queued_organizations_from_its_maintenance_tick():
    from cremore.worker.worker import JobWorker

    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    JobWorker(repo, settings=SETTINGS, http_client_factory=github.client).poll_triggers()
    assert github.posted == ["acme-labs"] and results(repo, connection_id)["acme-labs"]["state"] == "CHECKING"


def test_a_long_request_is_audited_in_full():
    repo = InMemoryRepository()
    connection_id = source(repo)
    logins = [f"org-{n:03d}-{'x' * 20}" for n in range(100)]
    github_enterprise.request(repo, SETTINGS, connection_id, logins, "admin")
    notes = [note for kind, _actor, note in audited(repo) if kind == "GITHUB_ENTERPRISE_INSTALL_REQUESTED"]
    assert sum(len(note.split(",")) for note in notes) == 100 and all(len(note) <= 900 for note in notes)


def test_upkeep_needs_no_github_time():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW)
    checked(repo, results(repo, connection_id)["acme-labs"]["connection_id"])
    # No time left for GitHub at all: activation still happens.
    github_enterprise.sweep(repo, SETTINGS, GitHub(refuse={"/app": 500}).client, now=NOW + MINUTE, budget=-1)
    assert results(repo, connection_id)["acme-labs"]["state"] == "ACTIVE"


def test_sources_take_turns_going_first(monkeypatch):
    repo = InMemoryRepository()
    first, second = source(repo), source(repo, organization="beta")
    github_enterprise.request(repo, SETTINGS, first, ["acme-labs"], "admin")
    github_enterprise.request(repo, SETTINGS, second, ["acme-data"], "admin")
    # Each source's GitHub part takes nearly the whole budget: one source a tick, a different one first each minute.
    slow = github_enterprise._github

    def slowly(*args, **kwargs):
        time.sleep(0.3)
        return slow(*args, **kwargs)

    monkeypatch.setattr(github_enterprise, "_github", slowly)
    monkeypatch.setattr(github_enterprise, "SOURCE_SECONDS", 0.3)
    monkeypatch.setattr(github_enterprise, "MIN_SOURCE_SECONDS", 0.2)
    github = GitHub()
    assert github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW, budget=0.35) == 1
    assert github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE, budget=0.35) == 1
    assert sorted(github.posted) == ["acme-data", "acme-labs"]


def test_a_copy_an_admin_changed_is_left_alone():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub()
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    labs_id = results(repo, connection_id)["acme-labs"]["connection_id"]
    # An admin gives that organization's connection another installation of its own.
    service.set_credential(repo, SETTINGS, labs_id, {"credential": {"app_id": "12345", "installation_id": "4242", "private_key": PEM}}, "admin")
    chosen = service.get(repo, labs_id)["secret_refs"]["credential"]
    service.set_credential(repo, SETTINGS, connection_id, {"credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + MINUTE)
    assert service.get(repo, labs_id)["secret_refs"]["credential"] == chosen
    assert ("GITHUB_ENTERPRISE_KEY_PROPAGATED", github_enterprise.ACTOR, "moved=0 left=1") in audited(repo)
    made = github_enterprise.status(repo, SETTINGS, connection_id, github.client)["made"]
    assert [(row["organization"], row["changed"]) for row in made] == [("acme-labs", True)]


def test_a_stopped_source_stops_its_queue_and_can_still_be_cancelled():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub(orgs=["acme", "acme-labs", "acme-data", "acme-mobile"])
    github_enterprise.set_auto(repo, SETTINGS, connection_id, True, "admin")
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs", "acme-data"], "admin")
    service.set_enabled(repo, connection_id, False, "admin")
    # Stopping controls answer for a stopped source.
    assert github_enterprise.cancel(repo, SETTINGS, connection_id, ["acme-labs"], "admin") == {"cancelled": ["acme-labs"]}
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)
    after = state(repo, connection_id)
    assert after["auto"] is False and after["requested"] == [] and github.posted == []
    assert ("GITHUB_ENTERPRISE_STOPPED_WITH_SOURCE", github_enterprise.ACTOR, "acme-data") in audited(repo)  # what it dropped
    # Turned on again, it installs nothing it was not asked for anew.
    service.set_enabled(repo, connection_id, True, "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + dt.timedelta(hours=1))
    assert github.posted == []
    assert github_enterprise.set_auto(repo, SETTINGS, connection_id, False, "admin") == {"auto": False}


def test_a_worker_that_lost_its_claim_makes_no_second_connection():
    repo = InMemoryRepository()
    connection_id = source(repo)
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme-labs"], "admin")
    _by, stalled = github_enterprise._claim(repo, connection_id, "acme-labs", NOW)
    # Its lease runs out and another worker takes the organization over.
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW + github_enterprise.LEASE + MINUTE)
    assert results(repo, connection_id)["acme-labs"]["state"] == "CHECKING"
    assert github_enterprise._renew(repo, connection_id, "acme-labs", stalled, NOW + github_enterprise.LEASE + 2 * MINUTE) is False
    assert len([c for c in ProviderConnectionStore(repo).list() if c["target"].get("organization") == "acme-labs"]) == 1


def test_auto_turned_off_during_a_look_queues_nothing(monkeypatch):
    repo = InMemoryRepository()
    connection_id = source(repo)
    github = GitHub(orgs=["acme", "acme-labs"])
    github_enterprise.set_auto(repo, SETTINGS, connection_id, True, "admin")
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW)  # the first look: the baseline
    github.orgs.append("acme-new")
    connected = github_enterprise._connected

    def and_off(repo_, record):
        github_enterprise.set_auto(repo, SETTINGS, connection_id, False, "admin")  # an admin, just now
        return connected(repo_, record)

    monkeypatch.setattr(github_enterprise, "_connected", and_off)
    github_enterprise.sweep(repo, SETTINGS, github.client, now=NOW + dt.timedelta(hours=1))
    assert github.posted == [] and state(repo, connection_id)["requested"] == []


def test_what_is_left_out_is_bounded_and_a_connected_organization_can_be_asked_again():
    repo = InMemoryRepository()
    connection_id = source(repo)
    for batch in range(10):
        github_enterprise.cancel(repo, SETTINGS, connection_id, [f"org-{batch}-{n}" for n in range(100)], "admin")
    with pytest.raises(github_enterprise.GitHubEnterpriseError) as full:
        github_enterprise.cancel(repo, SETTINGS, connection_id, ["one-more"], "admin")
    assert full.value.code == "GITHUB_ENTERPRISE_EXCLUDED_FULL"
    github_enterprise.request(repo, SETTINGS, connection_id, ["acme"], "admin")
    github_enterprise.sweep(repo, SETTINGS, GitHub().client, now=NOW)
    assert results(repo, connection_id)["acme"]["state"] == "CONNECTED"
    assert github_enterprise.request(repo, SETTINGS, connection_id, ["acme"], "admin")["requested"] == ["acme"]
