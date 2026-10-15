"""The Jira adapter against a synthetic Jira (httpx.MockTransport): nothing here reaches a real site or account."""

import base64
import datetime as dt
import importlib.metadata
import json
import socket
import threading
import time
import uuid

import httpx
import pytest
from cremore_ticket_jira import PROVIDER
from cremore_ticket_jira import jira as module

from cremore.db.repository import InMemoryRepository
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.remediation import owner_approval as oa
from cremore.ticketing import registry, setup
from cremore.ticketing import sweep as ticket_sweep
from cremore.ticketing.contract import ApprovalRequest, Approver, Opened, TicketError
from cremore.ticketing.ticketing_test import ask, plan

CLOUD = "https://acme.atlassian.net"
DC = "https://jira.corp.example/jira"
TOKEN = "jira-token-" + "t" * 20  # built at run time: nothing secret-shaped sits in the source
OWNER = "5b10ac8d82e05b22cc7d4ef5"
OTHER = "5b10ac8d82e05b22cc7d0000"
SERVICE = "557058:service-account"
TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:ticket_system")
WHEN = "2026-09-30T04:05:06.123+0000"
LEAK = "leaked-body-text"
STATUS = {"to do": "1", "in progress": "3", "reopened": "4", "done": "10001", "won't do": "10002"}
PERMITTED = {"permissions": {name: {"key": name, "havePermission": True} for name in module.PERMISSIONS}}


def values(**changes):
    return {"url": CLOUD, "email": "bot@acme.com", "project": "SEC", "issue_type": "Task",
            "approved_statuses": "Done", "declined_statuses": "Won't Do", **changes}


def user(account, email="kim@example.com", *, active=True, cloud=True):
    row = {"accountId": account} if cloud else {"key": account, "name": account.lower()}
    if email is not None:
        row["emailAddress"] = email
    return {**row, "active": active}


def change(number, author, item, *, cloud=True):
    return {"id": str(number), "author": {"accountId": author} if cloud else {"key": author}, "created": WHEN,
            "items": [item]}


def moved(number, author, to, *, to_id=None, cloud=True, fieldtype="jira"):
    """A status change into ``to``: the changelog keeps the name as it was then and the status id."""
    return change(number, author, {"field": "status", "fieldtype": fieldtype, "from": "1", "fromString": "To Do",
                                   "to": to_id or STATUS.get(to.casefold(), "99"), "toString": to}, cloud=cloud)


def edited(number, author=OTHER):
    return change(number, author, {"field": "summary", "fieldtype": "jira", "fromString": "a", "toString": "b"})


def issue(status, histories=(), total=None, number="10001", status_id=None):
    histories = list(histories)
    return {"id": number, "key": "SEC-7",
            "fields": {"status": {"name": status, "id": status_id or STATUS.get(status.casefold(), "99")}},
            "changelog": {"startAt": 0, "maxResults": len(histories),
                          "total": len(histories) if total is None else total, "histories": histories}}


class Jira:
    """A Jira site: one (status, body) per (method, path), or a function of the request giving it; a body that is an
    exception is raised as the transport's, bytes or an iterator of bytes are sent as they are."""

    def __init__(self, *, cloud=True):
        self.cloud, self.seen = cloud, []
        self.base = "/rest/api/2" if cloud else "/jira/rest/api/2"
        self.routes = {
            ("GET", "/serverInfo"): (200, {"deploymentType": "Cloud" if cloud else "DataCenter"}),
            ("GET", "/myself"): (200, {"accountId": SERVICE} if cloud else {"key": "JIRAUSER1", "name": "bot"}),
            ("GET", "/mypermissions"): (200, PERMITTED),
            ("GET", "/project/SEC"): (200, {"id": "1", "key": "SEC"}),
            ("GET", "/project/SEC/statuses"): (200, [
                {"name": "Bug", "statuses": [{"name": "Open"}]},
                {"name": "Task", "statuses": [{"name": "To Do"}, {"name": "Done"}, {"name": "Won't Do"}]}]),
            ("GET", "/user/search"): (200, [user(OWNER, cloud=cloud)]),
            # Everyone the search finds is assignable unless a test says otherwise.
            ("GET", "/user/assignable/search"): lambda request: self.routes[("GET", "/user/search")],
            ("GET", "/user"): (200, {"key": OWNER, "name": "kim"}),
            ("POST", "/issue"): (201, {"id": "10001", "key": "SEC-7", "self": f"{CLOUD}/rest/api/2/issue/10001"}),
            ("GET", "/issue/10001"): (200, issue("To Do")),
        }

    def handle(self, request):
        self.seen.append(request)
        route = self.routes.get((request.method, request.url.path.removeprefix(self.base)),
                                (404, {"errorMessages": [LEAK]}))
        status, body = route(request) if callable(route) else route
        if isinstance(body, bytes):
            return httpx.Response(status, content=body)
        if isinstance(body, list) and body and all(isinstance(part, bytes) for part in body):
            return httpx.Response(status, content=iter(body))  # streamed: no Content-Length
        if isinstance(body, Exception):
            raise body
        return httpx.Response(status, json=body)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handle))

    def system(self, **changes):
        url = {} if self.cloud else {"url": DC, "email": ""}
        return PROVIDER.build(values(**url, **changes), {"token": TOKEN}, self.client())

    def paths(self):
        return [(request.method, request.url.path.removeprefix(self.base)) for request in self.seen]

    def requests(self, path):
        return [request for request in self.seen if request.url.path.removeprefix(self.base) == path]


def refused(call, *args):
    with pytest.raises(TicketError) as caught:
        call(*args)
    return caught.value


# --- setup values ------------------------------------------------------------------------------------------------


def test_validate_normalizes_the_setup():
    kept = module.validate(values(url=" https://ACME.atlassian.net/ ", email=" Bot@Acme.com ", project=" sec ",
                                  approved_statuses="Done, done ,Closed,", declined_statuses="Won't Do"))
    assert kept == {"url": "https://acme.atlassian.net", "email": "bot@acme.com", "project": "SEC",
                    "issue_type": "Task", "approved_statuses": "Done, Closed", "declined_statuses": "Won't Do"}
    assert module.validate(values(url="http://10.0.0.5:8080/jira/", email=""))["url"] == "http://10.0.0.5:8080/jira"
    assert module.validate(values(email=None))["email"] is None


@pytest.mark.parametrize("change, code", [
    ({"url": "ftp://jira.example"}, "JIRA_URL_INVALID"),
    ({"url": "https://kim:pw@jira.example"}, "JIRA_URL_INVALID"),
    ({"url": "https://jira.example/?a=1"}, "JIRA_URL_INVALID"),
    ({"url": "https://jira.example/#top"}, "JIRA_URL_INVALID"),
    ({"url": "jira.example"}, "JIRA_URL_INVALID"),
    ({"url": "https://api.atlassian.com/ex/jira/0f3c"}, "JIRA_URL_INVALID"),  # the scoped-token gateway, not a site
    ({"email": "bot:x@acme.com"}, "JIRA_EMAIL_INVALID"),
    ({"email": "no-at-sign"}, "JIRA_EMAIL_INVALID"),
    ({"project": "1SEC"}, "JIRA_PROJECT_INVALID"),
    ({"project": "S"}, "JIRA_PROJECT_INVALID"),
    ({"project": "SEC-1"}, "JIRA_PROJECT_INVALID"),
    ({"issue_type": ""}, "JIRA_ISSUE_TYPE_INVALID"),
    ({"approved_statuses": " , "}, "JIRA_APPROVED_STATUSES_INVALID"),
    ({"approved_statuses": ",".join(f"S{n}" for n in range(11))}, "JIRA_APPROVED_STATUSES_INVALID"),
    ({"approved_statuses": "D" * 61}, "JIRA_APPROVED_STATUSES_INVALID"),
    ({"approved_statuses": "Do\u202ene"}, "JIRA_APPROVED_STATUSES_INVALID"),
    ({"declined_statuses": "No\tway"}, "JIRA_DECLINED_STATUSES_INVALID"),
    ({"declined_statuses": "Rejected, DONE"}, "JIRA_STATUSES_OVERLAP"),
])
def test_validate_refuses_bad_values_with_a_code(change, code):
    with pytest.raises(ValueError) as caught:
        module.validate(values(**change))
    assert str(caught.value) == code


def test_a_cloud_site_needs_the_accounts_email():
    with pytest.raises(TicketError) as caught:
        PROVIDER.build(values(email=""), {"token": TOKEN}, Jira().client())
    assert caught.value.code == "JIRA_EMAIL_REQUIRED"  # an *.atlassian.net site, known before any call
    server = Jira()  # Cloud on a custom domain: told by the anonymous /serverInfo
    system = PROVIDER.build(values(url="https://tickets.acme.com", email=""), {"token": TOKEN}, server.client())
    assert refused(system.check).code == "JIRA_EMAIL_REQUIRED"
    assert server.paths() == [("GET", "/serverInfo")]
    assert "authorization" not in server.seen[0].headers


def test_server_info_is_asked_anonymously_then_signed_in_when_refused():
    server = Jira(cloud=False)
    server.routes[("GET", "/serverInfo")] = lambda request: (
        (200, {"deploymentType": "DataCenter"}) if "authorization" in request.headers else (401, {}))
    server.system().check()
    first, second = server.requests("/serverInfo")
    assert "authorization" not in first.headers and second.headers["authorization"] == "Bearer " + TOKEN
    server.routes[("GET", "/serverInfo")] = (404, {})  # anything else is not retried
    assert refused(server.system().check).code == "JIRA_NOT_FOUND"
    assert len(server.requests("/serverInfo")) == 3


# --- check ------------------------------------------------------------------------------------------------------


def test_check_reads_permissions_the_project_and_its_statuses_with_basic_auth_on_cloud():
    server = Jira()
    server.system(approved_statuses="done").check()  # names compare by casefold
    assert server.paths() == [("GET", "/serverInfo"), ("GET", "/myself"), ("GET", "/mypermissions"),
                              ("GET", "/project/SEC"), ("GET", "/project/SEC/statuses")]
    assert dict(server.requests("/mypermissions")[0].url.params) == {
        "projectKey": "SEC", "permissions": "BROWSE_PROJECTS,CREATE_ISSUES,ASSIGN_ISSUES,USER_PICKER"}
    headers = server.requests("/myself")[0].headers
    assert headers["authorization"] == "Basic " + base64.b64encode(f"bot@acme.com:{TOKEN}".encode()).decode()
    assert (headers["accept"], headers["user-agent"], headers["accept-encoding"]) == (
        "application/json", "CreMore/1.0", "identity")


@pytest.mark.parametrize("cloud", [True, False], ids=["cloud", "data-center"])
@pytest.mark.parametrize("missing", module.PERMISSIONS)
def test_check_names_the_permission_the_account_lacks(cloud, missing):
    server = Jira(cloud=cloud)
    table = {name: {"havePermission": name != missing} for name in module.PERMISSIONS}
    server.routes[("GET", "/mypermissions")] = (200, {"permissions": table})
    assert refused(server.system().check).code == f"JIRA_PERMISSION_{missing}_MISSING"
    del table[missing]  # not reported at all: never taken as granted
    assert refused(server.system().check).code == f"JIRA_PERMISSION_{missing}_MISSING"
    assert ("GET", "/project/SEC") not in server.paths()


def test_check_refuses_a_missing_issue_type_or_status():
    server = Jira()
    assert refused(server.system(issue_type="Story").check).code == "JIRA_ISSUE_TYPE_NOT_FOUND"
    assert refused(server.system(declined_statuses="Rejected").check).code == "JIRA_STATUS_NOT_FOUND"
    assert refused(server.system(approved_statuses="Open").check).code == "JIRA_STATUS_NOT_FOUND"  # Bug's, not Task's


# --- find_approver -----------------------------------------------------------------------------------------------


def test_find_approver_takes_the_one_active_assignable_account_with_that_exact_email_on_cloud():
    server = Jira()
    assert server.system().find_approver("kim@example.com") == Approver(OWNER, ("kim@example.com",))
    assert dict(server.requests("/user/search")[0].url.params) == {"query": "kim@example.com", "maxResults": "10"}
    assert dict(server.requests("/user/assignable/search")[0].url.params) == {"project": "SEC", "accountId": OWNER}
    server.routes[("GET", "/user/search")] = (200, [user(OWNER, "Kim@Example.COM")])
    assert server.system().find_approver("KIM@example.com") == Approver(OWNER, ("kim@example.com",))


@pytest.mark.parametrize("rows, code", [
    ([user(OWNER, None)], "JIRA_USER_EMAIL_HIDDEN"),  # Cloud privacy: never guessed
    ([user(OWNER, "kim at example dot com")], "JIRA_USER_EMAIL_HIDDEN"),  # the site's masked addresses
    ([user(OWNER, "kim@example.com.evil.test"), user(OTHER, "kim2@example.com")], "JIRA_USER_NOT_FOUND"),
    ([user(OWNER, active=False)], "JIRA_USER_NOT_FOUND"),
    ([], "JIRA_USER_NOT_FOUND"),
    ([user(OWNER), user(OTHER)], "JIRA_USER_AMBIGUOUS"),
    # One exact match on a full page: a second account with the address may be on the next one.
    ([user(OWNER)] + [user(f"acct-{n}", f"kim{n}@example.com") for n in range(9)], "JIRA_USER_AMBIGUOUS"),
    ([user(SERVICE)], "JIRA_USER_IS_SERVICE_ACCOUNT"),
], ids=["hidden", "masked", "look-alike", "inactive", "none", "two", "full-page", "service-account"])
def test_find_approver_refuses_what_is_not_one_matching_account(rows, code):
    server = Jira()
    server.routes[("GET", "/user/search")] = (200, rows)
    assert refused(server.system().find_approver, "kim@example.com").code == code


@pytest.mark.parametrize("assignable", [[], [user(OTHER)]], ids=["none", "another"])
def test_find_approver_refuses_an_owner_who_cannot_be_assigned_before_anything_is_reserved(assignable):
    server = Jira()
    server.routes[("GET", "/user/assignable/search")] = (200, assignable)
    assert refused(server.system().find_approver, "kim@example.com").code == "JIRA_USER_NOT_ASSIGNABLE"


def test_find_approver_on_data_center_searches_by_username_and_keeps_the_user_key():
    server = Jira(cloud=False)
    server.routes[("GET", "/user/search")] = (200, [user("JIRAUSER10100", cloud=False)])
    assert server.system().find_approver("kim@example.com") == Approver("JIRAUSER10100", ("kim@example.com",))
    search = server.requests("/user/search")[0]
    assert dict(search.url.params) == {"username": "kim@example.com", "maxResults": "10"}
    assert search.url.path == "/jira/rest/api/2/user/search"
    assert search.headers["authorization"] == "Bearer " + TOKEN
    assert dict(server.requests("/user/assignable/search")[0].url.params) == {
        "project": "SEC", "username": "jirauser10100", "maxResults": "100"}
    # An old Server account whose key is its login (an address) is not a reference CreMore keeps.
    server.routes[("GET", "/user/search")] = (200, [user("kim@example.com", cloud=False)])
    assert refused(server.system().find_approver, "kim@example.com").code == "JIRA_USER_REFERENCE_UNSUPPORTED"


# --- open_approval -----------------------------------------------------------------------------------------------

REPORT_LINK = "https://cremore.example.com/?view=exposed&id=credential%3Aabc-1&dtab=owner"
REQUEST = ApprovalRequest(title="[CreMore] Key action\napproval · AKIA…<b>WXYZ</b>" + "x" * 300,
                          lines=("Intro {noformat} breakout {NoFormat}", "[link|https://evil.test] *bold*", "",
                                 "bidi\u202eend\r\nnext", "see https://cremore.example.com/ here",
                                 "https://evil.test/[x]|y", REPORT_LINK))


def test_open_approval_on_cloud_creates_one_assigned_issue_with_literal_text():
    server = Jira()
    system = server.system(approved_statuses="Done, Closed")
    opened = system.open_approval(REQUEST, Approver(OWNER, ("kim@example.com",)))
    assert opened == Opened(ticket="SEC-7", approval="10001", approver=OWNER, url=f"{CLOUD}/browse/SEC-7")
    [create] = server.requests("/issue")
    fields = json.loads(create.content)["fields"]
    assert (fields["project"], fields["issuetype"], fields["assignee"]) == (
        {"key": "SEC"}, {"name": "Task"}, {"accountId": OWNER})
    assert len(fields["summary"]) == 250 and "\n" not in fields["summary"]
    assert fields["summary"].startswith("[CreMore] Key action approval · AKIA…<b>WXYZ</b>")
    block, after = fields["description"].rsplit("\n{noformat}\n", 1)
    assert block.startswith("{noformat}\n") and block.count("{noformat}") == 1
    assert "(noformat} breakout (NoFormat}" in block
    assert "[link|https://evil.test] *bold*" in block  # inside the block: shown as typed, never a link
    assert "\u202e" not in block and "\r" not in block and "bidi end  next" in block
    # Only a line that is nothing but a plain address goes after the block, where Jira links it.
    assert after == REPORT_LINK and REPORT_LINK not in block
    assert "see https://cremore.example.com/ here" in block and "https://evil.test/[x]|y" in block
    assert block.endswith("\n마치면 이 이슈를 Done / Closed 상태로, 할 수 없으면 Won't Do 상태로 옮겨 주세요.\n"
                          "When done, move this issue to Done / Closed; if you cannot, move it to Won't Do.")


def test_open_approval_on_data_center_assigns_by_the_looked_up_user_name():
    server = Jira(cloud=False)
    opened = server.system().open_approval(REQUEST, Approver(OWNER, ("kim@example.com",)))
    assert opened.url == f"{DC}/browse/SEC-7"
    assert dict(server.requests("/user")[0].url.params) == {"key": OWNER}
    [create] = server.requests("/issue")
    assert json.loads(create.content)["fields"]["assignee"] == {"name": "kim"}


def test_open_approval_names_the_issue_when_it_exists_but_the_answer_is_unusable():
    server = Jira()
    server.routes[("POST", "/issue")] = (201, {"key": "SEC-7", "id": "not-a-number"})
    error = refused(server.system().open_approval, REQUEST, Approver(OWNER, ()))
    assert (error.code, error.ticket) == ("JIRA_INVALID_RESPONSE", "SEC-7")  # a person closes it in Jira
    server.routes[("POST", "/issue")] = (500, {"errorMessages": [LEAK]})
    error = refused(server.system().open_approval, REQUEST, Approver(OWNER, ()))
    assert (error.code, error.retryable, error.ticket) == ("JIRA_UNAVAILABLE", True, "")
    # Data Center: the user lookup fails before the issue exists, so nothing is left behind.
    server = Jira(cloud=False)
    server.routes[("GET", "/user")] = (404, {"errorMessages": [LEAK]})
    error = refused(server.system().open_approval, REQUEST, Approver(OWNER, ()))
    assert (error.code, error.ticket) == ("JIRA_NOT_FOUND", "") and ("POST", "/issue") not in server.paths()


# --- answer -----------------------------------------------------------------------------------------------------

ASKED = Opened(ticket="SEC-7", approval="10001", approver=OWNER)


def answer(server, histories=(), status="Done", total=None, status_id=None):
    server.routes[("GET", "/issue/10001")] = (200, issue(status, histories, total, status_id=status_id))
    return server.system().answer(ASKED)


def test_answer_reads_the_status_and_who_moved_the_issue_there():
    server = Jira()
    assert answer(server, status="In Progress").state == "WAITING"
    assert dict(server.seen[-1].url.params) == {"fields": "status", "expand": "changelog"}
    got = answer(server, [moved(1, OTHER, "In Progress"), moved(2, OWNER, "Done")])
    assert (got.state, got.by, got.at, got.report) == ("APPROVED", OWNER, WHEN, None)
    got = answer(server, [moved(3, OWNER, "Won't Do")], status="won't do")
    assert (got.state, got.by) == ("DECLINED", OWNER)
    # Reopened and closed again by someone else: the newest move counts, so the platform refuses it as not the owner's.
    got = answer(server, [moved(5, OWNER, "Done"), moved(9, OTHER, "Done"), moved(7, OWNER, "Reopened")])
    assert (got.state, got.by) == ("APPROVED", OTHER)


def test_answer_follows_the_status_id_not_the_name_the_changelog_kept():
    server = Jira()
    # The status was renamed (or is shown translated): the changelog keeps the old name, the id stays.
    got = answer(server, [moved(2, OWNER, "Closed", to_id=STATUS["done"])])
    assert (got.state, got.by) == ("APPROVED", OWNER)
    # The owner moved it there, then someone else moved it into the same status under another name: theirs counts.
    got = answer(server, [moved(2, OWNER, "Done"), moved(5, OTHER, "Resolved", to_id=STATUS["done"])])
    assert (got.state, got.by) == ("APPROVED", OTHER)


def test_answer_takes_only_the_newest_status_change_and_never_an_older_one():
    server = Jira()
    # The newest status change went elsewhere (the issue's status changed without a changelog entry): no answer.
    error = refused(answer, server, [moved(2, OWNER, "Done"), moved(3, OTHER, "In Progress"), edited(4)])
    assert error.code == "JIRA_ANSWER_AUTHOR_UNKNOWN"
    error = refused(answer, server, [moved(1, OWNER, "In Progress")])  # created in Done
    assert error.code == "JIRA_ANSWER_AUTHOR_UNKNOWN"
    error = refused(answer, server, [moved(2, OWNER, "Done", fieldtype="custom")])  # a custom field named status
    assert error.code == "JIRA_ANSWER_AUTHOR_UNKNOWN"


def test_answer_on_cloud_reads_the_newest_changelog_page_of_a_long_history():
    server = Jira()
    server.routes[("GET", "/issue/10001/changelog")] = (200, {"startAt": 50, "maxResults": 100, "total": 150,
        "values": [moved(n, OTHER, "In Progress") for n in range(51, 150)] + [moved(150, OWNER, "Done")]})
    got = answer(server, [moved(n, OTHER, "Done") for n in range(1, 101)], total=150)
    assert (got.state, got.by) == ("APPROVED", OWNER)
    page = server.seen[-1]
    assert page.url.path == "/rest/api/2/issue/10001/changelog"
    assert dict(page.url.params) == {"startAt": "50", "maxResults": "100"}
    # The owner's move sits in the embedded (oldest) part, a later move by someone else may sit in the unread gap,
    # and the newest page holds no status change: the older move is never taken as the answer.
    server.routes[("GET", "/issue/10001/changelog")] = (200, {"startAt": 200, "total": 300,
                                                               "values": [edited(n) for n in range(201, 301)]})
    error = refused(answer, server, [moved(1, OWNER, "Done")] + [edited(n) for n in range(2, 101)], "Done", 300)
    assert error.code == "JIRA_CHANGELOG_TOO_LONG"
    # A page that is not the newest suffix as counted (the changelog grew, or the page came short) is not trusted.
    for page in ({"startAt": 200, "total": 301, "values": [moved(300, OWNER, "Done")] * 100},
                 {"startAt": 200, "total": 300, "values": [moved(300, OWNER, "Done")]}):
        server.routes[("GET", "/issue/10001/changelog")] = (200, page)
        assert refused(answer, server, [edited(n) for n in range(1, 101)], "Done", 300).code == (
            "JIRA_CHANGELOG_TOO_LONG")


def test_answer_on_data_center_fails_closed_on_a_long_history():
    server = Jira(cloud=False)
    error = refused(answer, server, [moved(n, OWNER, "Done", cloud=False) for n in range(1, 101)], "Done", 150)
    assert error.code == "JIRA_CHANGELOG_TOO_LONG"
    assert not [path for _method, path in server.paths() if path.endswith("/changelog")]
    got = answer(server, [moved(4, OWNER, "Done", cloud=False)])
    assert (got.state, got.by) == ("APPROVED", OWNER)


def test_answer_refuses_references_it_did_not_make_and_another_issue():
    server = Jira()
    for opened in (Opened("SEC-7/../x", "10001", OWNER), Opened("SEC-7", "1e3", OWNER), Opened("sec-7", "1", OWNER)):
        assert refused(server.system().answer, opened).code == "JIRA_REFERENCE_INVALID"
    assert server.seen == []
    server.routes[("GET", "/issue/10001")] = (200, issue("Done", number="10002"))
    assert refused(server.system().answer, ASKED).code == "JIRA_INVALID_RESPONSE"
    no_id = issue("Done")
    del no_id["fields"]["status"]["id"]
    server.routes[("GET", "/issue/10001")] = (200, no_id)
    assert refused(server.system().answer, ASKED).code == "JIRA_INVALID_RESPONSE"


# --- errors -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("status, code, retryable", [
    (400, "JIRA_REQUEST_REFUSED", False), (401, "JIRA_TOKEN_REFUSED", False), (403, "JIRA_PERMISSION_MISSING", False),
    (404, "JIRA_NOT_FOUND", False), (408, "JIRA_UNAVAILABLE", True), (429, "JIRA_UNAVAILABLE", True),
    (500, "JIRA_UNAVAILABLE", True), (503, "JIRA_UNAVAILABLE", True), (302, "JIRA_HTTP_302", False),
    (409, "JIRA_HTTP_409", False),
])
def test_refusals_map_to_fixed_codes_without_response_text(status, code, retryable):
    server = Jira()
    server.routes[("GET", "/myself")] = (status, {"errorMessages": [LEAK, TOKEN]})
    error = refused(server.system().check)
    assert (error.code, error.retryable) == (code, retryable)
    assert LEAK not in str(error) + error.code and TOKEN not in str(error) + error.code
    assert len(server.requests("/myself")) == 1  # no redirect followed, no retry


@pytest.mark.parametrize("body, code", [
    (b"<html>" + LEAK.encode() + b"</html>", "JIRA_INVALID_RESPONSE"),
    (b"[" * 10 + b"x" * (2 << 20), "JIRA_RESPONSE_TOO_LARGE"),
    ([b"[" * 10, b"x" * (1 << 20)], "JIRA_RESPONSE_TOO_LARGE"),  # no Content-Length: counted as it arrives
    (httpx.ConnectError(f"connect failed Authorization: Bearer {TOKEN}"), "JIRA_UNAVAILABLE"),
], ids=["not-json", "oversized", "oversized-stream", "transport"])
def test_bodies_and_transport_failures_never_reach_the_error(body, code):
    server = Jira()
    server.routes[("GET", "/serverInfo")] = (200, body)
    error = refused(server.system().check)
    assert error.code == code and error.retryable is (code == "JIRA_UNAVAILABLE")
    assert error.__cause__ is None and (error.__context__ is None or error.__suppress_context__)
    assert TOKEN not in str(error) and LEAK not in str(error)


def test_a_compressed_answer_is_refused_since_none_was_asked_for():
    server = Jira()
    server.routes[("GET", "/serverInfo")] = lambda request: (200, {"deploymentType": "Cloud"})
    original = server.handle

    def gzip(request):
        response = original(request)
        response.headers["Content-Encoding"] = "gzip"
        return response

    system = PROVIDER.build(values(), {"token": TOKEN}, httpx.Client(transport=httpx.MockTransport(gzip)))
    assert refused(system.check).code == "JIRA_INVALID_RESPONSE"


def clock(*ticks):
    times = iter(ticks)
    return lambda: next(times)


def test_a_call_ends_at_its_total_deadline_however_slowly_the_body_drips():
    server = Jira()
    server.routes[("GET", "/serverInfo")] = (200, [b'{"deploymentType":', b' "Cloud"', b"}"])
    system = server.system()
    system.clock = clock(0, 1, 2, 3, 4, 5)  # start, after headers, then one tick per chunk
    system._deployment()  # well inside the deadline: read whole
    slow = server.system()
    slow.clock = clock(0, 1, 15, 29, 31)  # the third chunk arrives past 30 s
    error = refused(slow._deployment)
    assert (error.code, error.retryable) == ("JIRA_UNAVAILABLE", True)
    late = server.system()
    late.clock = clock(0, 31)  # the headers alone took longer
    assert refused(late._deployment).code == "JIRA_UNAVAILABLE"


def test_headers_that_never_complete_end_the_call_at_its_deadline():
    release = threading.Event()

    def stuck(request):
        release.wait(30)  # the headers never come while the test runs
        return httpx.Response(200, json={"deploymentType": "Cloud"})

    system = PROVIDER.build(values(), {"token": TOKEN}, httpx.Client(transport=httpx.MockTransport(stuck)))
    system.deadline = 0.2
    try:
        error = refused(system._deployment)
    finally:
        release.set()
    assert (error.code, error.retryable) == ("JIRA_UNAVAILABLE", True)


class Dripping:
    """A loopback HTTP server (no outside network): the first request is answered whole and the connection kept
    open; every later request gets a status line, then one header byte at a time, never ending its headers, until
    the client's side of the connection ends, which it records."""

    def __init__(self):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port, self.requests, self.ended = self.listener.getsockname()[1], 0, threading.Event()
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        with conn:
            conn.settimeout(10)
            while True:
                received = b""
                while b"\r\n\r\n" not in received:
                    part = conn.recv(4096)
                    if not part:
                        return
                    received += part
                self.requests += 1
                if self.requests == 1:
                    body = b'{"deploymentType": "DataCenter"}'
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                                 + str(len(body)).encode() + b"\r\n\r\n" + body)
                    continue
                conn.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                conn.settimeout(0.05)
                stop = time.monotonic() + 10  # safety bound: the client must end it long before
                while time.monotonic() < stop:
                    try:
                        if conn.recv(1) == b"":
                            self.ended.set()  # the client shut its side down
                            return
                    except TimeoutError:
                        conn.sendall(b"a")
                    except OSError:
                        self.ended.set()
                        return
                return

    def close(self):
        self.listener.close()


def test_a_dripping_server_is_cut_off_at_the_deadline_and_its_connection_shut_down():
    server = Dripping()
    try:
        system = PROVIDER.build(values(url=f"http://127.0.0.1:{server.port}", email=""), {"token": TOKEN},
                                httpx.Client())
        system.deadline = 0.5
        assert system._deployment() is False  # answered whole on a fresh connection
        started = time.monotonic()
        error = refused(system._myself)  # headers that never end
        assert (error.code, error.retryable) == ("JIRA_UNAVAILABLE", True)
        assert time.monotonic() - started < 5
        # The read blocked inside httpx is ended, not left running: the server sees the connection close.
        assert server.ended.wait(5)
    finally:
        server.close()


def test_close_drops_the_credential():
    system = Jira().system()
    system.close()
    assert TOKEN not in json.dumps(vars(system), default=str)


# --- the platform's contract ---------------------------------------------------------------------------------------


class _Entry:
    name = "jira"

    def load(self):
        return PROVIDER


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(registry, "entry_points",
                        lambda group: [_Entry()] if group == registry.ENTRY_POINT_GROUP else [])
    monkeypatch.setenv(registry.PLUGINS_ENV, "jira")


def test_the_installed_package_names_its_entry_point():
    [entry] = [item for item in importlib.metadata.entry_points(group=registry.ENTRY_POINT_GROUP)
               if item.name == "jira"]
    assert entry.load() is PROVIDER and PROVIDER.id == "jira"


def test_the_platform_loads_saves_and_builds_it(installed):
    assert registry.load("jira") is PROVIDER  # passes the registry's contract checks
    repo = InMemoryRepository()
    view, note = setup.save(repo, SETTINGS, {"system": "jira", "values": values(url=CLOUD + "/"),
                                             "secrets": {"token": TOKEN}}, "ada", TARGET)
    stored = json.dumps(repo.get_setting(setup.SETTING_KEY), default=str)
    assert TOKEN not in stored + json.dumps(view) + note
    assert view["current"]["values"]["url"] == CLOUD and view["current"]["secrets_saved"] == ["token"]
    with pytest.raises(setup.SetupError) as caught:
        setup.save(repo, SETTINGS, {"system": "jira", "values": values(project="1X")}, "ada", TARGET)
    assert caught.value.code == "JIRA_PROJECT_INVALID"
    ready = setup.open_system(repo, SETTINGS, Jira().client())
    assert isinstance(ready.system, module.Jira) and ready.name == "jira" and ready.binding == setup.binding(repo)


def test_an_owner_approval_asked_in_jira_is_recorded_only_from_the_account_asked(installed):
    now = dt.datetime(2026, 9, 30, 3, 0, tzinfo=dt.UTC)
    repo = InMemoryRepository()
    setup.save(repo, SETTINGS, {"system": "jira", "values": values(), "secrets": {"token": TOKEN}}, "ada", TARGET)
    server = Jira()
    target = repo.create_action_plan(plan())
    _request, opened = ask(repo, target, server)
    assert opened == Opened("SEC-7", "10001", OWNER, f"{CLOUD}/browse/SEC-7")
    assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=now) == 0  # still To Do
    server.routes[("GET", "/issue/10001")] = (200, issue("Done", [moved(1, OWNER, "Done")]))
    assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=now + dt.timedelta(minutes=1)) == 1
    shown = oa.current(repo, target.id, now)
    assert (shown["state"], shown["decided_by"]) == ("APPROVED", f"jira:user:{OWNER}")
    other = repo.create_action_plan(plan())
    ask(repo, other, server)
    server.routes[("GET", "/issue/10001")] = (200, issue("Done", [moved(1, OTHER, "Done")]))
    assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=now + dt.timedelta(minutes=2)) == 1
    assert oa.current(repo, other.id, now)["state"] == "ANSWERED_BY_OTHER" and not oa.granted(repo, other)
