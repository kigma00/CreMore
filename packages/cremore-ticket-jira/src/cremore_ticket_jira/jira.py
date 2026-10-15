"""Jira Cloud and Data Center/Server through REST API v2 (``/rest/api/2/``), one code path for both.

CreMore signs in as a dedicated account (Cloud: Basic ``email:classic API token`` of an Atlassian user account; Data
Center: Bearer personal access token), finds the owner's Jira account by mail address, opens an issue assigned to that
account, and reads the answer back from the issue: moved to an approved status is APPROVED, to a declined one DECLINED,
by the account whose status change (in the issue's changelog) moved it there. Which deployment it talks to is asked
once per built system (``/serverInfo``). No response text, comment or description is kept, returned or quoted in an
error.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import threading
import time
from urllib.parse import urlsplit

from cremore.domain.text import unsafe_text
from cremore.ticketing.contract import (
    Answer,
    ApprovalRequest,
    Approver,
    Field,
    Opened,
    TicketError,
    TicketSystemProvider,
)

TIMEOUT = 15.0  # httpx: per connect/read/write, i.e. inactivity
DEADLINE = 30.0  # the whole call, headers and body
MAX_BYTES = 1 << 20
API = "/rest/api/2"
PAGE = 100  # Cloud's changelog page
SEARCH = 10  # owner search page; a full page may hide a second account with the address
PERMISSIONS = ("BROWSE_PROJECTS", "CREATE_ISSUES", "ASSIGN_ISSUES", "USER_PICKER")
FIELDS = (
    Field("url", "Jira site address", "Jira 사이트 주소", "url", hint="https://acme.atlassian.net"),
    Field("email", "Atlassian account email (Cloud only)", "Atlassian 계정 이메일(Cloud만)", required=False,
          hint="cremore-bot@acme.com"),
    Field("token", "Classic API token (Cloud) or personal access token (Data Center)",
          "클래식 API 토큰(Cloud) 또는 개인 액세스 토큰(Data Center)", "secret",
          hint="Cloud: an unscoped API token of an Atlassian user account; service-account scoped tokens "
               "(api.atlassian.com) are not supported"),
    Field("project", "Project key", "프로젝트 키", hint="SEC"),
    Field("issue_type", "Issue type", "이슈 유형", hint="Task"),
    Field("approved_statuses", "Approved statuses (comma-separated)", "승인 상태(쉼표로 구분)", hint="Done"),
    Field("declined_statuses", "Declined statuses (comma-separated)", "거절 상태(쉼표로 구분)", hint="Won't Do"),
)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*")
_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")
_EMAIL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9.-]{1,253}")  # no ':' (Basic splits at it)
_TOKEN = re.compile(r"[\x21-\x7e]{1,1024}")  # a header value: printable ASCII, no spaces
_PROJECT = re.compile(r"[A-Z][A-Z0-9_]{1,19}")
_ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,19}-[1-9][0-9]{0,17}")
_ISSUE_ID = re.compile(r"[1-9][0-9]{0,17}")
_REFERENCE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_WHEN = re.compile(r"[0-9T:.+Z -]{1,40}")
_NOFORMAT = re.compile(r"\{(?=\s*noformat)", re.IGNORECASE)
_LINK = re.compile(r"https?://[A-Za-z0-9._~:/?#=&%-]+")  # a line Jira may show as a link: no markup characters


def _url(value) -> str:
    """``scheme://host[:port][/context]`` of the Jira site (http or https: the company's choice). The Atlassian API
    gateway (``api.atlassian.com``, scoped service-account tokens) is not a site."""
    if not isinstance(value, str) or len(value) > 300 or unsafe_text(value):
        raise ValueError("JIRA_URL_INVALID")
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise ValueError("JIRA_URL_INVALID") from None
    host = parts.hostname or ""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    path = parts.path.rstrip("/")
    if (parts.scheme not in ("http", "https") or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or value.strip().endswith(("?", "#")) or not _PATH.fullmatch(path)
            or not (literal or _HOST.fullmatch(host)) or host == "api.atlassian.com"):
        raise ValueError("JIRA_URL_INVALID")
    name = f"[{host}]" if literal and literal.version == 6 else host
    return f"{parts.scheme}://{name}" + (f":{port}" if port is not None else "") + path


def _email(value) -> str | None:
    text = value.strip() if isinstance(value, str) else value
    if text is None or text == "":
        return None
    if not isinstance(text, str) or not text.isascii() or len(text) > 254 or not _EMAIL.fullmatch(text):
        raise ValueError("JIRA_EMAIL_INVALID")
    return text.lower()


def _project(value) -> str:
    text = value.strip().upper() if isinstance(value, str) else ""
    if not _PROJECT.fullmatch(text):
        raise ValueError("JIRA_PROJECT_INVALID")
    return text


def _name_ok(name: str) -> bool:
    return 0 < len(name) <= 60 and name.isprintable() and not unsafe_text(name)


def _name(value, code: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not _name_ok(text):
        raise ValueError(code)
    return text


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _names(value, code: str) -> str:
    """A comma list of 1-10 status names, each kept once (names compare by casefold, as Jira's do)."""
    names = _split(value) if isinstance(value, str) and len(value) <= 1000 else []
    if not 1 <= len(names) <= 10 or not all(_name_ok(name) for name in names):
        raise ValueError(code)
    kept: dict[str, str] = {}
    for name in names:
        kept.setdefault(name.casefold(), name)
    return ", ".join(kept.values())


def _folded(value: str) -> frozenset[str]:
    return frozenset(name.casefold() for name in _split(value))


def validate(values) -> dict:
    """The plain setup values as kept (the token is sealed apart); ValueError names the first bad one."""
    values = values if isinstance(values, dict) else {}
    kept = {"url": _url(values.get("url")), "email": _email(values.get("email")),
            "project": _project(values.get("project")),
            "issue_type": _name(values.get("issue_type"), "JIRA_ISSUE_TYPE_INVALID"),
            "approved_statuses": _names(values.get("approved_statuses"), "JIRA_APPROVED_STATUSES_INVALID"),
            "declined_statuses": _names(values.get("declined_statuses"), "JIRA_DECLINED_STATUSES_INVALID")}
    if _folded(kept["approved_statuses"]) & _folded(kept["declined_statuses"]):
        raise ValueError("JIRA_STATUSES_OVERLAP")
    return kept


def _clean(text) -> str:
    """Plain text on one line: controls, line breaks, format and bidi characters become spaces."""
    return "".join(" " if unsafe_text(char) else char for char in str(text))


def _refused(code: int) -> TicketError:
    if code in (408, 429) or code >= 500:
        return TicketError("JIRA_UNAVAILABLE", retryable=True)
    return TicketError({400: "JIRA_REQUEST_REFUSED", 401: "JIRA_TOKEN_REFUSED", 403: "JIRA_PERMISSION_MISSING",
                        404: "JIRA_NOT_FOUND"}.get(code, f"JIRA_HTTP_{code}"))


def _row_email(row: dict) -> str:
    """A visible address, ASCII lower case; "" when hidden or masked (``user at example dot com``)."""
    email = row.get("emailAddress")
    return email.strip().lower() if isinstance(email, str) and email.isascii() and "@" in email else ""


class Jira:
    def __init__(self, values, secrets, client, clock=time.monotonic):
        self.values, self.client, self.clock, self.deadline = validate(values), client, clock, DEADLINE
        token = secrets.get("token")
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise TicketError("JIRA_TOKEN_INVALID")
        email = self.values["email"]
        self.url = self.values["url"]
        if email is None and (urlsplit(self.url).hostname or "").endswith(".atlassian.net"):
            raise TicketError("JIRA_EMAIL_REQUIRED")  # a Cloud site: its API tokens go with the account's email
        self.auth = "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode() if email else "Bearer " + token
        self.approved = _folded(self.values["approved_statuses"])
        self.declined = _folded(self.values["declined_statuses"])
        self._cloud: bool | None = None
        self._me: str | None = None

    def close(self) -> None:
        self.auth = ""

    def _receive(self, method: str, path: str, params, body, auth: bool) -> bytes:
        """The body of a 2xx answer within ``deadline`` seconds in all, headers included: httpx's timeout bounds only
        each wait, so a server sending a byte now and then could hold a read for ever. The exchange runs in a worker
        thread; past the deadline the call fails and the connection's socket is shut down, which ends a read blocked
        inside httpx (each call opens its own connection, ``Connection: close``, so its socket is always known)."""
        cancelled, done, sockets, outcome = threading.Event(), threading.Event(), [], {}

        def cut(sock) -> None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # already closed

        def trace(event: str, info) -> None:
            if event in ("connection.connect_tcp.complete", "connection.start_tls.complete"):
                stream = info.get("return_value")
                sock = stream.get_extra_info("socket") if stream is not None else None
                if sock is not None:
                    sockets.append(sock)
                    if cancelled.is_set():
                        cut(sock)

        def run() -> None:
            try:
                outcome["body"] = self._exchange(method, path, params, body, auth, trace)
            except TicketError as exc:
                outcome["error"] = exc
            finally:
                done.set()

        threading.Thread(target=run, name="cremore-jira-call", daemon=True).start()
        if not done.wait(self.deadline):
            cancelled.set()
            for sock in sockets:  # a socket appended meanwhile is cut by the trace hook, which sees ``cancelled``
                cut(sock)
            raise TicketError("JIRA_UNAVAILABLE", retryable=True)
        if "error" in outcome:
            raise outcome["error"]
        return outcome["body"]

    def _exchange(self, method: str, path: str, params, body, auth: bool, trace) -> bytes:
        """One request and its body, at most MAX_BYTES, never following a redirect; everything else a fixed code.
        ``clock`` checks the deadline between reads as well (deterministic in tests)."""
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "CreMore/1.0",
                   "Connection": "close"}  # never a pooled connection: its socket would be unknown to the deadline
        if auth:
            headers["Authorization"] = self.auth
        started = self.clock()
        try:
            with self.client.stream(method, self.url + API + path, params=params, json=body, headers=headers,
                                    timeout=TIMEOUT, follow_redirects=False,
                                    extensions={"trace": trace}) as response:
                if not 200 <= response.status_code < 300:
                    raise _refused(response.status_code)
                if response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
                    raise TicketError("JIRA_INVALID_RESPONSE")  # asked for none: every read below is a raw read
                length = response.headers.get("content-length", "")
                if length.strip().isdigit() and int(length) > MAX_BYTES:
                    raise TicketError("JIRA_RESPONSE_TOO_LARGE")
                received = bytearray()
                if self.clock() - started > self.deadline:
                    raise TicketError("JIRA_UNAVAILABLE", retryable=True)
                # Identity encoding and no chunk size: each network read (up to 64 KiB) as it arrives.
                for chunk in response.iter_bytes():
                    if self.clock() - started > self.deadline:
                        raise TicketError("JIRA_UNAVAILABLE", retryable=True)
                    if len(chunk) > MAX_BYTES - len(received):
                        raise TicketError("JIRA_RESPONSE_TOO_LARGE")
                    received.extend(chunk)
                return bytes(received)
        except TicketError:
            raise
        except Exception:  # noqa: BLE001 -- transport errors can quote the request and its Authorization header
            raise TicketError("JIRA_UNAVAILABLE", retryable=True) from None

    def _call(self, method: str, path: str, *, params=None, body=None, auth: bool = True):
        received = self._receive(method, path, params, body, auth)
        try:
            return json.loads(received)
        except (ValueError, RecursionError):
            raise TicketError("JIRA_INVALID_RESPONSE") from None

    def _deployment(self) -> bool:
        """Whether this is Jira Cloud (account ids ``accountId``) rather than Data Center/Server (user ``key``).
        Asked without sign-in first (Cloud documents ``serverInfo`` as anonymous), with it when that is refused."""
        if self._cloud is None:
            try:
                info = self._call("GET", "/serverInfo", auth=False)
            except TicketError as exc:
                if exc.code not in ("JIRA_TOKEN_REFUSED", "JIRA_PERMISSION_MISSING"):
                    raise
                info = self._call("GET", "/serverInfo")
            if not isinstance(info, dict):
                raise TicketError("JIRA_INVALID_RESPONSE")
            cloud = info.get("deploymentType") == "Cloud"
            if cloud and not self.values["email"]:
                raise TicketError("JIRA_EMAIL_REQUIRED")
            self._cloud = cloud
        return self._cloud

    def _field(self) -> str:
        return "accountId" if self._deployment() else "key"

    def _account(self, row) -> str:
        """An account's id as CreMore keeps it (Cloud ``accountId``, Data Center ``key``), or "" when unusable."""
        found = row.get(self._field()) if isinstance(row, dict) else None
        return found if isinstance(found, str) and _REFERENCE.fullmatch(found) else ""

    def _myself(self) -> str:
        if self._me is None:
            field = self._field()
            me = self._call("GET", "/myself")
            found = me.get(field) if isinstance(me, dict) else None
            if not isinstance(found, str) or not 0 < len(found) <= 255:
                raise TicketError("JIRA_INVALID_RESPONSE")
            self._me = found
        return self._me

    def check(self) -> None:
        self._myself()
        project = self.values["project"]
        granted = self._call("GET", "/mypermissions", params={"projectKey": project,
                                                              "permissions": ",".join(PERMISSIONS)})
        table = granted.get("permissions") if isinstance(granted, dict) else None
        if not isinstance(table, dict):
            raise TicketError("JIRA_INVALID_RESPONSE")
        for name in PERMISSIONS:
            entry = table.get(name)
            if not (isinstance(entry, dict) and entry.get("havePermission") is True):
                raise TicketError(f"JIRA_PERMISSION_{name}_MISSING")
        self._call("GET", f"/project/{project}")
        types = self._call("GET", f"/project/{project}/statuses")
        if not isinstance(types, list):
            raise TicketError("JIRA_INVALID_RESPONSE")
        wanted = self.values["issue_type"].casefold()
        found = [row for row in types if isinstance(row, dict) and isinstance(row.get("name"), str)
                 and row["name"].casefold() == wanted]
        if not found:
            raise TicketError("JIRA_ISSUE_TYPE_NOT_FOUND")
        names = {status["name"].casefold() for row in found
                 for status in (row.get("statuses") if isinstance(row.get("statuses"), list) else ())
                 if isinstance(status, dict) and isinstance(status.get("name"), str)}
        if not (self.approved | self.declined) <= names:
            raise TicketError("JIRA_STATUS_NOT_FOUND")

    def find_approver(self, address: str) -> Approver:
        """The one active account whose visible email is ``address``, assignable in the project (checked here,
        before CreMore reserves the request). A hidden email is never guessed at."""
        wanted = address.strip().lower() if isinstance(address, str) else ""
        if not wanted:
            raise TicketError("JIRA_USER_NOT_FOUND")
        me = self._myself()
        cloud = self._deployment()
        rows = self._call("GET", "/user/search", params={"query" if cloud else "username": wanted,
                                                        "maxResults": SEARCH})
        if not isinstance(rows, list):
            raise TicketError("JIRA_INVALID_RESPONSE")
        if len(rows) >= SEARCH:
            raise TicketError("JIRA_USER_AMBIGUOUS")  # the next page may hold another account with the address
        rows = [row for row in rows if isinstance(row, dict)]
        found = [row for row in rows if row.get("active") is True and _row_email(row) == wanted]
        if not found:
            hidden = any(not _row_email(row) for row in rows)
            raise TicketError("JIRA_USER_EMAIL_HIDDEN" if hidden else "JIRA_USER_NOT_FOUND")
        if len(found) > 1:
            raise TicketError("JIRA_USER_AMBIGUOUS")
        [row] = found
        if row.get(self._field()) == me:
            raise TicketError("JIRA_USER_IS_SERVICE_ACCOUNT")
        account = self._account(row)
        if not account:
            raise TicketError("JIRA_USER_REFERENCE_UNSUPPORTED")
        if cloud:
            who = {"accountId": account}
        else:
            name = row.get("name")
            if not isinstance(name, str) or not 0 < len(name) <= 255 or unsafe_text(name):
                raise TicketError("JIRA_INVALID_RESPONSE")
            who = {"username": name, "maxResults": 100}
        assignable = self._call("GET", "/user/assignable/search", params={"project": self.values["project"], **who})
        if not isinstance(assignable, list):
            raise TicketError("JIRA_INVALID_RESPONSE")
        if not any(self._account(item) == account for item in assignable):
            raise TicketError("JIRA_USER_NOT_ASSIGNABLE")
        return Approver(id=account, addresses=(wanted,))

    def _description(self, lines) -> str:
        """Every line literal in one ``{noformat}`` block (no markup, no links); a line that is only a plain web
        address follows the block bare, so Jira shows it as a link."""
        approved = " / ".join(_split(self.values["approved_statuses"]))
        declined = " / ".join(_split(self.values["declined_statuses"]))
        kept, links = [], []
        for line in lines:
            text = _clean(line)
            (links if _LINK.fullmatch(text) else kept).append(text)
        kept += ["", f"마치면 이 이슈를 {approved} 상태로, 할 수 없으면 {declined} 상태로 옮겨 주세요.",
                 f"When done, move this issue to {approved}; if you cannot, move it to {declined}."]
        return "\n".join(["{noformat}", _NOFORMAT.sub("(", "\n".join(kept)), "{noformat}", *links])

    def open_approval(self, request: ApprovalRequest, approver: Approver) -> Opened:
        if not isinstance(approver.id, str) or not _REFERENCE.fullmatch(approver.id):
            raise TicketError("JIRA_REFERENCE_INVALID")
        if self._deployment():
            assignee = {"accountId": approver.id}
        else:  # Data Center assigns by user name; looked up before the issue exists, so a failure leaves nothing
            user = self._call("GET", "/user", params={"key": approver.id})
            name = user.get("name") if isinstance(user, dict) else None
            if not isinstance(name, str) or not 0 < len(name) <= 255 or unsafe_text(name):
                raise TicketError("JIRA_INVALID_RESPONSE")
            assignee = {"name": name}
        summary = " ".join(_clean(request.title).split())[:250] or "[CreMore]"
        created = self._call("POST", "/issue", body={"fields": {
            "project": {"key": self.values["project"]}, "issuetype": {"name": self.values["issue_type"]},
            "summary": summary, "description": self._description(request.lines), "assignee": assignee}})
        key = created.get("key") if isinstance(created, dict) else None
        if not isinstance(key, str) or not _ISSUE_KEY.fullmatch(key):
            raise TicketError("JIRA_INVALID_RESPONSE")
        number = created.get("id")
        if not isinstance(number, str) or not _ISSUE_ID.fullmatch(number):
            raise TicketError("JIRA_INVALID_RESPONSE", ticket=key)  # the issue exists: a person closes it in Jira
        return Opened(ticket=key, approval=number, approver=approver.id, url=f"{self.url}/browse/{key}")

    def _histories(self, issue: dict, number: str) -> tuple[list, bool]:
        """(histories, complete): the whole changelog when it came whole; else (Cloud) only its newest page, checked to
        be the complete suffix. An older part already read is never used: a later move may sit in the gap between."""
        log = issue.get("changelog")
        histories = log.get("histories") if isinstance(log, dict) else None
        if not isinstance(histories, list):
            raise TicketError("JIRA_INVALID_RESPONSE")
        total = log.get("total") if type(log.get("total")) is int else len(histories)
        if total <= len(histories):
            return histories, True
        if not self._deployment():
            raise TicketError("JIRA_CHANGELOG_TOO_LONG")  # Data Center has no changelog page to read
        start = max(0, total - PAGE)
        page = self._call("GET", f"/issue/{number}/changelog", params={"startAt": start, "maxResults": PAGE})
        values = page.get("values") if isinstance(page, dict) else None
        if not isinstance(values, list):
            raise TicketError("JIRA_INVALID_RESPONSE")
        if page.get("startAt") != start or page.get("total") != total or len(values) != total - start:
            raise TicketError("JIRA_CHANGELOG_TOO_LONG")  # not the newest suffix as counted (it changed meanwhile)
        return values, start == 0

    def answer(self, opened: Opened) -> Answer:
        if not (isinstance(opened.ticket, str) and _ISSUE_KEY.fullmatch(opened.ticket)
                and isinstance(opened.approval, str) and _ISSUE_ID.fullmatch(opened.approval)):
            raise TicketError("JIRA_REFERENCE_INVALID")
        # Read by its id: a moved issue keeps it, and a reused key never names another issue here.
        issue = self._call("GET", f"/issue/{opened.approval}", params={"fields": "status", "expand": "changelog"})
        fields = issue.get("fields") if isinstance(issue, dict) and issue.get("id") == opened.approval else None
        status = fields.get("status") if isinstance(fields, dict) else None
        name = status.get("name") if isinstance(status, dict) else None
        status_id = status.get("id") if isinstance(status, dict) else None
        if not isinstance(name, str) or not isinstance(status_id, str) or not status_id:
            raise TicketError("JIRA_INVALID_RESPONSE")
        folded = name.casefold()  # the configured names decide the state; the id decides who moved it there
        state = "APPROVED" if folded in self.approved else "DECLINED" if folded in self.declined else "WAITING"
        if state == "WAITING":
            return Answer(state="WAITING")
        histories, complete = self._histories(issue, opened.approval)
        newest, moves = None, []
        for history in histories:
            number = history.get("id") if isinstance(history, dict) else None
            if not isinstance(number, str) or not number.isdigit():
                continue
            items = history.get("items") if isinstance(history.get("items"), list) else ()
            changed = [item for item in items if isinstance(item, dict) and item.get("field") == "status"
                       and item.get("fieldtype") == "jira"]
            if changed and (newest is None or int(number) > int(newest["id"])):
                newest, moves = history, changed
        if newest is None:
            # The last status change may sit in a part of a long changelog that was not read: never guessed.
            raise TicketError("JIRA_ANSWER_AUTHOR_UNKNOWN" if complete else "JIRA_CHANGELOG_TOO_LONG")
        # Only the newest status change counts, and only if it is the one into the status the issue has now (by
        # id: a renamed or translated status keeps it, while the changelog keeps the old name).
        if not any(item.get("to") == status_id for item in moves):
            raise TicketError("JIRA_ANSWER_AUTHOR_UNKNOWN")
        when = newest.get("created")
        return Answer(state=state, by=self._account(newest.get("author")),
                      at=when if isinstance(when, str) and _WHEN.fullmatch(when) else "")


def build(values, secrets, client) -> Jira:
    try:
        return Jira(values, secrets, client)
    except ValueError as exc:
        raise TicketError(str(exc)) from None


PROVIDER = TicketSystemProvider(id="jira", label="Jira", fields=FIELDS, build=build, validate=validate)
