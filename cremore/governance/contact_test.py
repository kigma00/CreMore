"""Owner contact sent by CreMore, against a fake SMTP relay and a fake Slack Web API: the setup keeps its secrets
sealed and out of every answer, messages go only where the admin allowed and carry no secret, each person's hour
is bounded, and each channel's failures come back as codes (what went out before a failure still counts)."""

import datetime as dt
import json
import smtplib
from urllib.parse import parse_qs

import httpx
import pytest

from cremore.db.repository import InMemoryRepository
from cremore.governance import contact
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.secretstore.sealed import unseal

# Built at run time: nothing secret-shaped sits in the source.
PASSWORD = "relay-" + "p" * 12
TOKEN = "xoxb-" + "1" * 12 + "-" + "a" * 24
MAIL = {"host": "smtp.example.com", "port": 587, "security": "starttls", "username": "cremore", "password": PASSWORD,
        "from_address": "security@example.com", "from_name": "보안팀"}
CHANNELS = ["#security-alerts", "C0123ABCD9"]
NOW = dt.datetime(2026, 9, 29, 9, 30, tzinfo=dt.UTC)


def no_secret(_text):
    return False


class Relay:
    """A fake SMTP connection that records what it was asked."""

    def __init__(self, *, refuse=(), fail=None):
        self.refuse, self.fail, self.calls, self.sent = set(refuse), fail, [], []

    def __call__(self, host, port, timeout=None, context=None):
        self.calls.append(("connect", host, port, timeout, context is not None))
        if self.fail == "connect":
            raise OSError("connection refused by " + host)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append(("quit",))

    def starttls(self, context=None):
        self.calls.append(("starttls", context is not None))
        if self.fail == "starttls":
            raise smtplib.SMTPNotSupportedError("STARTTLS extension not supported by server.")

    def login(self, user, password):
        self.calls.append(("login", user, password == PASSWORD))
        if self.fail == "auth":
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials for cremore")
        if self.fail == "noauth":
            raise smtplib.SMTPNotSupportedError("SMTP AUTH extension not supported by server.")
        if self.fail == "ascii":
            "é".encode("ascii")  # what smtplib does with a non-ASCII account

    def send_message(self, message):
        self.sent.append(message)
        return {address: (550, b"no such user") for address in self.refuse}


class Slack:
    """The Slack Web API methods the bot uses, each a POST."""

    def __init__(self, *, users=None, error=None, limit_after=None, odd=False):
        self.users, self.error, self.calls = users or {"kim@example.com": "U01"}, error, []
        self.limit_after, self.odd, self.posted = limit_after, odd, 0

    def __call__(self, request):
        assert request.headers["authorization"] == "Bearer " + TOKEN and request.url.host == "slack.com"
        assert request.method == "POST" and not request.url.query  # nothing in the URL
        method = request.url.path.rsplit("/", 1)[1]
        form = request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded")
        body = {k: v[0] for k, v in parse_qs(request.content.decode()).items()} if form else json.loads(request.content)
        self.calls.append((method, body))
        if self.error:
            return httpx.Response(200, json={"ok": False, "error": self.error})
        if method == "users.lookupByEmail":
            user = self.users.get(body["email"])
            if self.odd:
                return httpx.Response(200, json={"ok": True, "user": "U01"})  # not an object
            return httpx.Response(200, json={"ok": True, "user": {"id": user}} if user else {"ok": False, "error": "users_not_found"})
        if method == "conversations.open":
            return httpx.Response(200, json={"ok": True, "channel": {"id": "D" + body["users"]}})
        assert method == "chat.postMessage"
        if self.limit_after is not None and self.posted >= self.limit_after:
            return httpx.Response(429, headers={"retry-after": "30"})
        self.posted += 1
        return httpx.Response(200, json={"ok": True, "ts": "1.0"})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def setup(repo, **overrides):
    body = {"mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": CHANNELS}, "allowed_domains": ["Example.com"], **overrides}
    return contact.save(repo, SETTINGS, body, "admin")


def test_the_setup_is_sealed_and_never_shown():
    repo = InMemoryRepository()
    view, note = setup(repo)
    assert view["mail"] == {"host": "smtp.example.com", "port": 587, "security": "starttls", "username": "cremore",
                            "from_address": "security@example.com", "from_name": "보안팀", "password_saved": True}
    assert view["slack"] == {"token_saved": True, "allowed_channels": sorted(CHANNELS)} and view["allowed_domains"] == ["example.com"]
    # The audit note shows every value but the secrets, and what was allowed anew.
    assert note == ("mail=smtp.example.com:587/starttls from=security@example.com slack=on mail_secret=replaced"
                    " slack_secret=replaced console=off +example.com +#security-alerts +C0123ABCD9")
    stored = json.dumps(repo.get_setting(contact.SETTING_KEY), default=str)
    assert PASSWORD not in stored and TOKEN not in stored and PASSWORD not in json.dumps(view) + note
    assert unseal(SETTINGS.sealing_keys, repo.get_setting(contact.SETTING_KEY)["value"]["mail"]["sealed"])["password"] == PASSWORD
    # A blank secret keeps the saved one only for the same relay, port, security and account.
    _view, note = setup(repo, mail={**MAIL, "password": ""}, slack={"allowed_channels": CHANNELS}, allowed_domains=["example.com", "corp.example.com"])
    assert "mail_secret=kept slack_secret=kept console=off +corp.example.com" in note
    # A long list of changes ends with how many are not shown.
    many = [f"{'d' * 60}{number:02}.example.com" for number in range(20)]
    _view, note = setup(repo, mail={**MAIL, "password": ""}, slack={"allowed_channels": CHANNELS}, allowed_domains=["example.com", *many])
    assert len(note) < 900 and note.endswith(" more)") and "-corp.example.com" not in note
    shown = sum(item in note for item in many)
    assert note.endswith(f" (+{20 - shown + 1} more)")  # the domains not shown, and -corp.example.com after them
    for changed in ({"host": "relay.other.example"}, {"security": "none", "port": 25}, {"username": "someone"}):
        with pytest.raises(contact.ContactError) as refused:
            setup(repo, mail={**MAIL, "password": "", **changed})
        assert refused.value.code == "CONTACT_MAIL_PASSWORD_REQUIRED", changed
    # A relay without an account needs no password; mail needs allowed domains.
    view, _note = setup(repo, mail={**MAIL, "username": "", "password": ""})
    assert view["mail"]["password_saved"] is False
    with pytest.raises(contact.ContactError) as refused:
        setup(repo, allowed_domains=[])
    assert refused.value.code == "CONTACT_DOMAINS_REQUIRED"
    assert contact.channels(repo) == {"mail": True, "slack": True, "allowed_domains": ["example.com"],
                                      "allowed_channels": sorted(CHANNELS), "console_url": None}


@pytest.mark.parametrize(("given", "kept"), [
    ("https://CreMore.Example.com/", "https://cremore.example.com"), ("http://localhost:3000", "http://localhost:3000"),
    ("http://10.0.0.5:8443", "http://10.0.0.5:8443"), ("https://[::1]:3000", "https://[::1]:3000"), ("", None)])
def test_the_console_address_links_start_with_is_an_origin(given, kept):
    repo = InMemoryRepository()
    view, note = setup(repo, console_url=given)
    assert view["console_url"] == contact.channels(repo)["console_url"] == kept and f"console={kept or 'off'}" in note


@pytest.mark.parametrize(("field", "value", "code"), [
    ("console_url", "ftp://cremore.example.com", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "https://cremore.example.com/console", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "https://cremore.example.com?next=x", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "https://cremore.example.com#x", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "https://user@cremore.example.com", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "https://cremore.example.com:99999", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "https://cre more.example.com", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", "cremore.example.com", "CONTACT_CONSOLE_URL_INVALID"),
    ("console_url", ["https://cremore.example.com"], "CONTACT_CONSOLE_URL_INVALID"),
    ("mail", {**MAIL, "host": "smtp.example.com:25"}, "CONTACT_MAIL_INVALID"),
    ("mail", {**MAIL, "port": "587"}, "CONTACT_MAIL_INVALID"),
    ("mail", {**MAIL, "security": "ssl3"}, "CONTACT_MAIL_INVALID"),
    ("mail", {**MAIL, "from_name": "보안" + chr(0x202E) + "팀"}, "CONTACT_MAIL_INVALID"),
    ("mail", {**MAIL, "password": "relay-" + chr(0xE9) * 3}, "CONTACT_MAIL_INVALID"),  # smtplib sends ASCII only
    ("mail", {**MAIL, "username": "관리자"}, "CONTACT_MAIL_INVALID"),
    ("mail", {**MAIL, "from_address": "security@example.com\r\nBcc: x@evil.test"}, "CONTACT_ADDRESS_INVALID"),
    ("slack", {"token": "xoxp-" + "1" * 30}, "CONTACT_SLACK_TOKEN_INVALID"),
    ("slack", {}, "CONTACT_SLACK_TOKEN_REQUIRED"),
    ("slack", {"token": TOKEN, "allowed_channels": ["#General"]}, "CONTACT_SLACK_CHANNELS_INVALID"),
    ("slack", {"token": TOKEN, "allowed_channels": "#security-alerts"}, "CONTACT_SLACK_CHANNELS_INVALID"),
    ("allowed_domains", ["example"], "CONTACT_DOMAINS_INVALID"),
])
def test_a_setup_is_checked_before_it_is_saved(field, value, code):
    repo = InMemoryRepository()
    with pytest.raises(contact.ContactError) as refused:
        setup(repo, **{field: value})
    assert refused.value.code == code and repo.get_setting(contact.SETTING_KEY) is None


def test_messages_go_only_where_the_admin_allowed_and_carry_no_secret():
    domains = ["example.com"]
    assert contact.recipients("mail", ["Kim@Example.COM", "kim@example.com", "lee@example.com"], domains) == \
        ["Kim@example.com", "kim@example.com", "lee@example.com"]
    assert contact.recipients("slack", ["#security-alerts", "C0123ABCD9", "kim@example.com"], domains, CHANNELS) == \
        ["#security-alerts", "C0123ABCD9", "kim@example.com"]
    for channel, to, code in (("mail", ["kim@other.test"], "CONTACT_RECIPIENT_NOT_ALLOWED"),
                              ("mail", ["#security-alerts"], "CONTACT_ADDRESS_INVALID"),
                              ("slack", ["kim@other.test"], "CONTACT_RECIPIENT_NOT_ALLOWED"),
                              ("slack", ["#general"], "CONTACT_RECIPIENT_NOT_ALLOWED"),  # a channel the admin did not list
                              ("slack", ["G0123ABCD9"], "CONTACT_RECIPIENT_NOT_ALLOWED"),
                              ("mail", [], "CONTACT_RECIPIENTS_INVALID"),
                              ("mail", [f"u{n}@example.com" for n in range(21)], "CONTACT_RECIPIENTS_INVALID")):
        with pytest.raises(contact.ContactError) as refused:
            contact.recipients(channel, to, domains, CHANNELS)
        assert refused.value.code == code, to
    assert contact.message("mail", " 확인 요청 ", "첫 줄\n\t둘째 줄\n", no_secret) == ("확인 요청", "첫 줄\n\t둘째 줄")
    for channel, subject, body, code in (("mail", "a\nb", "text", "CONTACT_SUBJECT_INVALID"),
                                         ("mail", "", "text", "CONTACT_SUBJECT_INVALID"),
                                         ("mail", "=?utf-8?b?7ZmV7J24?=", "text", "CONTACT_SUBJECT_INVALID"),  # an encoded word
                                         ("slack", "", "hi " + chr(0x202E), "CONTACT_MESSAGE_INVALID"),
                                         ("slack", "", " ", "CONTACT_MESSAGE_INVALID"),
                                         ("slack", "", "x" * 4001, "CONTACT_MESSAGE_INVALID")):
        with pytest.raises(contact.ContactError) as refused:
            contact.message(channel, subject, body, no_secret)
        assert refused.value.code == code
    seen = []
    with pytest.raises(contact.ContactError) as refused:
        contact.message("mail", "subject", "body", lambda text: seen.append(text) or True)
    assert refused.value.code == "TEXT_CONTAINS_CREDENTIAL" and seen == ["subject\nbody"]


def test_mail_goes_through_the_relay_with_tls_and_its_account():
    repo = InMemoryRepository()
    setup(repo)
    relay = Relay(refuse={"lee@example.com"})
    sent = contact.send(repo, SETTINGS, "mail", ["kim@example.com", "lee@example.com"], "확인 요청", "본문", smtp=relay)
    assert sent == {"delivered": ["kim@example.com"], "failed": [{"to": "lee@example.com", "code": "SMTP_RECIPIENT_REFUSED"}]}
    assert relay.calls == [("connect", "smtp.example.com", 587, contact.TIMEOUT, False), ("starttls", True),
                           ("login", "cremore", True), ("quit",)]
    mail = relay.sent[0]
    assert mail["To"] == "kim@example.com, lee@example.com" and mail["Subject"] == "확인 요청" and "security@example.com" in mail["From"]
    assert mail.get_content().strip() == "본문"
    # Implicit TLS on its own port; each failure is its own code, never the relay's text.
    setup(repo, mail={**MAIL, "security": "tls", "port": 465})
    relay = Relay()
    contact.send(repo, SETTINGS, "mail", ["kim@example.com"], "s", "b", smtp_ssl=relay)
    assert relay.calls[0] == ("connect", "smtp.example.com", 465, contact.TIMEOUT, True)
    for fail, code in (("auth", "SMTP_AUTH_FAILED"), ("connect", "SMTP_UNAVAILABLE"), ("noauth", "SMTP_AUTH_UNSUPPORTED"),
                       ("ascii", "SMTP_AUTH_FAILED")):
        with pytest.raises(contact.ContactError) as failed:
            contact.send(repo, SETTINGS, "mail", ["kim@example.com"], "s", "b", smtp_ssl=Relay(fail=fail))
        assert failed.value.code == code and "cremore" not in str(failed.value) and failed.value.__cause__ is None
    setup(repo, mail={**MAIL, "port": 587})
    with pytest.raises(contact.ContactError) as failed:
        contact.send(repo, SETTINGS, "mail", ["kim@example.com"], "s", "b", smtp=Relay(fail="starttls"))
    assert failed.value.code == "SMTP_STARTTLS_UNSUPPORTED"


def test_slack_messages_a_person_by_their_address_or_a_listed_channel_as_plain_text():
    repo = InMemoryRepository()
    setup(repo)
    slack = Slack()
    sent = contact.send(repo, SETTINGS, "slack", ["kim@example.com", "#security-alerts", "park@example.com"], "",
                        "<!channel> 확인 & 회신", http_client_factory=slack.client)
    assert sent == {"delivered": ["kim@example.com", "#security-alerts"],
                    "failed": [{"to": "park@example.com", "code": "SLACK_USERS_NOT_FOUND"}]}
    assert slack.calls[0] == ("users.lookupByEmail", {"email": "kim@example.com"})  # in the form body, not the URL
    posted = [body for method, body in slack.calls if method == "chat.postMessage"]
    assert [body["channel"] for body in posted] == ["DU01", "#security-alerts"]
    assert posted[0]["text"] == "&lt;!channel&gt; 확인 &amp; 회신" and posted[0]["link_names"] is False and posted[0]["unfurl_links"] is False
    # A bot that cannot send stops the whole message, with Slack's code.
    with pytest.raises(contact.ContactError) as failed:
        contact.send(repo, SETTINGS, "slack", ["#security-alerts"], "", "text", http_client_factory=Slack(error="invalid_auth").client)
    assert failed.value.code == "SLACK_INVALID_AUTH" and failed.value.http_status == 502
    # What went out before Slack stopped answering is sent; the rest is not, with the reason.
    sent = contact.send(repo, SETTINGS, "slack", ["#security-alerts", "C0123ABCD9", "kim@example.com"], "", "text",
                        http_client_factory=Slack(limit_after=1).client)
    assert sent == {"delivered": ["#security-alerts"], "failed": [{"to": "C0123ABCD9", "code": "SLACK_RATE_LIMITED"},
                                                                 {"to": "kim@example.com", "code": "SLACK_RATE_LIMITED"}]}
    # An answer of the wrong shape is a code for that person, not a crash.
    sent = contact.send(repo, SETTINGS, "slack", ["kim@example.com", "#security-alerts"], "", "text", http_client_factory=Slack(odd=True).client)
    assert sent == {"delivered": ["#security-alerts"], "failed": [{"to": "kim@example.com", "code": "SLACK_USER_NOT_FOUND"}]}


def test_a_slack_server_error_stops_the_whole_message_whatever_its_body_says():
    repo = InMemoryRepository()
    setup(repo)
    calls = []

    def down():
        return httpx.Client(transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(503, text="<html>Service Unavailable</html>")))

    with pytest.raises(contact.ContactError) as failed:
        contact.send(repo, SETTINGS, "slack", ["#security-alerts", "C0123ABCD9"], "", "text", http_client_factory=down)
    assert (failed.value.code, len(calls)) == ("SLACK_UNAVAILABLE", 1)  # not a refusal of one recipient


@pytest.mark.parametrize(("value", "seconds"), [
    ("30", 30), ("0", 0), ("2.2", 3), ("-5", 0), ("999999", 86400), ("NaN", None), ("inf", None), ("soon", None),
    ("Mon, 01 Jan 2026 00:00:00", None), (None, None), ("1" * 200, None)])
def test_a_retry_after_is_whole_seconds_within_a_day(value, seconds):
    assert contact.retry_after(value) == seconds


def test_a_retry_after_date_counts_from_now_and_a_rate_limit_carries_it():
    later = (dt.datetime.now(dt.UTC) + dt.timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert 85 <= contact.retry_after(later) <= 91
    assert contact.retry_after("Mon, 01 Jan 2024 00:00:00 GMT") == 0
    repo = InMemoryRepository()
    setup(repo)
    with pytest.raises(contact.ContactError) as limited:
        contact.post_slack(repo, SETTINGS, "#security-alerts", {"text": "t", "blocks": []},
                           http_client_factory=Slack(limit_after=0).client)
    assert (limited.value.code, limited.value.retry_after) == ("SLACK_RATE_LIMITED", 30)
    with pytest.raises(contact.ContactError) as refused:
        contact.post_slack(repo, SETTINGS, "#general", {"text": "t", "blocks": []}, http_client_factory=Slack().client)
    assert refused.value.code == "CONTACT_RECIPIENT_NOT_ALLOWED"


def test_a_save_another_admin_overtook_is_refused(monkeypatch):
    from cremore import installation_settings

    repo = InMemoryRepository()
    setup(repo)
    real = installation_settings.locked_installation_settings

    def overtaken(bound_repo):
        contact.set_console_url(bound_repo, "https://other.example.com", "bob")  # bob's save lands first
        return real(bound_repo)

    monkeypatch.setattr(installation_settings, "locked_installation_settings", overtaken)
    with pytest.raises(contact.ContactError) as refused:
        setup(repo, slack={"allowed_channels": CHANNELS})
    assert (refused.value.code, refused.value.http_status) == ("SETTING_CHANGED_MEANWHILE", 409)
    assert contact.channels(repo)["console_url"] == "https://other.example.com"


def test_a_send_stops_at_its_deadline(monkeypatch):
    repo = InMemoryRepository()
    setup(repo)
    monkeypatch.setattr(contact, "SEND_SECONDS", -1)
    with pytest.raises(contact.ContactError) as failed:
        contact.send(repo, SETTINGS, "slack", ["#security-alerts"], "", "text", http_client_factory=Slack().client)
    assert failed.value.code == "CONTACT_TIMED_OUT"


def test_each_person_sends_a_bounded_number_an_hour():
    repo = InMemoryRepository()
    contact.reserve(repo, "ann", contact.HOURLY_RECIPIENTS - 5, NOW)
    contact.reserve(repo, "ann", 5, NOW + dt.timedelta(minutes=20))
    with pytest.raises(contact.ContactError) as refused:
        contact.reserve(repo, "ann", 1, NOW + dt.timedelta(minutes=25))
    assert (refused.value.code, refused.value.http_status) == ("CONTACT_RATE_LIMITED", 429)
    contact.reserve(repo, "bob", 20, NOW)  # another person has their own hour
    contact.reserve(repo, "ann", 20, NOW + dt.timedelta(minutes=40))  # the next hour starts over
    assert "ann" not in json.dumps([row["key"] for row in repo.list_settings(contact.BUDGET_PREFIX)])


def test_digests_confirm_a_message_without_showing_it():
    one = contact.fingerprints(SETTINGS, ["kim@example.com", "lee@example.com"], "확인 요청", "본문")
    assert one == contact.fingerprints(SETTINGS, ["lee@example.com", "kim@example.com"], "확인 요청", "본문")
    assert one[0] != contact.fingerprints(SETTINGS, ["kim@example.com"], "확인 요청", "본문")[0]
    assert one[1] != contact.fingerprints(SETTINGS, ["kim@example.com", "lee@example.com"], "확인 요청", "본문!")[1]
    assert all(len(mark) == 16 and "kim" not in mark for mark in one)


def test_nothing_is_sent_on_a_channel_that_is_not_set_up_or_whose_secret_cannot_be_opened():
    repo = InMemoryRepository()
    with pytest.raises(contact.ContactError) as refused:
        contact.send(repo, SETTINGS, "mail", ["kim@example.com"], "s", "b", smtp=Relay())
    assert (refused.value.code, refused.value.http_status) == ("CONTACT_CHANNEL_NOT_SET_UP", 409)
    setup(repo)
    value = repo.get_setting(contact.SETTING_KEY)["value"]
    repo.put_setting(contact.SETTING_KEY, {**value, "slack": {"sealed": "not-a-sealed-value"}}, "admin")
    with pytest.raises(contact.ContactError) as refused:
        contact.send(repo, SETTINGS, "slack", ["#security-alerts"], "", "b", http_client_factory=Slack().client)
    assert refused.value.code == "CONTACT_SECRET_UNAVAILABLE"
