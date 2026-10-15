"""Owner contact that CreMore sends itself (N2a): mail through the company's SMTP relay and Slack messages from a
bot, set up by an admin in the dashboard.

The relay password and the bot token are sealed in installation settings and opened only to send. A message goes
only where the admin allowed: mail addresses in the allowed domains (a Slack DM is found by such an address) and
the Slack channels the admin listed. It holds one line of subject and plain text, nothing the credential detector
reads as a secret, and each person sends at most ``HOURLY_RECIPIENTS`` recipients an hour. The routes audit every
send and failure by channel, template, count and keyed digests of the recipients and the text (an investigator
holding a message can confirm it came from CreMore), never the text or the addresses themselves. The setup also
names the address people open the console at, which links in CreMore's own messages start with. The bot also posts
CreMore's detection alerts (cremore/alerts) to a listed channel, through ``post_slack``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import ipaddress
import math
import re
import smtplib
import ssl
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from email.message import EmailMessage
from email.utils import formataddr, parsedate_to_datetime
from urllib.parse import urlsplit

from cremore.domain.text import unsafe_text
from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.secretstore.sealed import SealedSecretError, seal_fields, unseal

SETTING_KEY = "contact_delivery"
BUDGET_PREFIX = "contact_budget:"
LOCK_KEY = "contact-delivery:lock"
CHANNELS = ("mail", "slack")
SECURITY = ("starttls", "tls", "none")  # "none": an internal relay without TLS, the company's choice
MAX_RECIPIENTS = 20
MAX_DOMAINS = MAX_SLACK_CHANNELS = 50
HOURLY_RECIPIENTS = 200  # per person, whatever the channel
SUBJECT_MAX, BODY_MAX = 200, 4000
TIMEOUT = 10.0  # seconds for one SMTP or Slack call
SEND_SECONDS = 60.0  # for a whole send: what is not reached by then is reported as not sent
SLACK_API = "https://slack.com/api/"
# What the bot needs: post (chat:write), open a DM (im:write), find a person by mail (users:read.email), and read a
# channel's privacy and sharing before an exposure-response notice goes there (channels:read, groups:read). DMs work
# without the last two; only the channel notices then stop (SLACK_SCOPE_MISSING).
SLACK_SCOPES = ("chat:write", "im:write", "users:read.email", "channels:read", "groups:read")

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})+")
_HOST = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*")
_LOCAL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_SLACK_TOKEN = re.compile(r"xoxb-[A-Za-z0-9-]{10,250}")
_SLACK_CHANNEL = re.compile(r"[CG][A-Z0-9]{8,12}|#[a-z0-9][a-z0-9._-]{0,79}")
_SLACK_ERROR = re.compile(r"[a-z_]{1,60}")
_DIGEST_CONTEXT = b"cremore-contact-digest-v1"


class ContactError(Exception):
    def __init__(self, code: str, http_status: int = 422, retry_after: int | None = None) -> None:
        super().__init__(code)
        # retry_after: the seconds Slack's 429 asked to wait, when it said.
        self.code, self.http_status, self.retry_after = code, http_status, retry_after


def _address(value) -> str:
    """One plain mail address, its domain in lower case."""
    if not isinstance(value, str) or len(value) > 254 or unsafe_text(value):
        raise ContactError("CONTACT_ADDRESS_INVALID")
    local, at, domain = value.strip().rpartition("@")
    domain = domain.lower()
    if not at or len(local) > 64 or not _LOCAL.fullmatch(local) or not _DOMAIN.fullmatch(domain):
        raise ContactError("CONTACT_ADDRESS_INVALID")
    return f"{local}@{domain}"


def address(value) -> str:
    """One plain mail address as CreMore writes to it (ContactError otherwise): ASCII, its domain in lower case."""
    return _address(value)


def _saved(repo) -> dict:
    value = (repo.get_setting(SETTING_KEY) or {}).get("value")
    return value if isinstance(value, dict) else {}


def public(repo) -> dict:
    """The setup as an admin sees it: never the password or the token, only whether one is saved."""
    saved = _saved(repo)
    mail, slack = saved.get("mail"), saved.get("slack")
    return {
        "mail": {**{key: mail.get(key) for key in ("host", "port", "security", "username", "from_address", "from_name")},
                 "password_saved": bool(mail.get("sealed"))} if mail else None,
        "slack": {"token_saved": True, "allowed_channels": list(slack.get("allowed_channels") or [])} if slack else None,
        "allowed_domains": list(saved.get("allowed_domains") or []),
        "console_url": saved.get("console_url"),
        "slack_scopes": list(SLACK_SCOPES),
        "hourly_recipients": HOURLY_RECIPIENTS,
    }


def channels(repo) -> dict:
    """What the contact window needs: the channels CreMore sends itself, and where they may send."""
    saved = _saved(repo)
    return {"mail": bool(saved.get("mail")), "slack": bool(saved.get("slack")),
            "allowed_domains": list(saved.get("allowed_domains") or []),
            "allowed_channels": list((saved.get("slack") or {}).get("allowed_channels") or []),
            "console_url": saved.get("console_url")}


def save(repo, settings, body, actor: str) -> tuple[dict, str]:
    """Replace the setup; a blank secret keeps the saved one where it still applies. (public view, audit note)."""
    if not isinstance(body, dict):
        raise ContactError("CONTACT_SETTINGS_INVALID")
    saved = _saved(repo)
    domains = _names(body.get("allowed_domains", []), MAX_DOMAINS, "CONTACT_DOMAINS_INVALID",
                     lambda item: item.strip().lower(), _DOMAIN.fullmatch)
    console = _console_url(body.get("console_url"))
    try:
        mail, mail_secret = _mail_setup(body.get("mail"), saved.get("mail"), settings)
        slack, slack_secret = _slack_setup(body.get("slack"), saved.get("slack"), settings)
    except ContactError:
        raise
    except Exception:  # noqa: BLE001 -- the key store (Vault, KMS) did not answer: retry later, never a 500
        raise ContactError("CONTACT_SECRET_UNAVAILABLE", 503) from None
    if mail and not domains:
        raise ContactError("CONTACT_DOMAINS_REQUIRED")  # mail goes only to domains the admin allowed
    from cremore.installation_settings import locked_installation_settings

    # The settings lock, as the alert setup's console address change takes it: a save another admin's overtook since
    # this one read the setup (the secrets it keeps) is refused, never written over theirs.
    with locked_installation_settings(repo) as bound:
        if _saved(bound) != saved:
            raise ContactError("SETTING_CHANGED_MEANWHILE", 409)
        bound.put_setting(SETTING_KEY, {"mail": mail, "slack": slack, "allowed_domains": domains,
                                        "console_url": console}, actor)
    # What an audit reader needs to see a widened setup: every value but the secrets.
    before_domains, before_channels = set(saved.get("allowed_domains") or []), set((saved.get("slack") or {}).get("allowed_channels") or [])
    channels_now = set((slack or {}).get("allowed_channels") or [])
    parts = [f"mail={mail['host']}:{mail['port']}/{mail['security']} from={mail['from_address']}" if mail else "mail=off",
             f"slack={'on' if slack else 'off'}", f"mail_secret={mail_secret}", f"slack_secret={slack_secret}",
             f"console={console or 'off'}",
             *(f"+{item}" for item in sorted(set(domains) - before_domains)),
             *(f"-{item}" for item in sorted(before_domains - set(domains))),
             *(f"+{item}" for item in sorted(channels_now - before_channels)),
             *(f"-{item}" for item in sorted(before_channels - channels_now))]
    note, left = "", len(parts)
    for part in parts:
        if len(note) + len(part) > 880:
            break  # a long list ends with how many changes are not shown
        note, left = f"{note} {part}".lstrip(), left - 1
    return public(repo), note + (f" (+{left} more)" if left else "")


def _console_url(value) -> str | None:
    """The console's own address as ``scheme://host[:port]`` (http or https: the company's choice), or None."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 200 or unsafe_text(value):
        raise ContactError("CONTACT_CONSOLE_URL_INVALID")
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise ContactError("CONTACT_CONSOLE_URL_INVALID") from None
    host = parts.hostname or ""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if (parts.scheme not in ("http", "https") or parts.username is not None or parts.password is not None
            or parts.path not in ("", "/") or parts.query or parts.fragment or value.strip().endswith(("?", "#"))
            or not (literal or _HOST.fullmatch(host))):
        raise ContactError("CONTACT_CONSOLE_URL_INVALID")
    name = f"[{host}]" if literal and literal.version == 6 else host
    return f"{parts.scheme}://{name}" + (f":{port}" if port is not None else "")


def console_url(value) -> str | None:
    """The console's address as CreMore keeps it (ContactError otherwise): ``scheme://host[:port]``, or None."""
    return _console_url(value)


def set_console_url(repo, value, actor: str) -> str | None:
    """Change only the console's address (checked as ``save`` checks it), keeping the rest of the setup as saved: the
    address is kept once, here, for every link CreMore sends. The caller audits the change."""
    console = _console_url(value)
    repo.put_setting(SETTING_KEY, {**_saved(repo), "console_url": console}, actor)
    return console


def _names(value, limit: int, code: str, clean, valid) -> list[str]:
    if not isinstance(value, list) or len(value) > limit or any(not isinstance(item, str) for item in value):
        raise ContactError(code)
    out = sorted({clean(item) for item in value})
    if any(not valid(item) for item in out):
        raise ContactError(code)
    return out


def _mail_setup(value, before, settings) -> tuple[dict | None, str]:
    if value is None:
        return None, "none"
    if not isinstance(value, dict):
        raise ContactError("CONTACT_MAIL_INVALID")
    host, port, security = value.get("host"), value.get("port", 587), value.get("security", "starttls")
    username, password, name = value.get("username") or "", value.get("password") or "", value.get("from_name") or ""
    if (not isinstance(host, str) or not _HOST.fullmatch(host.strip().lower()) or type(port) is not int
            or not 1 <= port <= 65535 or security not in SECURITY
            # smtplib sends the account and password as ASCII only
            or not isinstance(username, str) or len(username) > 256 or not username.isascii() or unsafe_text(username)
            or not isinstance(password, str) or len(password) > 1024 or not password.isascii() or unsafe_text(password)
            or not isinstance(name, str) or len(name) > 100 or unsafe_text(name)):
        raise ContactError("CONTACT_MAIL_INVALID")
    host, sender = host.strip().lower(), _address(value.get("from_address"))
    sealed, kept = None, "none"
    if username and password:
        sealed, kept = seal_fields(settings.sealing_keys, {"password": password}), "replaced"
    elif username:
        # A blank password keeps the saved one only for the same relay, port, security and account: a saved
        # password never goes to another server, nor in clear to one it was sent to over TLS.
        same = before and before.get("sealed") and all(before.get(key) == now for key, now in (
            ("host", host), ("port", port), ("security", security), ("username", username)))
        if not same:
            raise ContactError("CONTACT_MAIL_PASSWORD_REQUIRED")
        sealed, kept = before["sealed"], "kept"
    return {"host": host, "port": port, "security": security, "username": username, "from_address": sender,
            "from_name": name.strip(), "sealed": sealed}, kept


def _slack_setup(value, before, settings) -> tuple[dict | None, str]:
    if value is None:
        return None, "none"
    if not isinstance(value, dict):
        raise ContactError("CONTACT_SLACK_INVALID")
    listed = _names(value.get("allowed_channels", []), MAX_SLACK_CHANNELS, "CONTACT_SLACK_CHANNELS_INVALID",
                    lambda item: item.strip(), _SLACK_CHANNEL.fullmatch)
    token = value.get("token")
    if token:
        if not isinstance(token, str) or not _SLACK_TOKEN.fullmatch(token):
            raise ContactError("CONTACT_SLACK_TOKEN_INVALID")  # a bot token (xoxb-), nothing else
        return {"sealed": seal_fields(settings.sealing_keys, {"token": token}), "allowed_channels": listed}, "replaced"
    if before and before.get("sealed"):
        return {"sealed": before["sealed"], "allowed_channels": listed}, "kept"
    raise ContactError("CONTACT_SLACK_TOKEN_REQUIRED")


def recipients(channel: str, to, domains, slack_channels=()) -> list[str]:
    """The recipients as sent: mail addresses in the allowed domains, and for Slack also the listed channels."""
    if not isinstance(to, list) or not 1 <= len(to) <= MAX_RECIPIENTS:
        raise ContactError("CONTACT_RECIPIENTS_INVALID")
    out = []
    for item in to:
        if channel == "slack" and isinstance(item, str) and _SLACK_CHANNEL.fullmatch(item.strip()):
            target = item.strip()
            if target not in slack_channels:
                raise ContactError("CONTACT_RECIPIENT_NOT_ALLOWED")
        else:
            target = _address(item)
            if target.rpartition("@")[2] not in domains:
                raise ContactError("CONTACT_RECIPIENT_NOT_ALLOWED")
        if target not in out:
            out.append(target)
    return out


def message(channel: str, subject, body, contains_credential: Callable[[str], bool]) -> tuple[str, str]:
    """The subject (mail) and text as sent: plain, bounded, and without anything the detector reads as a secret."""
    if not isinstance(body, str) or not body.strip() or len(body) > BODY_MAX or unsafe_text(body.replace("\t", " "), newlines=True):
        raise ContactError("CONTACT_MESSAGE_INVALID")
    if channel == "mail":
        # "=?": an encoded word, which mail clients show decoded, past these checks.
        if (not isinstance(subject, str) or not subject.strip() or len(subject) > SUBJECT_MAX or unsafe_text(subject)
                or "=?" in subject):
            raise ContactError("CONTACT_SUBJECT_INVALID")
        subject = subject.strip()
    else:
        subject = ""
    if contains_credential(f"{subject}\n{body}"):
        raise ContactError("TEXT_CONTAINS_CREDENTIAL")
    return subject, body.strip()


def fingerprints(settings, to: list[str], subject: str, body: str) -> tuple[str, str]:
    """Keyed digests of the recipients and the text, for the audit trail: they confirm a message a reader holds
    came from CreMore, and reveal neither."""
    key = hmac.new(settings.fingerprint_key_bytes, _DIGEST_CONTEXT, hashlib.sha256).digest()

    def mark(text: str) -> str:
        return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    return mark("\n".join(sorted(to))), mark(f"{subject}\n{body}")


def reserve(repo, actor: str, count: int, now: _dt.datetime) -> None:
    """Count ``count`` recipients against the person's hour, or refuse (the relay and the bot are the company's)."""
    from cremore.db.settings_store import locked_settings

    if repo.get_setting(LOCK_KEY) is None:
        repo.claim_slot(LOCK_KEY, 0, "system:contact")  # insert-if-absent: racing first writers both find it after
    key = BUDGET_PREFIX + hashlib.sha256(actor.encode("utf-8")).hexdigest()[:32]
    hour = now.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H")
    with locked_settings(repo, setting_key=LOCK_KEY) as bound:
        value = (bound.get_setting(key) or {}).get("value") or {}
        sent = int(value.get("sent", 0)) if value.get("hour") == hour else 0
        if sent + count > HOURLY_RECIPIENTS:
            raise ContactError("CONTACT_RATE_LIMITED", 429)
        bound.put_setting(key, {"hour": hour, "sent": sent + count}, "system:contact")


def send(repo, settings, channel: str, to: list[str], subject: str, body: str, *, smtp=None, smtp_ssl=None,
         http_client_factory=None) -> dict:
    """Send checked ``to``/``subject``/``body`` (see ``recipients`` and ``message``): {"delivered": [...],
    "failed": [{"to", "code"}]}. The secret is opened here and dropped when the call returns. ``smtp``,
    ``smtp_ssl`` and ``http_client_factory`` replace smtplib and httpx (tests)."""
    cfg = _saved(repo).get(channel) if channel in CHANNELS else None
    if not cfg:
        raise ContactError("CONTACT_CHANNEL_NOT_SET_UP", 409)
    secret = _opened(settings, cfg)
    try:
        if channel == "mail":
            return _send_mail(cfg, secret, to, subject, body, smtp or smtplib.SMTP, smtp_ssl or smtplib.SMTP_SSL)
        with _http_client(http_client_factory) as client:
            return _send_slack(client, secret.get("token", ""), to, body, time.monotonic() + SEND_SECONDS)
    finally:
        secret.clear()


@contextmanager
def slack_session(repo, settings, *, http_client_factory=None) -> Iterator[Callable[..., dict]]:
    """The saved bot opened once for a few Web API calls: ``call(method, data=None, json=None)`` returns Slack's
    answer or raises ContactError with a fixed code (``SLACK_SCOPE_MISSING`` for a scope the bot lacks). The token is
    opened here and dropped when the block ends."""
    cfg = _saved(repo).get("slack")
    if not cfg:
        raise ContactError("CONTACT_CHANNEL_NOT_SET_UP", 409)
    secret = _opened(settings, cfg)
    try:
        with _http_client(http_client_factory) as client:
            def call(method: str, *, data=None, json=None) -> dict:
                try:
                    return _slack(client, secret.get("token", ""), method, data=data, json=json)
                except ContactError as exc:
                    if exc.code == "SLACK_MISSING_SCOPE":
                        raise ContactError("SLACK_SCOPE_MISSING", 409) from None
                    raise

            yield call
    finally:
        secret.clear()


def slack_text(value: str) -> str:
    """Text Slack shows as written: ``<…>`` would be a link or a mention (``<!channel>`` notifies everyone)."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def post_slack(repo, settings, channel: str, message: dict, *, http_client_factory=None) -> None:
    """Post one prepared message (``text`` and Block Kit ``blocks``, cremore/alerts) to a channel the admin listed,
    with the saved bot. ContactError as ``send``; a 429 carries Slack's Retry-After. The token is opened here and
    dropped when the call returns."""
    cfg = _saved(repo).get("slack")
    if not cfg:
        raise ContactError("CONTACT_CHANNEL_NOT_SET_UP", 409)
    if channel not in (cfg.get("allowed_channels") or ()):
        raise ContactError("CONTACT_RECIPIENT_NOT_ALLOWED")
    secret = _opened(settings, cfg)
    try:
        with _http_client(http_client_factory) as client:
            _slack(client, secret.get("token", ""), "chat.postMessage", json={**message, "channel": channel})
    finally:
        secret.clear()


def _opened(settings, cfg) -> dict:
    try:
        return unseal(settings.sealing_keys, cfg["sealed"]) if cfg.get("sealed") else {}
    except SealedSecretError:
        raise ContactError("CONTACT_SECRET_UNAVAILABLE", 409) from None
    except Exception:  # noqa: BLE001 -- the key store (Vault, KMS) did not answer: retry later, never a 500
        raise ContactError("CONTACT_SECRET_UNAVAILABLE", 503) from None


def _http_client(http_client_factory):
    if http_client_factory is not None:
        return http_client_factory()
    import httpx

    return httpx.Client(follow_redirects=False)


def _send_mail(cfg, secret, to, subject, body, smtp, smtp_ssl) -> dict:
    mail = EmailMessage()  # the default policy refuses a line break in any header
    mail["From"] = formataddr((cfg["from_name"], cfg["from_address"])) if cfg.get("from_name") else cfg["from_address"]
    mail["To"] = ", ".join(to)
    mail["Subject"] = subject
    mail.set_content(body)
    context = ssl.create_default_context()
    stage = "connect"
    try:
        server = (smtp_ssl(cfg["host"], cfg["port"], timeout=TIMEOUT, context=context) if cfg["security"] == "tls"
                  else smtp(cfg["host"], cfg["port"], timeout=TIMEOUT))
        with server:
            if cfg["security"] == "starttls":
                stage = "starttls"
                server.starttls(context=context)
            if cfg.get("username"):
                stage = "login"
                server.login(cfg["username"], secret.get("password", ""))
            stage = "send"
            refused = server.send_message(mail) or {}
    except smtplib.SMTPAuthenticationError:
        raise ContactError("SMTP_AUTH_FAILED", 502) from None
    except smtplib.SMTPRecipientsRefused:
        raise ContactError("SMTP_RECIPIENTS_REFUSED", 502) from None
    except smtplib.SMTPNotSupportedError:
        raise ContactError("SMTP_STARTTLS_UNSUPPORTED" if stage == "starttls" else "SMTP_AUTH_UNSUPPORTED", 502) from None
    except UnicodeError:  # an account or password saved before only ASCII was taken
        raise ContactError("SMTP_AUTH_FAILED", 502) from None
    except (smtplib.SMTPException, OSError):  # connection, TLS and relay errors (their text can echo the account)
        raise ContactError("SMTP_UNAVAILABLE", 502) from None
    return {"delivered": [address for address in to if address not in refused],
            "failed": [{"to": address, "code": "SMTP_RECIPIENT_REFUSED"} for address in to if address in refused]}


def _slack(client, token: str, method: str, *, data=None, json=None) -> dict:
    try:
        # Always a POST: a person's address goes in the form body, never in a URL a proxy or log keeps.
        response = bounded_request(client, "POST", SLACK_API + method, data=data, json=json,
                                   headers={"Authorization": "Bearer " + token}, timeout=TIMEOUT,
                                   follow_redirects=False, max_response_bytes=1 << 20)
    except HTTPResponseTooLarge:
        raise ContactError("SLACK_RESPONSE_LIMIT", 502) from None
    except Exception:  # noqa: BLE001 -- transport errors can carry the token
        raise ContactError("SLACK_UNAVAILABLE", 502) from None
    if response.status_code == 429:
        headers = getattr(response, "headers", None) or {}
        raise ContactError("SLACK_RATE_LIMITED", 502, retry_after(headers.get("retry-after")))
    if response.status_code >= 500:  # Slack itself failed, whatever its body says: nothing else would go now either
        raise ContactError("SLACK_UNAVAILABLE", 502)
    try:
        payload = response.json()
    except (ValueError, RecursionError):
        payload = None
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        error = payload.get("error") if isinstance(payload, dict) else None
        raise ContactError("SLACK_" + error.upper() if isinstance(error, str) and _SLACK_ERROR.fullmatch(error)
                           else "SLACK_REQUEST_REFUSED", 502)
    return payload


def retry_after(value) -> int | None:
    """A 429's Retry-After (seconds or an HTTP date) as whole seconds within a day, or None when it says nothing."""
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            stamp = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if stamp.tzinfo is None:
            return None
        seconds = (stamp - _dt.datetime.now(_dt.UTC)).total_seconds()
    return min(86400, max(0, math.ceil(seconds))) if math.isfinite(seconds) else None


def _id(payload: dict, field: str) -> str | None:
    entry = payload.get(field)
    value = entry.get("id") if isinstance(entry, dict) else None
    return value if isinstance(value, str) and value else None


# The bot cannot send at all: nothing else would go either.
_SLACK_FATAL = ("SLACK_INVALID_AUTH", "SLACK_NOT_AUTHED", "SLACK_TOKEN_REVOKED", "SLACK_ACCOUNT_INACTIVE",
                "SLACK_MISSING_SCOPE", "SLACK_UNAVAILABLE", "SLACK_RATE_LIMITED")


def _send_slack(client, token: str, to: list[str], text: str, deadline: float) -> dict:
    text = slack_text(text)  # sent as text: never a link, a mention or a <!channel>
    delivered: list[str] = []
    failed: list[dict] = []
    for index, target in enumerate(to):
        if time.monotonic() > deadline:
            if not delivered:
                raise ContactError("CONTACT_TIMED_OUT", 502)
            failed.extend({"to": rest, "code": "CONTACT_TIMED_OUT"} for rest in to[index:])
            break
        try:
            channel = target
            if "@" in target:  # a person, by the address their workspace account has: a direct message
                user = _id(_slack(client, token, "users.lookupByEmail", data={"email": target}), "user")
                channel = _id(_slack(client, token, "conversations.open", json={"users": user}), "channel") if user else None
                if channel is None:
                    raise ContactError("SLACK_USER_NOT_FOUND", 502)
            _slack(client, token, "chat.postMessage", json={"channel": channel, "text": text, "link_names": False,
                                                            "unfurl_links": False, "unfurl_media": False})
            delivered.append(target)
        except ContactError as exc:
            if exc.code not in _SLACK_FATAL:
                failed.append({"to": target, "code": exc.code})
                continue
            if not delivered:
                raise  # nothing went out
            # Some did go: that is what happened, and the rest did not.
            failed.extend({"to": rest, "code": exc.code} for rest in to[index:])
            break
    return {"delivered": delivered, "failed": failed}
