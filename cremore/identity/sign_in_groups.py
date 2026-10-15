"""Console roles for people who sign in with Google, from the company's Workspace groups (owner decision 2026-10-02).

A Google ID token carries no groups claim. On a team install whose sign-in issuer is Google, the role groups
(``OIDC_*_GROUP`` set to group addresses such as cremore-admins@acme.com) are read from Google Workspace instead:

- the API publishes which groups it maps (``WANTED``) and never opens a credential;
- the worker reads their members, people in groups inside them included, every few minutes through the Google
  Workspace people connection -- the people directory a team install takes from its sign-in IdP
  (cremore.onboarding.sign_in) -- and keeps only keyed digests of the addresses (``KEY``, cremore.identity.keys);
- the API turns a sign-in's verified address of that Workspace (``hd``) into the groups holding its digest.

Each group is read on its own: one that cannot be read grants nothing until it can, and does not hold the others back.
When no group can be read the last membership is kept for an hour, so people keep signing in through a short Google
outage; a cause on the installation's or the company's side (``LOCAL``: no people connection, a credential it cannot
open, a delegation, admin or key Workspace no longer accepts) ends it at once.
Before any read, and after that hour, the groups grant nothing; Settings > Sign-in says why.
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
import time

GOOGLE = ("https://accounts.google.com", "accounts.google.com")
WANTED = "sign_in_groups:wanted"
KEY = "sign_in_groups"
SLOT = "sign_in_groups:slot"
INTERVAL = _dt.timedelta(minutes=5)
MAX_AGE = _dt.timedelta(hours=1)
SKEW = _dt.timedelta(minutes=5)  # a read stamped later than this is a clock that runs ahead: it grants nothing
ROLES = ("viewer", "analyst", "remediator", "admin")
# Causes on this installation's or the company's own side (no people connection, a credential or delegation that is
# not or no longer right): the membership read before them is not kept. Google's token endpoint refuses a deleted,
# disabled or expired key, a deleted admin or a removed delegation (invalid_grant, disabled_client, access_denied:
# TOKEN_REFUSED); a demoted admin is refused the read (ACCESS_DENIED). Rate limits and outages have codes of their own.
LOCAL = frozenset({"GOOGLE_WORKSPACE_PEOPLE_DIRECTORY_REQUIRED", "SECRET_UNAVAILABLE",
                   "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED", "GOOGLE_WORKSPACE_ADMIN_INVALID",
                   "GOOGLE_WORKSPACE_ADMIN_OUTSIDE_DOMAIN", "GOOGLE_WORKSPACE_KEY_INVALID",
                   "GOOGLE_WORKSPACE_TOKEN_REFUSED", "GOOGLE_WORKSPACE_ACCESS_DENIED"})
_ADDRESS = re.compile(r"[a-z0-9._%+'-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
logger = logging.getLogger(__name__)


def google(settings) -> bool:
    """Whether people sign in with Google on this install."""
    return (getattr(settings, "auth_mode", "local") == "oidc"
            and (getattr(settings, "oidc_issuer_url", "") or "").rstrip("/") in GOOGLE)


def role_groups(settings) -> dict[str, str]:
    """``{role: group address}`` as configuration names them, lower case; a value that is no address is left out."""
    found = {}
    for role in ROLES:
        value = (getattr(settings, f"oidc_{role}_group", "") or "").strip().lower()
        if value and _ADDRESS.fullmatch(value):
            found[role] = value
        elif value:
            logger.warning("OIDC_%s_GROUP is not a group address and grants nobody a role", role.upper())
    return found


def publish_wanted(repo, settings) -> None:
    """The API's part: which groups the worker reads (none unless people sign in with Google). Written only when it
    changes, so many API processes agree without churn."""
    groups = sorted(set(role_groups(settings).values())) if google(settings) else []
    current = (repo.get_setting(WANTED) or {}).get("value")
    if current is None and not groups:
        return
    if (current or {}).get("groups") != groups:
        repo.put_setting(WANTED, {"groups": groups}, "system:api")


def _iso(moment) -> str:
    return moment.astimezone(_dt.UTC).isoformat()


def _time(value):
    try:
        moment = _dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return moment if moment.tzinfo else None


def _ascii_address(value) -> str | None:
    """An address compared as Workspace keeps it: ASCII, trimmed, lower case (no Unicode folding)."""
    if not isinstance(value, str) or not value.isascii():
        return None
    value = value.strip().lower()
    return value if _ADDRESS.fullmatch(value) else None


def _directory(repo):
    """The Google Workspace people connection: the oldest active one that reads people (the store lists oldest first)."""
    from cremore.onboarding.store import ProviderConnectionStore, active_plans

    return next((record for record in ProviderConnectionStore(repo).list()
                 if record["provider"] == "google_workspace" and record["status"] == "ACTIVE"
                 and "identity" in active_plans(record)), None)


def _later(stamp, now) -> bool:
    """Whether a stored read began after this one did -- within the hour no read outlasts; a stamp further ahead is a
    clock that ran ahead, which never blocks the reads after it."""
    return stamp is not None and now < stamp <= now + MAX_AGE


def _write(repo, now, change) -> None:
    """Store ``change(current)`` unless a read that began later already stored its own (a slow read never writes
    an older membership over a newer one)."""
    from cremore.db.settings_store import locked_settings

    with locked_settings(repo, setting_key=KEY) as bound:
        current = (bound.get_setting(KEY) or {}).get("value") or {}
        if _later(_time(current.get("tried_at") or ""), now):
            return
        bound.put_setting(KEY, change(current), "worker")


def sweep(repo, settings, resolver, http_client_factory, *, now=None) -> bool:
    """The worker's part: read the wanted groups' members when due; True when it read (or tried to)."""
    from cremore.identity.idp import ReadError
    from cremore.identity.keys import Digester
    from cremore.onboarding import catalog

    groups = ((repo.get_setting(WANTED) or {}).get("value") or {}).get("groups") or []
    if not groups:
        return False
    record = _directory(repo)
    if record is not None and getattr(settings, "isolated_deployment", False):
        from cremore.secretstore.isolation import binding_for_record

        if not settings.credential_sealing_keys.can_open(binding_for_record(record)):
            return False
    now = now or _dt.datetime.now(_dt.UTC)
    kept = (repo.get_setting(KEY) or {}).get("value") or {}
    tried_at = _time(kept.get("tried_at") or "")
    if kept.get("wanted") == groups and tried_at is not None and _dt.timedelta(0) <= now - tried_at < INTERVAL:
        return False
    ahead = tried_at is not None and tried_at > now + MAX_AGE  # left by a worker whose clock ran ahead
    if not repo.claim_slot(SLOT, int(now.timestamp()) // int(INTERVAL.total_seconds()), "worker") and not ahead:
        return False  # another worker reads this interval's

    def failed(code):
        def change(current):
            value = {**current, "wanted": groups, "tried_at": _iso(now), "code": code, "codes": {}}
            return {**value, "groups": {}, "read_at": None} if code in LOCAL else value
        _write(repo, now, change)
        return True

    if record is None:
        return failed("GOOGLE_WORKSPACE_PEOPLE_DIRECTORY_REQUIRED")
    reader = getattr(catalog.module(record["provider"]), "role_group_members", None)
    try:
        if (getattr(settings, "isolated_deployment", False)
                or str(record["secret_refs"]["credential"]).startswith("sealed:v3:")):
            from cremore.secretstore.isolation import binding_for_record

            resolver = resolver.bound(binding_for_record(record))
        envelope = resolver.resolve(record["secret_refs"]["credential"])
        if not isinstance(envelope, dict) or not callable(reader):
            raise TypeError
    except Exception:  # noqa: BLE001 -- a resolver error can carry the value; only a code is kept
        return failed("SECRET_UNAVAILABLE")
    members, codes = {}, {}
    client = http_client_factory()
    try:
        for group in groups:  # one group that cannot be read holds no other back
            try:
                members[group] = reader(record, {"credential": envelope}, client, [group])[group]
            except ReadError as exc:
                codes[group] = exc.code
            except Exception as exc:  # noqa: BLE001 -- nothing of the answer is kept; the next interval reads again
                logger.warning("sign-in group read failed: %s", type(exc).__name__)
                codes[group] = "SIGN_IN_GROUPS_UNREADABLE"
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    if not members:
        return failed(next(iter(codes.values())))
    digester = Digester(settings.fingerprint_key_bytes)
    digests = {group: sorted({digester(address) for address in map(_ascii_address, people) if address})
               for group, people in members.items()}
    _write(repo, now, lambda _current: {
        "wanted": groups, "domain": record["target"]["domain"], "key_id": digester.key_id, "tried_at": _iso(now),
        "read_at": _iso(now), "code": next(iter(codes.values()), None), "codes": codes, "groups": digests})
    return True


class Lookup:
    """The API's part: the role groups a Google sign-in belongs to, from the last read (re-read every half minute)."""

    def __init__(self, repo, settings, *, ttl=30.0, clock=time.monotonic, now=None):
        from cremore.identity.keys import Digester

        self.repo, self.digester, self.ttl, self.clock = repo, Digester(settings.fingerprint_key_bytes), ttl, clock
        self.now = now or (lambda: _dt.datetime.now(_dt.UTC))
        self._value, self._at = None, None

    def _stored(self) -> dict:
        if self._at is None or self.clock() - self._at >= self.ttl:
            self._value, self._at = (self.repo.get_setting(KEY) or {}).get("value") or {}, self.clock()
        return self._value

    def __call__(self, claims) -> tuple[str, ...]:
        stored = self._stored()
        read_at = _time(stored.get("read_at") or "")
        domain = stored.get("domain")
        if (read_at is None or not -SKEW <= self.now() - read_at <= MAX_AGE
                or stored.get("key_id") != self.digester.key_id or not isinstance(domain, str) or not domain
                or claims.get("email_verified") is not True or str(claims.get("hd") or "").lower() != domain):
            return ()
        address = _ascii_address(claims.get("email"))
        digest = self.digester(address) if address else None
        groups = stored.get("groups")
        if digest is None or not isinstance(groups, dict):
            return ()
        return tuple(sorted(group for group, members in groups.items() if isinstance(members, list) and digest in members))


def company_account(repo, settings, claims) -> bool:
    """Whether a verified sign-in is one of the company's own: with Google, anyone holds a Google account, so the
    address must be verified by Google and of the Workspace the role groups are read from (``hd``)."""
    if not google(settings):
        return True
    domain = ((repo.get_setting(KEY) or {}).get("value") or {}).get("domain")
    return (claims.get("email_verified") is True and isinstance(domain, str) and bool(domain)
            and str(claims.get("hd") or "").lower() == domain)


def view(repo, settings) -> dict | None:
    """What the sign-in settings show of it: None unless people sign in with Google."""
    if not google(settings):
        return None
    stored = (repo.get_setting(KEY) or {}).get("value") or {}
    groups, codes = stored.get("groups") or {}, stored.get("codes") or {}
    return {"source": "WORKSPACE_GROUPS", "domain": stored.get("domain"), "read_at": stored.get("read_at"),
            "tried_at": stored.get("tried_at"), "code": stored.get("code"),
            "groups": {role: {"group": group, "members": len(groups[group]) if group in groups else None,
                              "code": codes.get(group)}
                       for role, group in role_groups(settings).items()}}
