"""CreMore's GitHub App on the other organizations of the enterprise (recommendation O-C2).

An active GitHub connection that uses CreMore's GitHub App and names its enterprise can put the same App on the
enterprise's other organizations and connect each of them. GitHub does the installing: the App's enterprise
installation installs it (cremore_github_provider.enterprise_install), once the App belongs to the enterprise,
holds "Enterprise organization installations: read and write" and is installed on the enterprise account.

An admin picks organizations (``request``), cancels waiting ones (``cancel``) or turns on ``auto``. One worker a
minute then does the work (``sweep``):

* for every source, without asking GitHub: queue again what a stopped worker left half done, activate checked
  organizations with the source's plans, put a replaced source key into the copies it made, and stop the queue and
  auto-install of a source that was disabled;
* then, starting with a different source each minute and within a time budget, for each active source: install
  the App (on all repositories) on a few queued organizations the enterprise lists, and connect each with its own
  installation and a sealed copy of the key, asking for its permission check.

``auto`` installs on organizations that appear after its first look: that look records the enterprise's
organizations as they are, and only later ones are queued, once an hour. Turning it off drops what it queued;
an organization an admin cancelled is never queued by it. An organization's connection scans no repository
content until its scan scope is approved; its inventory purposes collect as the source's do. The state lives in
installation settings under ``github_enterprise:<source connection id>``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import logging
import re
import time
import uuid

from cremore.onboarding import service, targets
from cremore.onboarding.store import ProviderConnectionStore

logger = logging.getLogger(__name__)

PREFIX = "github_enterprise:"
ACTOR = "system:github-enterprise"
LOCK_KEY = "onboarding:github-enterprise:lock"  # the one row every state change locks (it always exists)
SWEEP_KEY = "onboarding:github-enterprise:sweep"  # one worker a minute
AUTO_KEY = "onboarding:github-enterprise:auto:"
PER_TICK = 5  # organizations installed and connected per source in one maintenance tick
BUDGET_SECONDS = 20  # the tick's share of the worker loop for GitHub; the rest waits for the next tick
SOURCE_SECONDS = 15  # one source's share of it
MIN_SOURCE_SECONDS = 3  # less than this left: the next source waits for the next tick
AUTO_SECONDS = 3600
PAUSE = _dt.timedelta(minutes=15)  # after GitHub refuses, fails or is too slow, a source waits this long
LEASE = _dt.timedelta(minutes=10)  # an installation claimed longer ago than this is queued again
LISTING = _dt.timedelta(minutes=10)  # how long the enterprise's organization list is reused
FAILED_KEPT = _dt.timedelta(days=30)
MAX_QUEUED = 1000
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,80}")
# Results under way or done: asking again changes nothing (CONNECTED is looked at again).
_SETTLED = ("INSTALLING", "CHECKING", "ACTIVE")


class GitHubEnterpriseError(ValueError):
    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code, self.status = code, status


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _code(exc) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and _CODE.fullmatch(code) else "GITHUB_ENTERPRISE_FAILED"


def _audit(repo, connection_id, actor, action, note=None) -> None:
    from cremore.domain.models import FindingEvent

    repo.record_finding_event(FindingEvent(target_type="provider_connection", target_id=uuid.UUID(str(connection_id)),
                                           actor=actor, event_type=action, note=note))


def _audit_logins(repo, connection_id, actor, action, logins) -> None:
    """One audit row per 900 characters of logins: none is cut off."""
    chunk: list[str] = []
    for login in logins:
        if chunk and len(",".join([*chunk, login])) > 900:
            _audit(repo, connection_id, actor, action, ",".join(chunk))
            chunk = []
        chunk.append(login)
    if chunk:
        _audit(repo, connection_id, actor, action, ",".join(chunk))


def _record(repo, connection_id, *, active: bool = False, stopping: bool = False) -> dict:
    """The source connection, checked without opening its credential. ``stopping`` (cancel, auto off) takes any
    GitHub App connection, stopped or not."""
    from cremore.secretstore.sealed import is_sealed

    record = service.get(repo, connection_id)
    from cremore.secretstore.isolation import binding_for_record

    # A remediation connection's key is opened by the worker for an approved plan alone, never by the API here.
    if (record["provider"] != "github" or record["auth_method"] != "github_app"
            or "remediation" in (record.get("purposes") or [])):
        raise GitHubEnterpriseError("GITHUB_APP_CONNECTION_REQUIRED")
    # The following display/transfer fallbacks must not change the authority
    # which was pinned when the credential entered its real owner.
    record = {**record, "_credential_binding": binding_for_record(record)}
    if stopping:
        return record
    if record["status"] == "DISABLED":
        raise GitHubEnterpriseError("GITHUB_APP_CONNECTION_REQUIRED")
    if record["target"].get("version") == 2:
        roots = targets.records_of(record)
        # This organization's name is a display/transfer link fallback only. Every selected root is
        # still considered by _connected; collection and permissions keep the original v2 owner.
        record = {**record, "target": {**record["target"], "organization": roots[0]["target"]["organization"]}}
    enterprise = record["target"].get("enterprise") or record["target"].get("auth", {}).get("github_enterprise")
    if enterprise:
        record = {**record, "target": {**record["target"], "enterprise": enterprise}}
    if not record["target"].get("enterprise"):
        raise GitHubEnterpriseError("GITHUB_ENTERPRISE_REQUIRED")
    if not is_sealed((record.get("secret_refs") or {}).get("credential")):
        # A vault:// reference holds one organization's installation; each new one needs its own sealed copy.
        raise GitHubEnterpriseError("GITHUB_ENTERPRISE_SEALED_CREDENTIAL_REQUIRED")
    if active and (record["status"] != "ACTIVE" or not _plans(record)):
        # The organizations' connections take this one's plans: it must have them.
        raise GitHubEnterpriseError("GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE", 409)
    return record


def _credential(settings, record) -> dict:
    """The App credential (App ID, key), opened here only."""
    from cremore.secretstore.isolation import binding_for_record
    from cremore.secretstore.sealed import SealedSecretError, unseal

    envelope = None
    try:
        envelope = unseal(settings.credential_sealing_keys, record["secret_refs"]["credential"],
                          binding=record.get("_credential_binding") or binding_for_record(record)
                          if settings.isolated_deployment else None)
        return {"app_id": envelope["GITHUB_APP_ID"], "private_key": envelope["GITHUB_APP_PRIVATE_KEY_BASE64"]}
    except (SealedSecretError, KeyError, TypeError):
        raise GitHubEnterpriseError("CREDENTIAL_UNAVAILABLE", 409) from None
    finally:
        if isinstance(envelope, dict):
            envelope.clear()


def _source(repo, settings, connection_id, *, active: bool) -> tuple[dict, dict]:
    record = _record(repo, connection_id, active=active)
    return record, _credential(settings, record)


def _ref(record) -> str:
    """Which sealed credential a connection holds, without the credential: a digest of its reference."""
    return hashlib.sha256(str((record.get("secret_refs") or {}).get("credential")).encode()).hexdigest()


def _connected(repo, record) -> dict[str, dict]:
    """GitHub connections by organization (lower case) on the source's server."""
    host = record["target"].get("host") or ""
    out = {}
    for other in ProviderConnectionStore(repo).list():
        if other["provider"] != "github":
            continue
        for root in targets.records_of(other):
            target = root["target"]
            if (target.get("host") or "") == host and target.get("organization"):
                out.setdefault(target["organization"].lower(), other)
    return out


def _blank() -> dict:
    return {"requested": [], "results": {}, "auto": False, "baseline": None, "excluded": [], "made": {}, "key_ref": None,
            "listed": None, "paused_until": None, "paused_code": None}


def _state(repo, connection_id) -> dict:
    return {**_blank(), **((repo.get_setting(PREFIX + str(connection_id)) or {}).get("value") or {})}


def _change(repo, connection_id, actor, update) -> dict:
    """Read, change and write the source's state under the one lock row every change takes."""
    from cremore.db.settings_store import locked_settings

    if repo.get_setting(LOCK_KEY) is None:
        repo.claim_slot(LOCK_KEY, 0, ACTOR)  # insert-if-absent: racing first writers both find it after
    key = PREFIX + str(connection_id)
    with locked_settings(repo, setting_key=LOCK_KEY) as bound:
        current = {**_blank(), **((bound.get_setting(key) or {}).get("value") or {})}
        changed = update(current)
        if changed is not current:
            bound.put_setting(key, changed, actor)
    return changed


def _logins(organizations) -> list[str]:
    if (not isinstance(organizations, list) or not 1 <= len(organizations) <= 100
            or any(not isinstance(login, str) or not _LOGIN.fullmatch(login) for login in organizations)):
        raise GitHubEnterpriseError("GITHUB_ORGANIZATIONS_INVALID")
    return list(dict.fromkeys(login.lower() for login in organizations))


def _github(record, credential, http_client, deadline=None):
    """The App, where it is installed, and its enterprise installation's token (``None`` before step 2)."""
    from cremore_github_provider import enterprise_install

    host = record["target"].get("host")
    client = http_client()
    try:
        app = enterprise_install.app(client, host, credential["app_id"], credential["private_key"])
        where = enterprise_install.installations(client, host, credential["app_id"], credential["private_key"], deadline)
    finally:
        client.close()
    installation = where["enterprises"].get(record["target"]["enterprise"].lower())
    token = (enterprise_install.enterprise_token(http_client, host, credential["app_id"], installation,
                                                 credential["private_key"]) if installation else None)
    return app, where, token


def _listed(record, token, http_client, deadline=None) -> list[str]:
    from cremore_github_provider import enterprise_install

    client = http_client()
    try:
        return enterprise_install.installable_organizations(client, record["target"].get("host"), token,
                                                            record["target"]["enterprise"], deadline)
    finally:
        client.close()


def _revoke(record, token, http_client) -> None:
    from cremore_github_provider import enterprise_install

    if token is None:
        return
    client = http_client()
    try:
        enterprise_install.revoke(client, record["target"].get("host"), token)
    finally:
        client.close()


def status(repo, settings, connection_id, http_client) -> dict:
    """The API requests a refresh; only a credential-bearing worker contacts GitHub."""
    if not settings.isolated_deployment:
        return _read_status(repo, settings, connection_id, http_client)
    record = _record(repo, connection_id, active=False)
    state = _state(repo, record["id"])
    cached = state.get("status_snapshot") or {}
    current = service.check_digest(service.get(repo, connection_id))
    fresh = cached.get("credential") == current and cached.get("at", "") > (_now() - LISTING).isoformat()
    if not fresh:
        _change(repo, record["id"], "api", lambda s: {**s, "status_requested": True})
    if cached.get("credential") == current:
        return {**cached["data"], "refresh_pending": not fresh}
    return {"enterprise": record["target"]["enterprise"], "host": record["target"].get("host"),
            "organization": record["target"]["organization"], "source_status": record["status"],
            "auto": bool(state["auto"]), "state": "REFRESHING", "app": None, "organizations": [],
            "made": [], "paused_until": state["paused_until"], "paused_code": state["paused_code"],
            "refresh_pending": True}


def _read_status(repo, settings, connection_id, http_client, deadline=None) -> dict:
    """What GitHub and CreMore have for each organization of the enterprise, and what is left to do in GitHub."""
    from cremore_github_provider.github_auth import GitHubAuthError

    record, credential = _source(repo, settings, connection_id, active=False)
    enterprise, host = record["target"]["enterprise"], record["target"].get("host")
    state = _state(repo, record["id"])  # the record's own ID: any spelling of it in a URL is the same source
    out = {"enterprise": enterprise, "host": host or None, "organization": record["target"]["organization"],
           "source_status": record["status"], "auto": bool(state["auto"]), "state": "READY", "app": None, "organizations": [],
           "made": _made(repo, state, credential["app_id"]), "paused_until": state["paused_until"], "paused_code": state["paused_code"]}
    token = None
    try:
        app, where, token = _github(record, credential, http_client, deadline)
        out["app"] = {"slug": app["slug"], "owner": app["owner"], "owner_type": app["owner_type"]}
        if app["owner_type"] != "Enterprise":
            out["state"] = "TRANSFER_REQUIRED"  # step 1: the App still belongs to an organization
        elif token is None:
            out["state"] = "ENTERPRISE_INSTALL_REQUIRED"  # step 2: not installed on the enterprise account
        else:
            connected = _connected(repo, record)
            results, requested = state["results"], set(state["requested"])
            for login in _listed(record, token, http_client, deadline):
                connection = connected.get(login.lower())
                out["organizations"].append({
                    "organization": login, "installed": login.lower() in where["organizations"],
                    "connection": {"id": str(connection["id"]), "status": connection["status"],
                                   "name": connection["name"]} if connection else None,
                    "requested": login.lower() in requested, "result": results.get(login.lower())})
    except GitHubAuthError as exc:
        out["state"] = exc.code if exc.code == "GITHUB_ENTERPRISE_PERMISSION_REQUIRED" else "GITHUB_UNAVAILABLE"
        out["reason"] = exc.code
    finally:
        credential.clear()
        _revoke(record, token, http_client)
    return out


def _made(repo, state, app_id) -> list[dict]:
    """The connections this source made, as they are now (each holds a copy of the App key). ``same_app``: the
    source's key still reaches it; ``changed``: an admin gave it another credential since."""
    out = []
    for login, entry in sorted((state.get("made") or {}).items()):
        try:
            connection = service.get(repo, entry["connection_id"])
        except service.OnboardingError:
            continue
        out.append({"organization": login.split("~", 1)[0], "connection_id": str(connection["id"]), "status": connection["status"],
                    "same_app": entry.get("app_id") == app_id, "changed": bool(entry.get("ref")) and _ref(connection) != entry["ref"]})
    return out


def request(repo, settings, connection_id, organizations, actor) -> dict:
    """Queue organizations for the worker to install on and connect (at most 100 in one request)."""
    record = _record(repo, connection_id, active=True)
    wanted = _logins(organizations)
    queued: list[str] = []

    def update(state):
        queued[:] = [login for login in wanted if (state["results"].get(login) or {}).get("state") not in _SETTLED]
        requested = list(dict.fromkeys([*state["requested"], *queued]))
        if len(requested) > MAX_QUEUED:
            raise GitHubEnterpriseError("GITHUB_ENTERPRISE_QUEUE_FULL", 409)
        results = {**state["results"], **{login: {"state": "REQUESTED", "by": actor, "at": _now().isoformat()} for login in queued}}
        # Asked for by name: no longer left out of auto-install.
        return {**state, "requested": requested, "results": results, "excluded": [x for x in state["excluded"] if x not in queued]}

    _change(repo, record["id"], actor, update)
    if queued:
        _audit_logins(repo, record["id"], actor, "GITHUB_ENTERPRISE_INSTALL_REQUESTED", queued)
    return {"requested": queued, "unchanged": [login for login in wanted if login not in queued]}


def cancel(repo, settings, connection_id, organizations, actor) -> dict:
    """Take waiting organizations off the queue; auto-install leaves them out from then on. Any GitHub App
    connection, stopped or not."""
    record = _record(repo, connection_id, stopping=True)
    wanted = _logins(organizations)
    cancelled: list[str] = []

    def update(state):
        cancelled[:] = [login for login in wanted if login in state["requested"]
                        and (state["results"].get(login) or {}).get("state") == "REQUESTED"]
        excluded = list(dict.fromkeys([*state["excluded"], *wanted]))
        if len(excluded) > MAX_QUEUED:
            raise GitHubEnterpriseError("GITHUB_ENTERPRISE_EXCLUDED_FULL", 409)
        return {**state, "requested": [x for x in state["requested"] if x not in cancelled],
                "results": {key: value for key, value in state["results"].items() if key not in cancelled}, "excluded": excluded}

    _change(repo, record["id"], actor, update)
    _audit_logins(repo, record["id"], actor, "GITHUB_ENTERPRISE_INSTALL_CANCELLED", wanted)
    return {"cancelled": cancelled}


def _auto_off(state) -> dict:
    """Auto-install off: what it queued and has not started is dropped."""
    mine = {login for login, result in state["results"].items() if result.get("by") == ACTOR and result.get("state") == "REQUESTED"}
    return {**state, "auto": False, "baseline": None, "requested": [x for x in state["requested"] if x not in mine],
            "results": {key: value for key, value in state["results"].items() if key not in mine}}


def set_auto(repo, settings, connection_id, enabled: bool, actor) -> dict:
    """Turn auto-install on (organizations that appear after its first look) or off (what it queued is dropped).
    Turning it off works on any GitHub App connection, stopped or not."""
    record = _record(repo, connection_id, active=True) if enabled else _record(repo, connection_id, stopping=True)
    # On: the next look records the enterprise as it is. Off: see _auto_off.
    _change(repo, record["id"], actor, (lambda state: {**state, "auto": True, "baseline": None}) if enabled else _auto_off)
    _audit(repo, record["id"], actor, "GITHUB_ENTERPRISE_AUTO_INSTALL_ON" if enabled else "GITHUB_ENTERPRISE_AUTO_INSTALL_OFF")
    return {"auto": bool(enabled)}


def _connect(repo, settings, record, credential, login, installation) -> dict:
    """The organization's connection: the source's purposes and server, this organization's installation."""
    target = {"organization": login, **({"host": record["target"]["host"]} if record["target"].get("host") else {})}
    purposes = list(_plans(record))
    view = service.create(repo, settings, {
        "provider": "github", "edition": record["edition"], "purposes": purposes, "auth_method": "github_app",
        "target": target, "credential": {"app_id": credential["app_id"], "installation_id": installation,
                                         "private_key": credential["private_key"]}}, ACTOR)
    return service.request_check(repo, view["id"], ACTOR, {"plans": _plans(record)})


def _plans(record) -> dict:
    """The source's plans for an organization's connection: the enterprise-wide parts stay with the source."""
    from cremore.onboarding.store import active_plans

    out = {}
    for purpose, plan in active_plans(record).items():
        if purpose in ("exposure", "inventory", "vault"):
            out[purpose] = {key: value for key, value in (plan or {}).items() if key not in {
                "token_digests", "enterprise_inventory", "enterprise_audit", "enterprise_schedule_minutes"}}
    return out


def _activate(repo, settings, record, result) -> dict:
    """Activate a checked organization with the source's plans once their required permissions are granted."""
    try:
        connection = service.get(repo, result["connection_id"])
    except service.OnboardingError:
        return {**result, "state": "FAILED", "code": "PROVIDER_CONNECTION_NOT_FOUND"}
    if connection["status"] == "ACTIVE":
        return {**result, "state": "ACTIVE"}
    if connection["status"] != "CHECKED":
        return result
    plans = {purpose: plan for purpose, plan in _plans(record).items() if purpose in connection["purposes"]}
    if not plans:
        return {**result, "state": "NEEDS_REVIEW", "code": "SOURCE_NOT_ACTIVE"}
    try:
        service.activate(repo, settings, connection["id"], {"purposes": plans}, ACTOR)
    except service.OnboardingError as exc:
        code = "PERMISSIONS_NOT_GRANTED" if exc.code == "REQUIRED_PERMISSIONS_NOT_GRANTED" else exc.code
        return {**result, "state": "NEEDS_REVIEW", "code": code}
    _audit(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_ORG_ACTIVATED", str(connection["id"]))
    return {**result, "state": "ACTIVE"}


def _propagate(repo, settings, record, state) -> dict:
    """The source's key was replaced: put the new one into the copies it made for the same App, leaving any an
    admin has given another credential since."""
    ref = _ref(record)
    if not state["made"] or state["key_ref"] == ref:
        return state
    if state["key_ref"] is None:
        return _change(repo, record["id"], ACTOR, lambda s: {**s, "key_ref": ref})
    credential = _credential(settings, record)
    moved, left, made = 0, 0, dict(state["made"])
    try:
        for key, entry in state["made"].items():
            try:
                connection = service.get(repo, entry["connection_id"])
            except service.OnboardingError:
                left += 1
                continue
            if (entry.get("app_id") != credential["app_id"] or connection["status"] == "DISABLED"
                    or connection["auth_method"] != "github_app" or _ref(connection) != entry.get("ref")):
                left += 1  # another App, stopped, or changed by an admin: not the source's to overwrite
                continue
            try:
                service.set_credential(repo, settings, connection["id"], {"credential": {
                    "app_id": credential["app_id"], "installation_id": entry["installation_id"],
                    "private_key": credential["private_key"]}}, ACTOR)
            except service.OnboardingError:
                left += 1
                continue
            made[key] = {**entry, "ref": _ref(service.get(repo, connection["id"]))}
            moved += 1
    finally:
        credential.clear()
    _audit(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_KEY_PROPAGATED", f"moved={moved} left={left}")
    return _change(repo, record["id"], ACTOR, lambda s: {**s, "key_ref": ref, "made": {**s["made"], **{
        key: value for key, value in made.items() if key in s["made"]}}})


def _settle(repo, settings, connection_id, now) -> None:
    """A source's work that needs no GitHub: never held up by a slow one."""
    from cremore.secretstore.sealed import is_sealed

    try:
        record = _record(repo, connection_id, stopping=True)
    except (GitHubEnterpriseError, service.OnboardingError):
        return  # gone: its organizations stay as they are
    state = _state(repo, record["id"])
    # Claims a stopped worker left behind go back on the queue (still the same claim when the change is made).
    stale = {login: result.get("claim") for login, result in state["results"].items()
             if result.get("state") == "INSTALLING" and result.get("at", "") < (now - LEASE).isoformat()}
    if stale:
        def requeue(s):
            back = [login for login, claim in stale.items() if (s["results"].get(login) or {}).get("claim") == claim
                    and s["results"][login].get("state") == "INSTALLING"]
            return {**s, "requested": list(dict.fromkeys([*s["requested"], *back])),
                    "results": {**s["results"], **{login: {**s["results"][login], "state": "REQUESTED"} for login in back}}} if back else s
        state = _change(repo, record["id"], ACTOR, requeue)
    if record["status"] == "DISABLED" or not _plans(record):
        # A stopped source installs nothing: at the first tick that finds it stopped, its queue and auto-install
        # stop with it, and stay stopped when it is turned on again.
        if state["auto"] or any(result.get("state") == "REQUESTED" for result in state["results"].values()):
            dropped: list[str] = []

            def stop(s):
                dropped[:] = [login for login, result in s["results"].items() if result.get("state") == "REQUESTED"]
                s = _auto_off(s)
                return {**s, "requested": [x for x in s["requested"] if x not in dropped],
                        "results": {key: value for key, value in s["results"].items() if key not in dropped}}

            state = _change(repo, record["id"], ACTOR, stop)
            if dropped:
                _audit_logins(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_STOPPED_WITH_SOURCE", dropped)
            else:
                _audit(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_STOPPED_WITH_SOURCE")
    elif record["status"] == "ACTIVE":
        for login, result in state["results"].items():
            if result.get("state") == "CHECKING":
                moved = _activate(repo, settings, record, result)
                if moved != result:
                    state = _change(repo, record["id"], ACTOR, lambda s, login=login, moved=moved: {**s, "results": {**s["results"], login: moved}})
    if (record["status"] != "DISABLED" and _plans(record)
            and state["made"] and is_sealed((record.get("secret_refs") or {}).get("credential"))):
        state = _propagate(repo, settings, record, state)
    # Failed organizations are kept a month, and at most the newest thousand. Chosen again under the lock, so one an
    # admin asked for again meanwhile stays; with auto-install on, what goes joins the baseline: it is not "new".
    def prune(s):
        old = _old_failures(s, now)
        if not old:
            return s
        return {**s, "results": {key: value for key, value in s["results"].items() if key not in old},
                "baseline": sorted({*s["baseline"], *old}) if s["baseline"] is not None else None}

    if _old_failures(state, now):
        _change(repo, record["id"], ACTOR, prune)


def _old_failures(state, now) -> set[str]:
    cutoff = (now - FAILED_KEPT).isoformat()
    failed = sorted((result.get("at", ""), login) for login, result in state["results"].items() if result.get("state") == "FAILED")
    return {login for at, login in failed if at < cutoff} | {login for _at, login in failed[:max(0, len(failed) - MAX_QUEUED)]}


def _auto_due(repo, connection_id, now) -> bool:
    return repo.claim_slot(AUTO_KEY + str(connection_id), int(now.timestamp()) // AUTO_SECONDS, ACTOR)


def _claim(repo, connection_id, login, now) -> tuple[str, str] | None:
    """Take one queued organization for this worker: (who asked, the claim), or None when it is not ours to take."""
    token = uuid.uuid4().hex
    taken = {}

    def update(state):
        result = state["results"].get(login) or {}
        if login not in state["requested"] or result.get("state") != "REQUESTED":
            return state
        taken["by"] = result.get("by") or ACTOR
        return {**state, "requested": [x for x in state["requested"] if x != login],
                "results": {**state["results"], login: {**result, "state": "INSTALLING", "claim": token, "at": now.isoformat()}}}

    _change(repo, connection_id, ACTOR, update)
    return (taken["by"], token) if taken else None


def _renew(repo, connection_id, login, claim, now) -> bool:
    """Still this worker's claim? Then keep it for another lease, before anything is made."""
    kept = {}

    def update(state):
        result = state["results"].get(login) or {}
        if result.get("claim") != claim or result.get("state") != "INSTALLING":
            return state
        kept["yes"] = True
        return {**state, "results": {**state["results"], login: {**result, "at": now.isoformat()}}}

    _change(repo, connection_id, ACTOR, update)
    return bool(kept)


def _listing(repo, record, token, http_client, state, now, deadline) -> list[str]:
    """The enterprise's installable organizations (lower case), asked of GitHub at most every ten minutes."""
    cached = state.get("listed") or {}
    if cached.get("at", "") > (now - LISTING).isoformat():
        return cached["logins"]
    logins = [login.lower() for login in _listed(record, token, http_client, deadline)]
    _change(repo, record["id"], ACTOR, lambda s: {**s, "listed": {"at": now.isoformat(), "logins": logins}})
    return logins


def _install_one(repo, settings, record, credential, login, claim, app, where, token, listed, http_client, by, now):
    from cremore_github_provider import enterprise_install
    from cremore_github_provider.github_auth import GitHubAuthError

    connected = _connected(repo, record).get(login)
    if connected is not None:
        return {"state": "CONNECTED", "connection_id": str(connected["id"])}, None
    if login not in listed:
        # Only what the enterprise lists as installable, even where the App already has an installation.
        return {"state": "FAILED", "code": "GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE"}, None
    installation = where["organizations"].get(login)
    if installation is None:
        client = http_client()
        try:
            installation = enterprise_install.install(client, record["target"].get("host"), token,
                                                      record["target"]["enterprise"], login, app["client_id"])
        except GitHubAuthError as exc:
            if exc.code == "GITHUB_APP_UNAVAILABLE":
                raise  # Pause the source; the existing expired-claim path requeues this organization.
            return {"state": "FAILED", "code": exc.code}, None
        finally:
            client.close()
        _audit(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_ORG_INSTALLED", f"{login} requested by {by}")
    if not _renew(repo, record["id"], login, claim, now):
        return None, None  # another worker took it over after this one stalled: it connects the organization
    try:
        view = _connect(repo, settings, record, credential, login, installation)
    except service.OnboardingError as exc:
        return {"state": "FAILED", "code": exc.code}, None
    _audit(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_ORG_CONNECTED", f"{login} {view['id']} requested by {by}")
    made = {"connection_id": str(view["id"]), "installation_id": installation, "app_id": credential["app_id"],
            "ref": _ref(service.get(repo, view["id"]))}
    return {"state": "CHECKING", "connection_id": str(view["id"])}, made


def _sweep_source(repo, settings, connection_id, http_client, now, deadline, full: bool) -> int:
    """GitHub's part for one active source. ``full``: it had the whole per-source budget, so running out of it
    means GitHub is too slow for it, not that others took the time."""
    from cremore_github_provider.github_auth import GitHubAuthError

    try:
        record, credential = _source(repo, settings, connection_id, active=True)
    except (GitHubEnterpriseError, service.OnboardingError):
        return 0
    state = _state(repo, record["id"])
    if state["paused_until"] and state["paused_until"] > now.isoformat():
        credential.clear()
        return 0
    handled, token = 0, None
    try:
        auto = bool(state["auto"]) and _auto_due(repo, record["id"], now)
        if not state["requested"] and not auto:
            return 0
        app, where, token = _github(record, credential, http_client, deadline)
        if token is None or app["owner_type"] != "Enterprise":
            return 0
        refreshed = (state.get("listed") or {}).get("at", "") <= (now - LISTING).isoformat()  # read from GitHub now
        listed = _listing(repo, record, token, http_client, state, now, deadline)
        if auto:
            known = set(_connected(repo, record)) | set(state["results"]) | set(state["excluded"])
            if state["baseline"] is None:
                # The first look after auto was turned on: the enterprise as it is now is not "new".
                state = _change(repo, record["id"], ACTOR, lambda s: {**s, "baseline": sorted(set(listed) | known)} if s["auto"] else s)
            else:
                fresh = [login for login in listed if login not in known and login not in state["baseline"]]
                queued: list[str] = []

                def queue(s):
                    if not s["auto"] or s["baseline"] is None:
                        return s  # turned off (or on again) meanwhile
                    queued[:] = [login for login in fresh if login not in s["results"]][:max(0, MAX_QUEUED - len(s["requested"]))]
                    # Only what was queued joins the baseline: what did not fit is still new next hour.
                    return {**s, "requested": [*s["requested"], *queued], "baseline": sorted({*s["baseline"], *queued}),
                            "results": {**s["results"], **{login: {"state": "REQUESTED", "by": ACTOR, "at": now.isoformat()} for login in queued}}}

                state = _change(repo, record["id"], ACTOR, queue)
                if queued:
                    _audit_logins(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_AUTO_QUEUED", queued)
        batch = list(state["requested"])[:PER_TICK]
        if not refreshed and any(login not in listed or where["organizations"].get(login) for login in batch):
            # A reused list could be stale for these (a new organization, or one that left while the App stayed
            # installed there, where no install call asks GitHub): read it again, before anything is claimed.
            listed = _listing(repo, record, token, http_client, {**state, "listed": None}, now, deadline)
        for number, login in enumerate(batch):
            if number and time.monotonic() > deadline:
                break  # the listing is paid for: at least one goes on
            claimed = _claim(repo, record["id"], login, now)
            if claimed is None:
                continue  # another worker has it, or it was cancelled
            by, claim = claimed
            done, made = _install_one(repo, settings, record, credential, login, claim, app, where, token, listed, http_client, by, now)
            if done is None:
                continue
            if done["state"] == "FAILED":
                _audit(repo, record["id"], ACTOR, "GITHUB_ENTERPRISE_ORG_INSTALL_FAILED", f"{login} {done['code']}")
            done = {**done, "by": by, "at": now.isoformat()}

            def finish(s, login=login, done=done, made=made, claim=claim):
                out = dict(s)
                mine = s["results"].get(login) or {}
                # Still this worker's claim, and not put back on the queue after its lease ran out.
                if mine.get("claim") == claim and mine.get("state") == "INSTALLING":
                    out["results"] = {**s["results"], login: done}
                if made:
                    # Every copy of the key is recorded, so a replaced source key reaches each one.
                    key = login if login not in s["made"] else f"{login}~{made['connection_id'][:8]}"
                    out["made"] = {**s["made"], key: made}
                    out["key_ref"] = s["key_ref"] or _ref(record)
                return out

            state = _change(repo, record["id"], ACTOR, finish)
            handled += 1
    except GitHubAuthError as exc:
        code = _code(exc)
        if code == "GITHUB_TOO_SLOW" and not full:
            return handled  # it started late in the tick: it goes first another minute
        logger.warning("GitHub enterprise installation of %s paused: %s", connection_id, code)
        _change(repo, record["id"], ACTOR, lambda s: {**s, "paused_until": (now + PAUSE).isoformat(), "paused_code": code})
        return handled
    finally:
        credential.clear()
        _revoke(record, token, http_client)
    if state["paused_until"]:
        _change(repo, record["id"], ACTOR, lambda s: {**s, "paused_until": None, "paused_code": None})
    return handled


def sweep(repo, settings, http_client, *, now=None, budget=BUDGET_SECONDS) -> int:
    """One maintenance tick, by one worker. First, for every source, what needs no GitHub (_settle). Then GitHub's
    part, starting with a different source each minute, each within its share of the budget. One source's
    failure never stops the others."""
    now = now or _now()
    if not settings.isolated_deployment and not repo.claim_slot(SWEEP_KEY, int(now.timestamp()) // 60, ACTOR):
        return 0
    sources = [entry["key"][len(PREFIX):] for entry in repo.list_settings(PREFIX)]
    if settings.isolated_deployment:
        from cremore.secretstore.isolation import binding_for_record

        ring, groups, assigned = settings.credential_sealing_keys, {}, []
        for connection_id in sources:
            try:
                binding = binding_for_record(_record(repo, connection_id, stopping=True))
            except (GitHubEnterpriseError, service.OnboardingError):
                continue
            if binding["purpose"] != "collector" or not ring.can_open(binding):
                continue
            group = ring.group_id(binding)
            if group not in groups:
                groups[group] = repo.claim_slot(SWEEP_KEY + ":" + group, int(now.timestamp()) // 60, ACTOR)
            if groups[group]:
                assigned.append(connection_id)
        sources = assigned
    for connection_id in sources:
        try:
            _settle(repo, settings, connection_id, now)
        except Exception as exc:  # noqa: BLE001 -- one source never stops the others
            logger.warning("GitHub enterprise upkeep of %s failed: %s", connection_id, type(exc).__name__)
    deadline = time.monotonic() + budget
    start = (int(now.timestamp()) // 60) % max(len(sources), 1)
    handled = 0
    for connection_id in sources[start:] + sources[:start]:
        left = deadline - time.monotonic()
        if left < MIN_SOURCE_SECONDS:
            break
        try:
            if settings.isolated_deployment and _state(repo, connection_id).get("status_requested"):
                digest = service.check_digest(service.get(repo, connection_id))
                snapshot = _read_status(repo, settings, connection_id, http_client,
                                        time.monotonic() + min(left, SOURCE_SECONDS))
                # A changed owner does not inherit a refresh of the old credential or destination.
                if service.check_digest(service.get(repo, connection_id)) == digest:
                    _change(repo, connection_id, ACTOR, lambda s, digest=digest, snapshot=snapshot: {**s, "status_requested": False,
                        "status_snapshot": {"credential": digest, "at": now.isoformat(), "data": snapshot}})
            left = deadline - time.monotonic()
            if left < MIN_SOURCE_SECONDS:
                break
            handled += _sweep_source(repo, settings, connection_id, http_client, now,
                                     time.monotonic() + min(left, SOURCE_SECONDS), left >= SOURCE_SECONDS)
        except Exception as exc:  # noqa: BLE001 -- one source never stops the others
            logger.warning("GitHub enterprise installation of %s failed: %s", connection_id, type(exc).__name__)
    return handled
