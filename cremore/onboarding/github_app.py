"""A GitHub App made from a manifest in the connection wizard (recommendation O-C).

1. ``start``: the flow is bound to the admin, the browser that started it (the hash of a key only it holds) and
   a state GitHub hands back; the browser posts the manifest to the organization's "new GitHub App" page.
2. ``convert``: back from GitHub with a one-hour code, the server alone exchanges it for the App's ID and
   private key (cremore_github_provider.app_manifest), sealed at once into this flow's session; the admin then
   installs the App on the organization.
3. ``complete``: the server finds the App's installation on the organization with the App's own JWT.
   Auth-first flows transfer its sealed credential to a bound onboarding draft with no collection choices;
   legacy flows create or update a provider connection and ask for its permission check. Until the App is
   installed it answers ``GITHUB_APP_NOT_INSTALLED`` and can be asked again.

A flow lives in the installation settings under ``github_app_manifest:<id>`` for an hour after its last step;
the key is removed from it once stored in the draft or connection. The client and webhook secrets GitHub also returns
are never kept.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import secrets
import uuid

from cremore.onboarding import catalog, service, sessions
from cremore.onboarding.store import atomic

PREFIX = "github_app_manifest:"
TTL = _dt.timedelta(hours=1)
_KEY = re.compile(r"[A-Za-z0-9_-]{43,128}")


class GitHubAppError(ValueError):
    """A stable code and the HTTP status it maps to."""

    def __init__(self, code, status=422):
        super().__init__(code)
        self.code, self.status = code, status


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now():
    return _dt.datetime.now(_dt.UTC)


def _audit(repo, session_id, actor, action, note=None):
    from cremore.domain.models import FindingEvent

    repo.record_finding_event(FindingEvent(target_type="github_app_manifest", target_id=uuid.UUID(str(session_id)),
                                           actor=actor, event_type=action, note=note))


def _provider_error(exc):
    code = getattr(exc, "code", None)
    return GitHubAppError(code if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", code)
                          else "GITHUB_APP_UNAVAILABLE", 502 if code in (None, "GITHUB_APP_UNAVAILABLE") else 422)


def _request(repo, body):
    """The installation permissions and host, distinct from an auth-first draft's later collection choices."""
    connection_id = body.get("provider_connection_id")
    onboarding = body.get("onboarding") is True
    if onboarding and connection_id:
        raise GitHubAppError("GITHUB_APP_REQUEST_INVALID")
    descriptor = catalog.descriptor("github")
    method = next(item for item in descriptor["auth_methods"] if item["id"] == "github_app")

    def unserved(purposes, edition):
        """A purpose the App does not serve in that edition (the catalog's purpose_editions), before GitHub is asked."""
        return any(edition not in method.get("purpose_editions", {}).get(purpose, [edition]) for purpose in purposes)

    if connection_id:
        record = service.get(repo, connection_id)
        if record["provider"] != "github" or record["status"] == "DISABLED":
            raise GitHubAppError("GITHUB_APP_CONNECTION_REQUIRED")
        if unserved(record["purposes"], record["edition"]):
            raise GitHubAppError("AUTH_METHOD_NOT_FOR_PURPOSES")
        return {"provider_connection_id": str(record["id"]), "edition": record["edition"],
                "purposes": list(record["purposes"]), "target": {k: v for k, v in record["target"].items() if k != "auth"}}
    edition = body.get("edition") or descriptor["editions"][0]["id"]
    if edition not in [item["id"] for item in descriptor["editions"]]:
        raise GitHubAppError("EDITION_UNKNOWN")
    purposes = body.get("installation_purposes" if onboarding else "purposes")
    if (not isinstance(purposes, list) or (not purposes and not onboarding)
            or any(not isinstance(purpose, str) for purpose in purposes)
            or set(purposes) - set(method["purposes"]) or unserved(purposes, edition)
            or ("remediation" in purposes and set(purposes) != {"remediation"})):
        raise GitHubAppError("AUTH_METHOD_NOT_FOR_PURPOSES")
    try:
        target = service._fields(descriptor.get("target") or [], body.get("target") or {}, edition)
        target = catalog.module("github").target("github", edition, target)
    except service.OnboardingError as exc:
        raise GitHubAppError(exc.code) from None
    except ValueError as exc:
        raise GitHubAppError(getattr(exc, "code", None) or "TARGET_INVALID") from None
    name = body.get("name")
    return {"edition": edition, "purposes": list(dict.fromkeys(purposes)), "target": target,
            **({"onboarding": True} if onboarding else {}),
            **({"name": name} if isinstance(name, str) and name.strip() else {})}


def start(repo, settings, body, actor) -> dict:
    """The manifest and where the browser posts it; the flow's id and the state GitHub hands back."""
    from cremore_github_provider import app_manifest
    from cremore_github_provider.github_auth import GitHubAuthError
    from cremore_github_provider.onboarding import APP_PERMISSIONS

    body = body if isinstance(body, dict) else {}
    key = body.get("browser_key")
    if not isinstance(key, str) or not _KEY.fullmatch(key):
        raise GitHubAppError("GITHUB_APP_BROWSER_KEY_INVALID")
    request = _request(repo, body)
    target = request["target"]
    try:
        form = app_manifest.form_url(target.get("host"), target["organization"])
        manifest = app_manifest.manifest(target["organization"], request["purposes"], APP_PERMISSIONS)
    except GitHubAuthError as exc:
        raise _provider_error(exc) from None
    session_id = uuid.uuid4()
    state = f"{session_id}.{secrets.token_urlsafe(32)}"
    expires = _now() + TTL
    repo.delete_settings_before(PREFIX, _now() - TTL)  # flows nobody finished
    repo.put_setting(PREFIX + str(session_id), {
        "actor": actor, "binding": _digest(key), "state": _digest(state), "stage": "PENDING",
        "expires_at": expires.isoformat(), "request": request}, actor)
    _audit(repo, session_id, actor, "GITHUB_APP_MANIFEST_STARTED", target["organization"])
    return {"session_id": str(session_id), "state": state, "expires_at": expires.isoformat(),
            "form_url": f"{form}?state={state}",
            "manifest": manifest}


def _owned(repo, body, actor, stages):
    """The flow this admin's browser started, in one of ``stages`` and not expired."""
    body = body if isinstance(body, dict) else {}
    try:
        session_id = uuid.UUID(str(body.get("session_id")))
    except ValueError:
        raise GitHubAppError("GITHUB_APP_SESSION_EXPIRED", 409) from None
    key = body.get("browser_key")
    record = repo.get_setting(PREFIX + str(session_id))
    value = (record or {}).get("value") or {}
    if (not value or value.get("actor") != actor or not isinstance(key, str)
            or not secrets.compare_digest(value.get("binding", ""), _digest(key))
            or _dt.datetime.fromisoformat(value["expires_at"]) < _now()):
        raise GitHubAppError("GITHUB_APP_SESSION_EXPIRED", 409)
    if value.get("stage") not in stages:
        raise GitHubAppError("GITHUB_APP_SESSION_STAGE", 409)
    return session_id, value


def _save(repo, session_id, value, actor, stage, **changes):
    """Move the flow on, only from the stage it was read in (a second request finds it moved)."""
    from cremore.db.settings_store import locked_settings

    key = PREFIX + str(session_id)
    with locked_settings(repo, setting_key=key) as bound:
        current = ((bound.get_setting(key) or {}).get("value") or {})
        if current.get("stage") != value.get("stage"):
            raise GitHubAppError("GITHUB_APP_SESSION_STAGE", 409)
        saved = {**current, **changes, "stage": stage, "expires_at": (_now() + TTL).isoformat()}
        bound.put_setting(key, saved, actor)
    return saved


def convert(repo, settings, body, actor, http_client) -> dict:
    """Exchange GitHub's code for the App (the server alone), keep its ID and key sealed in this flow, and
    say where the admin installs it."""
    from cremore_github_provider import app_manifest
    from cremore_github_provider.github_auth import GitHubAuthError

    from cremore.secretstore.sealed import seal_fields

    session_id, value = _owned(repo, body, actor, {"PENDING"})
    state = body.get("state")
    if not isinstance(state, str) or not secrets.compare_digest(value["state"], _digest(state)):
        raise GitHubAppError("GITHUB_APP_STATE_INVALID")
    value = _save(repo, session_id, value, actor, "CONVERTING")  # the code is exchanged once
    target = value["request"]["target"]
    client = http_client()
    try:
        app = app_manifest.convert(client, target.get("host"), body.get("code"))
    except GitHubAuthError as exc:
        _save(repo, session_id, value, actor, "FAILED", code=exc.code)
        raise _provider_error(exc) from None
    finally:
        client.close()
    if app["owner"].lower() != target["organization"].lower():
        _save(repo, session_id, value, actor, "FAILED", code="GITHUB_APP_CREATED_ON_ANOTHER_ACCOUNT")
        raise GitHubAppError("GITHUB_APP_CREATED_ON_ANOTHER_ACCOUNT")
    sealed = seal_fields(settings.control_sealing_keys, {"app_id": app["app_id"], "private_key": app["private_key_base64"]})
    app["private_key_base64"] = ""
    install = app_manifest.install_url(target.get("host"), app["slug"])
    _save(repo, session_id, value, actor, "CREATED", app={"id": app["app_id"], "slug": app["slug"], "name": app["name"]},
          sealed=sealed, install_url=install)
    _audit(repo, session_id, actor, "GITHUB_APP_MANIFEST_CREATED", f"{app['slug']} {app['app_id']}")
    return {"install_url": install, "app": {"id": app["app_id"], "slug": app["slug"], "name": app["name"]}}


def complete(repo, settings, body, actor, http_client) -> dict:
    """Once the App is installed on the organization: its installation, and the connection that uses it."""
    from cremore_github_provider import app_manifest
    from cremore_github_provider.github_auth import GitHubAuthError

    from cremore.secretstore.sealed import SealedSecretError, unseal

    session_id, value = _owned(repo, body, actor, {"CREATED", "COMPLETED"})
    if value["stage"] == "COMPLETED":
        result_key = "onboarding_session_id" if value["request"].get("onboarding") else "provider_connection_id"
        return {result_key: value[result_key]}
    request = value["request"]
    target = request["target"]
    try:
        made = unseal(settings.control_sealing_keys, value["sealed"])
    except SealedSecretError:
        raise GitHubAppError("GITHUB_APP_SESSION_EXPIRED", 409) from None
    client = http_client()
    try:
        installation = app_manifest.installation(client, target.get("host"), made["app_id"], made["private_key"],
                                                 target["organization"])
    except GitHubAuthError as exc:
        raise _provider_error(exc) from None
    finally:
        client.close()
    if installation is None:
        raise GitHubAppError("GITHUB_APP_NOT_INSTALLED", 409)
    value = _save(repo, session_id, value, actor, "COMPLETING")  # a second click finds it moved
    credential = {"app_id": made["app_id"], "installation_id": installation, "private_key": made["private_key"]}
    made.clear()
    try:
        # Transfer the envelope and its completion pointer together; a failed final write must not
        # leave an orphan credential owner or draft which a retry would duplicate.
        with atomic(repo) as bound:
            result_key = "provider_connection_id"
            if request.get("onboarding"):
                view = sessions.create(bound, settings, {
                    "provider": "github", "edition": request["edition"], "auth_method": "github_app",
                    "context": {**({"host": "https://" + target["host"]} if target.get("host") else {}),
                                **({"enterprise": target["enterprise"]} if target.get("enterprise") else {})},
                    "credential": credential,
                    "credential_purpose": "remediator" if request["purposes"] == ["remediation"] else "collector",
                    "browser_key": body["browser_key"]}, actor)
                result_key = "onboarding_session_id"
            elif request.get("provider_connection_id"):
                view = service.set_credential(bound, settings, request["provider_connection_id"],
                                              {"auth_method": "github_app", "credential": credential}, actor)
            else:
                view = service.create(bound, settings, {
                    "provider": "github", "edition": request["edition"], "purposes": request["purposes"],
                    "auth_method": "github_app", "target": target, "credential": credential,
                    **({"name": request["name"]} if request.get("name") else {})}, actor)
                view = service.request_check(bound, view["id"], actor)
            _save(bound, session_id, value, actor, "COMPLETED", sealed=None, **{result_key: view["id"]})
            _audit(bound, session_id, actor, "GITHUB_APP_MANIFEST_COMPLETED", view["id"])
    except service.OnboardingError as exc:
        _save(repo, session_id, value, actor, "CREATED")  # nothing was stored; installing again is not needed
        raise GitHubAppError(exc.code, exc.status) from None
    except Exception:
        _save(repo, session_id, value, actor, "CREATED")
        raise
    finally:
        credential.clear()
    return {result_key: view["id"]}


def cancel(repo, body, actor) -> None:
    """Forget a flow that will not be finished (the App GitHub made stays; its key is gone from CreMore)."""
    try:
        session_id, value = _owned(repo, body, actor, {"PENDING", "CONVERTING", "CREATED", "FAILED"})
    except GitHubAppError:
        return
    _save(repo, session_id, value, actor, "CANCELLED", sealed=None)
