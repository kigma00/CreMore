"""Admin-only GCP onboarding; Google protocol belongs to the provider library."""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from cremore_gcp_provider import oauth
from cremore_gcp_provider.gcp_auth import GcpAuthError
from fastapi import Depends, Response
from pydantic import Field

from cremore.coverage.gcp_oauth_store import GcpOAuthStore, digest
from cremore.coverage.metadata_models import MetadataModel
from cremore.coverage.store import CoverageError
from cremore.db.task_store import TaskStore
from cremore.domain.models import FindingEvent
from cremore.secretstore.sealed import SealedSecretError, seal_fields, unseal


# Integration (refactoring + gcp-dashboard-oauth): every request model here carries the GcpOAuth prefix.
# OpenAPI component names are global, and cremore.coverage.models already publishes Start and Finish
# for the collector routes; the shared names renamed those existing schemas in /openapi.json. The
# other generic names (Session, Projects, Complete) were renamed too, before they were ever published.
class GcpOAuthStart(MetadataModel):
    """A Google sign-in for one provider connection (auth method ``google_oauth``)."""

    browser_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43,128}$", repr=False)
    connection_id: uuid.UUID = Field(strict=False)
    connection_kind: Literal["provider", "onboarding"] = "provider"


class GcpOAuthSession(MetadataModel):
    session_id: uuid.UUID = Field(strict=False)
    browser_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43,128}$", repr=False)


class GcpOAuthFinish(GcpOAuthSession):
    state: str = Field(min_length=40, max_length=200, repr=False)
    code: str = Field(min_length=1, max_length=4096, repr=False)


class GcpOAuthProjects(GcpOAuthSession):
    page_token: str = Field(default="", max_length=4096, repr=False)


# The Google OAuth client an admin saved in the dashboard: its ID and redirect URI in the clear, the secret sealed.
# GCP_OAUTH_* settings pin the client instead; then the dashboard shows it and cannot change it.
CLIENT_KEY = "gcp_oauth_client"


class GcpOAuthClient(MetadataModel):
    client_id: str = Field(min_length=1, max_length=512)
    client_secret: str = Field(default="", max_length=8192, repr=False)  # empty keeps the saved secret
    redirect_uri: str = Field(min_length=1, max_length=2048)


_CLIENT_ID = re.compile(r"[0-9A-Za-z-]{1,200}\.apps\.googleusercontent\.com\Z")


def pinned(settings) -> bool:
    return bool(settings.gcp_oauth_client_id or settings.gcp_oauth_client_secret or settings.gcp_oauth_redirect_uri)


def saved_client(repo) -> dict:
    """The client saved in the dashboard (ID, redirect URI, sealed secret), or {} when there is none."""
    saved = (repo.get_setting(CLIENT_KEY) or {}).get("value")
    return saved if isinstance(saved, dict) and all(saved.get(name) for name in ("client_id", "redirect_uri", "sealed")) else {}


def config(settings, repo=None):
    """The Google OAuth client the sign-in uses: the pinned one, else the one saved in the dashboard."""
    if pinned(settings) or repo is None:
        return oauth.OAuthConfig(settings.gcp_oauth_client_id, settings.gcp_oauth_client_secret,
                                 settings.gcp_oauth_redirect_uri).validate()
    saved = saved_client(repo)
    if not saved:
        raise GcpAuthError("GCP_OAUTH_SETUP_REQUIRED")  # nothing saved: no key store round trip
    try:
        secret = unseal(settings.control_sealing_keys, saved["sealed"])["client_secret"]
    except (KeyError, TypeError, SealedSecretError):
        raise GcpAuthError("GCP_OAUTH_SETUP_REQUIRED") from None
    except Exception:  # noqa: BLE001 -- Vault or KMS holding the sealing key did not answer; retry later, never a 500.
        raise GcpAuthError("GCP_OAUTH_STORED_AUTH_UNAVAILABLE") from None
    return oauth.OAuthConfig(saved["client_id"], secret, saved["redirect_uri"]).validate()


def _form_ok(client_id: str, secret: str, redirect_uri: str) -> bool:
    """What the dashboard may save: values validate() accepts, with nothing a URL parser drops or reads differently."""
    try:
        parts = urlsplit(redirect_uri)
        _ = parts.port  # an out-of-range port raises
    except ValueError:
        return False
    return (bool(_CLIENT_ID.fullmatch(client_id)) and secret.isprintable() and " " not in secret
            and redirect_uri.isascii() and redirect_uri.isprintable() and "\\" not in redirect_uri
            and urlunsplit(parts) == redirect_uri)


def _provider_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except GcpAuthError as exc:
        raise CoverageError(exc.code) from None
    except SealedSecretError:
        raise CoverageError("GCP_OAUTH_STORED_AUTH_UNAVAILABLE") from None


def register_gcp_oauth_routes(app, repo, settings, require_role):
    admin = require_role("admin")
    store = GcpOAuthStore(repo)

    def audit(bound, sid, actor, kind):
        bound.record_finding_event(FindingEvent(target_type="gcp_oauth", target_id=sid,
                                               actor=actor, event_type=kind))

    def open_fields(ref):
        return _provider_call(unseal, settings.control_sealing_keys, ref)

    def public_target(data):
        target = data.get("target")
        return {"id": target["id"], "kind": target["kind"]} if target else None

    @app.get("/api/v2/gcp/oauth/status")
    def status(response: Response, _actor=Depends(admin)):
        """Which client the sign-in uses. A saved client is described, not unsealed: the sign-in opens its secret."""
        response.headers["Cache-Control"] = "no-store"
        locked = pinned(settings)
        saved = {} if locked else saved_client(repo)
        if saved:
            return {"configured": True, "redirect_uri": saved["redirect_uri"], "client_id": saved["client_id"],
                    "source": "DASHBOARD", "locked": False, "scopes": list(oauth.SCOPES)}
        try:
            chosen = config(settings) if locked else None
        except GcpAuthError:
            chosen = None
        if chosen is not None:
            return {"configured": True, "redirect_uri": chosen.redirect_uri, "client_id": chosen.client_id,
                    "source": "SETTING", "locked": True, "scopes": list(oauth.SCOPES)}
        return {"configured": False, "reason": "GCP_OAUTH_SETUP_REQUIRED", "locked": locked, "scopes": list(oauth.SCOPES),
                "required_settings": ["GCP_OAUTH_CLIENT_ID", "GCP_OAUTH_CLIENT_SECRET", "GCP_OAUTH_REDIRECT_URI"]}

    @app.put("/api/v2/gcp/oauth/client")
    def save_client(body: GcpOAuthClient, response: Response, actor=Depends(admin)):
        """Save the Google OAuth client the sign-in uses; the secret is sealed and never shown again."""
        response.headers["Cache-Control"] = "no-store"
        if pinned(settings):
            raise CoverageError("GCP_OAUTH_CLIENT_PINNED")
        client_id, secret, redirect_uri = body.client_id.strip(), body.client_secret.strip(), body.redirect_uri.strip()
        replaced = bool(secret)
        if not replaced:
            # Only the same client keeps its saved secret (a new redirect URI, say); another client brings its own.
            if saved_client(repo).get("client_id") != client_id:
                raise CoverageError("GCP_OAUTH_SETUP_REQUIRED")
            secret = _provider_call(config, settings, repo).client_secret
        if not _form_ok(client_id, secret, redirect_uri):
            raise CoverageError("GCP_OAUTH_SETUP_REQUIRED")
        chosen = _provider_call(lambda: oauth.OAuthConfig(client_id, secret, redirect_uri).validate())
        repo.put_setting(CLIENT_KEY, {"client_id": chosen.client_id, "redirect_uri": chosen.redirect_uri,
                                      "sealed": seal_fields(settings.control_sealing_keys, {"client_secret": chosen.client_secret})}, actor)
        repo.record_finding_event(FindingEvent(
            target_type="gcp_oauth", target_id=uuid.uuid5(uuid.NAMESPACE_URL, CLIENT_KEY), actor=actor,
            event_type="GCP_OAUTH_CLIENT_SAVED",
            note=f"client_id={chosen.client_id} redirect_uri={chosen.redirect_uri} secret={'replaced' if replaced else 'kept'}"))
        return {"configured": True, "client_id": chosen.client_id, "redirect_uri": chosen.redirect_uri,
                "source": "DASHBOARD", "locked": False, "scopes": list(oauth.SCOPES)}

    @app.post("/api/v2/gcp/oauth/start")
    def start(body: GcpOAuthStart, response: Response, actor=Depends(admin)):
        chosen = _provider_call(config, settings, repo)
        from cremore.onboarding.store import ProviderConnectionStore

        cloud_access = True
        if body.connection_kind == "onboarding":
            from cremore.api.routes.onboarding import _call
            from cremore.onboarding import sessions

            row = _call(sessions._get, repo, body.connection_id, actor, {"browser_key": body.browser_key})
            owner = row["data"]
            if (owner["provider"] != "gcp" or owner["auth_method"] != "google_oauth"
                    or owner["state"] != "AWAITING_OAUTH"):
                raise CoverageError("GCP_SIGN_IN_CONNECTION_REQUIRED")
            target = {"id": str(row["id"]), "kind": "onboarding", "revision": row["revision"]}
            cloud_access = bool(owner.get("purposes"))
        else:
            owner = ProviderConnectionStore(repo).get(body.connection_id)
            if (owner is None or owner["provider"] != "gcp" or owner["auth_method"] != "google_oauth"
                    or owner["status"] == "DISABLED"):
                raise CoverageError("GCP_SIGN_IN_CONNECTION_REQUIRED")
            target = {"id": str(owner["id"]), "kind": "provider", "revision": owner["revision"]}
        sid, nonce, verifier = uuid.uuid4(), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        state = str(sid) + "." + nonce
        expires = datetime.now(UTC) + timedelta(minutes=15)
        store.create_session({"id": sid, "actor": actor, "binding_hash": digest(body.browser_key),
            "state_hash": digest(state), "stage": "PENDING", "expires_at": expires,
            "data": {"pending": seal_fields(settings.control_sealing_keys, {"verifier": verifier}), "target": target,
                     "client_id": chosen.client_id, "redirect_uri": chosen.redirect_uri, "cloud_access": cloud_access}})
        response.headers["Cache-Control"] = "no-store"
        audit(repo, sid, actor, "GCP_OAUTH_STARTED")
        return {"session_id": str(sid), "state": state, "expires_at": expires,
                "authorization_url": chosen.authorization_url(state, verifier, cloud_access=cloud_access)}

    @app.post("/api/v2/gcp/oauth/finish")
    def finish(body: GcpOAuthFinish, response: Response, actor=Depends(admin)):
        chosen = _provider_call(config, settings, repo)
        with store.transaction() as conn:
            row = store.owned(conn, body.session_id, actor, body.browser_key, {"PENDING"}, lock=True)
            if not secrets.compare_digest(row["state_hash"], digest(body.state)):
                raise CoverageError("GCP_OAUTH_STATE_INVALID")
            if (row["data"]["client_id"] != chosen.client_id or row["data"]["redirect_uri"] != chosen.redirect_uri):
                raise CoverageError("GCP_OAUTH_CONFIG_CHANGED")
            pending = open_fields(row["data"]["pending"])
            row["stage"] = "EXCHANGING"
            row["data"].pop("pending")
            store.save(conn, row)
        fields = {}
        try:
            with httpx.Client(timeout=20.0, follow_redirects=False) as client:
                fields, identity = _provider_call(oauth.exchange, chosen, body.code, pending["verifier"], client,
                    **({"cloud_access": False} if row["data"].get("cloud_access") is False else {}))
            sealed = seal_fields(settings.control_sealing_keys, fields)
        except Exception:
            with store.transaction() as conn:
                failed = store.owned(conn, body.session_id, actor, body.browser_key, {"EXCHANGING"}, lock=True)
                failed.update(stage="FAILED", data={})
                store.save(conn, failed)
            raise
        finally:
            pending.clear()
            fields.clear()
        with store.transaction() as conn:
            row = store.owned(conn, body.session_id, actor, body.browser_key, {"EXCHANGING"}, lock=True)
            row["stage"] = "AUTHORIZED"
            row["data"].update(sealed=sealed, identity=identity)
            store.save(conn, row)
            audit(TaskStore(repo)._bound(conn), row["id"], actor, "GCP_OAUTH_AUTHORIZED")
        response.headers["Cache-Control"] = "no-store"
        return {"session_id": str(body.session_id), "identity": identity, "target": public_target(row["data"])}

    @app.post("/api/v2/gcp/oauth/projects")
    def projects(body: GcpOAuthProjects, response: Response, actor=Depends(admin)):
        with store.transaction() as conn:
            row = store.owned(conn, body.session_id, actor, body.browser_key, {"AUTHORIZED"})
        if row["data"].get("target", {}).get("kind") == "onboarding":
            raise CoverageError("GCP_PROJECTS_USE_ONBOARDING_WORKER")
        fields = open_fields(row["data"]["sealed"])
        try:
            with httpx.Client(timeout=20.0, follow_redirects=False) as client:
                result = _provider_call(oauth.projects, fields, client, page_token=body.page_token)
        finally:
            fields.clear()
        response.headers["Cache-Control"] = "no-store"
        return {**result, "identity": row["data"]["identity"], "target": public_target(row["data"])}

    @app.post("/api/v2/gcp/oauth/cancel")
    def cancel(body: GcpOAuthSession, actor=Depends(admin)):
        with store.transaction() as conn:
            row = store.owned(conn, body.session_id, actor, body.browser_key, {"PENDING", "AUTHORIZED", "FAILED"}, lock=True)
            row.update(stage="CANCELLED", data={})
            store.save(conn, row)
        return {"cancelled": True}

    @app.post("/api/v2/gcp/oauth/complete")
    def complete(body: GcpOAuthSession, response: Response, actor=Depends(admin)):
        """Attach the Google sign-in to its provider connection: every use of the connection
        now reads with it, and the connection's permission check runs again."""
        from cremore.onboarding import children as owned
        from cremore.onboarding import service as onboarding
        from cremore.onboarding.store import ProviderConnectionConflict, ProviderConnectionStore
        from cremore.secretstore.isolation import binding_for_record, seal_credential

        def released(data, owner):
            if not settings.isolated_deployment:
                return data["sealed"]
            fields = open_fields(data["sealed"])
            try:
                return seal_credential(settings, fields, binding_for_record(owner))
            finally:
                fields.clear()

        response.headers["Cache-Control"] = "no-store"
        with store.transaction() as conn:
            row = store.owned(conn, body.session_id, actor, body.browser_key, {"AUTHORIZED", "COMPLETED"}, lock=True)
            if row["stage"] == "COMPLETED":
                return row["data"]["result"]
            data, bound = row["data"], TaskStore(repo)._bound(conn)
            target = data.get("target") or {}
            if target.get("kind") == "onboarding":
                from cremore.api.routes.onboarding import _call
                from cremore.onboarding import sessions
                from cremore.onboarding.session_store import SessionStore

                draft = _call(sessions._get, bound, target["id"], actor, {"browser_key": body.browser_key})
                if draft["revision"] != target["revision"] or draft["data"]["state"] != "AWAITING_OAUTH":
                    raise CoverageError("CONNECTION_REVISION_CONFLICT")
                draft = SessionStore(bound).save(draft, {**draft["data"], "secret_refs": {"credential": released(data, draft["data"])},
                    "target": {**draft["data"]["target"], "auth": {"oauth_cloud_access": data.get("cloud_access", True)}}})
                sessions._queue(bound, draft, "authenticate")
                result = {"onboarding_session_id": str(draft["id"])}
                row.update(stage="COMPLETED", data={"result": result})
                store.save(conn, row)
                audit(bound, draft["id"], actor, "GCP_OAUTH_CONNECTED")
                return result
            connections = ProviderConnectionStore(bound)
            record = connections.get(target.get("id")) if target.get("kind") == "provider" else None
            if record is None:
                raise CoverageError("PROVIDER_CONNECTION_NOT_FOUND")
            if record["revision"] != target["revision"]:
                raise CoverageError("CONNECTION_REVISION_CONFLICT")
            try:
                record = connections.update(record["id"], record["revision"], actor,
                                            secret_refs={"credential": released(data, record)},
                                            checks={**(record["checks"] or {}), "stale": True})
            except ProviderConnectionConflict:
                raise CoverageError("CONNECTION_REVISION_CONFLICT") from None
            owned.repoint(bound, record, actor)
            onboarding.request_check(bound, record["id"], actor)
            audit(bound, record["id"], actor, "GCP_OAUTH_CONNECTED")
            result = {"provider_connection_id": str(record["id"])}
            row.update(stage="COMPLETED", data={"result": result})
            store.save(conn, row)
        return result
