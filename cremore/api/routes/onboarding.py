"""Provider connections: the one way a provider is connected (design 4.4, cremore.onboarding).

Reading the catalog and the connections is open to every signed-in role: it names
providers, targets and check results, never a credential. Creating, checking,
activating, changing a credential and disabling are an administrator's, as is making
a GitHub App from a manifest (cremore.onboarding.github_app) and putting it on the enterprise's other
organizations (cremore.onboarding.github_enterprise).
"""

from __future__ import annotations

from fastapi import Depends, Response

from cremore.api.http_support import http_error as _http
from cremore.onboarding import catalog, github_app, github_enterprise, service, sessions
from cremore.onboarding.store import ProviderConnectionConflict


def _call(function, *args):
    try:
        return function(*args)
    except service.OnboardingError as exc:
        raise _http(exc.status, exc.code) from None
    except ProviderConnectionConflict as exc:
        raise _http(409, str(exc)) from None
    except catalog.CatalogError:
        raise _http(422, "PROVIDER_UNKNOWN") from None
    except ValueError as exc:
        # Provider validators expose only fixed codes; never echo credentials or responses.
        from cremore.onboarding.check import _code

        raise _http(422, _code(exc)) from None


def register(ctx) -> None:
    app, repo, settings = ctx.app, ctx.repo, ctx.settings
    require_auth, require_role = ctx.require_auth, ctx.require_role

    @app.post("/api/v1/onboarding-sessions", status_code=202)
    def create_onboarding_session(body: dict, response: Response, actor: str = Depends(require_role("admin"))):
        response.headers["Cache-Control"] = "no-store"
        return _call(sessions.create, repo, settings, body, actor)

    @app.post("/api/v1/onboarding-sessions/{session_id}/{action}")
    def advance_onboarding_session(session_id: str, action: str, body: dict, response: Response,
                                   actor: str = Depends(require_role("admin"))):
        response.headers["Cache-Control"] = "no-store"
        if action == "complete":
            return _call(sessions.complete, repo, settings, session_id, body, actor)
        function = {"read": sessions.read, "discover": sessions.discover, "inspect": sessions.inspect,
                    "select": sessions.select, "cancel": sessions.cancel, "authenticate": sessions.authenticate}.get(action)
        if function is None:
            raise _http(404, "ONBOARDING_ACTION_UNKNOWN")
        return _call(function, repo, session_id, body, actor)

    @app.get("/api/v1/provider-connections/catalog")
    def provider_catalog(_actor: str = Depends(require_auth)) -> dict:
        """The providers, editions, purposes, permission checklists and auth methods the wizard offers, and on a
        team install the sign-in IdP, the only one a people directory may be (cremore.onboarding.sign_in)."""
        from cremore.onboarding import sign_in

        return {"purposes": list(catalog.PURPOSES), "providers": catalog.public(), "sign_in_idp": sign_in.idp(settings),
                "schedules_allowed": settings.scan_schedules_allowed}

    def _flagged(view: dict) -> dict:
        """A people directory that is not the sign-in IdP -- made before people signed in through it -- says so
        (``sign_in_problem``); whether to stop it is the admin's call."""
        from cremore.onboarding import sign_in

        if view["status"] != "DISABLED" and "identity" in view["plans"]:
            code = sign_in.problem(settings, view["provider"], view["target"], ["identity"], repo=repo, excluding=view["id"])
            if code:
                return {**view, "sign_in_problem": code}
        return view

    @app.get("/api/v1/provider-connections")
    def list_provider_connections(_actor: str = Depends(require_auth)) -> list[dict]:
        return [_flagged(view) for view in service.list_views(repo)]

    @app.get("/api/v1/provider-connections/suggestions")
    def provider_suggestions(_actor: str = Depends(require_role("admin"))) -> dict:
        """Services the company's IdP already lists that no connection covers yet (a hint, from stored inventory)."""
        from cremore.onboarding.store import ProviderConnectionStore
        from cremore.onboarding.suggestions import suggestions

        return {"items": suggestions(repo, ProviderConnectionStore(repo).list())}

    @app.post("/api/v1/provider-connections", status_code=201)
    def create_provider_connection(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """Steps 1 and 2: provider, edition, purposes, auth method, target and credential."""
        response.headers["Cache-Control"] = "no-store"
        return _call(service.create, repo, settings, body, actor)

    @app.get("/api/v1/provider-connections/{connection_id}")
    def get_provider_connection(connection_id: str, _actor: str = Depends(require_auth)) -> dict:
        return _flagged(service.view(repo, _call(service.get, repo, connection_id)))

    @app.patch("/api/v1/provider-connections/{connection_id}")
    def rename_provider_connection(connection_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        return _call(service.rename, repo, connection_id, body, actor)

    @app.post("/api/v1/provider-connections/{connection_id}/check", status_code=202)
    def check_provider_connection(connection_id: str, body: dict | None = None,
                                  actor: str = Depends(require_role("admin"))) -> dict:
        """Step 3: the worker checks each purpose's permissions with the stored credential."""
        return _call(service.request_check, repo, connection_id, actor, body)

    @app.post("/api/v1/provider-connections/{connection_id}/targets/draft", status_code=202)
    def edit_provider_targets(connection_id: str, body: dict, response: Response, actor: str = Depends(require_role("admin"))):
        response.headers["Cache-Control"] = "no-store"
        return _call(sessions.edit, repo, settings, connection_id, body, actor)

    @app.put("/api/v1/provider-connections/{connection_id}/targets")
    def remove_provider_targets(connection_id: str, body: dict, response: Response, actor: str = Depends(require_role("admin"))):
        response.headers["Cache-Control"] = "no-store"
        return _call(service.remove_targets, repo, settings, connection_id, body, actor)

    @app.put("/api/v1/provider-connections/{connection_id}/purposes")
    def update_provider_connection_purposes(connection_id: str, body: dict,
                                           actor: str = Depends(require_role("admin"))) -> dict:
        """Choose features on the same identity; check again before activating additions."""
        return _call(service.update_purposes, repo, settings, connection_id, body, actor)

    @app.post("/api/v1/provider-connections/{connection_id}/activate")
    def activate_provider_connection(connection_id: str, body: dict, response: Response,
                                     actor: str = Depends(require_role("admin"))) -> dict:
        """Step 4: create what each chosen purpose runs on. A collector token is returned once."""
        response.headers["Cache-Control"] = "no-store"
        return _call(service.activate, repo, settings, connection_id, body, actor)

    @app.put("/api/v1/provider-connections/{connection_id}/plans/{purpose}")
    def update_provider_connection_plan(connection_id: str, purpose: str, body: dict, response: Response,
                                        actor: str = Depends(require_role("admin"))) -> dict:
        """Change an active purpose's plan; its collections follow it from their next run."""
        response.headers["Cache-Control"] = "no-store"  # a collection it adds may carry its collector token
        return _call(service.update_plan, repo, settings, connection_id, purpose, body, actor)

    @app.put("/api/v1/provider-connections/{connection_id}/credential")
    def change_provider_credential(connection_id: str, body: dict, response: Response,
                                   actor: str = Depends(require_role("admin"))) -> dict:
        response.headers["Cache-Control"] = "no-store"
        return _call(service.set_credential, repo, settings, connection_id, body, actor)

    @app.put("/api/v1/provider-connections/{connection_id}/features/{purpose}")
    def set_provider_feature(connection_id: str, purpose: str, body: dict, response: Response,
                             actor: str = Depends(require_role("admin"))) -> dict:
        response.headers["Cache-Control"] = "no-store"
        return _call(service.set_feature, repo, settings, connection_id, purpose, body, actor)

    @app.post("/api/v1/provider-connections/{connection_id}/disable")
    def disable_provider_connection(connection_id: str, actor: str = Depends(require_role("admin"))) -> dict:
        return _call(service.set_enabled, repo, connection_id, False, actor)

    @app.post("/api/v1/provider-connections/{connection_id}/enable")
    def enable_provider_connection(connection_id: str, actor: str = Depends(require_role("admin"))) -> dict:
        return _call(service.set_enabled, repo, connection_id, True, actor, settings)

    @app.delete("/api/v1/provider-connections/{connection_id}", status_code=204)
    def delete_provider_connection(connection_id: str, actor: str = Depends(require_role("admin"))) -> Response:
        """Only a connection that owns nothing is deleted; one in use is disabled instead."""
        _call(service.delete, repo, connection_id, actor)
        return Response(status_code=204)

    # --- a GitHub App made from a manifest ----------------------------------------------------------------

    def _github(function, *args):
        try:
            return function(*args)
        except github_app.GitHubAppError as exc:
            raise _http(exc.status, exc.code) from None

    def github_client():
        """The API's own client for GitHub's code exchange and installation lookup (tests inject one)."""
        factory = getattr(app.state, "github_app_http_client", None)
        if callable(factory):
            return factory()
        import httpx

        return httpx.Client(timeout=30, follow_redirects=False)

    @app.post("/api/v1/github/app-manifest/start")
    def github_manifest_start(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """The manifest and GitHub's page to post it to, for the wizard's choices or an existing connection."""
        response.headers["Cache-Control"] = "no-store"
        return _github(github_app.start, repo, settings, body, actor)

    @app.post("/api/v1/github/app-manifest/convert")
    def github_manifest_convert(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """GitHub's code for the App it made: exchanged here only; the App's key never reaches the browser."""
        response.headers["Cache-Control"] = "no-store"
        return _github(github_app.convert, repo, settings, body, actor, github_client)

    @app.post("/api/v1/github/app-manifest/complete")
    def github_manifest_complete(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """The App's installation on the organization, and the connection that signs in with it."""
        response.headers["Cache-Control"] = "no-store"
        return _github(github_app.complete, repo, settings, body, actor, github_client)

    @app.post("/api/v1/github/app-manifest/cancel", status_code=204)
    def github_manifest_cancel(body: dict, actor: str = Depends(require_role("admin"))) -> Response:
        github_app.cancel(repo, body, actor)
        return Response(status_code=204)

    def _enterprise(function, *args):
        from cremore_github_provider.github_auth import GitHubAuthError

        try:
            return function(*args)
        except (github_enterprise.GitHubEnterpriseError, service.OnboardingError) as exc:
            raise _http(exc.status, exc.code) from None
        except GitHubAuthError as exc:
            raise _http(502, exc.code) from None

    # One answer per source serves half a minute: each asks GitHub for a token and every organization.
    enterprise_seen: dict[str, tuple[float, dict]] = {}

    def _seen_key(connection_id: str) -> str:
        import uuid

        try:
            return str(uuid.UUID(str(connection_id)))
        except ValueError:
            return str(connection_id)

    def _forget(connection_id: str) -> None:
        enterprise_seen.pop(_seen_key(connection_id), None)
        if len(enterprise_seen) > 100:
            enterprise_seen.clear()

    @app.get("/api/v1/provider-connections/{connection_id}/github-enterprise")
    def github_enterprise_status(connection_id: str, response: Response, _actor: str = Depends(require_role("admin"))) -> dict:
        """What is left to do in GitHub, and each organization of the enterprise: App installed, connection, progress."""
        import time

        response.headers["Cache-Control"] = "no-store"
        key = _seen_key(connection_id)
        seen = enterprise_seen.get(key)
        if seen is not None and time.monotonic() - seen[0] < 30:
            return seen[1]
        answer = _enterprise(github_enterprise.status, repo, settings, connection_id, github_client)
        enterprise_seen[key] = (time.monotonic(), answer)
        return answer

    @app.post("/api/v1/provider-connections/{connection_id}/github-enterprise/install", status_code=202)
    def github_enterprise_install(connection_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Queue organizations; the worker installs the App on each, connects it and activates it once checked."""
        _forget(connection_id)
        return _enterprise(github_enterprise.request, repo, settings, connection_id, (body or {}).get("organizations"), actor)

    @app.post("/api/v1/provider-connections/{connection_id}/github-enterprise/cancel")
    def github_enterprise_cancel(connection_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Take waiting organizations off the queue; auto-install leaves them out from then on."""
        _forget(connection_id)
        return _enterprise(github_enterprise.cancel, repo, settings, connection_id, (body or {}).get("organizations"), actor)

    @app.put("/api/v1/provider-connections/{connection_id}/github-enterprise/auto")
    def github_enterprise_auto(connection_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Install on organizations that appear from now on, once an hour; off drops what it queued."""
        enabled = (body or {}).get("enabled")
        if not isinstance(enabled, bool):
            raise _http(422, "ENABLED_REQUIRED")
        _forget(connection_id)
        return _enterprise(github_enterprise.set_auto, repo, settings, connection_id, enabled, actor)
