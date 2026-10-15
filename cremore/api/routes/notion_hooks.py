"""Exact Notion ingress and authenticated subscription administration."""

from fastapi import Depends, Request, Response
from starlette.concurrency import run_in_threadpool

from cremore.api.http_support import http_error, parse_uuid
from cremore.scanning import notion_webhooks as hooks
from cremore.scanning.scope import ScopeError
from cremore.secretstore.sealed import SealedSecretError


def register(ctx):
    app, repo, settings = ctx.app, ctx.repo, ctx.settings
    admin = ctx.require_role("admin")

    def invoke(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except hooks.Error as exc:
            code = str(exc)
            status = 404 if code == "NOTION_WEBHOOK_UNKNOWN" else 403 if "SIGNATURE" in code else 409
            raise http_error(status, code) from None
        except ScopeError as exc:
            raise http_error(exc.http_status, exc.code) from None
        except SealedSecretError:
            raise http_error(409, "NOTION_WEBHOOK_SEALING_KEY_REQUIRED") from None

    @app.get("/api/v1/settings/notion-webhooks")
    def subscriptions(_actor: str = Depends(admin)):
        profiles = []
        for conn in repo.list_connections():
            if conn.provider == "notion" and conn.status != "DISABLED":
                profiles.extend({"id": str(p.id), "name": p.name, "connection": conn.name}
                    for p in repo.list_scope_profiles("source", conn.id)
                    if p.event_mode == "ENABLED" and p.state == "READY" and p.approved_at)
        return {"bindings": hooks.public(repo), "profiles": profiles}

    @app.post("/api/v1/settings/notion-webhooks")
    def create_subscription(body: dict, actor: str = Depends(admin)):
        return invoke(hooks.create, repo, settings, str(parse_uuid(body.get("profile_id"), "profile_id")), actor)

    @app.get("/api/v1/settings/notion-webhooks/{binding_id}/verification")
    def verification(binding_id: str, response: Response, _actor: str = Depends(admin)):
        response.headers["Cache-Control"] = "no-store"
        return invoke(hooks.challenge, repo, settings, str(parse_uuid(binding_id, "binding_id")))

    @app.post("/api/v1/settings/notion-webhooks/{binding_id}/confirm")
    def confirm(binding_id: str, body: dict, actor: str = Depends(admin)):
        if body.get("verified_in_notion") is not True:
            raise http_error(409, "NOTION_WEBHOOK_OPERATOR_CONFIRMATION_REQUIRED")
        return invoke(hooks.confirm, repo, settings, str(parse_uuid(binding_id, "binding_id")), actor,
                      probe_digest=body.get("probe_digest"))

    @app.delete("/api/v1/settings/notion-webhooks/{binding_id}")
    def disable(binding_id: str, actor: str = Depends(admin)):
        invoke(hooks.remove, repo, str(parse_uuid(binding_id, "binding_id")), actor)
        return {"disabled": True}

    @app.post("/api/v1/hooks/notion/{binding_id}")
    async def incoming(binding_id: str, request: Request):
        identity = str(parse_uuid(binding_id, "binding_id"))
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > hooks.provider.MAX_BODY:
                raise http_error(413, "NOTION_WEBHOOK_BODY_LIMIT")
            raw.extend(chunk)
        return await run_in_threadpool(invoke, hooks.receive, repo, settings, identity, bytes(raw),
                                       request.headers.get("X-Notion-Signature"))
