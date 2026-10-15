"""Departed owners' credentials: people, account links and verdicts (cremore.identity.leavers).

Reading is for analysts and up: the lists name people by their IdP user id and
provider accounts by login. Confirming or rejecting a link is an administrator's
decision. Disabling an AWS access key a departed person left goes through the
existing action plan: a remediator plans it, another administrator approves it,
and nothing runs unless ACTION_EXECUTION_ENABLED is on.
"""

from __future__ import annotations

import re
import uuid

from fastapi import Depends

from cremore.api.http_support import http_error as _http
from cremore.api.http_support import parse_uuid as _uuid
from cremore.detection.fingerprint import mask_hint
from cremore.domain.models import FindingEvent
from cremore.identity import leavers
from cremore.remediation.action_plans import ActionPlanError

_ACCOUNT_REF = re.compile(r"[a-z_]{1,32}\|[\x21-\x7e]{1,600}")
_VERDICT_ORDER = {verdict: index for index, verdict in enumerate(leavers.VERDICTS)}


class _OrphanKey:
    """The credential-shaped view of a departed person's IAM access key an action plan needs."""

    credential_type = "AWS_ACCESS_KEY_ID"

    def __init__(self, ref, action):
        self.id = ref
        self.principal_arn = action["principal_arn"]
        self.identifier = action["key_id"]
        # The same masked form every other screen shows (AKIA••••MPLE).
        self.identifier_hint = mask_hint(action["key_id"])


def public_orphan(row) -> dict:
    body = row["body"]
    credential = dict(body.get("credential") or {}) or None
    actionable = bool(credential and credential.pop("action", None))
    return {"ref": str(row["orphan_ref"]), "verdict": row["verdict"], "provider": row["provider"],
            "person": body["person"], "account": body["account"], "credential": credential,
            "reasons": body.get("reasons", []), "ticket_id": str(row["ticket_id"]) if row.get("ticket_id") else None,
            "actionable": actionable, "first_seen_at": _iso(row.get("first_seen_at")), "updated_at": _iso(row.get("updated_at"))}


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def register(ctx) -> None:
    app, repo, settings, action_plans = ctx.app, ctx.repo, ctx.settings, ctx.action_plans
    analyst, admin, remediator = ctx.require_role("analyst"), ctx.require_role("admin"), ctx.require_role("remediator")

    def _state():
        return leavers.LeaverStore(repo)

    def _open_candidates(last, state):
        """The last check's candidate links an administrator has not decided yet (a decision takes effect at once)."""
        decided = {key for key, link in state.links().items() if link["decision"] in ("CONFIRMED", "REJECTED")}
        return [item for item in last.get("candidate_links") or []
                if (item["account_ref"], uuid.UUID(item["person_ref"])) not in decided]

    def _audit(event_type, actor, target_type, target_id, note):
        repo.record_finding_event(FindingEvent(target_type=target_type, target_id=target_id, actor=actor,
                                               event_type=event_type, note=note))

    @app.get("/api/v1/leavers/summary")
    def leaver_summary(_actor: str = Depends(analyst)) -> dict:
        from cremore.coverage.metadata_store import MetadataStore
        from cremore.identity.idp import apps_only

        state = _state()
        people, orphans = state.people(), state.orphans()
        idps, directories = leavers.identity_providers()
        store = MetadataStore(repo)
        sources = []
        for row in store.list_connections():
            provider = row["spec"].get("provider")
            if (provider not in idps and provider not in directories) or (provider in idps and apps_only(row["spec"])):
                continue  # an IdP's app list names no people
            latest = store.connection_runs(row["id"], limit=1)["items"]
            sources.append({"connection_id": str(row["id"]), "name": row["spec"].get("name"), "provider": provider,
                            "role": "idp" if provider in idps else "directory", "enabled": row["enabled"],
                            "latest_run": {key: _iso(latest[0][key]) for key in ("status", "started_at", "finished_at")}
                            if latest else None})
        by_verdict = dict.fromkeys(leavers.VERDICTS, 0)
        for row in orphans.values():
            by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
        last = (repo.get_setting(leavers.RESULT_KEY) or {}).get("value") or {}
        return {"people": sum(row["state"] not in ("PURGED",) for row in people.values()),
                "departed": sum(row["state"] == leavers.DEPARTED for row in people.values()),
                "departed_with_credentials": len({row["person_ref"] for row in orphans.values()}),
                "orphans": len(orphans), "by_verdict": by_verdict,
                "candidates": len(_open_candidates(last, state)), "sources": sources,
                "evaluated_at": last.get("evaluated_at"),
                # PARTIAL: the latest check stopped at a listing it could not read whole (reasons say which); the
                # verdicts are the last complete check's.
                "status": last.get("status"), "reasons": last.get("reasons") or [],
                "retention_days": settings.leaver_retention_days,
                "history_days": leavers.IDENTITY_RUN_HISTORY_DAYS}

    @app.get("/api/v1/leavers/orphans")
    def leaver_orphans(verdict: str = "", provider: str = "", person_ref: str = "", offset: int = 0, limit: int = 50,
                       _actor: str = Depends(analyst)) -> dict:
        if offset < 0 or not 1 <= limit <= 200:
            raise _http(422, "offset must be >= 0 and limit 1-200")
        rows = list(_state().orphans().values())
        facets = {"verdict": sorted({row["verdict"] for row in rows}, key=_VERDICT_ORDER.get),
                  "provider": sorted({row["provider"] for row in rows})}
        person = str(_uuid(person_ref, "person_ref")) if person_ref else ""
        rows = [row for row in rows if (not verdict or row["verdict"] == verdict)
                and (not provider or row["provider"] == provider) and (not person or str(row["person_ref"]) == person)]
        rows.sort(key=lambda row: (_VERDICT_ORDER.get(row["verdict"], 9),
                                   -(_departed(row) or 0), str(row["orphan_ref"])))
        return {"items": [public_orphan(row) for row in rows[offset:offset + limit]], "total": len(rows),
                "offset": offset, "limit": limit, "facets": facets}

    def _departed(row):
        value = leavers._time(row["body"]["person"].get("departed_at"))
        return value.timestamp() if value else None

    @app.get("/api/v1/people")
    def people_directory(q: str = "", cursor: str = "", limit: int = 200, _actor: str = Depends(analyst)) -> dict:
        """The people IdP collections that keep profiles name: name, email, department, title and state."""
        from cremore.identity import people

        if not 1 <= limit <= 500 or len(q) > 200:
            raise _http(422, "limit must be 1-500 and q at most 200 characters")
        try:
            return people.directory(repo, settings, query=q, cursor=cursor, limit=limit)
        except people.DirectoryError as exc:
            raise _http(exc.http_status, exc.code) from None

    @app.get("/api/v1/leavers/people")
    def leaver_people(state: str = "DEPARTED", offset: int = 0, limit: int = 50, _actor: str = Depends(analyst)) -> dict:
        if state not in ("DEPARTED", "ACTIVE", "PENDING", "UNKNOWN") or offset < 0 or not 1 <= limit <= 200:
            raise _http(422, "state must be DEPARTED, ACTIVE, PENDING or UNKNOWN; limit 1-200")
        store = _state()
        orphans = store.orphans().values()
        links = store.links()
        rows = [row for row in store.people().values() if row["state"] == state]
        rows.sort(key=lambda row: (-(leavers._time(row.get("departed_at")) or leavers._now()).timestamp(),
                                   str(row["person_ref"])))
        items = []
        for row in rows[offset:offset + limit]:
            mine = [item for item in orphans if item["person_ref"] == row["person_ref"]]
            accounts = sorted({key[0] for key, link in links.items() if key[1] == row["person_ref"]
                               and link["decision"] in ("MATCHED", "CONFIRMED")})
            items.append({"ref": str(row["person_ref"]), "provider": row["provider"], "idp_user_id": row["idp_user_id"],
                          "state": row["state"], "idp_state": row["idp_state"],
                          "departed_at": _iso(row.get("departed_at")), "departure_basis": row.get("departure_basis"),
                          "first_seen_at": _iso(row.get("first_seen_at")), "last_seen_at": _iso(row.get("last_seen_at")),
                          "accounts": [{"ref": ref, "provider": ref.split("|", 1)[0], "label": ref.rsplit("|", 1)[-1]}
                                       for ref in accounts],
                          "verdicts": {verdict: sum(item["verdict"] == verdict for item in mine)
                                       for verdict in leavers.VERDICTS}})
        return {"items": items, "total": len(rows), "offset": offset, "limit": limit}

    @app.get("/api/v1/leavers/candidates")
    def leaver_candidates(_actor: str = Depends(analyst)) -> dict:
        last = (repo.get_setting(leavers.RESULT_KEY) or {}).get("value") or {}
        state = _state()
        people = state.people()
        items = []
        for item in _open_candidates(last, state):
            person = people.get(uuid.UUID(item["person_ref"]))
            if person is None or person["state"] != leavers.DEPARTED:
                continue
            items.append({**item, "person": {"provider": person["provider"], "idp_user_id": person["idp_user_id"],
                                             "departed_at": _iso(person.get("departed_at"))}})
        return {"items": items, "total": len(items), "evaluated_at": last.get("evaluated_at")}

    def _link_target(body):
        if not isinstance(body, dict):
            raise _http(422, "request must be an object")
        account = body.get("account_ref")
        if not isinstance(account, str) or not _ACCOUNT_REF.fullmatch(account):
            raise _http(422, "account_ref must be an account reference from a leaver list")
        person = _uuid(body.get("person_ref"), "person_ref")
        if person not in _state().people():
            raise _http(404, "person not found")
        return account, person

    @app.post("/api/v1/leavers/links")
    def decide_link(body: dict, actor: str = Depends(admin)) -> dict:
        account, person = _link_target(body)
        decision = body.get("decision")
        if decision not in ("CONFIRMED", "REJECTED"):
            raise _http(422, "decision must be CONFIRMED or REJECTED")
        row = {"account_ref": account, "person_ref": person, "decision": decision,
               "basis": "OPERATOR_CONFIRMED" if decision == "CONFIRMED" else "OPERATOR_REJECTED",
               "actor_ref": actor, "decided_at": leavers._now()}
        _state().save(links=[row])
        _audit("LEAVER_LINK_" + decision, actor, "identity_person", person, "provider " + account.split("|", 1)[0])
        return {"account_ref": account, "person_ref": str(person), "decision": decision,
                "decided_at": row["decided_at"].isoformat()}

    @app.delete("/api/v1/leavers/links")
    def clear_link(account_ref: str, person_ref: str, actor: str = Depends(admin)) -> dict:
        account, person = _link_target({"account_ref": account_ref, "person_ref": person_ref})
        current = _state().links().get((account, person))
        if current is None or current["decision"] not in ("CONFIRMED", "REJECTED"):
            raise _http(404, "no administrator decision for this link")
        _state().save(removed_links=[(account, person)])
        _audit("LEAVER_LINK_CLEARED", actor, "identity_person", person, "provider " + account.split("|", 1)[0])
        return {"account_ref": account, "person_ref": str(person), "decision": None}

    @app.post("/api/v1/leavers/evaluate")
    def evaluate_now(actor: str = Depends(admin)) -> dict:
        try:
            result = leavers.evaluate(repo, settings, getattr(app.state, "orchestrator", None))
        except ValueError:
            raise _http(409, "IDENTITY_KEY_UNAVAILABLE: FINGERPRINT_KEY is required")
        _audit("LEAVER_EVALUATED", actor, "identity_check", None, "manual evaluation")
        return result

    def _orphan_key(ref):
        row = _state().orphans().get(_uuid(ref, "orphan_ref"))
        if row is None:
            raise _http(404, "orphan not found")
        action = ((row["body"].get("credential") or {}).get("action")) or None
        if row["provider"] != "aws" or not action:
            raise _http(409, "CREDENTIAL_NOT_ELIGIBLE: only an AWS access key of a departed owner can be disabled here")
        return _OrphanKey(row["orphan_ref"], action)

    @app.get("/api/v1/leavers/orphans/{orphan_ref}/action-plans")
    def orphan_action_plans(orphan_ref: str, _actor: str = Depends(analyst)) -> dict:
        key = _orphan_key(orphan_ref)
        return {"plans": [action_plans.public(plan) for plan in repo.list_action_plans(key.id)],
                "policy": {**action_plans.policy(key), "supported_actions": ["DISABLE_ACCESS_KEY"],
                           "reason_code": "OWNER_DEPARTED"}}

    @app.post("/api/v1/leavers/orphans/{orphan_ref}/action-plans", status_code=201)
    def plan_orphan_disable(orphan_ref: str, body: dict, actor: str = Depends(remediator)) -> dict:
        """Plan disabling the key; another administrator approves it on the usual action-plan routes."""
        key = _orphan_key(orphan_ref)
        if not isinstance(body, dict) or body.get("action_type", "DISABLE_ACCESS_KEY") != "DISABLE_ACCESS_KEY":
            raise _http(422, "a departed owner's key can only be disabled")
        account = next((a for a in repo.list_aws_accounts()
                        if a.account_id == action_plans._iam_user(key.principal_arn)[1]), None)
        try:
            plan = action_plans.create(key, str(account.id) if account else "", actor,
                                       {**body, "action_type": "DISABLE_ACCESS_KEY", "reason_code": "OWNER_DEPARTED"})
        except ActionPlanError as exc:
            raise _http(exc.http_status, f"{exc.code}: {exc}")
        return action_plans.public(plan)
