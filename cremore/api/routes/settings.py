"""Installation switches an Admin owns, and what the environment hard-locks off.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

import datetime as _dt
import uuid

from cremore_aws_provider import aws_inventory_settings, aws_org_settings, aws_sso, aws_sso_settings
from cremore_aws_provider.investigation import investigation_switches
from fastapi import Depends, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from cremore.api.auth import LOCAL_ACTOR
from cremore.api.http_support import actor_label as _actor_label
from cremore.api.http_support import http_error as _http
from cremore.api.http_support import isoformat as _iso
from cremore.api.http_support import logger as _log
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.route_context import DashboardContext
from cremore.installation_settings import (  # noqa: F401 -- preserve old import paths
    change_note,
    locked_installation_settings,
    setting_changed,
)
from cremore.scanning import (
    inventory_manifests,
    learned_fp_settings,
    scan_switches,
    trigger_settings,
    verification_switch,
)

_CONTACT_TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:contact_delivery")
_OWNER_POLICY_TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:owner_approval_policy")
_TICKET_TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:ticket_system")


class ResponseChannelEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel_id: str = Field(min_length=1, max_length=20)
    allow_public: StrictBool = False


class ResponseChannelsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: StrictInt = Field(ge=0)
    channels: list[ResponseChannelEntry] = Field(max_length=50)


def register(ctx: DashboardContext) -> None:
    _INVESTIGATION_LABELS, app, repo, require_auth = ctx._INVESTIGATION_LABELS, ctx.app, ctx.repo, ctx.require_auth
    require_role, settings = ctx.require_role, ctx.settings

    def _changed(before: dict, after: dict, names) -> dict:
        """The named fields whose value the request changes (an unset text reads as empty): what the note names."""
        def plain(value):
            return "" if value is None else value
        return {name: after[name] for name in names if name in after and plain(after[name]) != plain(before.get(name))}

    def _saved(values: dict[str, dict], actor: str, what: str, changes: dict, plain: tuple[str, ...] = (),
               owners: dict[str, str] | None = None, base: dict | None = None) -> bool:
        """Store an Admin's settings and the audit row naming the change in one transaction (change_note), and say
        whether anything was stored. Only what changes is stored: nothing when no field changes, and of several
        settings only those holding a changed field (``owners`` names each field's setting), so no "last changed
        by" moves without a row saying what. ``base`` is each multi-field setting's row as the request read it before
        building on it: a save that another Admin's save overtook since is refused, never written over theirs (the
        stored value is compared, not its time: a clock tick can hold two saves)."""
        if owners is not None:
            values = {key: value for key, value in values.items() if key in {owners[name] for name in changes}}
        if not values or not changes:
            return False
        with locked_installation_settings(repo) as bound:
            for key, row in (base or {}).items():
                if key in values and (bound.get_setting(key) or {}).get("value") != (row or {}).get("value"):
                    raise _http(409, "SETTING_CHANGED_MEANWHILE: another admin saved this setting first; reload it "
                                     "and save again")
            bound.put_settings(values, actor)
            setting_changed(bound, actor, what, changes, plain)
        return True

    # --- the installation's machine identity from the organization's IdP -----------------------------------
    # Set here, used by every API and worker process (cremore/identity/machine.py). The client secret is
    # sealed on arrival and never returned; processes report their state and the tokens' non-secret claims.

    def _machine_view() -> dict:
        from cremore.identity import machine

        processes = [dict(item["value"]) for item in repo.list_settings(machine.STATUS_PREFIX)]
        test = repo.get_setting(machine.TEST_KEY)
        shown = dict(test["value"]) if test else None
        current = repo.get_setting(machine.KEY)
        if shown and getattr(settings, "isolated_deployment", False):
            if shown.get("revision") != machine.revision_of(current):
                shown.update(state="FAILED", error="MACHINE_IDENTITY_CHANGED", tokens={})
            elif shown.get("state") == "QUEUED":
                from cremore.domain.models import ACTIVE_JOB_STATUSES

                try:
                    job = repo.get_job(uuid.UUID(shown["job_id"]))
                except (ValueError, TypeError, KeyError):
                    job = None
                if job is None or job.status not in ACTIVE_JOB_STATUSES:
                    shown.update(state="FAILED", error="MACHINE_IDENTITY_TEST_NOT_COMPLETED", tokens={})
        return {**machine.public(current), "processes": processes, "test": shown}

    @app.get("/api/v1/settings/machine-identity")
    def get_machine_identity(_actor: str = Depends(require_role("admin"))) -> dict:
        return _machine_view()

    @app.put("/api/v1/settings/machine-identity")
    def put_machine_identity(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.identity import machine

        try:
            machine.save(repo, settings, body or {}, actor)
        except machine.MachineIdentityError as exc:
            code = str(exc)
            raise _http(409 if code == "MACHINE_IDENTITY_CHANGED" else 422, code) from None
        _log.info("machine identity changed by %s", actor)
        return _machine_view()

    @app.post("/api/v1/settings/machine-identity/test")
    def test_machine_identity(actor: str = Depends(require_role("admin"))) -> dict:
        """Fetch each configured token once from this API process; only codes and non-secret claims come back."""
        from cremore.identity import machine

        if getattr(settings, "isolated_deployment", False):
            from cremore.db.settings_store import locked_settings
            from cremore.domain.models import ACTIVE_JOB_STATUSES, ScanJob

            with locked_settings(repo, setting_key=machine.TEST_KEY) as bound:
                revision = machine.revision_of(bound.get_setting(machine.KEY))
                if not machine.in_use((bound.get_setting(machine.KEY) or {}).get("value")):
                    raise _http(409, "MACHINE_IDENTITY_NOT_CONFIGURED")
                previous = (bound.get_setting(machine.TEST_KEY) or {}).get("value") or {}
                old = bound.get_job(uuid.UUID(previous["job_id"])) if previous.get("job_id") else None
                if old is None or old.status not in ACTIVE_JOB_STATUSES or previous.get("revision") != revision:
                    job = bound.enqueue_job(ScanJob(kind="machine-identity-check", payload={"revision": revision, "actor": actor}))
                    bound.put_setting(machine.TEST_KEY, {"tokens": {}, "tested_by": actor, "revision": revision,
                                      "state": "QUEUED", "job_id": str(job.id)}, actor)
            return _machine_view()

        keeper = machine.Keeper(repo, settings, "test", client=getattr(app.state, "machine_identity_http_client", None))
        try:
            tokens = keeper.test()
        except machine.MachineIdentityError as exc:
            raise _http(409, str(exc)) from None
        repo.put_setting(machine.TEST_KEY, {"tokens": tokens, "tested_by": actor,
            "revision": machine.revision_of(repo.get_setting(machine.KEY))}, actor)
        return _machine_view()

    @app.get("/api/v1/settings/machine-identity/setup")
    def machine_identity_setup(_actor: str = Depends(require_role("admin"))) -> dict:
        """For each enabled cloud, the commands that make it trust the IdP token, named from the tokens seen."""
        from cremore_aws_provider import aws_identity

        from cremore.api.aws_support import SCANNER_ROLE_NAME, hub_scope
        from cremore.identity import machine

        row = repo.get_setting(machine.KEY)
        revision = machine.revision_of(row)
        observed: dict = {}
        for item in repo.list_settings(machine.STATUS_PREFIX):
            if item["value"].get("revision") != revision:
                continue
            for name, entry in (item["value"].get("tokens") or {}).items():
                if entry.get("claims"):
                    observed.setdefault(name, entry)
        test = repo.get_setting(machine.TEST_KEY)
        test_value = (test or {}).get("value", {})
        for name, entry in (test_value.get("tokens") or {}).items() if test_value.get("revision") == revision else ():
            if entry.get("claims"):
                observed[name] = entry
        role = ((row or {}).get("value") or {}).get("aws", {}).get("role_arn") or "arn:aws:iam::000000000000:role/x"
        policy = aws_identity.hub_policy(role.split(":")[1], SCANNER_ROLE_NAME, **hub_scope(repo))
        return {"steps": machine.setup_steps((row or {}).get("value"), observed, policy)}

    # --- owner contact that CreMore sends itself (cremore/governance/contact.py) ----------------------------
    # The relay password and the bot token are sealed on arrival and never returned; saves and tests are audited.

    def _contact_audit(actor: str, event_type: str, note: str) -> None:
        from cremore.domain.models import FindingEvent

        repo.record_finding_event(FindingEvent(target_type="contact_delivery", target_id=_CONTACT_TARGET, actor=actor,
                                               event_type=event_type, note=note))

    @app.get("/api/v1/settings/contact-delivery")
    def get_contact_delivery(response: Response, _actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.governance import contact

        response.headers["Cache-Control"] = "no-store"
        # Owner approval links are sent only with company sign-in, so only then does the console address matter.
        return {**contact.public(repo), "owner_links": settings.auth_mode == "oidc"}

    @app.put("/api/v1/settings/contact-delivery")
    def put_contact_delivery(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.governance import contact

        response.headers["Cache-Control"] = "no-store"
        try:
            view, note = contact.save(repo, settings, body, actor)
        except contact.ContactError as exc:
            raise _http(exc.http_status, exc.code) from None
        _contact_audit(actor, "CONTACT_DELIVERY_SAVED", note)
        return {**view, "owner_links": settings.auth_mode == "oidc"}

    # --- the Slack channels exposure-response notices may go to (cremore/governance/response_channels.py) ---------
    # Each is read again from Slack on every save; saves are versioned and audited (RESPONSE_CHANNELS_SAVED).

    def _slack_client_factory():
        return (getattr(app.state, "contact_transports", None) or {}).get("http_client_factory")

    @app.get("/api/v1/settings/response-channels")
    def get_response_channels(response: Response, _actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.governance import response_channels

        response.headers["Cache-Control"] = "no-store"
        return response_channels.public(repo)

    @app.put("/api/v1/settings/response-channels")
    def put_response_channels(body: ResponseChannelsBody, response: Response,
                              actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.governance import response_channels
        from cremore.governance.response import ResponseError

        response.headers["Cache-Control"] = "no-store"
        try:
            return response_channels.save(repo, settings, body.model_dump(), actor,
                                          http_client_factory=_slack_client_factory())
        except ResponseError as exc:
            raise _http(exc.http_status, exc.code) from None

    @app.get("/api/v1/settings/response-channels/candidates")
    def response_channel_candidates(response: Response, _actor: str = Depends(require_role("admin"))) -> dict:
        """The channels the bot is in, read from Slack now (bounded), for the Admin to pick from."""
        from cremore.governance import response_channels
        from cremore.governance.response import ResponseError

        response.headers["Cache-Control"] = "no-store"
        try:
            return response_channels.candidates(repo, settings, http_client_factory=_slack_client_factory())
        except ResponseError as exc:
            raise _http(exc.http_status, exc.code) from None

    @app.get("/api/v1/response-channels")
    def listed_response_channels(_actor: str = Depends(require_role("analyst"))) -> dict:
        """The approved channels as the request form and the rule editor show them: id, name and privacy only."""
        from cremore.governance import response_channels

        return response_channels.listed(repo)

    # --- whether key actions wait for the owner's approval (cremore/remediation/owner_approval.py) ---------------

    def _owner_policy() -> dict:
        from cremore.remediation import owner_approval

        current = owner_approval.switch(repo)
        return {"required": current["required"],
                "updated_by": "local operator" if current["updated_by"] == LOCAL_ACTOR else current["updated_by"],
                "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None}

    @app.get("/api/v1/settings/owner-approval")
    def get_owner_approval_policy(_actor: str = Depends(require_auth)) -> dict:
        return _owner_policy()

    @app.put("/api/v1/settings/owner-approval")
    def put_owner_approval_policy(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Turn off (or back on) the owner's approval before a key action runs; audited in the same transaction."""
        from cremore.remediation import owner_approval

        required = (body or {}).get("required")
        if not isinstance(required, bool):
            raise _http(422, "required must be true or false")
        owner_approval.set_required(repo, required, actor, _OWNER_POLICY_TARGET)
        return _owner_policy()

    @app.post("/api/v1/settings/contact-delivery/test")
    def test_contact_delivery(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """One short message on one channel to one recipient, so an admin sees the setup work."""
        from cremore.governance import contact

        channel = body.get("channel") if isinstance(body, dict) else None
        if channel not in contact.CHANNELS:
            raise _http(422, "CONTACT_CHANNEL_INVALID")
        try:
            ready = contact.channels(repo)
            to = contact.recipients(channel, [body.get("to")], ready["allowed_domains"], ready["allowed_channels"])
            contact.reserve(repo, actor, len(to), _dt.datetime.now(_dt.UTC))
            sent = contact.send(repo, settings, channel, to, "CreMore contact test",
                                "CreMore 연락 발송 시험입니다. A CreMore contact test.",
                                **(getattr(app.state, "contact_transports", None) or {}))
        except contact.ContactError as exc:
            if exc.http_status in (429, 502):  # not sent: the relay or Slack refused, or the hour's limit
                _contact_audit(actor, "CONTACT_DELIVERY_TESTED", f"{channel} failed={exc.code}")
            raise _http(exc.http_status, exc.code) from None
        _contact_audit(actor, "CONTACT_DELIVERY_TESTED", f"{channel} delivered={len(sent['delivered'])}"
                       + "".join(f" failed={item['code']}" for item in sent["failed"]))
        return sent

    # --- the company's ticket system, where an owner's approval can be asked (cremore/ticketing) ---------------
    # Its secrets are sealed on arrival and never returned; saves and checks are audited without them.

    def _ticket_audit(actor: str, event_type: str, note: str) -> None:
        from cremore.domain.models import FindingEvent

        repo.record_finding_event(FindingEvent(target_type="ticket_system", target_id=_TICKET_TARGET, actor=actor,
                                               event_type=event_type, note=note))

    @app.get("/api/v1/settings/ticket-system")
    def get_ticket_system(response: Response, _actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.ticketing import setup

        response.headers["Cache-Control"] = "no-store"
        return setup.public(repo)

    @app.put("/api/v1/settings/ticket-system")
    def put_ticket_system(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        from cremore.ticketing import setup

        response.headers["Cache-Control"] = "no-store"
        try:
            view, _note = setup.save(repo, settings, body, actor, _TICKET_TARGET)  # audited with the change
        except setup.SetupError as exc:
            raise _http(exc.http_status, exc.code) from None
        return view

    @app.post("/api/v1/settings/ticket-system/check")
    def check_ticket_system(actor: str = Depends(require_role("admin"))) -> dict:
        """Sign in to the saved system and read what asking needs, so an admin sees the setup work."""
        from cremore.ticketing import setup
        from cremore.ticketing.contract import TicketError, safe_code

        client = ticket_http_client()
        try:
            system = setup.open_system(repo, settings, client).system
            try:
                system.check()
            finally:
                system.close()
        except TicketError as exc:
            code = safe_code(exc)  # an installed adapter's own text never reaches the audit trail
            _ticket_audit(actor, "TICKET_SYSTEM_CHECKED", f"failed={code}")
            return {"ok": False, "code": code}
        finally:
            client.close()
        _ticket_audit(actor, "TICKET_SYSTEM_CHECKED", "ok")
        return {"ok": True, "code": None}

    def ticket_http_client():
        factory = getattr(app.state, "ticket_http_client_factory", None)
        if factory is not None:
            return factory()
        import httpx

        return httpx.Client(timeout=15.0, follow_redirects=False)

    @app.get("/api/v1/settings/sign-in")
    def get_sign_in(_actor: str = Depends(require_role("admin"))) -> dict:
        """How people sign in (AUTH_MODE, OIDC_*): set in the installation's configuration, read here. With OIDC, the
        issuer and audience the API accepts and which IdP group grants each role (one group each; unset grants none).
        With Google, ``role_groups`` says when the worker last read those Workspace groups (cremore.identity.sign_in_groups)."""
        from cremore.identity import sign_in_groups

        if settings.auth_mode != "oidc":
            return {"mode": settings.auth_mode, "issuer": None, "audience": None, "groups_claim": None, "groups": None,
                    "role_groups": None}
        return {"mode": "oidc", "issuer": settings.oidc_issuer_url, "audience": settings.oidc_audience,
                "groups_claim": settings.oidc_groups_claim,
                "groups": {role: getattr(settings, f"oidc_{role}_group") or None
                           for role in ("viewer", "analyst", "remediator", "admin")},
                "role_groups": sign_in_groups.view(repo, settings)}

    def _verification_view() -> dict:
        current = verification_switch.switch(repo)
        return {
            "enabled": bool(settings.verification_enabled) and current["enabled"],
            "switch": current["enabled"],
            "installation_allows": bool(settings.verification_enabled),
            "updated_by": "local operator" if current["updated_by"] == LOCAL_ACTOR else current["updated_by"],
            "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None,
        }

    @app.get("/api/v1/settings/credential-verification")
    def get_credential_verification(_actor: str = Depends(require_auth)) -> dict:
        return _verification_view()

    @app.put("/api/v1/settings/credential-verification")
    def put_credential_verification(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        enabled = (body or {}).get("enabled")
        if not isinstance(enabled, bool):
            raise _http(422, "enabled must be true or false")
        if enabled and not settings.verification_enabled:
            raise _http(409, "VERIFICATION_LOCKED: CREDENTIAL_VERIFICATION_MODE=disabled locks verification off "
                        "for this installation")
        _saved({verification_switch.KEY: {"enabled": enabled}}, actor, verification_switch.KEY,
               _changed(verification_switch.switch(repo), {"enabled": enabled}, ["enabled"]))
        _log.info("credential verification switched %s by %s", "on" if enabled else "off", actor)
        return _verification_view()

    def _scan_toggle_view(key: str, allowed: bool, switch_fn) -> dict:
        current = switch_fn(repo)
        return {
            "enabled": bool(allowed) and current["enabled"],
            "switch": current["enabled"],
            "installation_allows": bool(allowed),
            "requires_verification": True,
            "updated_by": "local operator" if current["updated_by"] == LOCAL_ACTOR else current["updated_by"],
            "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None,
        }

    def _put_scan_toggle(key: str, allowed: bool, lock_msg: str, body: dict, actor: str, switch_fn) -> dict:
        enabled = (body or {}).get("enabled")
        if not isinstance(enabled, bool):
            raise _http(422, "enabled must be true or false")
        if enabled and not allowed:
            raise _http(409, lock_msg)
        _saved({key: {"enabled": enabled}}, actor, key, _changed(switch_fn(repo), {"enabled": enabled}, ["enabled"]))
        _log.info("scan toggle %s switched %s by %s", key, "on" if enabled else "off", actor)
        return _scan_toggle_view(key, allowed, switch_fn)

    @app.get("/api/v1/settings/local-credentials")
    def get_local_credentials(_actor: str = Depends(require_role("admin"))) -> dict:
        """What this installation keeps on its own disk.

        Setting SEALING_KMS_KEY_ID and having the master in KMS are not the same
        sentence, and the difference only shows up when somebody copies the .env.
        This reads the settings the process booted with and says which is true.
        No value is returned, only whether one is set; the sealing key identifier
        is an HKDF output that the refusal for a missing key already prints.
        """
        from cremore.secretstore.stored_locally import local_credentials

        return local_credentials(settings)

    @app.get("/api/v1/settings/capability-probe")
    def get_capability_probe(_actor: str = Depends(require_auth)) -> dict:
        return _scan_toggle_view(scan_switches.PROBE_KEY, settings.capability_probe_allowed, scan_switches.probe_switch)

    @app.put("/api/v1/settings/capability-probe")
    def put_capability_probe(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        return _put_scan_toggle(scan_switches.PROBE_KEY, settings.capability_probe_allowed,
                                "capability probing is not available: enable verification and CREDENTIAL_CAPABILITY_PROBE_MODE",
                                body, actor, scan_switches.probe_switch)

    @app.get("/api/v1/settings/cross-host-verification")
    def get_cross_host(_actor: str = Depends(require_auth)) -> dict:
        return _scan_toggle_view(scan_switches.CROSS_HOST_KEY, settings.cross_host_verification_allowed, scan_switches.cross_host_switch)

    @app.put("/api/v1/settings/cross-host-verification")
    def put_cross_host(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        return _put_scan_toggle(scan_switches.CROSS_HOST_KEY, settings.cross_host_verification_allowed,
                                "cross-host verification is not available: enable verification and CREDENTIAL_CROSS_HOST_VERIFICATION",
                                body, actor, scan_switches.cross_host_switch)

    def _identity_center_view() -> dict:
        chosen = aws_sso_settings.permission_set(settings, repo)
        sweep = aws_sso_settings.discovery_switch(repo)
        return {
            "permission_set": chosen["name"],
            "locked": chosen["locked"],
            "source": chosen["source"],
            "permission_set_updated_by": _actor_label(chosen["updated_by"]) if chosen["updated_by"] else None,
            "permission_set_updated_at": _iso(chosen["updated_at"]) if chosen["updated_at"] else None,
            "discovery": {
                "enabled": aws_sso_settings.discovery_effective(settings, repo),
                "switch": sweep["enabled"],
                "installation_allows": bool(settings.sso_discovery_allowed),
                "updated_by": _actor_label(sweep["updated_by"]) if sweep["updated_by"] else None,
                "updated_at": _iso(sweep["updated_at"]) if sweep["updated_at"] else None,
            },
            "interval_minutes": settings.aws_sso_discovery_interval_minutes,
            "excluded_accounts": sorted(settings.aws_sso_discovery_exclude_set),
        }

    def _learned_fp_view() -> dict:
        current = learned_fp_settings.config(settings, repo)
        return {
            **{k: current[k] for k in ("enabled", "switch", "installation_allows", "threshold",
                                       "threshold_locked", "min_samples", "min_samples_locked",
                                       "max_confidence", "max_confidence_locked")},
            "confidence_levels": list(learned_fp_settings.CONFIDENCE_LEVELS),
            "min_sample_floor": learned_fp_settings.MIN_SAMPLE_FLOOR,
            "updated_by": _actor_label(current["updated_by"]) if current["updated_by"] else None,
            "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None,
        }

    def _investigations_view() -> dict:
        out = {}
        for key, label in _INVESTIGATION_LABELS.items():
            current = investigation_switches.switch(repo, key)
            out[label] = {
                "enabled": investigation_switches.effective(settings, repo, key),
                "switch": current["enabled"],
                "installation_allows": investigation_switches.allowed(settings, key),
                "updated_by": _actor_label(current["updated_by"]) if current["updated_by"] else None,
                "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None,
            }
        return out

    @app.get("/api/v1/settings/aws-investigations")
    def get_investigations(_actor: str = Depends(require_auth)) -> dict:
        return _investigations_view()

    @app.put("/api/v1/settings/aws-investigations")
    def put_investigations(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Switch a read-only AWS investigation on or off.

        Each reads metadata in the account a discovered credential belongs to.
        They are here rather than in the environment so an analyst can turn one
        on during an investigation, which is when it is wanted.
        """
        try:
            investigation_switches.save(repo, settings, body, actor)
        except investigation_switches.SettingsError as exc:
            raise _http(exc.status, str(exc)) from None
        return _investigations_view()

    def _triggers_view() -> dict:
        view = trigger_settings.config(settings, repo)
        return {**view, "updated_by": _actor_label(view["updated_by"]),
                "updated_at": _iso(view["updated_at"])}

    def _manifests_view() -> dict:
        current = inventory_manifests.config(settings, repo)
        return {**current, "updated_by": _actor_label(current["updated_by"]),
                "updated_at": _iso(current["updated_at"])}

    @app.get("/api/v1/settings/inventory-manifests")
    def get_inventory_manifests(_actor: str = Depends(require_auth)) -> dict:
        return _manifests_view()

    @app.put("/api/v1/settings/inventory-manifests")
    def put_inventory_manifests(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Point a connection's bucket at the S3 Inventory report AWS writes for it.

        Which report belongs to which bucket is known by whoever runs the scans,
        not by whoever can edit the deployment, and one binding used to mean
        editing a JSON object in an environment variable.

        Nothing is provisioned: this records where a report already is. It is not
        checked against S3 here, because a reachability check now would not make
        the report readable at scan time.
        """
        given = (body or {}).get("bindings")
        if given is None:
            raise _http(422, "MANIFEST_BINDINGS_REQUIRED: send {bindings: {\"<connection>/<bucket>\": "
                             "{manifest_bucket, manifest_key}}}")
        if inventory_manifests.pinned(settings) is not None:
            raise _http(409, "MANIFEST_BINDINGS_PINNED: SCAN_INVENTORY_MANIFESTS pins these bindings "
                        "for this installation")
        try:
            normalized = inventory_manifests.normalize(given)
        except inventory_manifests.ManifestBindingError as exc:
            raise _http(422, str(exc)) from None
        for identity in normalized:
            connection_id, _, _bucket = identity.partition("/")
            owner = _uuid(connection_id, "connection_id")
            # A scan finds the binding by its job's connection: a content source's, or the AWS account's through
            # which an AWS integration reaches its buckets (cremore/worker/runtime.py).
            if repo.get_connection(owner) is None and repo.get_aws_account(owner) is None:
                raise _http(409, "MANIFEST_CONNECTION_UNKNOWN: bind a bucket of a registered connection or AWS account")
        _saved({inventory_manifests.KEY: {"bindings": normalized}}, actor, inventory_manifests.KEY,
               _changed(inventory_manifests.config(settings, repo), {"bindings": normalized}, ["bindings"]))
        _log.info("inventory manifest bindings set by %s (%d)", actor, len(normalized))
        return _manifests_view()

    @app.get("/api/v1/settings/scan-triggers/bindable-profiles")
    def bindable_scope_profiles(_actor: str = Depends(require_auth)) -> list[dict]:
        """The approved scope profiles a trigger may be bound to.

        Profiles are otherwise listed per connection, which would make binding a
        trigger a matter of finding and copying a UUID. This is the same list a
        PUT will accept, so the dashboard can offer a choice instead of a field.
        """
        names = {str(c.id): c.name for c in repo.list_connections()}
        names.update({str(a.id): a.name for a in repo.list_aws_accounts()})
        rows, cursor = [], None
        while True:
            page, cursor = repo.list_scope_profiles_page(cursor=cursor, limit=100)
            rows.extend(p for p in page if p.approved_at and p.event_mode == "ENABLED")
            if not cursor or len(rows) >= 200:
                break
        return [{"id": str(p.id), "name": p.name, "version": p.version,
                 "connection": names.get(str(p.connection_id), ""),
                 "schedule_minutes": p.schedule_minutes} for p in rows[:200]]

    @app.get("/api/v1/settings/scan-triggers")
    def get_scan_triggers(_actor: str = Depends(require_auth)) -> dict:
        return _triggers_view()

    @app.put("/api/v1/settings/scan-triggers")
    def put_scan_triggers(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Switch a trigger on or off and bind it to an approved scope profile.

        A profile's own cadences are set on the profile, so this decides whether the
        installation honours them, and how often (from which UTC minute) a scope
        without a full-scan cadence of its own is scanned in full. Events and queue
        consumption also carry the profile they are bound to, which is a scanning
        decision and belongs with whoever owns the scope, not with whoever can edit
        the deployment.
        """
        body = body or {}
        base = {trigger_settings.KEY: repo.get_setting(trigger_settings.KEY)}
        try:
            given = trigger_settings.normalize(body)
        except trigger_settings.TriggerSettingError as exc:
            raise _http(422, str(exc)) from None
        for trigger in ("schedules", *trigger_settings.QUEUES, "change_feeds"):
            if given.get(f"{trigger}_enabled") and not trigger_settings.allowed(settings, trigger):
                raise _http(409, f"TRIGGER_LOCKED: SCAN_{trigger.upper()}_MODE=disabled locks {trigger} off "
                                 "for this installation")
        for kind in trigger_settings.QUEUES:
            if given.get(f"{kind}_profile_id"):
                bound = repo.get_scope_profile(_uuid(given[f"{kind}_profile_id"], f"{kind}_profile_id"))
                if bound is None or not getattr(bound, "approved_at", None):
                    raise _http(409, "TRIGGER_PROFILE_NOT_APPROVED: bind an approved scope profile")
        for name, pin in trigger_settings.PINS.items():
            # Refuse rather than accept a value the installation would override.
            if name in given and trigger_settings.pinned(settings, name) is not None:
                raise _http(409, f"TRIGGER_FIELD_PINNED: {pin.upper()} pins {name} for this installation")
        _saved({trigger_settings.KEY: trigger_settings.merged(repo, given)}, actor, trigger_settings.KEY,
               _changed(trigger_settings.stored(repo), given, given), plain=("change_feed_minutes",), base=base)
        current = _triggers_view()
        _log.info("scan triggers set by %s: schedules=%s sqs=%s change_feeds=%s", actor,
                  current["schedules"]["enabled"], current["sqs"]["enabled"], current["change_feeds"]["enabled"])
        return current

    @app.get("/api/v1/settings/learned-false-positives")
    def get_learned_fp(_actor: str = Depends(require_auth)) -> dict:
        return _learned_fp_view()

    @app.put("/api/v1/settings/learned-false-positives")
    def put_learned_fp(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Turn auto-triage on or off and tune what it suppresses.

        This decides which findings are closed without anyone reading them, so it
        belongs where it can be seen and where the change is recorded, not in the
        deployment's environment.
        """
        body = body or {}
        base = {learned_fp_settings.KEY: repo.get_setting(learned_fp_settings.KEY)}
        current = learned_fp_settings.config(settings, repo)
        value = dict(learned_fp_settings.stored(repo))

        if "threshold" in body:
            if current["threshold_locked"]:
                raise _http(409, "THRESHOLD_LOCKED: LEARNED_FP_THRESHOLD fixes it for this installation")
            given = body.get("threshold")
            if isinstance(given, bool) or not isinstance(given, (int, float)) or not 0 < given <= 1:
                raise _http(422, "threshold must be a similarity above 0 and at most 1")
            value["threshold"] = float(given)
        if "min_samples" in body:
            if current["min_samples_locked"]:
                raise _http(409, "MIN_SAMPLES_LOCKED: LEARNED_FP_MIN_SAMPLES fixes it for this installation")
            given = body.get("min_samples")
            floor = learned_fp_settings.MIN_SAMPLE_FLOOR
            if isinstance(given, bool) or not isinstance(given, int) or given < floor or given > 1000:
                raise _http(422, f"min_samples must be an integer between {floor} and 1000")
            value["min_samples"] = given
        if "max_confidence" in body:
            if current["max_confidence_locked"]:
                raise _http(409, "MAX_CONFIDENCE_LOCKED: LEARNED_FP_MAX_CONFIDENCE fixes it for this installation")
            given = str(body.get("max_confidence") or "").lower()
            if given not in learned_fp_settings.CONFIDENCE_LEVELS:
                raise _http(422, f"max_confidence must be one of {learned_fp_settings.CONFIDENCE_LEVELS}")
            value["max_confidence"] = given
        if "enabled" in body:
            given = body.get("enabled")
            if not isinstance(given, bool):
                raise _http(422, "enabled must be true or false")
            if given and not settings.learned_fp_allowed:
                raise _http(409, "LEARNED_FP_LOCKED: LEARNED_FP_MODE=disabled locks auto-triage off "
                        "for this installation")
            value["enabled"] = given
        _saved({learned_fp_settings.KEY: value}, actor, learned_fp_settings.KEY,
               _changed({**current, "enabled": current["switch"]}, value,
                        [name for name in ("enabled", "threshold", "min_samples", "max_confidence") if name in body]),
               plain=("max_confidence",), base=base)
        _log.info("learned false-positive policy updated by %s (enabled=%s)", actor, bool(value.get("enabled")))
        return _learned_fp_view()

    @app.get("/api/v1/settings/aws-identity-center")
    def get_identity_center(_actor: str = Depends(require_auth)) -> dict:
        return _identity_center_view()

    @app.put("/api/v1/settings/aws-identity-center")
    def put_identity_center(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Choose the permission set, and whether the assignment sweep runs.

        Both live here rather than in the environment because the operator who
        runs this deployment often cannot change it. A configured pin still wins
        and is refused politely rather than silently ignored.
        """
        body = body or {}
        chosen = aws_sso_settings.permission_set(settings, repo)
        name = chosen["name"]
        changes = {}
        if "permission_set" in body:
            if chosen["locked"]:
                raise _http(409, "PERMISSION_SET_LOCKED: AWS_SSO_DISCOVERY_PERMISSION_SET fixes the permission set "
                                 "for this installation")
            value = body.get("permission_set")
            if value in (None, ""):
                name = ""
            else:
                if not isinstance(value, str):
                    raise _http(422, "permission_set must be an IAM Identity Center permission set name")
                name = value.strip()
                if not aws_sso.PERMISSION_SET.fullmatch(name):
                    raise _http(422, "permission_set must be an IAM Identity Center permission set name")
            changes[aws_sso_settings.PERMISSION_SET_KEY] = {"permission_set": name}
        if "discovery_enabled" in body:
            enabled = body.get("discovery_enabled")
            if not isinstance(enabled, bool):
                raise _http(422, "discovery_enabled must be true or false")
            if enabled and not settings.sso_discovery_allowed:
                raise _http(409, "AWS_SSO_DISCOVERY_MODE=disabled locks Identity Center discovery off for this "
                                 "installation")
            if enabled and not name:
                raise _http(409, "PERMISSION_SET_NOT_CHOSEN: choose a permission set before turning the sweep on")
            changes[aws_sso_settings.DISCOVERY_KEY] = {"enabled": enabled}
        asked = {**({"permission_set": name} if "permission_set" in body else {}),
                 **({"discovery_enabled": enabled} if "discovery_enabled" in body else {})}
        noted = _changed({"permission_set": chosen["name"],
                          "discovery_enabled": aws_sso_settings.discovery_switch(repo)["enabled"]}, asked, asked)
        _saved(changes, actor, "aws_identity_center", noted,
               owners={"permission_set": aws_sso_settings.PERMISSION_SET_KEY,
                       "discovery_enabled": aws_sso_settings.DISCOVERY_KEY})
        if "permission_set" in noted:
            _log.info("AWS Identity Center permission set set to %s by %s", name or "(cleared)", actor)
        if "discovery_enabled" in noted:
            _log.info("AWS Identity Center discovery switched %s by %s", "on" if enabled else "off", actor)
        return _identity_center_view()

    def _organizations_view() -> dict:
        current = aws_org_settings.config(settings, repo)
        return {
            **{k: current[k] for k in ("enabled", "installation_allows", "external_id", "external_id_locked",
                                       "ou_ids", "ou_ids_locked", "excludes", "excludes_locked", "auto_validate",
                                       *aws_org_settings.CONTEXT_FIELDS)},
            "effective": aws_org_settings.effective(settings, repo),
            "interval_minutes": settings.aws_org_discovery_interval_minutes,
            "updated_by": _actor_label(current["updated_by"]) if current["updated_by"] else None,
            "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None,
        }

    @app.get("/api/v1/settings/aws-organizations")
    def get_organizations(_actor: str = Depends(require_auth)) -> dict:
        return _organizations_view()

    @app.put("/api/v1/settings/aws-organizations")
    def put_organizations(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Set the StackSet's shared ExternalId, its OU scope, and the sweep switch.

        None of these are secrets or infrastructure: they are values an
        administrator copies out of AWS, so an operator who cannot change the
        deployment can still complete organization onboarding.
        """
        body = body or {}
        base = {aws_org_settings.KEY: repo.get_setting(aws_org_settings.KEY)}
        current = aws_org_settings.config(settings, repo)
        value = dict(aws_org_settings.stored(repo))

        if any(key in body for key in aws_org_settings.CONTEXT_FIELDS):
            try:
                context = aws_org_settings.normalize_context(body, value)
            except ValueError:
                raise _http(422, "AWS_CONTROL_TOWER_INVALID_SETTINGS") from None
            if context["control_tower_enabled"] and not settings.org_discovery_allowed:
                raise _http(409, "AWS_ORG_DISCOVERY_MODE=disabled locks Control Tower context off")
            if context["control_tower_enabled"] and context["lifecycle_queue_acknowledged"] and context["lifecycle_queue_url"]:
                if not settings.scan_sqs_allowed:
                    raise _http(409, "SCAN_SQS_MODE=disabled locks lifecycle queue consumption off")
                if context["lifecycle_queue_url"] == trigger_settings.config(settings, repo)["sqs"]["queue_url"]:
                    raise _http(409, "AWS_CONTROL_TOWER_SEPARATE_QUEUE_REQUIRED")
            value.update(context)

        if "external_id" in body:
            if current["external_id_locked"]:
                raise _http(409, "EXTERNAL_ID_LOCKED: AWS_ORG_DISCOVERY_EXTERNAL_ID fixes it for this installation")
            given = str(body.get("external_id") or "").strip()
            if given and not aws_org_settings.EXTERNAL_ID.fullmatch(given):
                raise _http(422, "external_id must be the StackSet's shared STS ExternalId")
            value["external_id"] = given
        for field, locked, pattern, what in (
                ("ou_ids", "ou_ids_locked", aws_org_settings.OU_ID, "organizational unit ids"),
                ("excludes", "excludes_locked", aws_org_settings.ACCOUNT_ID, "12-digit AWS account ids")):
            if field not in body:
                continue
            if current[locked]:
                raise _http(409, f"{field.upper()}_LOCKED: this installation fixes {field} in its configuration")
            given = body.get(field) or []
            if not isinstance(given, list) or len(given) > 500:
                raise _http(422, f"{field} must be a list of at most 500 {what}")
            cleaned = [str(item).strip() for item in given]
            if any(not pattern.fullmatch(item) for item in cleaned):
                raise _http(422, f"{field} must contain only {what}")
            value[field] = sorted(set(cleaned))
        for flag in ("auto_validate", "enabled"):
            if flag not in body:
                continue
            given = body.get(flag)
            if not isinstance(given, bool):
                raise _http(422, f"{flag} must be true or false")
            if flag == "enabled" and given and not settings.org_discovery_allowed:
                raise _http(409, "AWS_ORG_DISCOVERY_MODE=disabled locks organization discovery off for this "
                                 "installation")
            value[flag] = given
        if value.get("enabled") and not (value.get("external_id") or current["external_id_locked"]):
            # A role deployed with a different ExternalId can never be assumed,
            # so a sweep without one would only register broken records.
            raise _http(409, "EXTERNAL_ID_NOT_SET: the StackSet's shared ExternalId is needed before the sweep "
                             "can register accounts it could actually assume")
        if not _saved({aws_org_settings.KEY: value}, actor, aws_org_settings.KEY,
                      _changed(current, value, [name for name in body if name in value]), plain=("control_tower_region",),
                      base=base):
            return _organizations_view()  # nothing changed: no scope to revoke and no sweep to wake
        from cremore_aws_provider.aws_controltower import request_rediscovery
        # Exclusions revoke local use immediately. OU narrowing is conservative
        # until the requested complete sweep proves the new membership.
        effective = aws_org_settings.config(settings, repo)
        scope_changed = current["ou_ids"] != effective["ou_ids"]
        for account in repo.list_aws_accounts():
            if account.source == "ORGANIZATION" and (account.account_id in effective["excludes"]
                                                       or (scope_changed and effective["ou_ids"])):
                repo.update_aws_account(account.id, in_deployment_scope=False)
        request_rediscovery(repo)
        _log.info("AWS organization discovery updated by %s (enabled=%s)", actor, bool(value.get("enabled")))
        return _organizations_view()

    def _aws_inventory_view():
        current = aws_inventory_settings.config(settings, repo)
        return {**current, "effective": aws_inventory_settings.effective(settings, repo),
                "updated_by": _actor_label(current["updated_by"]) if current["updated_by"] else None,
                "updated_at": _iso(current["updated_at"]) if current["updated_at"] else None}

    @app.get("/api/v1/settings/aws-credential-inventory")
    def get_aws_inventory_settings(_actor: str = Depends(require_auth)) -> dict:
        return _aws_inventory_view()

    @app.put("/api/v1/settings/aws-credential-inventory")
    def put_aws_inventory_settings(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        base = {aws_inventory_settings.KEY: repo.get_setting(aws_inventory_settings.KEY)}
        try:
            saved = (base[aws_inventory_settings.KEY] or {}).get("value") or {}
            value = aws_inventory_settings.normalize(body, saved)
        except ValueError:
            raise _http(422, "AWS_INVENTORY_INVALID_SETTINGS") from None
        if value["enabled"] and not settings.scan_schedules_allowed:
            raise _http(409, "SCAN_SCHEDULES_MODE=disabled locks automatic inventory off")
        current = aws_inventory_settings.config(settings, repo)
        # A saved setting that cannot be read is shown as the defaults: saving them rewrites it, so none is unchanged.
        _saved({aws_inventory_settings.KEY: value}, actor, aws_inventory_settings.KEY,
               _changed({} if current["reason"] else current, value, [name for name in body if name in value]),
               plain=("cloudtrail_source",), base=base)
        return _aws_inventory_view()
