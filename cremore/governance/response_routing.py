"""Explicit responsibility and current issuer-owner evidence for response tickets.

No provider requests are made here. An exact inventory match is required before
using an issuer's owner. A location rule assigns cleanup responsibility, never key
ownership. Display names, creators and partial/stale observations cannot assign.
"""
from __future__ import annotations

import datetime as dt
import uuid
from importlib import import_module

from cremore.domain.models import FindingEvent
from cremore.governance import response
from cremore.identity import people
from cremore.identity.keys import EXACT_BASES, Digester
from cremore.identity.leavers import LeaverStore, account_ref, fits

ASSIGN_PREFIX = "response:assignment:"
RULE_PREFIX = "response:responsibility:"


def resolve(repo, settings, person_ref, *, now=None):
    try:
        return people.resolve_person(repo, settings, person_ref, now=now)
    except people.DirectoryError as exc:
        raise response.ResponseError(exc.code, exc.http_status) from None


def _profile(person):
    return {key: person.get(key) for key in ("id", "person_ref", "name", "email", "department", "title", "state",
                                           "selectable", "reason", "observed_at")}


def clean_team(value):
    from cremore.governance.tickets import TicketError, _text

    try:
        return _text(value, "team", 100, required=False) or None
    except TicketError:
        raise response.ResponseError("RESPONSE_TEAM_INVALID", 422) from None


def _key(kind, coordinate):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:response-rule:{kind}:{coordinate}"))


def _complete(row):
    run = row.get("observation_run") or {}
    return run.get("status") == "COMPLETE" and not run.get("reasons")


def _accounts(repo, settings, finding, orchestrator, now):
    """Bounded current owner accounts; old MATCHED links are not ownership proof."""
    from cremore.coverage import metadata_correlation
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.coverage.providers import _ADAPTERS

    store = MetadataStore(repo)
    key = orchestrator.config.fingerprint_key if orchestrator else settings.fingerprint_key_bytes
    try:
        digester = Digester(key)
    except ValueError:
        return {}, None
    accounts = {}

    def add(provider, origin, owner):
        if not owner or not owner.get("account"):
            return
        ref = account_ref(provider, origin, owner["account"])
        found = accounts.setdefault(ref, {"ref": ref, "label": owner.get("label") or owner["account"],
                                          "provider": provider, "origin": origin, "account": owner["account"], "keys": set()})
        found["keys"].update((basis, digester(value)) for basis, value in owner.get("keys", []) if digester(value))

    credential = repo.get_credential(finding.credential_id)
    if credential and credential.provider == "aws" and orchestrator:
        from cremore_aws_provider.leavers import credential_owner

        from cremore.coverage.correlation import report
        from cremore.coverage.models import Contract

        contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                            policy_digest=orchestrator.coverage_policy_digest).model_dump()
        linked = (report(repo, contract, finding_id=finding.id, settings=settings, now=now).get("item") or {})
        if linked.get("inventory_matches_truncated"):
            return {}, digester
        for row in linked.get("inventory_matches", []):
            if row.get("current_evidence") and row.get("collection_status") == "COMPLETE" and not row.get("collection_reasons"):
                add("aws", "aws", credential_owner(row))
    elif credential:
        linked = metadata_correlation.finding_links(store, repo, finding.id, limit=50, now=now)
        if linked.get("match_count", 0) > 50 or "CANDIDATE_LIMIT_REACHED" in linked.get("reasons", []):
            return {}, digester
        for link in linked["items"]:
            registration = _ADAPTERS.get(link["provider"])
            if (link["evidence"] not in ("VALUE", "IDENTIFIER") or not link["current_evidence"]
                    or not _complete(link) or not registration):
                continue
            row = store.entity_detail(link["entity_id"], limit=1)["entity"]
            owner = import_module(registration.owners).credential_owner(row) if registration.owners else None
            if owner:
                add(link["provider"], link["origin"], owner)
            else:
                # A machine/app credential has no human owner. Its confirmed
                # tenant (otherwise just this object) can receive an explicit
                # responsibility rule; no identity keys are invented.
                target = "tenant:" + row["tenant"] if row["tenant_confirmed"] and row["tenant"] else "object:" + row["object_id"]
                add(link["provider"], link["origin"], {"account": target,
                    "label": link["provider"] + " · " + target, "keys": []})

    # GitHub personal tokens name a login; a current SAML/SCIM directory supplies
    # its exact external identity. Scope and origin must match that same account.
    connections = {row["id"]: row for row in store.list_connections()}
    for account in accounts.values():
        if account["provider"] != "github":
            continue
        page = store.inventory(provider="github_identity", purpose="identity_status", object_kind="principal",
                               q="user:" + account["account"], limit=100)
        if page["total"] > 100:
            continue
        for row in page["items"]:
            summary = row.get("summary") or {}
            if (row["origin"] == account["origin"] and row["object_id"] == "user:" + account["account"]
                    and summary.get("identity_key_id") == digester.key_id and _complete(row)
                    and summary.get("normalized_state") == "ACTIVE"
                    and metadata_correlation.current_issuer_observation(row,
                        connections.get((row.get("observation_run") or {}).get("connection_id")), now=now)):
                account["keys"].update((item["kind"], item["digest"]) for item in summary.get("identity_keys", [])
                                       if item["kind"] in EXACT_BASES)
    return accounts, digester


def _targets(repo, finding, accounts):
    targets = {}
    for exposure in repo.exposures_for_credential(finding.credential_id):
        if exposure.status in ("REMOVED", "FALSE_POSITIVE") or not exposure.source_connection_id:
            continue
        connection = repo.get_connection(exposure.source_connection_id)
        if connection is None or connection.status == "DISABLED":
            continue
        coordinate = f"{exposure.source_type}|{exposure.source_connection_id}|{exposure.resource_name}"
        key = _key("location", coordinate)
        targets[key] = {"kind": "location", "key": key, "label": exposure.resource_name,
                        "source_connection_id": str(exposure.source_connection_id)}
    for ref, account in accounts.items():
        key = _key("account", ref)
        targets[key] = {"kind": "account", "key": key, "label": account["label"], "account_ref": ref}
    return targets


def _recommend(repo, settings, accounts, digester, now):
    decisions = LeaverStore(repo).links_for(accounts)
    out = []
    for ref, account in accounts.items():
        confirmed = [(person, row) for (account_id, person), row in decisions.items()
                     if account_id == ref and row["decision"] == "CONFIRMED"]
        candidates = []
        for person_ref, _row in confirmed:
            try:
                candidates.append((resolve(repo, settings, person_ref, now=now), "ADMIN_CONFIRMED"))
            except response.ResponseError:
                pass
        if not confirmed:
            keys = {}
            for basis, value in account["keys"]:
                if basis in EXACT_BASES:
                    keys.setdefault(value, set()).add(basis)
            # A GitHub account's exact keys are its directory identity's values (its owner names a login only): like
            # GitLab's extern_uid, each matches only the kinds of IdP value it can be.
            directory = account["provider"] == "github"
            for person in people.eligible_people_for_digests(repo, settings, list(keys), key_id=digester.key_id, now=now):
                decision = decisions.get((ref, uuid.UUID(person["person_ref"]))) or {}
                if decision.get("decision") == "REJECTED":
                    continue
                matched = min((basis for item in person["keys"] for basis in keys.get(item["digest"], ())
                               if fits(basis, item["kind"], directory=directory)), default=None)
                if matched:
                    candidates.append((person, matched))
        for person, basis in candidates:
            out.append({"person": _profile(person), "basis": basis, "account_ref": ref})
    return out


def public(repo, settings, finding_id, *, orchestrator=None, now=None):
    from cremore.governance import response_channels

    now = now or dt.datetime.now(dt.UTC)
    approved = response_channels.approved(repo)
    finding_id = response._id(finding_id)
    finding = response._finding(repo, finding_id)
    stored = response._row(repo, ASSIGN_PREFIX + finding_id)
    accounts, digester = _accounts(repo, settings, finding, orchestrator, now)
    targets = _targets(repo, finding, accounts)
    for target in targets.values():
        target["rule"] = response._row(repo, RULE_PREFIX + target["key"]) or None
    assignment, recommendations, reasons = stored.get("assignment"), [], []
    if assignment:
        try:
            person = resolve(repo, settings, assignment["person_ref"], now=now)
            recommendations = [{"person": _profile(person), "basis": "MANUAL_ASSIGNMENT", "team": assignment.get("team")}]
        except response.ResponseError as exc:
            reasons.append(exc.code)
    else:
        if digester is None:
            reasons.append("DIRECTORY_IDENTITY_KEY_UNAVAILABLE")
        else:
            try:
                recommendations = _recommend(repo, settings, accounts, digester, now)
            except people.DirectoryError as exc:
                reasons.append(exc.code)
        if not recommendations:
            for target in targets.values():
                rule = target["rule"] or {}
                if not rule.get("person_ref"):
                    continue
                try:
                    person = resolve(repo, settings, rule["person_ref"], now=now)
                    recommendations.append({"person": _profile(person), "basis": "RESPONSIBILITY_RULE",
                                            "rule_id": target["key"], "team": rule.get("team"),
                                            "slack_channel": _channel(approved, rule)})
                except response.ResponseError as exc:
                    reasons.append(exc.code)
    refs = {row["person"]["person_ref"] for row in recommendations}
    status = "READY" if len(refs) == 1 else "AMBIGUOUS" if refs else "UNAVAILABLE" if reasons else "UNASSIGNED"
    # The team channel the location's or account's rules name, when they name one approved channel.
    channels = {item["channel_id"]: item for item in (_channel(approved, target["rule"] or {})
                                                      for target in targets.values()) if item}
    return {"version": stored.get("version", 0), "assignment": assignment, "recommendations": recommendations,
            "status": status, "reasons": sorted(set(reasons)), "targets": list(targets.values()),
            "manual_email_allowed": getattr(settings, "auth_mode", "local") != "oidc",
            "slack_channel": next(iter(channels.values())) if len(channels) == 1 else None}


def _channel(approved, rule):
    """A rule's team channel as the request form shows it, while the Admin still approves it; else None."""
    entry = approved.get(rule.get("channel_id") or "")
    return {key: entry.get(key) for key in ("channel_id", "name", "is_private")} if entry else None


def assign(repo, settings, finding_id, actor, *, person_ref, team=None, expected_version, now=None):
    now = now or dt.datetime.now(dt.UTC)
    team = clean_team(team)
    finding_id = response._id(finding_id)
    with response._locked(repo) as bound:
        response._finding(bound, finding_id)
        before = response._row(bound, ASSIGN_PREFIX + finding_id)
        response._version(before, expected_version)
        person = resolve(bound, settings, person_ref, now=now) if person_ref else None
        value = {"person_ref": person["person_ref"], "team": team, "basis": "MANUAL_ASSIGNMENT",
                 "updated_by": actor, "updated_at": now.isoformat()} if person else None
        bound.put_setting(ASSIGN_PREFIX + finding_id, {"version": expected_version + 1, "assignment": value}, actor)
        bound.assign_finding(uuid.UUID(finding_id), person["person_ref"] if person else None)
        bound.record_finding_event(FindingEvent(finding_id=uuid.UUID(finding_id), actor=actor,
            event_type="RESPONSE_ASSIGNED" if person else "RESPONSE_UNASSIGNED",
            note=f"person_ref={person['person_ref']} team={team or '-'}" if person else "unassigned"))
    return {"version": expected_version + 1, "assignment": value}


def owners(repo, settings, finding_ids, responses, *, now=None):
    """Batch current profile display; dispatch always resolves again separately."""
    wanted = {str(value) for value in finding_ids}
    assignments = {row["key"][len(ASSIGN_PREFIX):]: (row["value"] or {}).get("assignment")
                   for row in repo.list_settings(ASSIGN_PREFIX) if row["key"][len(ASSIGN_PREFIX):] in wanted}
    selected = {}
    for finding_id in wanted:
        assignment = assignments.get(finding_id)
        if assignment:
            selected[finding_id] = assignment
        elif finding_id not in assignments:
            cycle = (responses.get(finding_id) or {}).get("current") or {}
            recipient = cycle.get("recipient") or {}
            if recipient.get("person_ref"):
                selected[finding_id] = {"person_ref": recipient["person_ref"], "team": cycle.get("team"), "basis": "TICKET_RESPONDER"}
    profiles = people.profiles_for(repo, settings, {row["person_ref"] for row in selected.values()}, now=now)
    result = {fid: {**_profile(profiles.get(row["person_ref"]) or {}), "person_ref": row["person_ref"],
                  "team": row.get("team"), "basis": row["basis"],
                  "observed_at": (profiles.get(row["person_ref"]) or {}).get("observed_at")}
            for fid, row in selected.items()}
    result.update({fid: None for fid, assignment in assignments.items() if assignment is None})
    return result


def save_rule(repo, settings, finding_id, actor, *, kind, key, person_ref, team, expected_version,
              orchestrator=None, now=None, channel_id=None):
    """A location's or account's responsibility rule: the person and team asked, and optionally the team's Slack
    channel (one the Admin approved, cremore.governance.response_channels)."""
    from cremore.governance import response_channels

    now = now or dt.datetime.now(dt.UTC)
    team = clean_team(team)
    if channel_id is not None and channel_id not in response_channels.approved(repo):
        raise response.ResponseError("RESPONSE_CHANNEL_NOT_APPROVED", 422)
    with response._locked(repo) as bound:
        available = public(bound, settings, finding_id, orchestrator=orchestrator, now=now)
        target = next((item for item in available["targets"] if item["key"] == key and item["kind"] == kind), None)
        if target is None:
            raise response.ResponseError("RESPONSE_RULE_TARGET_INVALID", 422)
        response._version(target["rule"] or {}, expected_version)
        person = resolve(bound, settings, person_ref, now=now) if person_ref else None
        rule = {"version": expected_version + 1, "person_ref": person["person_ref"] if person else None,
                "team": team if person else None, "channel_id": channel_id, "kind": kind, "key": key,
                "updated_by": actor, "updated_at": now.isoformat()}
        bound.put_setting(RULE_PREFIX + key, rule, actor)
        bound.record_finding_event(FindingEvent(finding_id=uuid.UUID(str(finding_id)), actor=actor,
            event_type="RESPONSE_RESPONSIBILITY_CHANGED", note=f"rule={key} person_ref={rule['person_ref'] or '-'} "
                                                               f"team={rule['team'] or '-'} channel={channel_id or '-'}"))
    return rule
