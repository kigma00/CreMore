"""Detection rules: the shipped engine, and the ones this installation added.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

from fastapi import Depends

from cremore.api.http_support import http_error as _http
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.route_context import DashboardContext
from cremore.api.rule_payloads import MAX_SAMPLE as _MAX_SAMPLE
from cremore.api.rule_payloads import RULE_FIELDS as _RULE_FIELDS
from cremore.api.rule_payloads import present_rule as _rule_public
from cremore.api.rule_payloads import rule_from_body as _rule_from_body
from cremore.detection.custom import FIXTURE_DEFAULT_EXPECTED, FIXTURES, evaluate_rule_sample


def register(ctx: DashboardContext) -> None:
    app, learned_fp, repo, require_auth = ctx.app, ctx.learned_fp, ctx.repo, ctx.require_auth
    require_role = ctx.require_role

    @app.get("/api/v1/rules")
    def list_rules(_actor: str = Depends(require_auth)) -> list[dict]:
        return [_rule_public(r) for r in repo.list_rules()]

    @app.post("/api/v1/rules", status_code=201)
    def create_rule(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        rule = _rule_from_body(body)
        rule.updated_by = actor
        try:
            return _rule_public(repo.create_rule(rule))
        except ValueError as exc:
            raise _http(409, str(exc))

    @app.put("/api/v1/rules/{rule_id}")
    def update_rule(rule_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        current = repo.get_rule(_uuid(rule_id, "rule_id"))
        if current is None:
            raise _http(404, "rule not found")
        rule = _rule_from_body(body, base=current)
        changes = {k: getattr(rule, k) for k in _RULE_FIELDS}
        changes["revision"] = current.revision + 1  # every edit is a new revision
        changes["updated_by"] = actor
        if rule.name != current.name and any(r.name == rule.name for r in repo.list_rules()):
            raise _http(409, f"RULE_NAME_TAKEN: rule {rule.name!r} already exists")
        return _rule_public(repo.update_rule(current.id, **changes))

    @app.delete("/api/v1/rules/{rule_id}", status_code=204)
    def delete_rule(rule_id: str, _actor: str = Depends(require_role("admin"))) -> None:
        if not repo.delete_rule(_uuid(rule_id, "rule_id")):
            raise _http(404, "rule not found")

    @app.post("/api/v1/rules/{rule_id}/test")
    def test_rule(rule_id: str, body: dict, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Run a draft rule against an operator sample or a synthetic fixture.
        Nothing is stored; the sample is never persisted."""

        base = repo.get_rule(_uuid(rule_id, "rule_id")) if rule_id != "new" else None
        rule = _rule_from_body(body.get("rule") or {}, base=base)
        fixture_id = body.get("fixture_id")
        if fixture_id is not None:
            if fixture_id not in FIXTURES:
                raise _http(422, f"unknown fixture {fixture_id!r}")
            expected = next((bool(f.get("expected")) for f in rule.fixture_tests if f.get("id") == fixture_id),
                            FIXTURE_DEFAULT_EXPECTED[fixture_id])
            matched = evaluate_rule_sample(rule, FIXTURES[fixture_id]).matched
            return {"id": fixture_id, "matched": matched, "expected": expected, "passed": matched == expected}
        sample = body.get("sample")
        if not isinstance(sample, str) or len(sample.encode("utf-8")) > _MAX_SAMPLE:
            raise _http(422, "sample must be a string of at most 64 KiB")
        return {"matched": evaluate_rule_sample(rule, sample).matched}

    def _fp_scope_label(profile) -> tuple[str, str]:
        if profile.scope_kind == "aws":
            acct = repo.get_aws_account(profile.scope_id)
            return (acct.account_id, acct.name) if acct else (str(profile.scope_id), "unknown account")
        conn = repo.get_connection(profile.scope_id)
        return (str(profile.scope_id), conn.name if conn else "unknown connection")

    def _fp_public(profile) -> dict:
        account_id, name = _fp_scope_label(profile)
        return learned_fp.public(profile, account_id=account_id, account_name=name)

    @app.get("/api/v1/rules/learned-fp")
    def learned_fp_profiles(_actor: str = Depends(require_role("admin"))) -> list[dict]:
        """Per-scope learned false-positive profiles (empty while auto-triage is off)."""

        if learned_fp is None or not learned_fp.enabled:
            return []
        return [_fp_public(p) for p in repo.list_fp_profiles()[:200]]

    def _fp_profile_or_404(profile_id: str):
        profile = repo.get_fp_profile_by_id(_uuid(profile_id, "profile_id")) if learned_fp is not None else None
        if profile is None:
            raise _http(404, "learned false-positive profile not found")
        return profile

    def _fp_audit(profile_id, note: str, actor: str, event_type: str) -> None:
        """An Admin's hand on auto-triage, in the audit trail: which profile (its type, where it learned and how many
        samples it held before), never a sample."""
        from cremore.domain.models import FindingEvent

        repo.record_finding_event(FindingEvent(target_type="learned_fp_profile", target_id=profile_id, actor=actor,
                                               event_type=event_type, note=note))

    def _fp_note(profile) -> str:
        return f"{profile.credential_type} {profile.source_type} samples={profile.sample_count}"

    @app.post("/api/v1/rules/learned-fp/{profile_id}/deactivate")
    def deactivate_learned_fp(profile_id: str, actor: str = Depends(require_role("admin"))) -> dict:
        """Stop a profile from auto-triaging until it is re-confirmed (samples kept); audited."""

        profile = _fp_profile_or_404(profile_id)
        note = _fp_note(profile)
        stopped = learned_fp.deactivate(profile.id)
        _fp_audit(profile.id, note, actor, "LEARNED_FP_PROFILE_STOPPED")
        return _fp_public(stopped)

    @app.post("/api/v1/rules/learned-fp/{profile_id}/reset")
    def reset_learned_fp(profile_id: str, actor: str = Depends(require_role("admin"))) -> dict:
        """Drop a profile's samples; it relearns from the next confirmation. Audited with the count it held."""

        profile = _fp_profile_or_404(profile_id)
        note = _fp_note(profile)  # before the reset, which may change the stored record in place
        cleared = learned_fp.reset(profile.id)
        _fp_audit(profile.id, note, actor, "LEARNED_FP_PROFILE_RESET")
        return _fp_public(cleared)
