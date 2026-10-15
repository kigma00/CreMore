"""Externally signed, exact-plan, expiring one-use execution authorizations.

Run ``python -m cremore.remediation.authorization --help`` on the independent
approver's machine. No signing private key belongs on an application host.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CONTEXT = b"cremore-remediation-authorization-v1\x00"
FIELDS = ("id", "credential_id", "aws_account_id", "account_id", "user_name", "principal_arn", "key_id",
          "target", "action_type", "plan_hash", "reason_code", "operational_review", "rotation",
          "requested_by", "requested_at", "expires_at", "policy_revision", "workflow_version",
          "adapter_version", "semantics_revision")


def _error(code):
    from cremore.remediation.action_plans import ActionPlanError

    return ActionPlanError(code, "independent signed authorization is required", http_status=409)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def request_for(plan, mode="execute", *, repo=None):
    if mode not in ("execute", "emergency", "recheck"):
        raise _error("AUTHORIZATION_MODE_INVALID")
    snapshot = {key: plan.model_dump(mode="json")[key] for key in FIELDS}
    if plan.action_type == "PUBLISH_ACCESS_KEY_ROTATION":
        try:
            preparation = repo.get_action_plan(uuid.UUID((plan.rotation or {})["preparation_plan_id"]))
            if preparation is None:
                raise ValueError("missing preparation")
            snapshot["preparation"] = {key: preparation.model_dump(mode="json")[key] for key in
                                       ("id", "plan_hash", "status", "new_key_id", "pending_version", "access_pin")}
        except (AttributeError, ValueError, KeyError, TypeError):
            raise _error("AUTHORIZATION_PREPARATION_UNAVAILABLE") from None
    # Reconciliation also binds the observed rotation outputs it will read.
    if mode == "recheck":
        snapshot.update(new_key_id=plan.new_key_id, pending_version=plan.pending_version,
                        rotation_progress=plan.rotation_progress)
    return {"version": 1, "plan": snapshot, "plan_digest": hashlib.sha256(canonical(snapshot)).hexdigest(), "mode": mode}


def _stamp(value):
    if not isinstance(value, str):
        raise TypeError("invalid timestamp")
    stamp = dt.datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError("timezone required")
    return stamp


def sign(request, private_key, expires_at, *, nonce=None):
    """Only the offline CLI calls this; request JSON is displayed for human review."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("ED25519_SIGNING_KEY_REQUIRED")
    snapshot = request["plan"]
    digest = hashlib.sha256(canonical(snapshot)).hexdigest()
    if request.get("version") != 1 or digest != request["plan_digest"]:
        raise ValueError("AUTHORIZATION_REQUEST_INVALID")
    expires = _stamp(expires_at)
    if expires <= dt.datetime.now(dt.UTC) or (request["mode"] != "recheck" and expires > _stamp(snapshot["expires_at"])):
        raise ValueError("AUTHORIZATION_EXPIRY_INVALID")
    payload = {"version": 1, "plan_id": snapshot["id"], "plan_hash": snapshot["plan_hash"],
               "plan_digest": digest, "action": snapshot["action_type"], "mode": request["mode"],
               "expires_at": expires.isoformat(), "nonce": str(uuid.UUID(nonce)) if nonce else str(uuid.uuid4())}
    return {"claims": payload, "signature": base64.b64encode(private_key.sign(CONTEXT + canonical(payload))).decode()}


def verifier(settings):
    """Fail startup if an enabled isolated executor lacks its external verifier."""
    try:
        public = serialization.load_pem_public_key(Path(settings.remediation_approval_public_key_file).read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            raise TypeError("wrong key type")
        return public
    except (ValueError, TypeError, OSError):
        raise ValueError("REMEDIATION_APPROVAL_VERIFIER_INVALID") from None


def verify(settings, plan, authorization, mode="execute", *, now=None, repo=None):
    if not getattr(settings, "isolated_deployment", False):
        return None
    try:
        if not isinstance(authorization, dict) or set(authorization) != {"claims", "signature"}:
            raise ValueError("invalid envelope")
        if len(canonical(authorization)) > 4096:
            raise ValueError("oversized envelope")
        payload = authorization["claims"]
        if set(payload) != {"version", "plan_id", "plan_hash", "plan_digest", "action", "mode", "expires_at", "nonce"}:
            raise ValueError("invalid claims")
        public = verifier(settings)
        public.verify(base64.b64decode(authorization["signature"], validate=True), CONTEXT + canonical(payload))
        wanted = request_for(plan, mode, repo=repo)
        if (payload["version"] != 1 or payload["plan_id"] != str(plan.id) or payload["plan_hash"] != plan.plan_hash
                or payload["plan_digest"] != wanted["plan_digest"] or payload["action"] != plan.action_type
                or payload["mode"] != mode or str(uuid.UUID(payload["nonce"])) != payload["nonce"]):
            raise ValueError("mismatch")
        expires = _stamp(payload["expires_at"])
        if expires <= (now or dt.datetime.now(dt.UTC)) or not plan.expires_at or (mode != "recheck" and expires > plan.expires_at):
            raise ValueError("expired")
    except (ValueError, TypeError, KeyError, OSError, InvalidSignature):
        raise _error("SIGNED_AUTHORIZATION_INVALID") from None
    return payload


def consume(repo, claims):
    """Insert-only nonce, in the same fenced transaction as execution start."""
    from cremore.db.task_store import TaskStore

    if claims is not None and not TaskStore(repo).consume_authorization(claims["nonce"], claims["plan_id"]):
        raise _error("SIGNED_AUTHORIZATION_ALREADY_USED")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sign a reviewed CreMore authorization request on an independent host")
    parser.add_argument("--request", required=True, help="JSON from the plan authorization-request endpoint")
    parser.add_argument("--private-key", required=True, help="external Ed25519 PEM private key (never mounted in the app)")
    parser.add_argument("--expires-at", required=True, help="ISO-8601 timestamp with timezone; no later than plan expiry")
    parser.add_argument("--output", required=True, help="new JSON file to submit as signed_approval")
    args = parser.parse_args(argv)
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    key = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
    result = sign(request, key, args.expires_at)
    with Path(args.output).open("x", encoding="utf-8") as out:
        json.dump(result, out, sort_keys=True, indent=2)
        out.write("\n")


if __name__ == "__main__":
    main()
