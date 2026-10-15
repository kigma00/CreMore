"""Who owns an IAM access key the IAM inventory listed (departed-owner check).

An IAM user carries no link to an IdP, so its name is only a candidate: an
administrator confirms which person it is. The inventory lists every access key of
every IAM user it read. Disabling a key goes through the existing approved action
plan (``cremore.remediation.action_plans``), which this module only prepares for.
"""

from __future__ import annotations

import re

from cremore.detection.fingerprint import mask_hint

PROVIDER = "aws"
LISTS_EVERY_USER_CREDENTIAL = True
_USER_ARN = re.compile(r"arn:aws(?:-[a-z]+)*:iam::(\d{12}):user/(?:[\w+=,.@-]+/)*([\w+=,.@-]{1,64})")
_KEY_ID = re.compile(r"AKIA[A-Z0-9]{16}")


def credential_owner(issued):
    """An issued-key location from the coverage comparison (schema 1 observation fields)."""
    if issued.get("credential_type") != "AWS_ACCESS_KEY" or issued.get("evidence") != "ISSUED":
        return None
    match = _USER_ARN.fullmatch(issued.get("principal_arn") or "")
    key_id = issued.get("identifier") or ""
    if not match or not _KEY_ID.fullmatch(key_id):
        return None
    account, user = match.groups()
    state = issued.get("state")
    return {"account": account + ":" + user, "label": user + " (" + account + ")",
            "keys": [("PROVIDER_LOGIN", user)], "credential_type": "AWS_ACCESS_KEY",
            "name": mask_hint(key_id),
            "state": "ACTIVE" if state == "Active" else "REVOKED_OR_EXPIRED" if state == "Inactive" else "UNKNOWN",
            "last_used_at": issued.get("last_used_at") or None, "expires_at": None,
            "action": {"principal_arn": issued["principal_arn"], "key_id": key_id, "account_id": account}}
