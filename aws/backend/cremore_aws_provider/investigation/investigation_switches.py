"""Dashboard switches for the three optional read-only AWS investigations.

Each calls AWS in the account a discovered credential belongs to, with the
scanner identity, and reads nothing but metadata. They were opt-in through the
environment, which meant an analyst could not turn one on in the middle of an
investigation -- the one moment they are wanted -- and on a cluster nobody but
the platform team could turn one on at all.

They follow the same shape as ``cremore/scanning/scan_switches.py``: the
environment ALLOWS a feature (the default) or hard-locks it off, and an Admin
switches the allowed ones from the dashboard. All three default off, so an
installation that upgrades gains no new AWS calls until somebody asks for them.

* ``usage_lookup`` -- CloudTrail event history and ``iam:GetAccessKeyLastUsed``
  for a discovered access key, across the account's enabled Regions.
* ``potential_access`` -- ``iam:SimulatePrincipalPolicy`` against a curated
  action list, with the policies of the resources the principal's own policies name
  (``GetBucketPolicy``, Secrets Manager ``GetResourcePolicy``, ``kms:GetKeyPolicy``),
  reported as POTENTIAL evidence and never merged into observed use.
  Legacy IAM connections without an explicit policy-metadata option also use this switch.
* ``secrets_inventory`` -- Secrets Manager listing and metadata-only reads
  (``DescribeSecret``, ``ListSecretVersionIds``); never ``GetSecretValue``.
"""

from __future__ import annotations

USAGE_LOOKUP = "aws_usage_lookup"
POTENTIAL_ACCESS = "iam_potential_access"
SECRETS_INVENTORY = "aws_secrets_inventory"
KEYS = (USAGE_LOOKUP, POTENTIAL_ACCESS, SECRETS_INVENTORY)
NAMES = {"usage_lookup": USAGE_LOOKUP, "potential_access": POTENTIAL_ACCESS, "secrets_inventory": SECRETS_INVENTORY}
# Which configuration property allows each one.
ALLOWED_BY = {
    USAGE_LOOKUP: "aws_usage_lookup_allowed",
    POTENTIAL_ACCESS: "iam_potential_access_allowed",
    SECRETS_INVENTORY: "aws_secrets_inventory_allowed",
}


def switch(repo, key: str) -> dict:
    """The Admin's choice for one investigation. Off until someone turns it on."""
    record = repo.get_setting(key) or {}
    value = record.get("value") or {}
    return {"enabled": value.get("enabled", False) is True,
            "updated_by": record.get("updated_by") or None,
            "updated_at": record.get("updated_at")}


def allowed(settings, key: str) -> bool:
    return bool(getattr(settings, ALLOWED_BY[key], True))


def effective(settings, repo, key: str) -> bool:
    """Allowed by configuration and switched on by an Admin."""
    return allowed(settings, key) and switch(repo, key)["enabled"]


class SettingsError(ValueError):
    def __init__(self, code, status=422):
        super().__init__(code)
        self.status = status


def onboarding_keys(purposes):
    return (["usage_lookup", "potential_access"] if set(purposes) & {"exposure", "inventory"} else []) + (
        ["secrets_inventory"] if "vault" in purposes else [])


def save(repo, settings, changes, actor, *, expected=None):
    """Reuse the installation lock/audit; an onboarding draft also pins edited switches."""
    from cremore.installation_settings import locked_installation_settings, setting_changed

    if not isinstance(changes, dict) or set(changes) - NAMES.keys() or any(type(v) is not bool for v in changes.values()):
        raise SettingsError("AWS_INVESTIGATIONS_INVALID")
    if expected is not None and (not isinstance(expected, dict) or expected.keys() != changes.keys()
                                 or any(type(v) is not bool for v in expected.values())):
        raise SettingsError("AWS_INVESTIGATIONS_INVALID")
    for name, value in changes.items():
        if value and not allowed(settings, NAMES[name]):
            raise SettingsError(f"INVESTIGATION_LOCKED: {NAMES[name].upper()}_MODE=disabled locks {name} off for this installation", 409)
    if not changes:
        return
    with locked_installation_settings(repo) as bound:
        current = {name: switch(bound, NAMES[name])["enabled"] for name in changes}
        if expected is not None and current != expected:
            raise SettingsError("SETTING_CHANGED_MEANWHILE", 409)
        changed = {name: value for name, value in changes.items() if current[name] != value}
        if changed:
            bound.put_settings({NAMES[name]: {"enabled": value} for name, value in changed.items()}, actor)
            setting_changed(bound, actor, "aws_investigations", changed)


def policy_metadata_enabled(settings, repo, spec) -> bool:
    """Explicit connection choice; preserve the old switch and installation hard lock."""
    selected = spec.iam_policy_metadata
    return allowed(settings, POTENTIAL_ACCESS) and (
        switch(repo, POTENTIAL_ACCESS)["enabled"] if selected is None else selected)


def switched_potential_access(evaluate, settings, repo):
    """Wrap a potential-access provider so it reads the switch per principal.

    The worker wires its provider once and then scans for hours; reading the
    switch at start-up would mean an Admin turning the investigation off does
    not stop the IAM calls until someone restarts the process. An unevaluated
    signal is what the risk model already expects when the privilege axis
    cannot be filled in, so nothing downstream has to know why.
    """
    from cremore.risk.model import AWSPrivilegeSignal

    def provider(principal_arn: str):
        if not effective(settings, repo, POTENTIAL_ACCESS):
            return AWSPrivilegeSignal(evaluated=False)
        return evaluate(principal_arn)

    return provider
