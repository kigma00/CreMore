"""Expand one credential owner's selected targets without copying its credential.

Version 1 is the existing single target. Version 2 keeps authentication context
beside explicit roots. Provider functions always receive one complete target;
renewal still runs once on the owner and repoints all of its children.
"""

import hashlib
import json


def target_id(target):
    return hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def records_of(record, purpose=None):
    target = record["target"]
    if "version" not in target:
        return [record] if purpose is None or purpose in record["purposes"] else []
    if (type(target.get("version")) is not int or target["version"] != 2
            or not isinstance(target.get("roots"), list) or not 1 <= len(target["roots"]) <= 100):
        raise ValueError("TARGET_VERSION_UNSUPPORTED")
    ids = set()
    for root in target["roots"]:
        if (not isinstance(root, dict) or set(root) not in ({"id", "target"}, {"id", "target", "purposes"})
                or not isinstance(root["target"], dict) or root["id"] != target_id(root["target"])
                or root["id"] in ids or set(root["target"]) & {"version", "roots", "auth", "generated"}):
            raise ValueError("TARGET_ROOT_INVALID")
        if "purposes" in root and (not isinstance(root["purposes"], list) or not root["purposes"]
                                    or any(p not in record["purposes"] for p in root["purposes"])):
            raise ValueError("TARGET_ROOT_INVALID")
        ids.add(root["id"])
    context = {key: value for key, value in target.items() if key not in ("version", "roots")}
    return [{**record, "target": {**context, **root["target"]}, "target_id": root["id"],
             "purposes": root.get("purposes", record["purposes"])}
            for root in target["roots"] if purpose is None or purpose in root.get("purposes", record["purposes"])]


def described(module, record, purpose, plan):
    return [child for root in records_of(record, purpose)
            for child in module.children(root, purpose, _plan_for(root, purpose, plan))]


def _plan_for(record, purpose, given):
    from cremore.onboarding import catalog, service

    fields = catalog.descriptor(record["provider"])["purposes"][purpose].get("plan") or []
    applicable = {f["name"] for f in fields if catalog.applies(f, record["target"])
                  and (not f.get("editions") or record["edition"] in f["editions"])}
    values = {**{f["name"]: record["target"][f["target_default"]] for f in fields
                 if f.get("target_default") in record["target"]}, **(given or {})}
    return service._fields(fields, {k: v for k, v in values.items() if k in applicable}, record["edition"],
                           what="PLAN", target=record["target"])


def normalize_plan(record, purpose, given):
    from cremore.onboarding import catalog, service

    fields = catalog.descriptor(record["provider"])["purposes"][purpose].get("plan") or []
    roots = records_of(record, purpose)
    if not roots:
        raise service.OnboardingError("ONBOARDING_EACH_FEATURE_NEEDS_TARGET")
    given = given or {}
    if not isinstance(given, dict):
        raise service.OnboardingError("PLAN_INVALID")
    allowed = {f["name"] for f in fields if (not f.get("editions") or record["edition"] in f["editions"])
               and any(catalog.applies(f, root["target"]) for root in roots)}
    if set(given) - allowed:
        raise service.OnboardingError(f"PLAN_FIELD_UNKNOWN:{min(set(given) - allowed)}")
    merged = {}
    for root in roots:
        for name, value in _plan_for(root, purpose, given).items():
            if name in merged and merged[name] != value:
                raise service.OnboardingError("TARGETS_REQUIRE_DIFFERENT_OPTIONS")
            merged[name] = value
    # Only here are all of a plan's targets known at once (one target per root later on).
    problem = getattr(catalog.module(record["provider"]), "plan_problem", None)
    if callable(problem) and (code := problem(roots, purpose, merged)):
        raise service.OnboardingError(code)
    return merged
