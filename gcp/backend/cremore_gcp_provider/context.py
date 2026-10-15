"""Current bucket IAM bindings and version-pinned object ACL grants, not effective readers."""

from urllib.parse import quote

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_gcp_provider.content import SourceHTTP


def read(payload, location, *, http_client, members=True):
    from cremore_gcp_provider.source import validate_config

    out = {"codeowners": {"status": "UNSUPPORTED"}, "author": {"status": "UNSUPPORTED"}}
    if not members:
        return out
    result = {"basis": "GCS_BUCKET_IAM_OBJECT_ACL", "evidence_kind": "PROVIDER_GRANTS", "visibility": "UNKNOWN",
        "limitations": ["INHERITED_PERMISSIONS_NOT_EVALUATED", "GROUP_MEMBERS_NOT_EXPANDED",
        "GRANT_IS_NOT_EFFECTIVE_PERMISSION", "SIGNED_URLS_NOT_ENUMERATED", "CURRENT_POLICY_NOT_HISTORICAL"]}
    bucket, key = location.get("repository"), location.get("path")
    try:
        validate_config({"bucket": bucket})
    except ValueError:
        return {**out, "members": {**result, "status": "UNSUPPORTED"}}
    if payload.get("bucket") not in (None, "", bucket) or not isinstance(key, str) or not key or len(key) > 1024:
        return {**out, "members": {**result, "status": "UNSUPPORTED"}}
    http = SourceHTTP(payload, http_client, budget=RequestBudget(5))
    route, people, partial, failure = "/b/" + quote(bucket, safe=""), [], False, None
    try:
        metadata, _ = http.get(route, params={"projection": "noAcl"})
        if not isinstance(metadata, dict) or metadata.get("name") != bucket:
            return {**out, "members": {**result, "status": "UNAVAILABLE"}}
    except CollectorError as exc:
        return {**out, "members": {**result, "status": "FORBIDDEN" if exc.detail in ("401", "403") else "UNAVAILABLE"}}

    def add(ident, permission, kind, role):
        nonlocal partial
        if not isinstance(ident, str) or not 0 < len(ident) <= 256 or len(people) >= 300:
            partial = True
            return
        people.append({"login": ident, "principal_id": ident, "principal_kind": kind, "name": None,
            "role": role, "permission": permission, "effect": "ALLOW", "read_access": "UNKNOWN"})

    def fail(exc):
        nonlocal failure, partial
        failure, partial = ("FORBIDDEN" if failure == "FORBIDDEN" or exc.detail in ("401", "403") else "UNAVAILABLE"), True
        result["limitations"].append("ACCESS_LIST_PERMISSION_REQUIRED" if failure == "FORBIDDEN" else "ACCESS_LIST_UNAVAILABLE")

    try:
        policy, _ = http.get(route + "/iam", params={"optionsRequestedPolicyVersion": 3})
        bindings = policy.get("bindings", []) if isinstance(policy, dict) else None
        if not isinstance(bindings, list):
            raise CollectorError("SOURCE_RESPONSE_MALFORMED")
        partial |= len(bindings) > 300
        for binding in bindings[:300]:
            principals = binding.get("members") if isinstance(binding, dict) else None
            permission = binding.get("role") if isinstance(binding, dict) else None
            if not isinstance(principals, list) or not isinstance(permission, str) or len(permission) > 256:
                partial = True
                continue
            if binding.get("condition"):
                result["limitations"].append("CONDITIONAL_GRANTS_NOT_EVALUATED")
            partial |= len(principals) > 300
            for ident in principals[:300]:
                kind = ("PUBLIC" if ident == "allUsers" else "AUTHENTICATED" if ident == "allAuthenticatedUsers" else
                    {"user": "USER", "group": "GROUP", "serviceAccount": "SERVICE_PRINCIPAL"}.get(str(ident).split(":", 1)[0], "UNKNOWN"))
                add(ident, permission, kind, "iam_binding")
    except CollectorError as exc:
        fail(exc)
    iam = metadata.get("iamConfiguration") if isinstance(metadata.get("iamConfiguration"), dict) else {}
    uniform = iam.get("uniformBucketLevelAccess") if isinstance(iam.get("uniformBucketLevelAccess"), dict) else {}
    if uniform.get("enabled") is True:
        result["limitations"].append("OBJECT_ACL_DISABLED_BY_UNIFORM_ACCESS")
    else:
        version = location.get("object_version")
        params = {"generation": version} if isinstance(version, str) and version.isdecimal() else {}
        try:
            acl, _ = http.get(route + "/o/" + quote(key, safe="") + "/acl", params=params)
            rows = acl.get("items", []) if isinstance(acl, dict) else None
            if not isinstance(rows, list):
                raise CollectorError("SOURCE_RESPONSE_MALFORMED")
            partial |= len(rows) > 300
            for row in rows[:300]:
                if not isinstance(row, dict) or row.get("role") not in ("READER", "OWNER"):
                    partial = True
                    continue
                ident = row.get("entity")
                kind = "PUBLIC" if ident == "allUsers" else "AUTHENTICATED" if ident == "allAuthenticatedUsers" else (
                    "USER" if str(ident).startswith("user-") else "GROUP" if str(ident).startswith("group-") else "UNKNOWN")
                add(ident, row["role"], kind, "object_acl")
        except CollectorError as exc:
            fail(exc)
    if any(p["principal_kind"] in ("PUBLIC", "AUTHENTICATED") for p in people):
        result["limitations"].append("PUBLIC_GRANT_NOT_EFFECTIVE_ACCESS")
    return {**out, "members": {**result, "status": failure or "OBSERVED", "people": people, "truncated": partial,
        "limitations": list(dict.fromkeys(result["limitations"]))}}
