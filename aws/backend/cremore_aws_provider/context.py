"""Bounded S3 policy/ACL principals from the account's approved scanner; never an IAM evaluator."""

import fnmatch
import json
import re

from cremore_aws_provider import aws_access

_ACCOUNT = re.compile(r"[0-9]{12}")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


def _matches(value, pattern):
    # IAM resource wildcards are '*' and '?'; bracket characters are literal object-key bytes.
    return fnmatch.fnmatchcase(value, pattern.replace("[", "[[]"))


def read(payload, location, *, aws_sessions, check_scope, members=True):
    out = {"codeowners": {"status": "UNSUPPORTED"}, "author": {"status": "UNSUPPORTED"}}
    if not members:
        return out
    result = {"basis": "AWS_S3_POLICY_ACL", "evidence_kind": "PROVIDER_GRANTS", "visibility": "UNKNOWN",
        "limitations": ["GRANT_IS_NOT_EFFECTIVE_PERMISSION", "IAM_POLICIES_NOT_EVALUATED", "GROUP_MEMBERS_NOT_EXPANDED",
        "SIGNED_URLS_NOT_ENUMERATED", "CURRENT_POLICY_NOT_HISTORICAL", "NETWORK_AND_KMS_NOT_EVALUATED"]}
    account, bucket, key = payload.get("account_id"), location.get("repository"), location.get("path")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account) or not isinstance(bucket, str)
            or not _BUCKET.fullmatch(bucket) or payload.get("bucket") != bucket or not isinstance(key, str)
            or not key or len(key) > 1024 or not aws_sessions or not callable(check_scope)):
        return {**out, "members": {**result, "status": "BLOCKED", "limitations": ["AWS_APPROVED_SCANNER_REQUIRED"]}}
    try:
        check_scope()
        session = aws_sessions.open(account, aws_access.SCANNER)
        code, _current, approved = aws_sessions.refusal(account, aws_access.SCANNER)
        partition = approved.get("partition") if isinstance(approved, dict) else None
        if code or partition not in ("aws", "aws-cn", "aws-us-gov", "aws-eusc"):
            raise ValueError("AWS_PARTITION_UNAVAILABLE")
        client = session.client("s3", payload.get("region") or None)
    except Exception:  # noqa: BLE001 -- expose only a fixed authorization code, never credential-bearing errors
        return {**out, "members": {**result, "status": "BLOCKED", "limitations": ["AWS_APPROVED_SCANNER_REQUIRED"]}}

    def check():
        check_scope()
        code, current, approved = aws_sessions.refusal(account, aws_access.SCANNER)
        if code or session.account_id != account or session.pin != aws_access.validation_key(current, aws_access.SCANNER, approved["revision"]):
            raise ValueError("AWS_ACCOUNT_SETTINGS_CHANGED")

    people, partial, failures, observed = [], False, [], 0
    def add(ident, kind, permission, effect, role):
        nonlocal partial
        if not isinstance(ident, str) or not 0 < len(ident) <= 256 or len(people) >= 300:
            partial = True
            return
        people.append({"login": ident, "principal_id": ident, "principal_kind": kind, "name": None,
            "role": role, "permission": permission, "effect": effect, "read_access": "UNKNOWN"})

    def read_call(operation, **kwargs):
        nonlocal observed
        check()
        try:
            body = getattr(client, operation)(Bucket=bucket, ExpectedBucketOwner=account, **kwargs)
            if not isinstance(body, dict):
                raise TypeError("MALFORMED")
            observed += 1
            return body
        except Exception as exc:  # noqa: BLE001 -- normalize SDK/network failures without keeping response text
            response = getattr(exc, "response", None)
            error = response.get("Error") if isinstance(response, dict) else None
            code = error.get("Code") if isinstance(error, dict) else None
            if code in ("NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration"):
                observed += 1
                return {"_absent": True}
            failures.append("FORBIDDEN" if code in ("AccessDenied", "AccessDeniedException", "403") else "UNAVAILABLE")
            return {}

    try:
        policy_body = read_call("get_bucket_policy")
        raw_policy = policy_body.get("Policy")
        partial |= raw_policy is None and not policy_body.get("_absent")
        if raw_policy is not None:
            if not isinstance(raw_policy, str) or len(raw_policy) > 1 << 20:
                partial = True
            else:
                try:
                    policy = json.loads(raw_policy)
                    statements = policy.get("Statement", []) if isinstance(policy, dict) else None
                    statements = [statements] if isinstance(statements, dict) else statements
                    if not isinstance(statements, list):
                        raise TypeError("MALFORMED")
                    partial |= len(statements) > 100
                    for statement in statements[:100]:
                        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
                            partial = True
                            continue
                        if any(field in statement for field in ("NotPrincipal", "NotResource", "NotAction")):
                            result["limitations"].append("NEGATED_POLICY_NOT_EVALUATED")
                            continue
                        resources, actions = statement.get("Resource", []), statement.get("Action", [])
                        resources = [resources] if isinstance(resources, str) else resources
                        actions = [actions] if isinstance(actions, str) else actions
                        if not isinstance(resources, list) or not isinstance(actions, list):
                            partial = True
                            continue
                        partial |= len(resources) > 100 or len(actions) > 32
                        resource = f"arn:{partition}:s3:::{bucket}/{key}"
                        if any(not isinstance(value, str) or len(value) > 2048 or "${" in value for value in resources[:100]):
                            result["limitations"].append("POLICY_RESOURCE_NOT_EVALUATED")
                            partial = True
                        applicable = any(isinstance(value, str) and len(value) <= 2048 and "${" not in value and _matches(resource, value)
                            for value in resources[:100])
                        reads = [action for action in actions[:32] if isinstance(action, str) and len(action) <= 256
                            and (_matches("s3:getobject", action.lower()) or _matches("s3:getobjectversion", action.lower()))]
                        if not applicable or not reads:
                            continue
                        if statement.get("Condition"):
                            result["limitations"].append("CONDITIONAL_GRANTS_NOT_EVALUATED")
                        principals = statement.get("Principal")
                        principals = {"AWS": principals} if isinstance(principals, (str, list)) else principals
                        if not isinstance(principals, dict):
                            partial = True
                            continue
                        for principal_type, values in list(principals.items())[:5]:
                            values = [values] if isinstance(values, str) else values
                            if not isinstance(values, list):
                                partial = True
                                continue
                            partial |= len(values) > 100
                            for ident in values[:100]:
                                kind = "PUBLIC" if ident == "*" else "SERVICE_PRINCIPAL" if principal_type == "Service" else "UNKNOWN"
                                for action in reads:
                                    add(ident, kind, action, statement["Effect"].upper(), "bucket_policy")
                except (ValueError, TypeError):
                    partial = True
        for operation in ("get_bucket_acl", "get_object_acl"):
            version = location.get("object_version")
            kwargs = {"Key": key, **({"VersionId": version} if isinstance(version, str) and version else {})} if operation == "get_object_acl" else {}
            body = read_call(operation, **kwargs)
            grants = body.get("Grants")
            if not isinstance(grants, list):
                partial = True
                continue
            partial |= len(grants) > 100
            for grant in grants[:100]:
                subject = grant.get("Grantee") if isinstance(grant, dict) else None
                permission = grant.get("Permission") if isinstance(grant, dict) else None
                if not isinstance(subject, dict):
                    partial = True
                    continue
                if permission not in ("READ", "FULL_CONTROL"):
                    continue
                ident = subject.get("ID") or subject.get("URI") or subject.get("EmailAddress")
                kind = "PUBLIC" if ident == "http://acs.amazonaws.com/groups/global/AllUsers" else (
                    "AUTHENTICATED" if ident == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" else "UNKNOWN")
                add(ident, kind, permission, "ALLOW", "object_acl" if operation == "get_object_acl" else "bucket_acl")
                if operation == "get_bucket_acl":
                    result["limitations"].append("BUCKET_ACL_IS_NOT_OBJECT_READ")
        block_body = read_call("get_public_access_block")
        block = block_body.get("PublicAccessBlockConfiguration")
        partial |= not isinstance(block, dict) and not block_body.get("_absent")
        if isinstance(block, dict) and any(block.get(flag) is True for flag in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            result["limitations"].append("PUBLIC_ACCESS_BLOCK_ENABLED")
        check()
    except Exception:  # noqa: BLE001 -- a revoked scanner/scope discards all previously read principals
        return {**out, "members": {**result, "status": "BLOCKED", "limitations": ["AWS_AUTHORIZATION_CHANGED"]}}
    if any(p["principal_kind"] in ("PUBLIC", "AUTHENTICATED") for p in people):
        result["limitations"].append("PUBLIC_GRANT_NOT_EFFECTIVE_ACCESS")
    if failures:
        result["limitations"].append("ACCESS_LIST_PERMISSION_REQUIRED" if "FORBIDDEN" in failures else "ACCESS_LIST_UNAVAILABLE")
    return {**out, "members": {**result, "status": ("FORBIDDEN" if "FORBIDDEN" in failures else "UNAVAILABLE") if failures else "OBSERVED",
        "people": people, "truncated": partial or bool(failures) or observed != 4,
        "limitations": list(dict.fromkeys(result["limitations"]))}}
