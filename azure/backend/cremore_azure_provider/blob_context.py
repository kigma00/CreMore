"""Container public configuration and stored access-policy IDs, never effective readers."""

from urllib.parse import quote
from xml.etree import ElementTree

from cremore.collectors.base import RequestBudget
from cremore.http_client import bounded_request
from cremore_azure_provider.blob_content import ACCOUNT, CONTAINER, VERSION, SourceHTTP


def read(payload, location, *, http_client, members=True):
    out = {"codeowners": {"status": "UNSUPPORTED"}, "author": {"status": "UNSUPPORTED"}}
    if not members:
        return out
    result = {"basis": "AZURE_BLOB_CONTAINER_ACCESS", "evidence_kind": "PROVIDER_GRANTS", "visibility": "UNKNOWN",
        "limitations": ["RBAC_AND_ADLS_ACL_NOT_EVALUATED", "SIGNED_URLS_NOT_ENUMERATED", "SHARED_KEY_NOT_ENUMERATED",
            "GRANT_IS_NOT_EFFECTIVE_PERMISSION", "NETWORK_AND_ACCOUNT_POLICY_NOT_EVALUATED",
            "STORED_ACCESS_POLICIES_NOT_IDENTITIES"]}
    parts = str(location.get("repository") or "").split("/")
    if (len(parts) != 2 or not ACCOUNT.fullmatch(parts[0]) or not CONTAINER.fullmatch(parts[1])
            or parts[0] != payload.get("account") or payload.get("container") not in (None, "", parts[1])):
        return {**out, "members": {**result, "status": "UNSUPPORTED"}}
    try:
        http = SourceHTTP(payload, http_client, budget=RequestBudget(3))
        token = http.token() if callable(http.token) else http.token
        if not token:
            raise ValueError("NO_CREDENTIAL")
        response = bounded_request(http_client, "GET", http.base + "/" + quote(parts[1], safe="$"),
            params={"restype": "container", "comp": "acl"}, headers={"Authorization": http.authorization(token), "x-ms-version": VERSION},
            follow_redirects=False, retry_429=True, before_attempt=http.budget.consume, max_response_bytes=1 << 16)
    except Exception:  # noqa: BLE001 -- never expose token-bearing transport or identity exceptions
        return {**out, "members": {**result, "status": "UNAVAILABLE"}}
    if response.status_code != 200:
        return {**out, "members": {**result, "status": "FORBIDDEN" if response.status_code in (401, 403) else "UNAVAILABLE",
            "limitations": [*result["limitations"], "ACCESS_LIST_PERMISSION_REQUIRED" if response.status_code in (401, 403)
                            else "ACCESS_LIST_UNAVAILABLE"]}}
    public = response.headers.get("x-ms-blob-public-access")
    if public not in (None, "", "blob", "container"):
        return {**out, "members": {**result, "status": "UNAVAILABLE"}}
    people = []
    try:
        root = ElementTree.fromstring(response.content)
    except ElementTree.ParseError:
        return {**out, "members": {**result, "status": "UNAVAILABLE"}}
    if root.tag != "SignedIdentifiers":
        return {**out, "members": {**result, "status": "UNAVAILABLE"}}
    policies = root.findall("SignedIdentifier")
    partial = len(policies) > 5
    for policy in policies[:5]:
        ident, permission = policy.findtext("Id"), policy.findtext("AccessPolicy/Permission") or ""
        if (not isinstance(ident, str) or not 0 < len(ident) <= 256 or not ident.isprintable()
                or len(permission) > 32 or any(letter not in "racwdlmeop" for letter in permission)):
            partial = True
            continue
        if "r" in permission:
            people.append({"login": ident, "principal_id": ident, "principal_kind": "POLICY", "name": None,
                "role": "stored_access_policy", "permission": permission, "effect": "ALLOW", "read_access": "UNKNOWN"})
    result["limitations"].append("POLICY_TIME_NOT_EVALUATED")
    if public:
        people.append({"login": "anonymous", "principal_id": "anonymous", "principal_kind": "PUBLIC", "name": None,
            "role": "public_configuration", "permission": public, "effect": "ALLOW", "read_access": "UNKNOWN"})
        result["limitations"].append("PUBLIC_GRANT_NOT_EFFECTIVE_ACCESS")
    # No header means no container public grant, never an empty effective-reader list.
    return {**out, "members": {**result, "status": "OBSERVED", "people": people, "truncated": partial}}
