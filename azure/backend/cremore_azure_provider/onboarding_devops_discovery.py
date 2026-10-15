"""PAT authentication and bounded project metadata lists within one organization."""

import base64
from urllib.parse import quote

from cremore.onboarding.probe import json_body, probe
from cremore_azure_provider.devops_content import API_VERSION, CLOUD, valid_name


def _read(connection, secrets, context, path, params=None):
    from cremore_azure_provider.onboarding import OnboardingValueError

    target = connection["target"]
    base = target.get("base_url") or CLOUD
    authorization = "Basic " + base64.b64encode((":" + secrets["credential"]["token"]).encode()).decode()
    with context.http_client() as client:
        result = probe(client, "GET", base + "/" + quote(target["organization"], safe="") + path,
                       params=params, headers={"Authorization": authorization, "Accept": "application/json"},
                       missing=(203, 401, 403))
    if result[0] != "GRANTED":
        raise OnboardingValueError(result[1] or "REQUEST_FAILED")
    body = json_body(result[2])
    if not isinstance(body, dict):
        raise OnboardingValueError("MALFORMED_RESPONSE")
    return body, result[2].headers


def authenticate(connection, secrets, context):
    from cremore_azure_provider.onboarding import OnboardingValueError, _guid

    body, _ = _read(connection, secrets, context, "/_apis/connectionData", {"connectOptions": 0})
    user = body.get("authenticatedUser")
    try:
        ident = _guid(user.get("id") if isinstance(user, dict) else None, "AUTHENTICATION_REQUIRED")
    except OnboardingValueError:
        return {"status": "MISSING", "detail": "AUTHENTICATION_REQUIRED"}
    if ident in {"00000000-0000-0000-0000-000000000000", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"} or user.get("isAnonymous"):
        return {"status": "MISSING", "detail": "AUTHENTICATION_REQUIRED"}
    return {"status": "GRANTED", "subject": ident}


def discover(connection, secrets, context):
    from cremore_azure_provider.onboarding import OnboardingValueError

    target, purposes = connection["target"], connection["purposes"]
    base = {k: v for k, v in target.items() if k in {"base_url", "organization"}}
    organization_purposes = [p for p in purposes if p in {"inventory", "remediation"}]
    roots = ([{"label": target["organization"], "target": base, "purposes": organization_purposes}]
             if organization_purposes and not connection.get("discovery_cursor") else [])
    if "exposure" not in purposes:
        return roots, "COMPLETE"
    cursor = connection.get("discovery_cursor")
    body, headers = _read(connection, secrets, context, "/_apis/projects", {
        "api-version": API_VERSION[connection["edition"]], "$top": 100, "stateFilter": "wellFormed",
        **({"continuationToken": cursor} if cursor is not None else {})})
    rows = body.get("value")
    if not isinstance(rows, list) or len(rows) > 100:
        raise OnboardingValueError("MALFORMED_RESPONSE")
    for row in rows:
        if not isinstance(row, dict) or not valid_name(row.get("name")):
            raise OnboardingValueError("MALFORMED_RESPONSE")
        roots.append({"label": row["name"], "target": {**base, "project": row["name"]}, "purposes": ["exposure"]})
    following = headers.get("x-ms-continuationtoken") or None
    if following is not None and (not isinstance(following, str) or len(following) > 20 or not following.isdigit()
                                   or int(following) <= int(cursor or 0)):
        raise OnboardingValueError("PAGINATION_INVALID")
    return roots, "PARTIAL" if following else "COMPLETE", following
