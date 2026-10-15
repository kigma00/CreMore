"""Graph GET paths and national-cloud origins; never follows response URLs."""

import re
from urllib.parse import parse_qs, urlsplit

from cremore_azure_provider.metadata.transport import ApiError, ReadTransport, default_token

GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
CLOUDS = {
    "https://graph.microsoft.com": "login.microsoftonline.com",
    "https://graph.microsoft.us": "login.microsoftonline.us",
    "https://dod-graph.microsoft.us": "login.microsoftonline.us",
    "https://microsoftgraph.chinacloudapi.cn": "login.chinacloudapi.cn",
}


def cursor_from_link(link, origin, path):
    if link in (None, ""):
        return ""
    if not isinstance(link, str) or len(link) > 8192:
        raise ApiError("invalid_pagination")
    try:
        parsed = urlsplit(link)
        approved = urlsplit(origin)
        if (parsed.scheme != "https" or parsed.hostname != approved.hostname
                or parsed.port not in (None, 443) or parsed.username or parsed.password
                or parsed.fragment or parsed.path != path):
            raise ValueError
        query = parse_qs(parsed.query)
        values = query.get("$skiptoken", [])
        if len(values) != 1 or not valid_cursor(values[0]):
            raise ValueError
    except ValueError:
        raise ApiError("invalid_pagination") from None
    return values[0]


def valid_cursor(value):
    return isinstance(value, str) and 0 < len(value) <= 4096 and all(32 <= ord(c) <= 126 for c in value)


class GraphTransport(ReadTransport):
    paths = (re.compile(r"/v1\.0/(?:organization|applications|servicePrincipals)"),
             re.compile(r"/v1\.0/applications/" + GUID + r"/federatedIdentityCredentials"))

    def __init__(self, client, token, *, origin, options, max_requests, check):
        if origin not in CLOUDS:
            raise ValueError("AZURE_ENTRA_GRAPH_ORIGIN_REQUIRED")
        # One object read is a narrow $select: a certificate's public key, or an API's app roles.
        self.selects = []
        if "public_certificates" in options.sources:
            self.paths = (*self.paths, re.compile(r"/v1\.0/(?:applications|servicePrincipals)/" + GUID))
            self.selects.append({"$select": "id,appId,keyCredentials"})
        if "app_permissions" in options.sources:
            self.paths = (*self.paths, re.compile(r"/v1\.0/servicePrincipals/" + GUID + r"(?:/appRoleAssignments)?"),
                          re.compile(r"/v1\.0/roleManagement/directory/(?:roleAssignments|roleDefinitions/" + GUID + ")"))
            self.selects.append({"$select": "id,displayName,appRoles"})
        if "credential_sign_ins" in options.sources:
            self.paths = (*self.paths, re.compile(r"/beta/auditLogs/signIns"))
        if "directory_audits" in options.sources:
            self.paths = (*self.paths, re.compile(r"/v1\.0/auditLogs/directoryAudits"))
        super().__init__(client, token, origin=origin, options=options,
                         max_requests=max_requests, check=check, api_version=None)

    def get(self, path, params=None):
        if re.fullmatch(r"/v1\.0/(?:applications|servicePrincipals)/" + GUID, path) and (
                params not in self.selects or path.startswith("/v1.0/applications/")
                and params != {"$select": "id,appId,keyCredentials"}):
            raise ValueError("UNAPPROVED_AZURE_CERTIFICATE_QUERY")
        return super().get(path, params)


def token_for_spec(spec):
    return default_token(spec.origin + "/.default", authority=CLOUDS[spec.origin], tenant_id=spec.tenant)
