"""Pinned ARM reads, plus one explicit read-only POST action: listKeys."""

import re
from urllib.parse import parse_qs, urlsplit

from cremore_azure_provider.entra.transport import GUID
from cremore_azure_provider.metadata.transport import ApiError, ReadTransport, default_token

from . import ORIGIN, STORAGE_VERSION

# Azure allows Unicode letters and digits (Char.IsLetterOrDigit) in resource group names; str `\w` is that plus `_`.
RESOURCE_GROUP = r"[\w.()-]{1,90}"
STORAGE_ID = re.compile(r"/subscriptions/(" + GUID + r")/resourceGroups/" + RESOURCE_GROUP
                        + r"/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}", re.IGNORECASE)
VAULT_ID = re.compile(r"/subscriptions/(" + GUID + r")/resourceGroups/" + RESOURCE_GROUP
                      + r"/providers/Microsoft\.KeyVault/vaults/[A-Za-z][A-Za-z0-9-]{1,23}", re.IGNORECASE)


def page_query(link, *, path, subscription, vaults=False):
    """Retain an ARM pagination URL only inside its approved collection."""
    if link in (None, ""):
        return None
    if not isinstance(link, str) or len(link) > 12000:
        raise ApiError("invalid_pagination")
    try:
        parsed = urlsplit(link)
        allowed_paths = {path.casefold()}
        if vaults:
            # Microsoft's vault list response can continue through the ARM
            # resources listing, still within the same approved subscription.
            allowed_paths.add(f"/subscriptions/{subscription}/resources".casefold())
        if (parsed.scheme != "https" or parsed.hostname != "management.azure.com"
                or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443)
                or parsed.path.casefold() not in allowed_paths):
            raise ValueError
        query = parse_qs(parsed.query)
        if (set(query) - {"api-version", "$skiptoken", "$top", "$filter"}
                or any(len(values) != 1 for values in query.values())
                or not query.get("$skiptoken") or not 1 <= len(query["$skiptoken"][0]) <= 4096):
            raise ValueError
        params = {key: values[0] for key, values in query.items()}
        if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}(?:-preview)?", params.get("api-version", "")):
            raise ValueError
        if "$top" in params and (not params["$top"].isdigit() or not 1 <= int(params["$top"]) <= 1000):
            raise ValueError
        if "$filter" in params and (not vaults or params["$filter"].casefold() != "resourcetype eq 'microsoft.keyvault/vaults'"):
            raise ValueError
    except (ValueError, TypeError):
        raise ApiError("invalid_pagination") from None
    return {"path": parsed.path, "params": params}


class ArmTransport(ReadTransport):
    def __init__(self, client, token, *, spec, max_requests, check):
        self.spec = spec
        if spec.origin != ORIGIN:
            raise ValueError("AZURE_ARM_ORIGIN_REQUIRED")
        self.subscriptions = {s.id.casefold() for s in spec.scopes if s.kind == "subscription"}
        super().__init__(client, token, origin=spec.origin, options=spec.options,
                         api_version=None, max_requests=max_requests, check=check)

    def get(self, path, params=None):
        discovery = all(s.kind == "organization" for s in self.spec.scopes)
        allowed = discovery and path in {"/subscriptions", "/tenants"}
        match = VAULT_ID.fullmatch(path) or re.fullmatch(
            r"/subscriptions/(" + GUID + r")(?:/(?:resources|providers/Microsoft\.(?:KeyVault/vaults|Storage/storageAccounts)))?",
            path, re.IGNORECASE)
        if match and match[1].casefold() in self.subscriptions:
            allowed = True
        if not allowed:
            raise ValueError("UNAPPROVED_AZURE_ARM_PATH")
        return self._request("GET", path, params)

    def list_keys(self, account):
        if (not self.spec.options.include_values or "issuer_value" not in self.spec.capabilities
                or account.casefold() not in {item.casefold() for item in self.spec.options.azure_storage_accounts}
                or not STORAGE_ID.fullmatch(account)
                or account.split("/")[2].casefold() not in self.subscriptions):
            raise ValueError("AZURE_STORAGE_ACCOUNT_NOT_APPROVED_FOR_VALUES")
        return self._request("POST", account + "/listKeys", {"api-version": STORAGE_VERSION})


def token_for_spec(spec):
    # Configured tenant is verified against each subscription response before
    # any resource-specific operation; no token claims are logged or persisted.
    return default_token(ORIGIN + "/.default", authority="login.microsoftonline.com", tenant_id=spec.tenant)
